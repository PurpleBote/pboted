/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <arpa/inet.h>
#include <cstring>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "BoteContext.h"
#include "compat.h"
#include "Logging.h"
#include "SMTP.h"

namespace bote
{
namespace smtp
{

SMTP::SMTP (const std::string &address, int port)
  : started (false),
    smtp_thread (nullptr),
    m_address (address),
    m_port (port)
{}

SMTP::~SMTP ()
{
  stop ();

  if (smtp_thread)
    {
      smtp_thread->join ();
      delete smtp_thread;
      smtp_thread = nullptr;
    }
}

void
SMTP::start ()
{
  /* ToDo: add error handling */

  if (started)
    return;

  struct addrinfo hints;
  memset(&hints, 0, sizeof(struct addrinfo));

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV | AI_NUMERICHOST;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  struct addrinfo *res;

  char c_port[16];
  sprintf(c_port, "%d", m_port);

  int rc = getaddrinfo (m_address.c_str (), c_port, &hints, &res);
  if (rc != RC_SUCCESS || res == nullptr)
    {
      LogPrint (eLogError, "SMTP Invalid address or port: ",
                m_address, ":", m_port, ": ", gai_strerror(rc));
      return;
    }

  server_sockfd = socket (res->ai_family, res->ai_socktype, res->ai_protocol);

  if (server_sockfd == SOCKET_INVALID)
    {
      freeaddrinfo (res);
      LogPrint (eLogError, "SMTP: Socket create error: ", strerror (errno));
    }

  int on = 1; 
  rc = setsockopt(server_sockfd, SOL_SOCKET,  SO_REUSEADDR,
                  (char *)&on, sizeof(on));
  if (rc == RC_ERROR)
  {
    LogPrint (eLogError, "SMTP: setsockopt(SO_REUSEADDR) failed: ",
              strerror (errno));
    CLOSE_SOCKET (server_sockfd);
    freeaddrinfo (res);
    return;
  }

/*
#ifndef _WIN32
  struct timeval tv;
  tv.tv_sec = SMTP_SOCK_TIMEOUT;
  tv.tv_usec = 0;
  rc = setsockopt(server_sockfd, SOL_SOCKET, SO_RCVTIMEO,
                  (const char*)&tv, sizeof tv);
#else
  DWORD timeout = SMTP_SOCK_TIMEOUT * 1000;
  rc = setsockopt(server_sockfd, SOL_SOCKET, SO_RCVTIMEO,
                  (const char*)&timeout, sizeof timeout);
#endif
  if (rc == RC_ERROR)
  {
    LogPrint (eLogError, "SMTP: setsockopt(SO_RCVTIMEO) failed: ",
              strerror (errno));
    CLOSE_SOCKET (server_sockfd);
    freeaddrinfo (res);
    return;
  }
*/

  rc = ioctl(server_sockfd, FIONBIO, (char *)&on);
  if (rc == RC_ERROR)
  {
    LogPrint (eLogError, "SMTP: ioctl() failed: ", strerror (errno));
    CLOSE_SOCKET (server_sockfd);
    freeaddrinfo (res);
    return;
  }

  rc = bind (server_sockfd, res->ai_addr, res->ai_addrlen);
  if (rc == RC_ERROR)
    {
      freeaddrinfo (res);
      LogPrint (eLogError, "SMTP: Bind error: ", strerror (errno));
      return;
    }

  freeaddrinfo (res);

  rc = listen (server_sockfd, SMTP_MAX_CLIENTS);
  if (rc == RC_ERROR)
    {
      LogPrint (eLogError, "SMTP: Listen error: ", strerror (errno));
      return;
    }

  memset(fds, 0, sizeof(fds));

  fds[0].fd = server_sockfd;
  fds[0].events = POLLIN;

  started = true;

  smtp_thread = new std::thread ([this] { run (); });
}

void
SMTP::stop ()
{
  if (!started)
    return;

  LogPrint (eLogInfo, "SMTP: Stopping");

  started = false;

  
  for (int sid = 0; sid < nfds; sid++)
    {
      /* Clean up all of the sockets that are open */
      if (fds[sid].fd != SOCKET_INVALID)
        {
          CLOSE_SOCKET (fds[sid].fd);
          fds[sid].revents = POLLHUP;
        }

      /* Free allocated session buffer */
      if (session.need_clean)
        {
          free (session.buf);
          session.need_clean = false;
        }
    }
  LogPrint (eLogInfo, "SMTP: Sockets closed");

  LogPrint (eLogInfo, "SMTP: Stopped");
}

void
SMTP::run ()
{
  LogPrint (eLogInfo, "SMTP: Started");

  int rc = 0, current_sc = 0;
  bool compress_array = false;

  while (started)
    {
      LogPrint(eLogDebug, "SMTP: run: Waiting on poll");
      rc = poll(fds, nfds, SMTP_POLL_TIMEOUT);

      if (!started)
        return;

      /* Check to see if the poll call failed */
      if (rc == POLL_ERROR)
        {
          if (errno == EINTR) continue;

          LogPrint(eLogError, "SMTP: Poll error: ", strerror (errno));
          break;
        }

      if (rc == POLL_TIMEOUT)
        {
          LogPrint(eLogDebug, "SMTP: Poll timed out");
          continue;
        }
      current_sc = nfds;
      for (int sid = 0; sid < current_sc; sid++)
        {
          LogPrint(eLogDebug, "SMTP: Revents ", sid, ": ", fds[sid].revents);
          if (fds[sid].revents == 0)
            continue;

          if (fds[sid].revents != POLLIN)
            {
              LogPrint(eLogError, "SMTP: Revents ", sid, ": ", fds[sid].revents);
              continue;
            }
      
          if (fds[sid].fd == server_sockfd && fds[sid].revents & POLLIN)
            {
              LogPrint(eLogDebug, "SMTP: run: Checking server socket");
              do
                {
                  struct sockaddr_in client_addr;
                  memset(&client_addr, 0, sizeof(struct sockaddr_in));
                  socklen_t sin_size = sizeof (client_addr);

                  client_sockfd = accept(fds[sid].fd, (struct sockaddr *)&client_addr,
                                         &sin_size);

                  if (client_sockfd == RC_ERROR)
                  {
                    /*
                     * EWOULDBLOCK and EAGAIN - socket is marked nonblocking
                     * and no connections are present to be accepted
                     */
                    if (started && errno != EWOULDBLOCK && errno != EAGAIN)
                    {
                      LogPrint (eLogError, "SMTP: Accept error: ",
                                strerror (errno));
                    }
                    break;
                  }

                  LogPrint (eLogInfo, "SMTP: Received connection ", nfds, " from ",
                            inet_ntoa (client_addr.sin_addr));

                  if (nfds >= SMTP_MAX_CLIENTS)
                    {
                      LogPrint (eLogWarning, "SMTP: run: Session limit");
                      CLOSE_SOCKET (client_sockfd);
                      continue;
                    }

                  fds[nfds].fd = client_sockfd;
                  fds[nfds].events = POLLIN;

                  session.state = STATE_QUIT;

                  nfds++;
                } while (client_sockfd != SOCKET_INVALID);
              LogPrint (eLogDebug, "SMTP: End of accept");
            }
        }

      LogPrint(eLogDebug, "SMTP: run: Checking clients sockets");
      current_sc = nfds;
      for (int sid = 0; sid < current_sc; sid++)
        {
          LogPrint(eLogDebug, "SMTP: Revents ", sid, ": ", fds[sid].revents);
          
          if (fds[sid].fd != server_sockfd)
            {
              if (session.state == STATE_QUIT)
                {
                  reply (sid, reply_2XX[CODE_220]);
                  session.state = STATE_INIT;
                }

              LogPrint (eLogDebug, "SMTPsession: New data ", sid, ": ");
              bool need_close = false;
              /* Receive all incoming data on this socket */
              /* until the recv fails with EWOULDBLOCK */
              do
                {
                  if (fds[sid].fd == SOCKET_INVALID)
                    {
                      LogPrint (eLogWarning, "SMTPsession: Session #", sid,
                           " closed");
                        need_close = true;
                        break;
                    }

                  if (session.need_clean)
                    {
                      free (session.buf);
                      session.need_clean = false;
                    }

                  session.buf = (char *)malloc (SMTP_BUF_SIZE);
                  session.need_clean = true;
                  memset (session.buf, 0, SMTP_BUF_SIZE);
                  ssize_t rc = recv (fds[sid].fd, session.buf,
                                     SMTP_BUF_SIZE - 1, MSG_DONTWAIT);
                  if (rc == RECV_ERROR)
                  {
                    if (started && errno != EWOULDBLOCK && errno != EAGAIN)
                      {
                        LogPrint (eLogError, "SMTPsession: recv error: ",
                                  strerror (errno));
                        need_close = true;
                      }
                    break;
                  }

                  if (rc == RECV_CLOSED)
                    {
                      LogPrint (eLogDebug, "SMTPsession: Connection ", sid,
                                " closed");
                      need_close = true;
                      break;
                    }

                  /* Data was received  */
                  std::string str_buf (session.buf);
                  str_buf = str_buf.substr (0, str_buf.size () - 2);
                  LogPrint (eLogDebug, "SMTPsession: Request stream ", sid, ": ", str_buf);

                  respond (sid);
                } while (started);

              if (need_close)
                {
                  fds[sid].revents = POLLHUP;
                  if (fds[sid].fd != SOCKET_INVALID)
                    {
                      CLOSE_SOCKET (fds[sid].fd);
                      fds[sid].fd = SOCKET_INVALID;
                    }
                  
                  compress_array = true;

                  if (session.need_clean)
                    {
                      free (session.buf);
                      session.need_clean = false;
                    }

                  LogPrint (eLogDebug, "SMTPsession: Closed ", sid);
                }
            }
        }

      if (!compress_array)
        continue;

      /* We need to squeeze together the array and */
      /* decrement the number of file descriptors */
      compress_array = false;
      for (int sid = 0; sid < nfds; sid++)
        {
          LogPrint (eLogDebug, "POP3session: sid: ", sid, ", nfds: ", nfds);
          /* Skip good FD */
          if (fds[sid].fd != SOCKET_INVALID)
            continue;

          for(int j = sid; j < nfds; j++)
            {
              LogPrint (eLogDebug, "POP3session: Session #", j + 1, " to #", j);
              fds[j].fd = fds[j + 1].fd;
            }
          sid--;
          nfds--;
          LogPrint (eLogDebug, "POP3session: sid: ", sid, ", nfds: ", nfds);
        }
    }
}

void
SMTP::respond (int sid)
{
  /// https://datatracker.ietf.org/doc/html/rfc5321#section-2.4
  cmd_to_upper (session.buf);

  /// SMTP Basic
  if (strncmp (session.buf, "HELO", SMTP_COMMAND_LEN) == 0)
    {
      HELO (sid);
    }
  else if (strncmp (session.buf, "EHLO", SMTP_COMMAND_LEN) == 0)
    {
      EHLO (sid);
    }
  else if (strncmp (session.buf, "MAIL", SMTP_COMMAND_LEN) == 0)
    {
      MAIL (sid);
    }
  else if (strncmp (session.buf, "RCPT", SMTP_COMMAND_LEN) == 0)
    {
      RCPT (sid);
    }
  else if (strncmp (session.buf, "DATA", SMTP_COMMAND_LEN) == 0)
    {
      DATA (sid);
    }
  else if (strncmp (session.buf, "RSET", SMTP_COMMAND_LEN) == 0)
    {
      RSET (sid);
    }
  else if (strncmp (session.buf, "VRFY", SMTP_COMMAND_LEN) == 0)
    {
      VRFY (sid);
    }
  else if (strncmp (session.buf, "NOOP", SMTP_COMMAND_LEN) == 0)
    {
      NOOP (sid);
    }
  else if (strncmp (session.buf, "QUIT", SMTP_COMMAND_LEN) == 0)
    {
      QUIT (sid);
    }
  /// Extensions
  else if (strncmp (session.buf, "AUTH", SMTP_COMMAND_LEN) == 0)
    {
      AUTH (sid);
    }
  else if (strncmp (session.buf, "EXPN", SMTP_COMMAND_LEN) == 0)
    {
      EXPN (sid);
    }
  else if (strncmp (session.buf, "HELP", SMTP_COMMAND_LEN) == 0)
    {
      HELP (sid);
    }
  else
    {
      reply (sid, reply_5XX[CODE_502]);
    }
}

void
SMTP::reply (int sid, const char *data)
{
  if (!data)
    return;

  ssize_t rc = send (fds[sid].fd, data, strlen (data), 0);
  if (rc == SEND_ERROR)
    {
      LogPrint (eLogError, "SMTPsession: reply: Send error");
      return;
    }

  std::string str_data (data);
  str_data = str_data.substr (0, str_data.size () - 2);

  LogPrint (eLogDebug, "SMTPsession: reply: Reply stream: ", str_data);
}

/// SMTP
void
SMTP::HELO (int sid)
{
  if (session.state != STATE_INIT)
    {
      reply (sid, reply_5XX[CODE_503]);
      return;
    }

  session.nrcpt = 0;
  memset (session.rcpt, 0, sizeof (session.rcpt));

  session.state = STATE_HELO;

  reply (sid, reply_2XX[CODE_250]);
}

void
SMTP::EHLO (int sid)
{
  if (session.state != STATE_INIT)
    {
      reply (sid, reply_5XX[CODE_501]);
      return;
    }

  // ToDo: looks like in EHLO client try to use PIPELINING
  //   without declaration in EHLO, for now disabled

  /*
  std::string reply_str;
  for (auto line : reply_info)
    reply_str.append(line);

  reply (sid, reply_str.c_str());
  session.state = STATE_EHLO;
  */

  reply (sid, reply_5XX[CODE_502]);    
}

void
SMTP::MAIL (int sid)
{
  cmd_to_upper (session.buf, 10);
  if (strncmp (session.buf, "MAIL FROM:", 10) != 0)
    {
      reply (sid, reply_5XX[CODE_501]);
      return;
    }

  if (session.state == STATE_EHLO)
    {
      reply (sid, reply_5XX[CODE_553]);
      return;
    }

  if (session.state != STATE_HELO &&
      session.state != STATE_AUTH)
    {
      reply (sid, reply_5XX[CODE_503_2]);
      return;
    }

  std::string user, alias;

  /// Use first part as identity name
  std::string str_req (session.buf);
  std::size_t pos = str_req.find ('<');

  if (pos != std::string::npos)
    {
      user = str_req.substr (10, pos);
      str_req.erase (0, pos + 1);
    }
  else
    {
      str_req.erase (0, 11);
    }

  pos = str_req.find ('@');
  alias = str_req.substr (0, pos);

  LogPrint (eLogDebug, "SMTPsession: MAIL: user: ", user, ", alias: ", alias);

  // ToDo: if no name in FROM - use identity alias
  strncpy (session.from, user.c_str (), user.size ());

  if (check_identity (alias))
    {
      reply (sid, reply_2XX[CODE_250]);
      session.state = STATE_MAIL;
    }
  else
    {
      reply (sid, reply_5XX[CODE_550]);
    }
}

void
SMTP::RCPT (int sid)
{
  cmd_to_upper (session.buf, 8);

  if (strncmp (session.buf, "RCPT TO:", 8) != 0)
    {
      reply (sid, reply_5XX[CODE_501]);
      return;
    }

  if ((session.state != STATE_MAIL &&
       session.state != STATE_RCPT)
      && session.nrcpt > SMTP_MAX_RCPT_USR)
    {
      reply (sid, reply_5XX[CODE_503]);
      return;
    }

  std::string user, alias;

  // Use first part as identity name
  std::string str_req (session.buf);
  std::size_t pos = str_req.find ('<');

  if (pos != std::string::npos)
    {
      user = str_req.substr (8, pos);
      str_req.erase (0, pos + 1);
    }
  else
    {
      str_req.erase (0, 9);
    }

  pos = str_req.find ('>');
  alias = str_req.substr (0, pos);

  LogPrint (eLogDebug, "SMTPsession: RCPT: user: ", user, ", alias: ", alias);

  // ToDo: if no name in FROM - use identity alias
  // char current_rcpt_user[100];
  // strncpy(current_rcpt_user, user.c_str(), user.size());

  if (check_recipient (alias))
    {
      strncpy (session.rcpt[session.nrcpt++], user.c_str (), user.size ());
      reply (sid, reply_2XX[CODE_250]);
    }
  else
    {
      reply (sid, reply_5XX[CODE_551]);
    }

  session.state = STATE_RCPT;
}

void
SMTP::DATA (int sid)
{
  if (session.state != STATE_RCPT)
    {
      reply (sid, reply_5XX[CODE_503]);
      return;
    }

  reply (sid, reply_3XX[CODE_354]);

  memset (session.buf, 0, SMTP_BUF_SIZE);

  ssize_t recv_len = recv (client_sockfd,
                           session.buf,
                           SMTP_BUF_SIZE - 1, 0);
  if (recv_len == RECV_ERROR)
    {
      LogPrint (eLogError, "SMTPsession: DATA: Receive: ", strerror (errno));
      reply (sid, reply_4XX[CODE_451]);
      return;
    }

  LogPrint (eLogDebug, "SMTPsession: DATA: Mail content:\n", session.buf);

  /* ToDo: save to user subdir */
  std::vector<uint8_t> mail_data (session.buf, session.buf + recv_len);
  pbote::Email mail;
  mail.fromMIME (mail_data);
  mail.save ("outbox");

  session.state = STATE_DATA;

  reply (sid, reply_2XX[CODE_250]);
}

void
SMTP::RSET (int sid)
{
  session.state = STATE_INIT;
  reply (sid, reply_2XX[CODE_250]);
}

void
SMTP::VRFY (int sid)
{
  reply (sid, reply_2XX[CODE_252]);
}

void
SMTP::NOOP (int sid)
{
  reply (sid, reply_2XX[CODE_250]);
}

void
SMTP::QUIT (int sid)
{
  session.state = STATE_QUIT;
  reply (sid, reply_2XX[CODE_221]);

  fds[sid].revents = POLLHUP;
  CLOSE_SOCKET (fds[sid].fd);
  fds[sid].fd = SOCKET_INVALID;

  if (session.need_clean)
    {
      free (session.buf);
      session.need_clean = false;
    }
}

/// Extension
void
SMTP::AUTH (int sid)
{
  cmd_to_upper (session.buf, 10);
  // ToDo: looks like we can keep pass hash in identity file
  //   for now ignored
  if (strncmp (session.buf, "AUTH LOGIN", 10) == 0)
    {
      LogPrint (eLogDebug, "SMTPsession: AUTH: Auth login OK");
      session.state = STATE_AUTH;
      reply (sid, reply_2XX[CODE_235]);
    }
  else if (strncmp (session.buf, "AUTH PLAIN", 10) == 0)
    {
      LogPrint (eLogDebug, "SMTPsession: AUTH: Auth plain OK");
      session.state = STATE_AUTH;
      reply (sid, reply_2XX[CODE_235]);
    }
  else
    {
      reply (sid, reply_5XX[CODE_504]);
    }
}

void
SMTP::EXPN (int sid)
{
  reply (sid, reply_2XX[CODE_252]);
}

void
SMTP::HELP (int sid)
{
  reply (sid, reply_2XX[CODE_214]);
}

bool
SMTP::check_identity (const std::string &name)
{
  LogPrint (eLogDebug, "SMTPsession: check_identity: name: ",
            name.substr (0, name.size () - 2));
  if (pbote::context.identityByName (name))
    return true;
  return false;
}

bool
SMTP::check_recipient (const std::string &name)
{
  LogPrint (eLogDebug, "SMTPsession: check_recipient: name: ",
            name.substr (0, name.size () - 2));
  if (pbote::context.alias_exist (name))
    return true;
  return false;
}

void
SMTP::cmd_to_upper(char *data, int len)
{
  char *s = data;
  int counter = 0;
  while (*s && counter < len)
    {
      *s = toupper((unsigned char) *s);
      s++;
      counter++;
    }
}

} // namespace smtp
} // namespace bote
