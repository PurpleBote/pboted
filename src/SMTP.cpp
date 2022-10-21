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
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "BoteContext.h"
#include "Logging.h"
#include "SMTP.h"

namespace bote
{
namespace smtp
{

SMTP::SMTP (const std::string &address, int port)
  : started (false),
    smtp_accepting_thread (nullptr),
    smtp_processing_thread (nullptr),
    m_address (address),
    m_port (port)
{}

SMTP::~SMTP ()
{
  stop ();

  smtp_processing_thread->join ();

  delete smtp_processing_thread;
  smtp_processing_thread = nullptr;

  smtp_accepting_thread->join ();

  delete smtp_accepting_thread;
  smtp_accepting_thread = nullptr;
}

void
SMTP::start ()
{
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
  if (rc != 0 || res == nullptr)
    {
      LogPrint (eLogError, "SMTP Invalid address or port: ",
                m_address, ":", m_port, ": ", gai_strerror(rc));
      return;
    }

  server_sockfd = socket (res->ai_family, res->ai_socktype, res->ai_protocol);

  if (server_sockfd == -1)
    {
      // ToDo: add error handling
      freeaddrinfo (res);
      LogPrint (eLogError, "SMTP: Socket create error: ", strerror (errno));
    }

  rc = bind (server_sockfd, res->ai_addr, res->ai_addrlen);
  if (rc == -1)
    {
      // ToDo: add error handling
      freeaddrinfo (res);
      LogPrint (eLogError, "SMTP: Bind error: ", strerror (errno));
      return;
    }

  freeaddrinfo (res);

  rc = listen (server_sockfd, SMTP_MAX_CLIENTS);
  if (rc == -1)
    {
      // ToDo: add error handling
      LogPrint (eLogError, "SMTP: Listen error: ", strerror (errno));
      return;
    }

  memset(fds, 0, sizeof(fds));
  memset(sessions, 0, sizeof(sessions));

  fds[0].fd = server_sockfd;
  fds[0].events = POLLIN;

  started = true;

  smtp_accepting_thread = new std::thread ([this] { run (); });
  smtp_processing_thread = new std::thread ([this] { process (); });
}

void
SMTP::stop ()
{
  if (!started)
    return;

  LogPrint (eLogInfo, "SMTP: Stopping");

  started = false;

  /* Clean up all of the sockets that are open */
  for (int i = 0; i < nfds; i++)
    {
      if(fds[i].fd >= 0)
        {
          close(fds[i].fd);
          fds[i].revents = POLLHUP;
        }
    }
  LogPrint (eLogInfo, "SMTP: Sockets closed");

  /*close(fds[0].fd);*/
  close (server_sockfd);

  LogPrint (eLogInfo, "SMTP: Stopped");
}

void
SMTP::run ()
{
  LogPrint (eLogInfo, "SMTP: Started");

  int rc = 0, current_size = 0;

  while (started)
    {
      rc = poll(fds, nfds, SMTP_WAIT_TIMEOUT);

      if (!started)
        return;

      /* Check to see if the poll call failed */
      if (rc < 0)
        {
          LogPrint(eLogError, "SMTP: Poll error: ", strerror (errno));
          continue;
        }

      if (rc == 0)
        {
          LogPrint(eLogDebug, "SMTP: Poll timed out");
          continue;
        }

      current_size = nfds;
      for (int i = 0; i < current_size; i++)
        {
          if(fds[i].revents == 0)
            continue;

          if(fds[i].revents != POLLIN)
            {
              LogPrint(eLogError, "SMTP: Revents: ", fds[i].revents);
              continue;
            }

          if (fds[i].fd != server_sockfd)
            continue;

          LogPrint (eLogDebug, "SMTP: Server socket readable");
          do
            {
              LogPrint (eLogDebug, "SMTP: New accept");

              struct sockaddr_in client_addr;
              memset(&client_addr, 0, sizeof(struct sockaddr_in));
              socklen_t sin_size = sizeof (client_addr);

              client_sockfd = accept(server_sockfd,
                                     (struct sockaddr *)&client_addr,
                                     &sin_size);

              if (client_sockfd < 0)
              {
                if (started && errno != EWOULDBLOCK && errno != EAGAIN)
                {
                  LogPrint (eLogError, "SMTP: Accept error: ",
                            strerror (errno));
                }
                break;
              }

              LogPrint (eLogInfo, "SMTP: Received connection from ",
                        inet_ntoa (client_addr.sin_addr));

              fds[nfds].fd = client_sockfd;
              fds[nfds].events = POLLIN;
              sessions[nfds].state = STATE_QUIT;

              nfds++;
            } while (client_sockfd != -1);
        }
    }
}

void
SMTP::process ()
{
  bool compress_array = false;
  do
    {
      int current_sc = nfds;
      for (int sid = 0; sid < current_sc; sid++)
        {
          if (fds[sid].fd == server_sockfd)
            continue;

          if (sessions[sid].state == STATE_QUIT)
            {
              reply (sid, reply_2XX[CODE_220]);
              sessions[sid].state = STATE_INIT;
            }

          LogPrint (eLogDebug, "SMTPsession: New data");
          bool close_conn = false;
          /* Receive all incoming data on this socket */
          /* until the recv fails with EWOULDBLOCK */
          do
          {
            memset (sessions[sid].buf, 0, sizeof (sessions[sid].buf));
            ssize_t rc = recv (fds[sid].fd, sessions[sid].buf,
                               sizeof (sessions[sid].buf), 0);
            if (rc < 0)
            {
              LogPrint (eLogError, "SMTPsession: Can't receive data, close");
              close_conn = true;
              break;
            }

            if (rc == 0)
            {
              LogPrint (eLogDebug, "SMTPsession: Connection closed");
              close_conn = true;
              break;
            }

            /* Data was received  */
            std::string str_buf (sessions[sid].buf);
            str_buf = str_buf.substr (0, str_buf.size () - 2);

            LogPrint (eLogDebug, "SMTPsession: Request stream: ", str_buf);
            respond (sid);
          } while (started);

          if (close_conn)
            {
              close(fds[sid].fd);
              fds[sid].fd = -1;
              compress_array = true;
            }
        }

      /* we need to squeeze together the array and */
      /* decrement the number of file descriptors and sessions*/
      if (!compress_array)
        continue;

      compress_array = false;
      for (int sid = 0; sid < nfds; sid++)
        {
          if (fds[sid].fd != INVALID_SOCKET)
            continue;

          for(int j = sid; j < nfds; j++)
            {
              fds[j].fd = fds[j + 1].fd;
              sessions[j] = sessions[j + 1];
            }
          sid--;
          nfds--;
        }
    } while (started);
}

void
SMTP::respond (int sid)
{
  /// https://datatracker.ietf.org/doc/html/rfc5321#section-2.4
  cmd_to_upper (sessions[sid].buf);

  /// SMTP Basic
  if (strncmp (sessions[sid].buf, "HELO", 4) == 0)
    {
      HELO (sid);
    }
  else if (strncmp (sessions[sid].buf, "EHLO", 4) == 0)
    {
      EHLO (sid);
    }
  else if (strncmp (sessions[sid].buf, "MAIL", 4) == 0)
    {
      MAIL (sid);
    }
  else if (strncmp (sessions[sid].buf, "RCPT", 4) == 0)
    {
      RCPT (sid);
    }
  else if (strncmp (sessions[sid].buf, "DATA", 4) == 0)
    {
      DATA (sid);
    }
  else if (strncmp (sessions[sid].buf, "RSET", 4) == 0)
    {
      RSET (sid);
    }
  else if (strncmp (sessions[sid].buf, "VRFY", 4) == 0)
    {
      VRFY (sid);
    }
  else if (strncmp (sessions[sid].buf, "NOOP", 4) == 0)
    {
      NOOP (sid);
    }
  else if (strncmp (sessions[sid].buf, "QUIT", 4) == 0)
    {
      QUIT (sid);
    }
  /// Extensions
  else if (strncmp (sessions[sid].buf, "AUTH", 4) == 0)
    {
      AUTH (sid);
    }
  else if (strncmp (sessions[sid].buf, "EXPN", 4) == 0)
    {
      EXPN (sid);
    }
  else if (strncmp (sessions[sid].buf, "HELP", 4) == 0)
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
  if (rc < 0)
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
  if (sessions[sid].state != STATE_INIT)
    {
      reply (sid, reply_5XX[CODE_503]);
      return;
    }

  sessions[sid].nrcpt = 0;
  memset (sessions[sid].rcpt, 0, sizeof (sessions[sid].rcpt));

  sessions[sid].state = STATE_HELO;

  reply (sid, reply_2XX[CODE_250]);
}

void
SMTP::EHLO (int sid)
{
  if (sessions[sid].state != STATE_INIT)
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
  sessions[sid].state = STATE_EHLO;
  */

  reply (sid, reply_5XX[CODE_502]);    
}

void
SMTP::MAIL (int sid)
{
  cmd_to_upper (sessions[sid].buf, 10);
  if (strncmp (sessions[sid].buf, "MAIL FROM:", 10) != 0)
    {
      reply (sid, reply_5XX[CODE_501]);
      return;
    }

  if (sessions[sid].state == STATE_EHLO)
    {
      reply (sid, reply_5XX[CODE_553]);
      return;
    }

  if (sessions[sid].state != STATE_HELO &&
      sessions[sid].state != STATE_AUTH)
    {
      reply (sid, reply_5XX[CODE_503_2]);
      return;
    }

  std::string user, alias;

  /// Use first part as identity name
  std::string str_req (sessions[sid].buf);
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
  strncpy (sessions[sid].from, user.c_str (), user.size ());

  if (check_identity (alias))
    {
      reply (sid, reply_2XX[CODE_250]);
      sessions[sid].state = STATE_MAIL;
    }
  else
    {
      reply (sid, reply_5XX[CODE_550]);
    }
}

void
SMTP::RCPT (int sid)
{
  cmd_to_upper (sessions[sid].buf, 8);

  if (strncmp (sessions[sid].buf, "RCPT TO:", 8) != 0)
    {
      reply (sid, reply_5XX[CODE_501]);
      return;
    }

  if ((sessions[sid].state != STATE_MAIL &&
       sessions[sid].state != STATE_RCPT)
      && sessions[sid].nrcpt > MAX_RCPT_USR)
    {
      reply (sid, reply_5XX[CODE_503]);
      return;
    }

  std::string user, alias;

  // Use first part as identity name
  std::string str_req (sessions[sid].buf);
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
      strncpy (sessions[sid].rcpt[sessions[sid].nrcpt++], user.c_str (), user.size ());
      reply (sid, reply_2XX[CODE_250]);
    }
  else
    {
      reply (sid, reply_5XX[CODE_551]);
    }

  sessions[sid].state = STATE_RCPT;
}

void
SMTP::DATA (int sid)
{
  if (sessions[sid].state != STATE_RCPT)
    {
      reply (sid, reply_5XX[CODE_503]);
      return;
    }

  reply (sid, reply_3XX[CODE_354]);

  memset (sessions[sid].buf, 0, sizeof (sessions[sid].buf));

  ssize_t recv_len = recv (client_sockfd,
                           sessions[sid].buf,
                           sizeof (sessions[sid].buf), 0);
  if (recv_len == -1)
    {
      LogPrint (eLogError, "SMTPsession: DATA: Receive: ", strerror (errno));
      reply (sid, reply_4XX[CODE_451]);
      return;
    }

  LogPrint (eLogDebug, "SMTPsession: DATA: Mail content:\n", sessions[sid].buf);

  /* ToDo: save to user subdir */
  std::vector<uint8_t> mail_data (sessions[sid].buf, sessions[sid].buf + recv_len);
  pbote::Email mail;
  mail.fromMIME (mail_data);
  mail.save ("outbox");

  sessions[sid].state = STATE_DATA;

  reply (sid, reply_2XX[CODE_250]);
}

void
SMTP::RSET (int sid)
{
  sessions[sid].state = STATE_INIT;
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
  sessions[sid].state = STATE_QUIT;
  reply (sid, reply_2XX[CODE_221]);
}

/// Extension
void
SMTP::AUTH (int sid)
{
  cmd_to_upper (sessions[sid].buf, 10);
  // ToDo: looks like we can keep pass hash in identity file
  //   for now ignored
  if (strncmp (sessions[sid].buf, "AUTH LOGIN", 10) == 0)
    {
      LogPrint (eLogDebug, "SMTPsession: AUTH: Auth login OK");
      sessions[sid].state = STATE_AUTH;
      reply (sid, reply_2XX[CODE_235]);
    }
  else if (strncmp (sessions[sid].buf, "AUTH PLAIN", 10) == 0)
    {
      LogPrint (eLogDebug, "SMTPsession: AUTH: Auth plain OK");
      sessions[sid].state = STATE_AUTH;
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
