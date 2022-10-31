/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

#include "BoteContext.h"
#include "EmailWorker.h"
#include "FileSystem.h"
#include "Logging.h"
#include "POP3.h"

namespace bote
{
namespace pop3
{

POP3::POP3 (const std::string &address, int port)
  : started (false),
    pop3_thread (nullptr),
    m_address (address),
    m_port (port)
{
}

POP3::~POP3 ()
{
  stop ();

  if (pop3_thread)
    {
      pop3_thread->join ();
      delete pop3_thread;
      pop3_thread = nullptr;
    }
}

void
POP3::start ()
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
      LogPrint (eLogError, "POP3 Invalid address or port: ",
                m_address, ":", m_port, ": ", gai_strerror(rc));
      return;
    }

  server_sockfd = socket (res->ai_family, res->ai_socktype, res->ai_protocol);

  if (server_sockfd == PB_SOCKET_INVALID)
    {
      freeaddrinfo (res);
      LogPrint (eLogError, "POP3: Socket create error: ", strerror (errno));
    }

/*
#ifndef _WIN32
  int on = 1;
#else
  DWORD on = 1;
#endif
*/

  int on = 1;
  rc = PB_SOCKET_SETSOCKOPT(server_sockfd, SOL_SOCKET,  SO_REUSEADDR, on);
  if (rc == RC_ERROR)
  {
    LogPrint (eLogError, "POP3: setsockopt(SO_REUSEADDR) failed: ",
              strerror (errno));
    PB_SOCKET_CLOSE (server_sockfd);
    freeaddrinfo (res);
    return;
  }

/*
#ifndef _WIN32
  struct timeval tv;
  tv.tv_sec = POP3_SOCK_TIMEOUT;
  tv.tv_usec = 0;
  rc = setsockopt(server_sockfd, SOL_SOCKET, SO_RCVTIMEO,
                  (const char*)&tv, sizeof tv);
#else
  DWORD timeout = POP3_SOCK_TIMEOUT * 1000;
  rc = setsockopt(server_sockfd, SOL_SOCKET, SO_RCVTIMEO,
                  (const char*)&timeout, sizeof timeout);
#endif
  if (rc == RC_ERROR)
  {
    LogPrint (eLogError, "POP3: setsockopt(SO_RCVTIMEO) failed: ",
              strerror (errno));
    PB_SOCKET_CLOSE (server_sockfd);
    freeaddrinfo (res);
    return;
  }
*/
/*#ifndef _WIN32
  rc = ioctl(server_sockfd, FIONBIO, (char *)&on);
#else
  rc = ioctlsocket(server_sockfd, FIONBIO, &on);
#endif*/
  rc = PB_SOCKET_IOCTL(server_sockfd, FIONBIO, on);
  if (rc == RC_ERROR)
  {
    LogPrint (eLogError, "POP3: ioctl(FIONBIO) failed: ", strerror (errno));
    PB_SOCKET_CLOSE (server_sockfd);
    freeaddrinfo (res);
    return;
  }

  rc = bind (server_sockfd, res->ai_addr, res->ai_addrlen);
  if (rc == RC_ERROR)
    {
      freeaddrinfo (res);
      LogPrint (eLogError, "POP3: Bind error: ", strerror (errno));
      return;
    }

  freeaddrinfo (res);

  rc = listen (server_sockfd, POP3_MAX_CLIENTS);
  if (rc == RC_ERROR)
    {
      LogPrint (eLogError, "POP3: Listen error: ", strerror (errno));
      return;
    }

  memset(fds, 0, sizeof(fds));

  fds[0].fd = server_sockfd;
  fds[0].events = POLLIN;

  started = true;

  pop3_thread = new std::thread ([this] { run (); });
}

void
POP3::stop ()
{
  if (!started)
    return;

  LogPrint (eLogInfo, "POP3: Stopping");

  started = false;

  /* Clean up all of the sockets that are open */
  for (int sid = 0; sid < nfds; sid++)
    {
      if (fds[sid].fd != PB_SOCKET_INVALID)
        {
          PB_SOCKET_CLOSE (fds[sid].fd);
          fds[sid].revents = POLLHUP;
        }

      /* Free allocated session buffer */
      if (session.need_clean)
        {
          free (session.buf);
          session.need_clean = false;
        }
    }
  LogPrint (eLogInfo, "POP3: Sockets closed");

  LogPrint (eLogInfo, "POP3: Stopped");
}

void
POP3::run ()
{
  LogPrint (eLogInfo, "POP3: Started");

  int rc = 0, current_sc = 0;
  bool compress_array = false;

  while (started)
    {
      LogPrint(eLogDebug, "POP3: run: Waiting on poll");
      rc = PB_SOCKET_POLL(fds, nfds, POP3_POLL_TIMEOUT);

      if (!started)
        return;

      /* Check to see if the poll call failed */
      if (rc == POLL_ERROR)
        {
          if (errno == EINTR) continue;

          LogPrint(eLogError, "POP3: Poll error: ", strerror (errno));
          break;
        }

      if (rc == POLL_TIMEOUT)
        {
          LogPrint(eLogDebug, "POP3: Poll timed out");
          continue;
        }
      current_sc = nfds;
      for (int sid = 0; sid < current_sc; sid++)
        {
          LogPrint(eLogDebug, "POP3: Revents ", sid, ": ", fds[sid].revents);
          if (fds[sid].revents == 0)
            continue;

          if (fds[sid].revents != POLLIN)
            {
              LogPrint(eLogError, "POP3: Revents ", sid, ": ", fds[sid].revents);
              continue;
            }

          if (fds[sid].fd == server_sockfd && fds[sid].revents & POLLIN)
            {
              LogPrint(eLogDebug, "POP3: run: Checking server socket");
              do
                {
                  struct sockaddr_in client_addr;
                  memset(&client_addr, 0, sizeof(struct sockaddr_in));
                  socklen_t sin_size = sizeof (client_addr);

                  client_sockfd = accept(fds[sid].fd, (struct sockaddr *)&client_addr,
                                         &sin_size);

                  if (client_sockfd == PB_SOCKET_INVALID)
                  {
                    /*
                     * EWOULDBLOCK and EAGAIN - socket is marked nonblocking
                     * and no connections are present to be accepted
                     */
                    if (started && errno != EWOULDBLOCK && errno != EAGAIN)
                    {
                      LogPrint (eLogError, "POP3: Accept error: ",
                                strerror (errno));
                    }
                    break;
                  }

                  LogPrint (eLogInfo, "POP3: Received connection ", nfds, " from ",
                            inet_ntoa (client_addr.sin_addr));

                  if (nfds >= POP3_MAX_CLIENTS)
                    {
                      LogPrint (eLogWarning, "POP3: run: Session limit");
                      PB_SOCKET_CLOSE (client_sockfd);
                      continue;
                    }

                  fds[nfds].fd = client_sockfd;
                  fds[nfds].events = POLLIN;

                  session.state = POP3_STATE_QUIT;

                  nfds++;
                } while (client_sockfd != PB_SOCKET_INVALID);
              LogPrint (eLogDebug, "POP3: End of accept");
            }
        }

      LogPrint(eLogDebug, "POP3: run: Checking clients sockets");
      current_sc = nfds;
      for (int sid = 0; sid < current_sc; sid++)
        {
          LogPrint(eLogDebug, "POP3: Revents ", sid, ": ", fds[sid].revents);

          if (fds[sid].fd != server_sockfd)
            {
              if (session.state == POP3_STATE_QUIT)
                {
                  reply (sid, reply_ok[OK_HELO]);
                  session.state = POP3_STATE_USER;
                }

              LogPrint (eLogDebug, "POP3session: New data ", sid, ": ");
              bool need_close = false;
              /* Receive all incoming data on this socket */
              /* until the recv fails with EWOULDBLOCK */
              do
                {
                  if (fds[sid].fd == PB_SOCKET_INVALID)
                    {
                      LogPrint (eLogWarning, "POP3session: Session #", sid,
                           " closed");
                        need_close = true;
                        break;
                    }

                  if (session.need_clean)
                    {
                      free (session.buf);
                      session.need_clean = false;
                    }

                  session.buf = (char *)malloc (POP3_BUF_SIZE);
                  session.need_clean = true;
                  memset (session.buf, 0, POP3_BUF_SIZE);
                  ssize_t rc = recv (fds[sid].fd, session.buf,
                                     POP3_BUF_SIZE - 1, MSG_DONTWAIT);
                  if (rc == RECV_ERROR)
                  {
                    if (started && errno != EWOULDBLOCK && errno != EAGAIN)
                      {
                        LogPrint (eLogError, "POP3session: recv error: ",
                                  strerror (errno));
                        need_close = true;
                      }
                    break;
                  }

                  if (rc == RECV_CLOSED)
                    {
                      LogPrint (eLogDebug, "POP3session: Connection ", sid, " closed");
                      need_close = true;
                      break;
                    }

                  /* Data was received  */
                  std::string str_buf (session.buf);
                  str_buf = str_buf.substr (0, str_buf.size () - 2);
                  LogPrint (eLogDebug, "POP3session: Request stream #", sid, ": ", str_buf);

                  respond (sid);
                } while (started);

              if (need_close)
                {
                  fds[sid].revents = POLLHUP;
                  if (fds[sid].fd != PB_SOCKET_INVALID)
                    {
                      PB_SOCKET_CLOSE (fds[sid].fd);
                      fds[sid].fd = PB_SOCKET_INVALID;
                    }
                  compress_array = true;

                  if (session.need_clean)
                    {
                      free (session.buf);
                      session.need_clean = false;
                    }

                  LogPrint (eLogDebug, "POP3session: Closed ", sid);
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
          if (fds[sid].fd != PB_SOCKET_INVALID)
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
POP3::respond (int sid)
{
  /// POP3 basic
  if (strncmp (session.buf, "USER", 4) == 0)
    {
      USER (sid);
    }
  else if (strncmp (session.buf, "PASS", 4) == 0)
    {
      PASS (sid);
    }
  else if (strncmp (session.buf, "STAT", 4) == 0)
    {
      STAT (sid);
    }
  else if (strncmp (session.buf, "LIST", 4) == 0)
    {
      LIST (sid);
    }
  else if (strncmp (session.buf, "RETR", 4) == 0)
    {
      RETR (sid);
    }
  else if (strncmp (session.buf, "DELE", 4) == 0)
    {
      DELE (sid);
    }
  else if (strncmp (session.buf, "NOOP", 4) == 0)
    {
      NOOP (sid);
    }
  else if (strncmp (session.buf, "RSET", 4) == 0)
    {
      RSET (sid);
    }
  else if (strncmp (session.buf, "QUIT", 4) == 0)
    {
      QUIT (sid);
    }
  /// Extensions RFC 2449
  else if (strncmp (session.buf, "CAPA", 4) == 0)
    {
      CAPA (sid);
    }
  else if (strncmp (session.buf, "APOP", 4) == 0)
    {
      APOP (sid);
    }
  else if (strncmp (session.buf, "TOP", 3) == 0)
    {
      TOP (sid);
    }
  else if (strncmp (session.buf, "UIDL", 4) == 0)
    {
      UIDL (sid);
    }
  else
    {
      reply (sid, reply_err[ERR_NO_COMMAND]);
    }
}

void
POP3::reply (int sid, const char *data)
{
  if (!data)
    return;

  ssize_t rc = send (fds[sid].fd, data, strlen (data), 0);
  if (rc == SEND_ERROR)
    {
      LogPrint (eLogError, "POP3session: reply: Send error: ",
                strerror (errno));
      return;
    }

  std::string str_data (data);
  str_data = str_data.substr (0, str_data.size () - 2);

  LogPrint (eLogDebug, "POP3session: reply: Reply stream: ", str_data);
}

void
POP3::USER (int sid)
{
  if (session.state != POP3_STATE_USER)
    {
      reply (sid, reply_err[ERR_DENIED]);
      return;
    }
  /// User is identity public name
  std::string str_req (session.buf);

  LogPrint (eLogDebug, "POP3session: USER: Request: ", session.buf,
            ", size: ", str_req.size ());

  str_req.erase (0, 5);

  LogPrint (eLogDebug, "POP3session: USER: Request: ", session.buf,
            ", size: ", str_req.size ());

  std::string user = str_req.substr (0, str_req.size () - 2);

  if (check_user (user))
    {
      session.state = POP3_STATE_PASS;
      auto res = format_response (reply_ok[OK_USER], user.c_str ());
      reply (sid, res.c_str ());
    }
  else
    {
      auto res = format_response (reply_err[ERR_USER], user.c_str ());
      reply (sid, res.c_str ());
    }
}

void
POP3::PASS (int sid)
{
  if (session.state != POP3_STATE_PASS)
    {
      reply (sid, reply_err[ERR_DENIED]);
      return;
    }

  // ToDo: looks like we can keep pass hash in identity file
  //   for now ignored
  std::string str_req (session.buf);

  if (check_pass (str_req.substr (5, str_req.size () - 5)))
    {
      // ToDo: lock mail directory
      session.state = POP3_STATE_TRANSACTION;
      /* ToDo: pass username */
      session.emails = bote::email_worker.check_inbox ();
      reply (sid, reply_ok[OK_LOCK]);
    }
  else
    {
      session.state = POP3_STATE_USER;
      reply (sid, reply_err[ERR_PASS]);
    }
}

void
POP3::STAT (int sid)
{
  if (session.state != POP3_STATE_TRANSACTION)
    {
      reply (sid, reply_err[ERR_DENIED]);
      return;
    }

  size_t emails_size = 0;
  for (const auto &email : session.emails)
    emails_size += email->bytes ().size ();

  auto res
      = format_response (reply_ok[OK_STAT], session.emails.size (), emails_size);
  reply (sid, res.c_str ());
}

void
POP3::LIST (int sid)
{
  if (session.state != POP3_STATE_TRANSACTION)
    {
      reply (sid, reply_err[ERR_DENIED]);
      return;
    }

  size_t emails_size = 0;
  std::string mail_list;
  size_t email_counter = 1;

  for (const auto &email : session.emails)
    {
      if (email->deleted ())
        continue;

      size_t email_size = email->bytes ().size ();
      emails_size += email_size;
      mail_list += format_response (templates[TEMPLATE_LIST_ITEM],
                                    email_counter, email_size)
                   + "\n";
      email_counter++;
    }

  auto res
      = format_response (reply_ok[OK_LIST], session.emails.size (), emails_size)
        + mail_list + ".\r\n";

  reply (sid, res.c_str ());
}

void
POP3::RETR (int sid)
{
  if (session.state != POP3_STATE_TRANSACTION)
    {
      reply (sid, reply_err[ERR_DENIED]);
      return;
    }

  std::string req_str (session.buf);
  LogPrint (eLogDebug, "POP3session: RETR: Request string: ", req_str);

  req_str.erase (0, 5);

  if (req_str.size () - 1 < 1)
    {
      LogPrint (eLogError, "POP3session: RETR: Request is too short");
      reply (sid, reply_err[ERR_SIMP]);
      return;
    }

  std::replace (req_str.begin (), req_str.end (), '\n', ';');
  std::replace (req_str.begin (), req_str.end (), '\r', ';');
  std::string message_number = req_str.substr (0, req_str.find (';'));

  LogPrint (eLogDebug, "POP3session: RETR: Message number: ", message_number);

  size_t message_num_int = size_t (std::stoi (message_number));
  if (message_num_int > session.emails.size ())
    {
      LogPrint (eLogError, "POP3session: RETR: Message number is to high");
      reply (sid, reply_err[ERR_NOT_FOUND]);
      return;
    }

  auto bytes = session.emails[message_num_int - 1]->bytes ();
  std::string res = format_response (reply_ok[OK_RETR], bytes.size ());
  res.append (bytes.begin (), bytes.end ());
  res.append ("\n.\r\n");
  reply (sid, res.c_str ());
}

void
POP3::DELE (int sid)
{
  if (session.state != POP3_STATE_TRANSACTION)
    {
      reply (sid, reply_err[ERR_DENIED]);
      return;
    }

  std::string req_str (session.buf);
  LogPrint (eLogDebug, "POP3session: DELE: Request string: ", req_str);

  req_str.erase (0, 5);

  // ToDo: validation
  int message_number = std::stoi (req_str) - 1;
  if (message_number < 0 &&
      (size_t)message_number >= session.emails.size ())
    {
      auto response = format_response (reply_err[ERR_NOT_FOUND]);
      reply (sid, response.c_str ());
      return;
    }

  /// On DELE step we can only mark message as deleted
  /// file deletion occurs only in phase UPDATE at step QUIT
  /// https://datatracker.ietf.org/doc/html/rfc1939#page-8
  if (session.emails[message_number]->deleted ())
    {
      auto response = format_response (reply_err[ERR_REMOVED], message_number + 1);
      reply (sid, response.c_str ());
      return;
    }

  session.emails[message_number]->deleted (true);
  auto response = format_response (reply_ok[OK_DEL], message_number + 1);
  reply (sid, response.c_str ());
}

void
POP3::NOOP (int sid)
{
  if (session.state != POP3_STATE_TRANSACTION)
  {
    reply (sid, reply_err[ERR_DENIED]);
    return;
  }

  reply (sid, reply_ok[OK_SIMP]);
}

void
POP3::RSET (int sid)
{
  if (session.state != POP3_STATE_TRANSACTION)
    {
      reply (sid, reply_err[ERR_DENIED]);
      return;
    }

  // ToDo
  auto response = format_response (reply_ok[OK_MAILDROP], 0, 0);
  reply (sid, response.c_str ());
}

void
POP3::QUIT (int sid)
{
  if (session.state == POP3_STATE_TRANSACTION)
    {
      /// Now we can remove marked emails
      /// https://datatracker.ietf.org/doc/html/rfc1939#section-6
      for (const auto &email : session.emails)
        {
          if (email->deleted ())
            bote::fs::Remove (email->filename ());
        }
    }

  session.state = POP3_STATE_QUIT;
  reply (sid, reply_ok[OK_QUIT]);

  PB_SOCKET_CLOSE (fds[sid].fd);
  fds[sid].fd = PB_SOCKET_INVALID;

  if (session.need_clean)
    {
      free (session.buf);
      session.need_clean = false;
    }
}

/* Extension */
void
POP3::CAPA (int sid)
{
  std::string reply_str;

  for (auto line : capa_list)
    reply_str.append (line);

  reply (sid, reply_str.c_str ());
}

void
POP3::APOP (int sid)
{
  // ToDo: looks like we can keep pass hash in identity file
  //   for now ignored
  if (strncmp (session.buf, "APOP", 4) != 0)
    {
      reply (sid, reply_err[ERR_DENIED]);
      return;
    }

  // ToDo
  LogPrint (eLogDebug, "POP3session: APOP: Login successfully");

  session.state = POP3_STATE_TRANSACTION;

  reply (sid, reply_ok[OK_LOCK]);
}

void
POP3::TOP (int sid)
{
  if (session.state != POP3_STATE_TRANSACTION)
    {
      reply (sid, reply_err[ERR_DENIED]);
      return;
    }

  reply (sid, reply_ok[OK_TOP]);
  // ToDo
}

void
POP3::UIDL (int sid)
{
  if (session.state != POP3_STATE_TRANSACTION)
    {
      reply (sid, reply_err[ERR_DENIED]);
      return;
    }

  std::string uidl_list;
  size_t email_counter = 1;

  for (const auto &email : session.emails)
    {
      std::string email_uid = email->field ("Message-ID");
      uidl_list += format_response (templates[TEMPLATE_UIDL_ITEM],
                                    email_counter, email_uid.c_str ())
                   + "\n";
      email_counter++;
    }

  auto res = format_response (reply_ok[OK_UIDL], session.emails.size ())
             + uidl_list + ".\r\n";

  reply (sid, res.c_str ());
}

bool
POP3::check_user (const std::string &user)
{
  LogPrint (eLogDebug, "POP3session: check_user: user: ", user);

  if (bote::context.identityByName (user))
    return true;

  return false;
}

bool
POP3::check_pass (const std::string &pass)
{
  auto clean_pass = pass.substr (0, pass.size () - 2);
  LogPrint (eLogDebug, "POP3session: check_pass: pass: ", clean_pass);
  // ToDo
  // if (bote::context.recipient_exist(pass))
  return true;
  // return false;
}

} // namespace pop3
} // namespace bote
