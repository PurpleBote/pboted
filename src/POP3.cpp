/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
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
    pop3_accepting_thread (nullptr),
    pop3_processing_thread (nullptr),
    m_address (address),
    m_port (port)  
{}

POP3::~POP3 ()
{
  stop ();

  if (pop3_processing_thread)
    {
      pop3_processing_thread->join ();

      delete pop3_processing_thread;
      pop3_processing_thread = nullptr;
    }

  if (pop3_accepting_thread)
    {
      pop3_accepting_thread->join ();
  
      delete pop3_accepting_thread;
      pop3_accepting_thread = nullptr;
    }
}

void
POP3::start ()
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
      LogPrint (eLogError, "POP3 Invalid address or port: ",
                m_address, ":", m_port, ": ", gai_strerror(rc));
      return;
    }

  server_sockfd = socket (res->ai_family, res->ai_socktype, res->ai_protocol);

  if (server_sockfd == -1)
    {
      // ToDo: add error handling
      freeaddrinfo (res);
      LogPrint (eLogError, "POP3: Socket create error: ", strerror (errno));
    }

  rc = bind (server_sockfd, res->ai_addr, res->ai_addrlen);
  if (rc == -1)
    {
      // ToDo: add error handling
      freeaddrinfo (res);
      LogPrint (eLogError, "POP3: Bind error: ", strerror (errno));
      return;
    }

  freeaddrinfo (res);

  rc = listen (server_sockfd, POP3_MAX_CLIENTS);
  if (rc == -1)
    {
      // ToDo: add error handling
      LogPrint (eLogError, "POP3: Listen error: ", strerror (errno));
      return;
    }

  memset(fds, 0, sizeof(fds));
  memset(sessions, 0, sizeof(sessions));

  fds[0].fd = server_sockfd;
  fds[0].events = POLLIN;

  started = true;

  pop3_accepting_thread = new std::thread ([this] { run (); });
  pop3_processing_thread = new std::thread ([this] { process (); });
}

void
POP3::stop ()
{
  if (!started)
    return;

  LogPrint (eLogInfo, "POP3: Stopping");

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
  LogPrint (eLogInfo, "POP3: Sockets closed");

  /*close(fds[0].fd);*/
  //close (server_sockfd);

  LogPrint (eLogInfo, "POP3: Stopped");
}

void
POP3::run ()
{
  LogPrint (eLogInfo, "POP3: Started");

  int rc = 0, current_size = 0;

  while (started)
    {
      rc = poll(fds, nfds, POP3_WAIT_TIMEOUT);

      if (!started)
        return;

      /* Check to see if the poll call failed */
      if (rc < 0)
        {
          LogPrint(eLogError, "POP3: Poll error: ", strerror (errno));
          continue;
        }

      if (rc == 0)
        {
          LogPrint(eLogDebug, "POP3: Poll timed out");
          continue;
        }

      current_size = nfds;
      for (int i = 0; i < current_size; i++)
        {
          if(fds[i].revents == 0)
            continue;

          if(fds[i].revents != POLLIN)
            {
              LogPrint(eLogError, "POP3: Revents: ", fds[i].revents);
              continue;
            }

          if (fds[i].fd != server_sockfd)
            continue;

          LogPrint (eLogDebug, "POP3: Server socket readable");
          do
            {
              LogPrint (eLogDebug, "POP3: New accept");

              struct sockaddr_in client_addr;
              memset(&client_addr, 0, sizeof(struct sockaddr_in));
              socklen_t sin_size = sizeof (client_addr);

              client_sockfd = accept(fds[i].fd,
                                     (struct sockaddr *)&client_addr,
                                     &sin_size);

              if (client_sockfd < 0)
              {
                if (started && errno != EWOULDBLOCK && errno != EAGAIN)
                {
                  LogPrint (eLogError, "POP3: Accept error: ",
                            strerror (errno));
                }
                break;
              }

              LogPrint (eLogInfo, "POP3: Received connection from ",
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
POP3::process ()
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
            reply (sid, reply_ok[OK_HELO]);
            sessions[sid].state = STATE_USER;
          }

          LogPrint (eLogDebug, "POP3session: New data");
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
              LogPrint (eLogError, "POP3session: Can't receive data, close");
              close_conn = true;
              break;
            }

            if (rc == 0)
            {
              LogPrint (eLogDebug, "POP3session: Connection closed");
              close_conn = true;
              break;
            }

            /* Data was received  */
            std::string str_buf (sessions[sid].buf);
            str_buf = str_buf.substr (0, str_buf.size () - 2);

            LogPrint (eLogDebug, "POP3session: Request stream: ", str_buf);
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
POP3::respond (int sid)
{
  /// POP3 basic
  if (strncmp (sessions[sid].buf, "USER", 4) == 0)
    {
      USER (sid);
    }
  else if (strncmp (sessions[sid].buf, "PASS", 4) == 0)
    {
      PASS (sid);
    }
  else if (strncmp (sessions[sid].buf, "STAT", 4) == 0)
    {
      STAT (sid);
    }
  else if (strncmp (sessions[sid].buf, "LIST", 4) == 0)
    {
      LIST (sid);
    }
  else if (strncmp (sessions[sid].buf, "RETR", 4) == 0)
    {
      RETR (sid);
    }
  else if (strncmp (sessions[sid].buf, "DELE", 4) == 0)
    {
      DELE (sid);
    }
  else if (strncmp (sessions[sid].buf, "NOOP", 4) == 0)
    {
      NOOP (sid);
    }
  else if (strncmp (sessions[sid].buf, "RSET", 4) == 0)
    {
      RSET (sid);
    }
  else if (strncmp (sessions[sid].buf, "QUIT", 4) == 0)
    {
      QUIT (sid);
    }
  /// Extensions RFC 2449
  else if (strncmp (sessions[sid].buf, "CAPA", 4) == 0)
    {
      CAPA (sid);
    }
  else if (strncmp (sessions[sid].buf, "APOP", 4) == 0)
    {
      APOP (sid);
    }
  else if (strncmp (sessions[sid].buf, "TOP", 3) == 0)
    {
      TOP (sid);
    }
  else if (strncmp (sessions[sid].buf, "UIDL", 4) == 0)
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
  if (rc < 0)
    {
      LogPrint (eLogError, "POP3session: reply: Send error");
      return;
    }

  std::string str_data (data);
  str_data = str_data.substr (0, str_data.size () - 2);

  LogPrint (eLogDebug, "POP3session: reply: Reply stream: ", str_data);
}

void
POP3::USER (int sid)
{
  if (sessions[sid].state != STATE_USER)
    {
      reply (sid, reply_err[ERR_DENIED]);
      return;
    }
  /// User is identity public name
  std::string str_req (sessions[sid].buf);

  LogPrint (eLogDebug, "POP3session: USER: Request: ", sessions[sid].buf,
            ", size: ", str_req.size ());

  str_req.erase (0, 5);

  LogPrint (eLogDebug, "POP3session: USER: Request: ", sessions[sid].buf,
            ", size: ", str_req.size ());

  std::string user = str_req.substr (0, str_req.size () - 2);

  if (check_user (user))
    {
      sessions[sid].state = STATE_PASS;
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
  if (sessions[sid].state != STATE_PASS)
    {
      reply (sid, reply_err[ERR_DENIED]);
      return;
    }

  // ToDo: looks like we can keep pass hash in identity file
  //   for now ignored
  std::string str_req (sessions[sid].buf);

  if (check_pass (str_req.substr (5, str_req.size () - 5)))
    {
      // ToDo: lock mail directory
      sessions[sid].state = STATE_TRANSACTION;
      /* ToDo: pass username */
      sessions[sid].emails = pbote::kademlia::email_worker.check_inbox ();
      reply (sid, reply_ok[OK_LOCK]);
    }
  else
    {
      sessions[sid].state = STATE_USER;
      reply (sid, reply_err[ERR_PASS]);
    }
}

void
POP3::STAT (int sid)
{
  if (sessions[sid].state != STATE_TRANSACTION)
    {
      reply (sid, reply_err[ERR_DENIED]);
      return;
    }

  size_t emails_size = 0;
  for (const auto &email : sessions[sid].emails)
    emails_size += email->bytes ().size ();

  auto res
      = format_response (reply_ok[OK_STAT], sessions[sid].emails.size (), emails_size);
  reply (sid, res.c_str ());
}

void
POP3::LIST (int sid)
{
  if (sessions[sid].state != STATE_TRANSACTION)
    {
      reply (sid, reply_err[ERR_DENIED]);
      return;
    }

  size_t emails_size = 0;
  std::string mail_list;
  size_t email_counter = 1;

  for (const auto &email : sessions[sid].emails)
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
      = format_response (reply_ok[OK_LIST], sessions[sid].emails.size (), emails_size)
        + mail_list + ".\r\n";

  reply (sid, res.c_str ());
}

void
POP3::RETR (int sid)
{
  if (sessions[sid].state != STATE_TRANSACTION)
    {
      reply (sid, reply_err[ERR_DENIED]);
      return;
    }

  std::string req_str (sessions[sid].buf);
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
  if (message_num_int > sessions[sid].emails.size ())
    {
      LogPrint (eLogError, "POP3session: RETR: Message number is to high");
      reply (sid, reply_err[ERR_NOT_FOUND]);
      return;
    }

  auto bytes = sessions[sid].emails[message_num_int - 1]->bytes ();
  std::string res = format_response (reply_ok[OK_RETR], bytes.size ());
  res.append (bytes.begin (), bytes.end ());
  res.append ("\n.\r\n");
  reply (sid, res.c_str ());
}

void
POP3::DELE (int sid)
{
  if (sessions[sid].state != STATE_TRANSACTION)
    {
      reply (sid, reply_err[ERR_DENIED]);
      return;
    }

  std::string req_str (sessions[sid].buf);
  LogPrint (eLogDebug, "POP3session: DELE: Request string: ", req_str);

  req_str.erase (0, 5);

  // ToDo: validation
  int message_number = std::stoi (req_str) - 1;
  if (message_number < 0 &&
      (size_t)message_number >= sessions[sid].emails.size ())
    {
      auto response = format_response (reply_err[ERR_NOT_FOUND]);
      reply (sid, response.c_str ());
      return;
    }

  /// On DELE step we can only mark message as deleted
  /// file deletion occurs only in phase UPDATE at step QUIT
  /// https://datatracker.ietf.org/doc/html/rfc1939#page-8
  if (sessions[sid].emails[message_number]->deleted ())
    {
      auto response = format_response (reply_err[ERR_REMOVED], message_number + 1);
      reply (sid, response.c_str ());
      return;
    }

  sessions[sid].emails[message_number]->deleted (true);
  auto response = format_response (reply_ok[OK_DEL], message_number + 1);
  reply (sid, response.c_str ());
}

void
POP3::NOOP (int sid)
{
  if (sessions[sid].state != STATE_TRANSACTION)
  {
    reply (sid, reply_err[ERR_DENIED]);
    return;
  }
    
  reply (sid, reply_ok[OK_SIMP]);
}

void
POP3::RSET (int sid)
{
  if (sessions[sid].state != STATE_TRANSACTION)
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
  if (sessions[sid].state == STATE_TRANSACTION)
    {
      /// Now we can remove marked emails
      /// https://datatracker.ietf.org/doc/html/rfc1939#section-6
      for (const auto &email : sessions[sid].emails)
        {
          if (email->deleted ())
            pbote::fs::Remove (email->filename ());
        }
    }

  sessions[sid].state = STATE_QUIT;
  reply (sid, reply_ok[OK_QUIT]);
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
  if (strncmp (sessions[sid].buf, "APOP", 4) != 0)
    {
      reply (sid, reply_err[ERR_DENIED]);
      return;
    }

  // ToDo
  LogPrint (eLogDebug, "POP3session: APOP: Login successfully");

  sessions[sid].state = STATE_TRANSACTION;

  reply (sid, reply_ok[OK_LOCK]);
}

void
POP3::TOP (int sid)
{
  if (sessions[sid].state != STATE_TRANSACTION)
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
  if (sessions[sid].state != STATE_TRANSACTION)
    {
      reply (sid, reply_err[ERR_DENIED]);
      return;
    }

  std::string uidl_list;
  size_t email_counter = 1;

  for (const auto &email : sessions[sid].emails)
    {
      std::string email_uid = email->field ("Message-ID");
      uidl_list += format_response (templates[TEMPLATE_UIDL_ITEM],
                                    email_counter, email_uid.c_str ())
                   + "\n";
      email_counter++;
    }

  auto res = format_response (reply_ok[OK_UIDL], sessions[sid].emails.size ())
             + uidl_list + ".\r\n";

  reply (sid, res.c_str ());
}

bool
POP3::check_user (const std::string &user)
{
  LogPrint (eLogDebug, "POP3session: check_user: user: ", user);

  if (pbote::context.identityByName (user))
    return true;

  return false;
}

bool
POP3::check_pass (const std::string &pass)
{
  auto clean_pass = pass.substr (0, pass.size () - 2);
  LogPrint (eLogDebug, "POP3session: check_pass: pass: ", clean_pass);
  // ToDo
  // if (pbote::context.recipient_exist(pass))
  return true;
  // return false;
}

} // namespace pop3
} // namespace bote
