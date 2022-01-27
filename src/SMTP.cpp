/**
 * Copyright (c) 2019-2022 polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
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
    processing (false),
    smtp_thread (nullptr),
    server_sockfd (-1),
    client_sockfd (-1),
    sin_size (0),
    server_addr (),
    client_addr (),
    session_state (STATE_QUIT),
    rcpt_user_num (0),
    from_user (),
    rcpt_user ()
{
  std::memset (&server_addr, 0, sizeof (server_addr));

  if ((server_sockfd = socket (AF_INET, SOCK_STREAM, 0)) == -1)
    {
      // ToDo: add error handling
      LogPrint (eLogError, "SMTP: socket create error: ", strerror (errno));
    }

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons (port);
  server_addr.sin_addr.s_addr = htonl (INADDR_ANY);
  bzero (&(server_addr.sin_zero), 8);

  memset (buf, 0, sizeof (buf));
}

SMTP::~SMTP ()
{
  stop ();

  smtp_thread->join ();

  delete smtp_thread;
  smtp_thread = nullptr;
}

void
SMTP::start ()
{
  if (!started)
    {
      if (bind (server_sockfd, (struct sockaddr *)&server_addr,
                sizeof (struct sockaddr))
          == -1)
        {
          // ToDo: add error handling
          LogPrint (eLogError, "SMTP: Bind error: ", strerror (errno));
        }

      fcntl (server_sockfd, F_SETFL,
             fcntl (server_sockfd, F_GETFL, 0) | O_NONBLOCK);

      if (listen (server_sockfd, MAX_CLIENTS) == -1)
        {
          // ToDo: add error handling
          LogPrint (eLogError, "SMTP: Listen error: ", strerror (errno));
        }

      started = true;
      smtp_thread = new std::thread ([this] { run (); });
    }
}

void
SMTP::stop ()
{
  LogPrint (eLogInfo, "SMTP: Stopping server");
  started = false;
  close (server_sockfd);
}

void
SMTP::run ()
{
  LogPrint (eLogInfo, "SMTP: Started");
  sin_size = sizeof (client_addr);

  while (started)
    {
      client_sockfd =
        accept (server_sockfd, (struct sockaddr *)&client_addr, &sin_size);
      if (client_sockfd == -1)
        {
          if (errno != EWOULDBLOCK && errno != EAGAIN)
            {
              // ToDo: add error handling
              LogPrint (eLogError, "SMTP: Accept error: ", strerror (errno));
            }
            std::this_thread::sleep_for (std::chrono::seconds (1));
        }
      else
        {
          LogPrint (eLogInfo, "SMTP: Received connection from ",
                    inet_ntoa (client_addr.sin_addr));

          s_handle ();
        }
    }
}

void
SMTP::s_handle ()
{
  processing = true;
  s_process ();
}

void
SMTP::s_finish ()
{
  LogPrint (eLogDebug, "SMTPsession: Finish session");
  processing = false;
  close (client_sockfd);
}

void
SMTP::s_process ()
{
  LogPrint (eLogDebug, "SMTPsession: s_process: Prepare buffer");
  ssize_t len;

  reply (reply_2XX[CODE_220]);
  session_state = STATE_INIT;

  while (processing)
    {
      memset (buf, 0, sizeof (buf));
      len = recv (client_sockfd, buf, sizeof (buf), 0);
      if (len > 0)
        {
          std::string str_buf (buf);
          LogPrint (eLogDebug, "SMTPsession: s_process: Request stream: ",
                    str_buf.substr (0, str_buf.size () - 2));
          respond (buf);
        }
      else if (len == 0)
        {
          // LogPrint(eLogDebug, "SMTPsession: run: no data received");
          continue;
        }
      else
        {
          // ToDo: add error handling
          // The server exit permanently
          LogPrint (eLogError,
            "SMTPsession: s_process: Can't recieve data, exit");
          started = false;
          break;
        }
    }
  LogPrint (eLogInfo, "SMTPsession: s_process: socket closed by client");
  s_finish ();
}

void
SMTP::respond (char *request)
{
  char output[1024];
  memset (output, 0, sizeof (output));

  // ToDo: command part to upper case
  //   https://datatracker.ietf.org/doc/html/rfc5321#section-2.4

  /// SMTP
  if (strncmp (request, "HELO", 4) == 0)
    {
      HELO ();
    }
  else if (strncmp (request, "EHLO", 4) == 0)
    {
      EHLO ();
    }
  else if (strncmp (request, "MAIL", 4) == 0)
    {
      MAIL (request);
    }
  else if (strncmp (request, "RCPT", 4) == 0)
    {
      RCPT (request);
    }
  else if (strncmp (request, "DATA", 4) == 0)
    {
      DATA ();
    }
  else if (strncmp (request, "RSET", 4) == 0)
    {
      RSET ();
    }
  else if (strncmp (request, "VRFY", 4) == 0)
    {
      VRFY ();
    }
  else if (strncmp (request, "NOOP", 4) == 0)
    {
      NOOP ();
    }
  else if (strncmp (request, "QUIT", 4) == 0)
    {
      QUIT ();
    }
  /// Extension
  else if (strncmp (request, "AUTH", 4) == 0)
    {
      AUTH (request);
    }
  else if (strncmp (request, "EXPN", 4) == 0)
    {
      EXPN ();
    }
  else if (strncmp (request, "HELP", 4) == 0)
    {
      HELP ();
    }
  else
    {
      reply (reply_5XX[CODE_502]);
    }
}

void
SMTP::reply (const char *data)
{
  if (data != nullptr)
    {
      send (client_sockfd, data, strlen (data), 0);
      std::string str_data (data);
      LogPrint (eLogDebug, "SMTPsession: reply: Reply stream: ",
                str_data.substr (0, str_data.size () - 2));
    }
}

/// SMTP
void
SMTP::HELO ()
{
  if (session_state == STATE_INIT)
    {
      reply (reply_2XX[CODE_250]);
      rcpt_user_num = 0;
      memset (rcpt_user, 0, sizeof (rcpt_user));
      session_state = STATE_HELO;
    }
  else
    {
      reply (reply_5XX[CODE_503]);
    }
}

void
SMTP::EHLO ()
{
  if (session_state == STATE_INIT)
    {
      // ToDo: looks like in EHLO client try to use PIPELINING
      //   without declaration in EHLO, for now disabled
      /*std::string reply_str;
      for (auto line : reply_info) {
        reply_str.append(line);
      }
      reply(reply_str.c_str());
      session_state = STATE_EHLO;*/
      reply (reply_5XX[CODE_502]);
    }
  else
    {
      reply (reply_5XX[CODE_501]);
    }
}

void
SMTP::MAIL (char *request)
{
  if (strncmp (request, "MAIL FROM:", 10) == 0)
    {
      if (session_state == STATE_HELO || session_state == STATE_AUTH)
        {
          std::string user, alias;

          // Use first part as identity name
          std::string str_req (request);
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

          LogPrint (eLogDebug, "SMTPsession: MAIL: user: ", user,
                    ", alias: ", alias);

          // ToDo: if no name in FROM - use identity alias
          strncpy (from_user, user.c_str (), user.size ());

          if (check_identity (alias))
            {
              reply (reply_2XX[CODE_250]);
              session_state = STATE_MAIL;
            }
          else
            {
              reply (reply_5XX[CODE_550]);
            }
        }
      else if (session_state == STATE_EHLO)
        {
          reply (reply_5XX[CODE_553]);
        }
      else
        {
          reply (reply_5XX[CODE_503_2]);
        }
    }
}

void
SMTP::RCPT (char *request)
{
  if (strncmp (request, "RCPT TO:", 8) == 0)
    {
      if ((session_state == STATE_MAIL || session_state == STATE_RCPT)
          && rcpt_user_num < MAX_RCPT_USR)
        {
          std::string user, alias;

          // Use first part as identity name
          std::string str_req (request);
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

          LogPrint (eLogDebug, "SMTPsession: RCPT: user: ", user,
                    ", alias: ", alias);

          // ToDo: if no name in FROM - use identity alias
          // char current_rcpt_user[100];
          // strncpy(current_rcpt_user, user.c_str(), user.size());

          if (check_recipient (alias))
            {
              strncpy (rcpt_user[rcpt_user_num++], user.c_str (),
                       user.size ());
              reply (reply_2XX[CODE_250]);
            }
          else
            {
              reply (reply_5XX[CODE_551]);
            }
          session_state = STATE_RCPT;
        }
      else
        {
          reply (reply_5XX[CODE_503]);
        }
    }
}

void
SMTP::DATA ()
{
  if (session_state == STATE_RCPT)
    {
      reply (reply_3XX[CODE_354]);

      memset (buf, 0, sizeof (buf));

      ssize_t recv_len = recv (client_sockfd, buf, sizeof (buf), 0);
      if (recv_len == -1)
        {
          LogPrint (eLogError,
                    "SMTPsession: DATA: Receive error: ", strerror (errno));
          reply (reply_4XX[CODE_451]);
        }
      else
        {
          LogPrint (eLogDebug, "SMTPsession: DATA: mail content:\n", buf);

          std::vector<uint8_t> mail_data (buf, buf + recv_len);
          mail.fromMIME (mail_data);
          mail.save ("outbox");

          session_state = STATE_DATA;

          reply (reply_2XX[CODE_250]);
        }
    }
  else
    {
      reply (reply_5XX[CODE_503]);
    }
}

void
SMTP::RSET ()
{
  session_state = STATE_INIT;
  reply (reply_2XX[CODE_250]);
}

void
SMTP::VRFY ()
{
  reply (reply_2XX[CODE_252]);
}

void
SMTP::NOOP ()
{
  reply (reply_2XX[CODE_250]);
}

void
SMTP::QUIT ()
{
  session_state = STATE_QUIT;
  reply (reply_2XX[CODE_221]);
  s_finish ();
}

/// Extension
void
SMTP::AUTH (char *request)
{
  // ToDo: looks like we can keep pass hash in identity file
  //   for now ignored
  if (strncmp (request, "AUTH LOGIN", 10) == 0)
    {
      LogPrint (eLogDebug, "SMTPsession: AUTH: Login successfully");
      session_state = STATE_AUTH;
      reply (reply_2XX[CODE_235]);
    }
  else if (strncmp (request, "AUTH PLAIN", 10) == 0)
    {
      LogPrint (eLogDebug, "SMTPsession: AUTH: Plain successfully");
      session_state = STATE_AUTH;
      reply (reply_2XX[CODE_235]);
    }
  else
    {
      reply (reply_5XX[CODE_504]);
    }
}

void
SMTP::EXPN ()
{
  reply (reply_2XX[CODE_252]);
}

void
SMTP::HELP ()
{
  reply (reply_2XX[CODE_214]);
}

bool
SMTP::check_identity (const std::string &name)
{
  LogPrint (eLogDebug, "SMTPsession: check_identity: name:",
            name.substr (0, name.size () - 2));
  if (pbote::context.identityByName (name))
    return true;
  return false;
}

bool
SMTP::check_recipient (const std::string &name)
{
  LogPrint (eLogDebug, "SMTPsession: check_recipient: name:",
            name.substr (0, name.size () - 2));
  if (pbote::context.alias_exist (name))
    return true;
  return false;
}

} // namespace smtp
} // namespace bote
