/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#ifndef BOTE_SRC_POP3_H
#define BOTE_SRC_POP3_H

#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>

#include "compat.h"
#include "Email.h"

namespace bote
{
namespace pop3
{

#define POP3_MAX_CLIENTS 2
#define POP3_BUF_SIZE 10485760 // 10MB
// In milliseconds
#define POP3_POLL_TIMEOUT 10000
// In seconds
#define POP3_SOCK_TIMEOUT 10

const char capa_list[][100] =
{
  { "+OK Capability list follows\n" },
  { "USER\n" }, // added USER PASS
  // ToDo: {"APOP\n"}, // added APOP
  // ToDo: {"TOP\n"}, // added TOP
  // ToDo: {"UIDL\n"}, // added UIDL
  // ToDo: {"SASL\n"}, // added AUTH; reference: POP-AUTH, SASL. libsasl2?
  // ToDo: {"STARTTLS\n"},
  // ToDo: {"RESP-CODES\n"},
  // ToDo: {"LOGIN-DELAY 900\n"}, // affected USER PASS APOP AUTH
  // ToDo: {"PIPELINING\n"},
  // ToDo: {"EXPIRE 60\n"},
  // ToDo: {"IMPLEMENTATION\n"},
  { ".\r\n" }
};

enum ok_res
{
  OK_SIMP     = 0,
  OK_HELO     = 1,
  OK_USER     = 2,
  OK_LOCK     = 3,
  OK_QUIT     = 4,
  OK_MAILDROP = 5,
  OK_STAT     = 6,
  OK_DEL      = 7,
  OK_LIST     = 8,
  OK_RETR     = 9,
  OK_TOP      = 10,
  OK_UIDL     = 11,
};

const char reply_ok[][100] = {
  { "+OK\r\n" },                                       // 0
  { "+OK pboted POP3 server ready <pboted.i2p>\r\n" }, // 1
  { "+OK %s is a valid mailbox\r\n" },                 // 2
  { "+OK maildrop locked and ready\r\n" },             // 3
  { "+OK pboted POP3 server signing off\r\n" },        // 4
  { "+OK maildrop has %d messages (%d octets)\r\n" },  // 5
  { "+OK %d %d\r\n" },                                 // 6
  { "+OK message %d deleted\r\n" },                    // 7
  { "+OK %d messages (%d octets)\n" },                 // 8
  { "+OK %d octets\n" },                               // 9
  { "+OK top of message follows\r\n" },                // 10
  { "+OK unique-id listing for %d emails follows\n" }  // 11
};

enum err_res
{
  ERR_SIMP        = 0,
  ERR_NO_COMMAND  = 1,
  ERR_USER        = 2,
  ERR_PASS        = 3,
  ERR_LOCK        = 4,
  ERR_DENIED      = 5,
  ERR_NOT_FOUND   = 6,
  ERR_REMOVED     = 7,
  ERR_NOT_REMOVED = 8
};

const char reply_err[][100] = {
  { "-ERR\r\n" },                                  // 0
  { "-ERR Command not implemented\r\n" },          // 1
  { "-ERR never heard of mailbox %s\r\n" },        // 2
  { "-ERR invalid password\r\n" },                 // 3
  { "-ERR unable to lock maildrop\r\n" },          // 4
  { "-ERR permission denied\r\n" },                // 5
  { "-ERR no such message\r\n" },                  // 6
  { "-ERR message %d already deleted\r\n" },       // 7
  { "-ERR some deleted messages not removed\r\n" } // 8
};

#define TEMPLATE_LIST_ITEM 0
#define TEMPLATE_UIDL_ITEM 1

const char templates[][100] = {
  { "%d %d" }, // 0
  { "%d %s" }  // 1
};

/* POP3 session states */
enum pop3_state
{
  STATE_QUIT = 0,        // Only after quit
  STATE_USER = 1,        // After TCP connection
  STATE_PASS = 2,        // After successful USER
  STATE_TRANSACTION = 3, // After successful PASS
  STATE_UPDATE = 4      // After disconnect from TRANSACTION
};

struct pop3_session
{
  pop3_state state = STATE_QUIT;
  bool need_clean = false;
  char *buf;
  std::vector<std::shared_ptr<pbote::Email> > emails;
};

class POP3
{
public:
  POP3 (const std::string &address, int port);
  ~POP3 ();

  void start ();
  void stop ();

private:
  void run ();

  void respond (int sid);
  void reply (int sid, const char *data);

  void USER (int sid);
  void PASS (int sid);

  void STAT (int sid);
  void LIST (int sid);
  void RETR (int sid);
  void DELE (int sid);
  void NOOP (int sid);
  void RSET (int sid);
  void QUIT (int sid);

  /// Extensions RFC 2449
  void CAPA (int sid);
  void APOP (int sid);
  void TOP (int sid);
  void UIDL (int sid);

  static bool check_user (const std::string &user);
  static bool check_pass (const std::string &pass);

  bool started;
  std::thread *pop3_thread;

  int server_sockfd = SOCKET_INVALID, client_sockfd = SOCKET_INVALID;
  std::string m_address;
  uint16_t m_port = 0;
  int nfds = 1; /* descriptors count */

  struct pollfd fds[POP3_MAX_CLIENTS];
  struct pop3_session session;
};

template <typename... t_args>
std::string
format_response (const char *msg)
{
  return { msg };
}

template <typename... t_args>
std::string
format_response (const char *format, t_args &&... args)
{
  const int bufferStatus = std::snprintf (nullptr, 0, format, args...);

  if (bufferStatus < 0)
    {
      LogPrint (eLogError, "POP3: format_response: Failed to allocate buffer");
      return {};
    }

  std::vector<char> buffer (bufferStatus + 1);
  const int status
      = std::snprintf (buffer.data (), buffer.size (), format, args...);

  if (status < 0)
    {
      LogPrint (eLogError, "POP3: format_response: Failed to format message");
      return {};
    }

  return { buffer.data () };
}

} // namespace pop3
} // namespace bote

#endif // BOTE_SRC_POP3_H
