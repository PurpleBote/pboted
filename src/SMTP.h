/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#ifndef BOTE_SRC_SMTP_H
#define BOTE_SRC_SMTP_H

#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>

#include "Email.h"
#include "NetworkWorker.h"

namespace bote
{
namespace smtp
{

#define SMTP_MAX_CLIENTS 2
#define SMTP_MAX_RCPT_USR 1
#define SMTP_BUF_SIZE 10485760 // 10MB
// In milliseconds
#define SMTP_POLL_TIMEOUT 10000
// In seconds
#define SMTP_SOCK_TIMEOUT 10
#define SMTP_COMMAND_LEN 4

const char reply_info[][100]
    = { { "250-pboted.i2p is pleased to meet you\n" },
        // ToDo: {"250-SIZE 10485760\n"}, // RFC 1870
        { "250-AUTH LOGIN PLAIN\n" }, // RFC 4954. libsasl2?
        // ToDo: {"250-ENHANCEDSTATUSCODES\n"}, // RFC 3463
        // ToDo: {"250-CHUNKING\n"}, // RFC 3030
        // ToDo: {"250-PIPELINING\n"}, // RFC 2920
        // ToDo: {"250-STARTTLS\n"}, // RFC 3207
        // ToDo: {"250-8BITMIME\n"},
        // ToDo: {"250-SMTPUTF8\n"}, // RFC 6531
        // ToDo: {"250-EXPN\n"},
        { "250-HELP\n" }, // RFC 821
        { "250 HELO\r\n" } };

const char reply_help[][100]
    = { { "help" } };

enum code_2xx
{
  CODE_211 = 0,
  CODE_214 = 1,
  CODE_220 = 2,
  CODE_221 = 3,
  CODE_235 = 4,
  CODE_250 = 5,
  CODE_251 = 6,
  CODE_252 = 7,
};

const char reply_2XX[][100] = {
  { "211 System status, or system help reply.\r\n" },                 // 0
  { "214 Help message.\r\n" },                                        // 1
  { "220 pboted SMTP Service ready\r\n" },                            // 2
  { "221 pboted Service closing transmission channel\r\n" },          // 3
  { "235 2.7.0 Authentication Succeeded\r\n" },                       // 4
  { "250 OK\r\n" },                                                   // 5
  { "251 User not local\r\n" },                                       // 6
  { "252 Cannot VRFY user, accept message and attempt delivery\r\n" } // 7
};

enum code_3xx
{
  CODE_354 = 0,
};

const char reply_3XX[][100] = {
  { "354 Start mail input\r\n" } // 0
};

enum code_4xx
{
  CODE_421 = 0,
  CODE_450 = 1,
  CODE_451 = 2,
  CODE_452 = 3,
  CODE_455 = 4,
};

const char reply_4XX[][100] = {
  { "421 service not available, closing transmission channel\r\n" },     // 0
  { "450 Requested mail action not taken: mailbox unavailable\r\n" },    // 1
  { "451 Requested action aborted: local error in processing\r\n" },     // 2
  { "452 Requested action not taken: insufficient system storage\r\n" }, // 3
  { "455 Server unable to accommodate parameters\r\n" },                 // 4
};

enum code_5xx
{
  CODE_500    = 0,
  CODE_501    = 1,
  CODE_502    = 2,
  CODE_503    = 3, /* for any other state */
  CODE_503_2  = 4, /* for HELO state */
  CODE_504    = 5,
  CODE_550    = 6,
  CODE_551    = 7,
  CODE_552    = 8,
  CODE_553    = 9,
  CODE_554    = 10,
  CODE_555    = 11,
};

const char reply_5XX[][100] = {
  { "500 Syntax error, command unrecognised\r\n" },                         // 0
  { "501 Syntax error in parameters or arguments\r\n" },                    // 1
  { "502 Command not implemented\r\n" },                                    // 2
  { "503 Bad sequence of commands\r\n" },                                   // 3
  { "503 Send HELO/EHLO first\r\n" },                                       // 4
  { "504 Command parameter not implemented\r\n" },                          // 5
  { "550 Requested action not taken: mailbox unavailable\r\n" },            // 6
  { "551 User not local\r\n" },                                             // 7
  { "552 Requested mail action aborted: exceeded storage allocation\r\n" }, // 8
  { "553 Requested action not taken: mailbox name not allowed\r\n" },       // 9
  { "554 Transaction failed\r\n" },                                        // 10
  { "555 MAIL FROM/RCPT TO parameters not recognized or not "
    "implemented\r\n" } // 11
};

/* SMTP session state */
enum smtp_state
{
  STATE_QUIT = 0,  // Only after quit
  STATE_INIT = 1,  // After TCP connection
  STATE_HELO = 2,  // After HELO command
  STATE_MAIL = 3,  // After MAIL command
  STATE_RCPT = 4,  // After RCPT command
  STATE_DATA = 5,  // After DATA command
/* For extensions */
  STATE_EHLO = 10, // After HELO command
  STATE_STLS = 11, // After STARTTLS command
  STATE_AUTH = 12, // After AUTH command
};

struct smtp_session
{
  smtp_state state = STATE_QUIT;
  bool need_clean = false;
  char *buf;
  int nrcpt = 0; /* number of filed RCPT users */
  char from[512];
  char rcpt[SMTP_MAX_RCPT_USR][512];
};

class SMTP
{
public:
  SMTP (const std::string &address, int port);
  ~SMTP ();

  void start ();
  void stop ();

private:
  void run ();

  void respond (int sid);
  void reply (int sid, const char *data);

  /* SMTP*/
  /* https://datatracker.ietf.org/doc/html/rfc5321#section-4.5.1 */
  void HELO (int sid);
  void EHLO (int sid);
  void MAIL (int sid);
  void RCPT (int sid);
  void DATA (int sid);
  void RSET (int sid);
  void VRFY (int sid);
  void NOOP (int sid);
  void QUIT (int sid);

  /* Extensions */
  void AUTH (int sid);
  void EXPN (int sid);
  void HELP (int sid);

  static bool check_identity (const std::string &name);
  static bool check_recipient (const std::string &name);

  void cmd_to_upper(char *data, int len = SMTP_COMMAND_LEN);

  bool started;
  std::thread *smtp_thread;

  int server_sockfd = SOCKET_INVALID, client_sockfd = SOCKET_INVALID;
  std::string m_address;
  uint16_t m_port = 0;
  int nfds = 1; /* descriptors count */

  struct pollfd fds[SMTP_MAX_CLIENTS];
  struct smtp_session session;
};

} // namespace smtp
} // namespace bote

#endif /* BOTE_SRC_SMTP_H*/
