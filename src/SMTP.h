/**
 * Copyright (c) 2019-2021 polistern
 */

#ifndef BOTE_SRC_SMTP_H_
#define BOTE_SRC_SMTP_H_

#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>

#include "Email.h"

namespace bote {
namespace smtp {

#define MAX_CLIENTS 5
#define MAX_RCPT_USR 1
#define BUF_SIZE 10485760 // 10MB

const char reply_info[][100] = {
    {"250-pboted.i2p is pleased to meet you\n"},
    // ToDo: {"250-SIZE 10485760\n"}, // RFC 1870
    {"250-AUTH LOGIN PLAIN\n"}, // RFC 4954. libsasl2?
    // ToDo: {"250-ENHANCEDSTATUSCODES\n"}, // RFC 3463
    // ToDo: {"250-CHUNKING\n"}, // RFC 3030
    // ToDo: {"250-PIPELINING\n"}, // RFC 2920
    // ToDo: {"250-STARTTLS\n"}, // RFC 3207
    // ToDo: {"250-8BITMIME\n"},
    // ToDo: {"250-SMTPUTF8\n"}, // RFC 6531
    // ToDo: {"250-EXPN\n"},
    {"250-HELP\n"}, // RFC 821
    {"250 HELO\r\n"}
};

const char reply_help[][100] = {
    {""}
};

#define CODE_211 0
#define CODE_214 1
#define CODE_220 2
#define CODE_221 3
#define CODE_235 4
#define CODE_250 5
#define CODE_251 6
#define CODE_252 7

const char reply_2XX[][100] = {
    {"211 System status, or system help reply.\r\n"},              // 0
    {"214 Help message.\r\n"},                                     // 1
    {"220 pboted SMTP Service ready\r\n"},                         // 2
    {"221 pboted Service closing transmission channel\r\n"},       // 3
    {"235 2.7.0 Authentication Succeeded\r\n"},                    // 4
    {"250 OK\r\n"},                                                // 5
    {"251 User not local\r\n"},                                    // 6
    {"252 Cannot VRFY user, but will accept message and attempt delivery\r\n"} // 7
};

#define CODE_354 0

const char reply_3XX[][100] = {
    {"354 Start mail input\r\n"} // 0
};

#define CODE_421 0
#define CODE_450 1
#define CODE_451 2
#define CODE_452 3
#define CODE_455 4

const char reply_4XX[][100] = {
    {"421 service not available, closing transmission channel\r\n"},     // 0
    {"450 Requested mail action not taken: mailbox unavailable\r\n"},    // 1
    {"451 Requested action aborted: local error in processing\r\n"},     // 2
    {"452 Requested action not taken: insufficient system storage\r\n"}, // 3
    {"455 Server unable to accommodate parameters\r\n"},                 // 4
};

#define CODE_500 0
#define CODE_501 1
#define CODE_502 2
#define CODE_503 3
#define CODE_503_2 4
#define CODE_504 5
#define CODE_550 6
#define CODE_551 7
#define CODE_552 8
#define CODE_553 9
#define CODE_554 10
#define CODE_555 11

const char reply_5XX[][100] = {
    {"500 Syntax error, command unrecognised\r\n"},                         // 0
    {"501 Syntax error in parameters or arguments\r\n"},                    // 1
    {"502 Command not implemented\r\n"},                                    // 2
    {"503 Bad sequence of commands\r\n"},                                   // 3
    {"503 Send HELO/EHLO first\r\n"},                                       // 4
    {"504 Command parameter not implemented\r\n"},                          // 5
    {"550 Requested action not taken: mailbox unavailable\r\n"},            // 6
    {"551 User not local\r\n"},                                             // 7
    {"552 Requested mail action aborted: exceeded storage allocation\r\n"}, // 8
    {"553 Requested action not taken: mailbox name not allowed\r\n"},       // 9
    {"554 Transaction failed\r\n"},                                         // 10
    {"555 MAIL FROM/RCPT TO parameters not recognized or not implemented\r\n"} // 11
};

class SMTPsession;

class SMTP {
public:
  SMTP(const std::string &address, int port);
  ~SMTP();

  void start();
  void stop();

private:
  void run();

  int server_sockfd, client_sockfd;
  socklen_t sin_size;
  struct sockaddr_in server_addr, client_addr;

  bool started;
  std::thread *smtp_thread;
  std::vector<std::shared_ptr<SMTPsession>> sessions;
};

/// SMTP
#define STATE_QUIT 0 // Only after quit
#define STATE_INIT 1 // After TCP connection
#define STATE_HELO 2 // After HELO command
#define STATE_MAIL 3 // After MAIL command
#define STATE_RCPT 4 // After RCPT command
#define STATE_DATA 5 // After DATA command
/// Extension
#define STATE_EHLO 10 // After HELO command
#define STATE_STLS 11 // After STARTTLS command
#define STATE_AUTH 12 // After AUTH command

class SMTPsession {
public:
  SMTPsession(int socket);
  ~SMTPsession();

  void start();
  void stop();

  bool stopped() const { return !started; }

private:
  void run();
  void respond(char *request);
  void reply(const char *data);

  /// SMTP https://datatracker.ietf.org/doc/html/rfc5321#section-4.5.1
  void HELO();
  void EHLO();
  void MAIL(char *request);
  void RCPT(char *request);
  void DATA();
  void RSET();
  void VRFY();
  void NOOP();
  void QUIT();

  /// Extension
  void AUTH(char *request);
  void EXPN();
  void HELP();

  static bool check_identity(const std::string &name);
  static bool check_recipient(const std::string &name);

  bool started;
  std::thread *session_thread;

  int client_sockfd;
  int session_state;
  char buf[BUF_SIZE];

  int rcpt_user_num;
  char from_user[512];
  char rcpt_user[MAX_RCPT_USR][512];
  pbote::Email mail;
};

} // namespace smtp
} // namespace bote

#endif // BOTE_SRC_SMTP_H_
