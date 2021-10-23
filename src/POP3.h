/**
 * Copyright (c) 2019-2021 polistern
 */

#ifndef BOTE_SRC_POP3_H_
#define BOTE_SRC_POP3_H_

#include <cstdarg>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>

#include "Email.h"

namespace bote {
namespace pop3 {

#define MAX_CLIENTS 5
#define MAX_RCPT_USR 1
#define BUF_SIZE 10485760 // 10MB

const char capa_list[][100] = {
    {"+OK Capability list follows\n"},
    {"USER\n"}, // added USER PASS
    // ToDo: {"APOP\n"}, // added APOP
    // ToDo: {"TOP\n"}, // added TOP
    // ToDo: {"UIDL\n"}, // added UIDL
    // ToDo: {"SASL\n"}, // added AUTH; reference: POP-AUTH, SASL
    // ToDo: {"STARTTLS\n"},
    // ToDo: {"RESP-CODES\n"},
    // ToDo: {"LOGIN-DELAY 900\n"}, // affected USER PASS APOP AUTH
    // ToDo: {"PIPELINING\n"},
    // ToDo: {"EXPIRE 60\n"},
    // ToDo: {"IMPLEMENTATION\n"},
    {".\r\n"}
};

#define OK_SIMP 0
#define OK_HELO 1
#define OK_USER 2
#define OK_LOCK 3
#define OK_QUIT 4
#define OK_MAILDROP 5
#define OK_STAT 6
#define OK_DEL 7
#define OK_LIST 8
#define OK_RETR 9
#define OK_TOP  10
#define OK_UIDL  11

const char reply_ok[][100] = {
    {"+OK\r\n"},                                          // 0
    {"+OK pboted POP3 server ready <pboted.i2p>\r\n"},    // 1
    {"+OK %s is a valid mailbox\r\n"},                    // 2
    {"+OK maildrop locked and ready\r\n"},                // 3
    {"+OK pboted POP3 server signing off\r\n"},           // 4
    {"+OK maildrop has %d messages (%d octets)\r\n"},     // 5
    {"+OK %d %d\r\n"},                                    // 6
    {"+OK message %d deleted\r\n"},                       // 7
    {"+OK %d messages (%d octets)\n"},                    // 8
    {"+OK %d octets\n"},                                  // 9
    {"+OK top of message follows\r\n"},                   // 10
    {"+OK unique-id listing for %d emails follows\n"}     // 11
};

#define ERR_SIMP 0
#define ERR_NO_COMMAND 1
#define ERR_USER 2
#define ERR_PASS 3
#define ERR_LOCK 4
#define ERR_DENIED 5
#define ERR_NOT_FOUND 6
#define ERR_REMOVED 7
#define ERR_NOT_REMOVED 8

const char reply_err[][100] = {
    {"-ERR\r\n"},                                   // 0
    {"-ERR Command not implemented\r\n"},           // 1
    {"-ERR never heard of mailbox %s\r\n"},       // 2
    {"-ERR invalid password\r\n"},                  // 3
    {"-ERR unable to lock maildrop\r\n"},           // 4
    {"-ERR permission denied\r\n"},                 // 5
    {"-ERR no such message\r\n"},                   // 6
    {"-ERR message %d already deleted\r\n"},        // 7
    {"-ERR some deleted messages not removed\r\n"}  // 8
};

#define TEMPLATE_LIST_ITEM 0
#define TEMPLATE_UIDL_ITEM 0

const char templates[][100] = {
    {"%d %d"}, // 0
    {"%d %s"}  // 1
};

class POP3session;

class POP3 {
public:
  POP3(const std::string &address, int port);
  ~POP3();

  void start();
  void stop();

private:
  void run();

  int server_sockfd, client_sockfd;
  socklen_t sin_size;
  struct sockaddr_in server_addr, client_addr;

  bool started;
  std::thread *pop3_thread;
  std::vector<std::shared_ptr<POP3session>> sessions;
};

/// POP3 session states
#define STATE_QUIT 0 // Only after quit
#define STATE_USER 1 // After TCP connection
#define STATE_PASS 2 // After successful USER
#define STATE_TRANSACTION 3 // After successful PASS
#define STATE_UPDATE 4 // After disconnect from TRANSACTION

class POP3session {
public:
  POP3session(int socket);
  ~POP3session();

  void start();
  void stop();

  bool stopped() const { return !started; }

private:
  void run();
  void respond(char *request);
  void reply(const char *data);

  void USER(char *request);
  void PASS(char *request);

  void STAT();
  void LIST(char *request);
  void RETR(char *request);
  void DELE(char *request);
  void NOOP();
  void RSET();
  void QUIT();

  /// Extension RFC 2449
  void CAPA();
  void APOP(char *request);
  void TOP(char *request);
  void UIDL(char *request);

  static bool check_user(const std::string &user);
  static bool check_pass(const std::string &pass);

  bool started;
  std::thread *session_thread;

  int client_sockfd;
  int session_state;
  char buf[BUF_SIZE];

  std::vector<std::shared_ptr<pbote::Email>> emails;
};

inline std::string format_response(const char *format, ...) {
  std::va_list args;
  va_start(args, format);

  std::va_list argsCopy;
  va_copy(argsCopy, args);
  const char * const formatCopy = format;
  const int bufferStatus = std::vsnprintf(nullptr, 0, formatCopy, argsCopy);
  va_end(argsCopy);

  if (bufferStatus < 0) {
    LogPrint(eLogError, "POP3: format_response: Failed to allocate buffer");
    return {};
  }

  std::vector<char> buffer(bufferStatus + 1);
  const int status = std::vsnprintf(buffer.data(), buffer.size(), formatCopy, args);
  va_end(args);

  if (status < 0) {
    LogPrint(eLogError, "POP3: format_response: Failed to format message");
    return {};
  }

  return {buffer.data()};
}

} // namespace pop3
} // namespace bote

#endif // BOTE_SRC_POP3_H_
