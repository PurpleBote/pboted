/**
 * Copyright (c) 2019-2021 polistern
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

namespace bote {
namespace smtp {

SMTP::SMTP(const std::string &address, int port)
    : server_sockfd(-1), client_sockfd(-1), sin_size(0), server_addr(),
      client_addr(), started(false), smtp_thread(nullptr) {
  std::memset(&server_addr, 0, sizeof(server_addr));

  if ((server_sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    // ToDo: add error handling
    LogPrint(eLogError, "SMTP: socket create error: ", strerror(errno));
  }

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  bzero(&(server_addr.sin_zero), 8);
}

SMTP::~SMTP() { stop(); }

void SMTP::start() {
  if (!started) {
    if (bind(server_sockfd, (struct sockaddr *)&server_addr,
             sizeof(struct sockaddr)) == -1) {
      // ToDo: add error handling
      LogPrint(eLogError, "SMTP: bind error: ", strerror(errno));
    }

    fcntl(server_sockfd, F_SETFL,
          fcntl(server_sockfd, F_GETFL, 0) | O_NONBLOCK);

    if (listen(server_sockfd, MAX_CLIENTS - 1) == -1) {
      // ToDo: add error handling
      LogPrint(eLogError, "SMTP: listen error: ", strerror(errno));
    }

    started = true;
    smtp_thread = new std::thread([this] { run(); });
  }
}

void SMTP::stop() {
  for (auto &session : sessions)
    session->stop();

  started = false;
  close(server_sockfd);

  smtp_thread->join();
  delete smtp_thread;
  smtp_thread = nullptr;
}

void SMTP::run() {
  LogPrint(eLogInfo, "SMTP: Started");
  sin_size = sizeof(client_addr);

  while (started) {
    if ((client_sockfd = accept(server_sockfd, (struct sockaddr *)&client_addr,
                                &sin_size)) == -1) {
      if (errno != EWOULDBLOCK && errno != EAGAIN) {
        // ToDo: add error handling
        LogPrint(eLogError, "SMTP: Accept error: ", strerror(errno));
      }
    } else {
      LogPrint(eLogInfo, "SMTP: received connection from ",
               inet_ntoa(client_addr.sin_addr));

      std::shared_ptr<SMTPsession> new_session =
          std::make_shared<SMTPsession>(client_sockfd);
      new_session->start();
      sessions.push_back(new_session);
    }

    // ToDo:
    //   Check and remove closed sessions
    /*for (auto it = sessions.begin(); it != sessions.end(); it++) {
      if (it.operator*()->stopped()) {
        sessions.erase(it);
      }
    }*/
  }
}

SMTPsession::SMTPsession(int socket)
    : started(false), session_thread(nullptr), client_sockfd(socket),
      session_stat(STATE_QUIT), rcpt_user_num(0), from_user(), rcpt_user() {
  memset(buf, 0, sizeof(buf));
}

SMTPsession::~SMTPsession() {
  LogPrint(eLogDebug, "SMTPsession: Destructor");
  stop();

  session_thread->join();
  delete session_thread;
  session_thread = nullptr;
}

void SMTPsession::start() {
  started = true;
  session_thread = new std::thread([this] { run(); });
}

void SMTPsession::stop() {
  LogPrint(eLogDebug, "SMTPsession: stop");
  started = false;
  close(client_sockfd);
}

void SMTPsession::run() {
  LogPrint(eLogDebug, "SMTPsession: run: Prepare buffer");
  ssize_t len;

  LogPrint(eLogDebug, "SMTPsession: run: Reply OK");
  reply(reply_2XX[CODE_220]);
  session_stat = STATE_INIT;

  LogPrint(eLogDebug, "SMTPsession: run: start loop");
  while (started) {
    memset(buf, 0, sizeof(buf));
    len = recv(client_sockfd, buf, sizeof(buf), 0);
    if (len > 0) {
      std::string str_buf(buf);
      LogPrint(eLogDebug, "SMTPsession: run: Request stream: ",
               str_buf.substr(0, str_buf.size() - 2));
      respond(buf);
    } else if (len == 0) {
      //LogPrint(eLogDebug, "SMTPsession: run: no data received");
      continue;
    } else {
      // ToDo: add error handling
      // The server exit permanently
      LogPrint(eLogError, "SMTPsession: run: Can't recieve data, exit");
      started = false;
      break;
    }
  }
  LogPrint(eLogInfo, "SMTPsession: run: socket closed by client");
  stop();
}

void SMTPsession::respond(char *request) {
  char output[1024];
  memset(output, 0, sizeof(output));

  // ToDo: command part to upper case
  //   https://datatracker.ietf.org/doc/html/rfc5321#section-2.4

  /// SMTP
  if (strncmp(request, "HELO", 4) == 0) {
    HELO();
  } else if (strncmp(request, "EHLO", 4) == 0) {
    EHLO();
  } else if (strncmp(request, "MAIL", 4) == 0) {
    MAIL(request);
  } else if (strncmp(request, "RCPT", 4) == 0) {
    RCPT(request);
  } else if (strncmp(request, "DATA", 4) == 0) {
    DATA();
  } else if (strncmp(request, "RSET", 4) == 0) {
    RSET();
  } else if (strncmp(request, "VRFY", 4) == 0) {
    VRFY();
  } else if (strncmp(request, "NOOP", 4) == 0) {
    NOOP();
  } else if (strncmp(request, "QUIT", 4) == 0) {
    QUIT();
  }
  /// Extension
  else if (strncmp(request, "AUTH", 4) == 0) {
    AUTH(request);
  } else if (strncmp(request, "EXPN", 4) == 0) {
    EXPN();
  } else if (strncmp(request, "HELP", 4) == 0) {
    HELP();
  } else {
    reply(reply_5XX[CODE_502]);
  }
}

void SMTPsession::reply(const char *data) {
  if (data != nullptr) {
    send(client_sockfd, data, strlen(data), 0);
    std::string str_data(data);
    LogPrint(eLogDebug, "SMTPsession: reply: Reply stream: ",
             str_data.substr(0, str_data.size() - 2));
  }
}

/// SMTP
void SMTPsession::HELO() {
  if (session_stat == STATE_INIT) {
    reply(reply_2XX[CODE_250]);
    rcpt_user_num = 0;
    memset(rcpt_user, 0, sizeof(rcpt_user));
    session_stat = STATE_HELO;
  } else {
    reply(reply_5XX[CODE_503]);
  }
}

void SMTPsession::EHLO() {
  if (session_stat == STATE_INIT) {
    std::string reply_str;
    for (auto line : reply_info) {
      reply_str.append(line);
    }
    reply(reply_str.c_str());
    session_stat = STATE_EHLO;
  } else {
    reply(reply_5XX[CODE_501]);
  }
}

void SMTPsession::MAIL(char *request) {
  if (strncmp(request, "MAIL FROM", 9) == 0) {
    if (session_stat == STATE_HELO || session_stat == STATE_AUTH) {
      // Use first part as identity name
      std::string str_req(request);
      std::size_t pos = str_req.find(" <");
      std::string user = str_req.substr(9, pos);

      strncpy(from_user, user.c_str(), user.size());

      if (check_identity(from_user)) {
        reply(reply_2XX[CODE_250]);
        session_stat = STATE_MAIL;
      } else {
        reply(reply_5XX[CODE_550]);
      }
    } else if (session_stat == STATE_EHLO) {
      reply(reply_5XX[CODE_553]);
    } else {
      reply(reply_5XX[CODE_503_2]);
    }
  }
}

void SMTPsession::RCPT(char *request) {
  if (strncmp(request, "RCPT TO", 7) == 0) {
    if ((session_stat == STATE_MAIL || session_stat == STATE_RCPT) &&
        rcpt_user_num < MAX_RCPT_USR) {
      // Use first part as identity name
      std::string str_req(request);
      std::size_t pos = str_req.find(" <");
      std::string user = str_req.substr(9, pos);

      char current_rcpt_user[100];
      strncpy(current_rcpt_user, user.c_str(), user.size());

      if (check_recipient(current_rcpt_user)) {
        strncpy(rcpt_user[rcpt_user_num++], user.c_str(), user.size());
        reply(reply_2XX[CODE_250]);
      } else {
        reply(reply_5XX[CODE_551]);
      }
      session_stat = STATE_RCPT;
    } else {
      reply(reply_5XX[CODE_503]);
    }
  }
}

void SMTPsession::DATA() {
  if (session_stat == STATE_RCPT) {
    reply(reply_3XX[CODE_354]);

    char buf[BUF_SIZE];
    memset(buf, 0, sizeof(buf));

    if (recv(client_sockfd, buf, sizeof(buf), 0) == -1) {
      LogPrint(eLogError,
               "SMTPsession: DATA: Receive error: ", strerror(errno));
      reply(reply_4XX[CODE_451]);
    } else {
      LogPrint(eLogDebug, "SMTPsession: DATA: mail content:\n", buf);

      std::vector<uint8_t> mail_data(buf, buf + sizeof(buf));
      mail.fromMIME(mail_data);
      mail.save("outbox");

      session_stat = STATE_DATA;

      reply(reply_2XX[CODE_250]);
    }
  } else {
    reply(reply_5XX[CODE_503]);
  }
}

void SMTPsession::RSET() {
  session_stat = STATE_INIT;
  reply(reply_2XX[CODE_250]);
}

void SMTPsession::VRFY() { reply(reply_2XX[CODE_252]); }

void SMTPsession::NOOP() { reply(reply_2XX[CODE_250]); }

void SMTPsession::QUIT() {
  session_stat = STATE_QUIT;
  reply(reply_2XX[CODE_221]);
  stop();
}

/// Extension
void SMTPsession::AUTH(char *request) {
  // ToDo: looks like we can keep pass hash in identity file
  //   for now ignored
  if (strncmp(request, "AUTH LOGIN", 10) == 0) {
    LogPrint(eLogDebug, "SMTPsession: AUTH: Login successfully");
    session_stat = STATE_AUTH;
    reply(reply_2XX[CODE_235]);
  } else if (strncmp(request, "AUTH PLAIN", 10) == 0) {
    LogPrint(eLogDebug, "SMTPsession: AUTH: Plain successfully");
    session_stat = STATE_AUTH;
    reply(reply_2XX[CODE_235]);
  } else {
    reply(reply_5XX[CODE_504]);
  }
}

void SMTPsession::EXPN() { reply(reply_2XX[CODE_252]); }

void SMTPsession::HELP() { reply(reply_2XX[CODE_214]); }

bool SMTPsession::check_identity(const std::string &name) {
  LogPrint(eLogDebug, "SMTPsession: identity_check: identity:",
           name.substr(0, name.size() - 2));
  if (pbote::context.identityByName(name))
    return true;
  return false;
}

bool SMTPsession::check_recipient(const std::string &name) {
  LogPrint(eLogDebug, "SMTPsession: identity_check: identity:",
           name.substr(0, name.size() - 2));
  if (pbote::context.recipient_exist(name))
    return true;
  return false;
}

} // namespace smtp
} // namespace bote
