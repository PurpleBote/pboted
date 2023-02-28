/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022-2023, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#pragma once
#ifndef PBOTED_SRC_BOTECONTROL_H
#define PBOTED_SRC_BOTECONTROL_H

#include <map>
#include <string>
#include <sys/types.h>
#include <thread>

#if !defined(_WIN32) && !defined(DISABLE_SOCKET)
#include <sys/un.h>
#endif

#include "json.hpp"
#include "jsonrpcpp.hpp"

#include "compat.h"

namespace bote
{
namespace module
{

using json = nlohmann::json;

#define CONTROL_MAX_CLIENTS 3
#define CONTROL_BUFF_SIZE 8192
// In milliseconds
#define CONTROL_POLL_TIMEOUT 10000

/// Default socket filename
const std::string CONTROL_DEFAULT_SOCKET_NAME = "pboted.sock";

enum control_state
{
  CONTROL_STATE_QUIT = 0,  // Only after quit
  CONTROL_STATE_INIT = 1,  // After TCP connection
  CONTROL_STATE_AUTH = 2,  // ToDo
};

struct control_session
{
  control_state state = CONTROL_STATE_QUIT;
  bool need_clean = false, is_error = false;
  char *buf;
};


/* Control interface for daemon */
class BoteControl
{
public:
  BoteControl ();
  ~BoteControl ();

  void start ();
  void stop ();

  bool running () { return m_is_running; };

  typedef void (BoteControl::*Handler) (const jsonrpcpp::request_ptr req,
                                        json& results);

private:
  void run ();

  void handle_request (int sid);
  void reply (int sid, const std::string &msg);

  /// Handlers
  void all (const jsonrpcpp::request_ptr req, json& results);
  //
  void addressbook (const jsonrpcpp::request_ptr req, json& results);
  void daemon (const jsonrpcpp::request_ptr req, json& results);
  void identity (const jsonrpcpp::request_ptr req, json& results);
  void storage (const jsonrpcpp::request_ptr req, json& results);
  void peer (const jsonrpcpp::request_ptr req, json& results);
  void node (const jsonrpcpp::request_ptr req, json& results);
  /// For unknown
  void unknown_method (const jsonrpcpp::request_ptr req, json& results);
  void unknown_param (const jsonrpcpp::request_ptr req, json& results);

  ///
  bool m_is_running = false;
  std::thread *m_control_thread;

#if !defined(DISABLE_SOCKET)
  /* Socket stuff */
  bool m_socket_enabled = false;

#ifndef _WIN32
  int conn_sockfd = PB_SOCKET_INVALID;
#else
  SOCKET conn_sockfd = PB_SOCKET_INVALID;
#endif
  std::string socket_path;
  struct sockaddr_un file_addr;
#endif /* DISABLE_SOCKET */

  /* TCP stuff */
#ifndef _WIN32
  int tcp_fd = PB_SOCKET_INVALID;
#else
  SOCKET tcp_fd = PB_SOCKET_INVALID;
#endif
  std::string m_address;
  uint16_t m_port = 0;

  /* For both */
  int nfds = 1;
#ifndef _WIN32
  int client_sockfd = PB_SOCKET_INVALID;
#else
  SOCKET client_sockfd = PB_SOCKET_INVALID;
#endif
  struct pollfd fds[CONTROL_MAX_CLIENTS];

  /* Sessions stuff */
  struct control_session session;

  std::map<std::string, Handler> handlers;
};

} /* module */
} /* bote */

#endif // PBOTED_SRC_BOTECONTROL_H
