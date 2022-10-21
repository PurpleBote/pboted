/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#ifndef PBOTED_SRC_BOTECONTROL_H
#define PBOTED_SRC_BOTECONTROL_H

#define DISABLE_SOCKET

#include <map>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>

#if !defined(_WIN32) || !defined(DISABLE_SOCKET)
#include <sys/un.h>
#else
// NOOP
#endif

#include "i2psam.hpp"

namespace bote
{

#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif

#define BUFF_SIZE 8192
// Timeout in milliseconds
#define CONTROL_WAIT_TIMEOUT 10000
#define CONTROL_MAX_CLIENTS 5

/// Default socket filename
const std::string DEFAULT_SOCKET_NAME = "pboted.sock";


enum control_state
{
  STATE_INIT = 0,
  STATE_AUTH = 1,
};

struct control_session
{
  control_state state;
  char buf[BUFF_SIZE];
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

  typedef void (BoteControl::*Handler) (const std::string &cmd_id,
                                        std::ostringstream &results);

private:
  void run ();
  void handle ();

  void handle_request (int sid);

  void reply (int sid, const std::string &msg);

  void insert_param (std::ostringstream &ss, const std::string &name,
                     int value) const;
  void insert_param (std::ostringstream &ss, const std::string &name,
                     double value) const;
  void insert_param (std::ostringstream &ss, const std::string &name,
                     const std::string &value) const;

  /// Handlers
  void all (const std::string &cmd_id, std::ostringstream &results);
  void daemon (const std::string &cmd_id, std::ostringstream &results);
  void identity (const std::string &cmd_id, std::ostringstream &results);
  void storage (const std::string &cmd_id, std::ostringstream &results);
  void peer (const std::string &cmd_id, std::ostringstream &results);
  void node (const std::string &cmd_id, std::ostringstream &results);
  /// For unknown
  void unknown_cmd (const std::string &cmd, std::ostringstream &results);

  bool m_is_running = false;
  std::thread *m_control_acceptor_thread;
  std::thread *m_control_handler_thread;

#if !defined(_WIN32) || !defined(DISABLE_SOCKET)
  /* Socket stuff */
  bool m_socket_enabled = false;

  int conn_sockfd = INVALID_SOCKET;
  std::string socket_path;
  struct sockaddr_un file_addr;
#endif

  /* TCP stuff */
  int tcp_fd = INVALID_SOCKET;
  std::string m_address;
  uint16_t m_port = 0;
  socklen_t sin_size; /* for client addr */
  struct sockaddr_in tcp_addr, client_addr;

  /* For both */
  int nfds = 1;
  int client_sockfd = INVALID_SOCKET;
  struct pollfd fds[CONTROL_MAX_CLIENTS];
  control_session sessions[CONTROL_MAX_CLIENTS];

  std::map<std::string, Handler> handlers;
};

} // bote

#endif // PBOTED_SRC_BOTECONTROL_H
