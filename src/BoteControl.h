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

#include <map>
#include <string>
#include <sys/types.h>
#include <thread>

#if !defined(_WIN32) && !defined(DISABLE_SOCKET)
#include <sys/un.h>
#endif

#include "compat.h"

namespace bote
{

#define CONTROL_MAX_CLIENTS 3
#define CONTROL_BUFF_SIZE 8192
// In milliseconds
#define CONTROL_POLL_TIMEOUT 10000

/// Default socket filename
const std::string DEFAULT_SOCKET_NAME = "pboted.sock";

enum control_state
{
  STATE_QUIT = 0,  // Only after quit
  STATE_INIT = 1,  // After TCP connection
  STATE_AUTH = 2,  // ToDo
};

struct control_session
{
  control_state state = STATE_QUIT;
  bool need_clean = false;
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

  typedef void (BoteControl::*Handler) (const std::string &cmd_id,
                                        std::ostringstream &results);

private:
  void run ();

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
#endif

  /* TCP stuff */
#ifndef _WIN32
  int tcp_fd = PB_SOCKET_INVALID;
#else
  SOCKET tcp_fd = PB_SOCKET_INVALID;
#endif
  std::string m_address;
  uint16_t m_port = 0;
  socklen_t sin_size; /* for client addr */
  struct sockaddr_in tcp_addr, client_addr;

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

} // bote

#endif // PBOTED_SRC_BOTECONTROL_H
