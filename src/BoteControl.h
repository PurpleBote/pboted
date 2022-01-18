/**
 * Copyright (c) 2019-2022 polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#ifndef PBOTED_SRC_BOTECONTROL_H_
#define PBOTED_SRC_BOTECONTROL_H_

#include <map>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>

#include "i2psam.h"

namespace bote
{

#define BUFF_SIZE 8192

class BoteControl
{
public:
  BoteControl (const std::string &file_path);
  ~BoteControl ();

  void start ();
  void stop ();

  typedef void (BoteControl::*Handler) (const std::string &cmd_id,
                                        std::ostringstream &results);

private:
  void run ();
  void handle_request ();

  void write_data (const std::string &msg);
  std::string read_data ();
  int release ();
  void close ();

  void insert_param (std::ostringstream &ss, const std::string &name,
                     int value) const;
  void insert_param (std::ostringstream &ss, const std::string &name,
                     double value) const;
  void insert_param (std::ostringstream &ss, const std::string &name,
                     const std::string &value) const;

  // handlers
  void daemon (const std::string &cmd_id, std::ostringstream &results);
  void identity (const std::string &cmd_id, std::ostringstream &results);
  void storage (const std::string &cmd_id, std::ostringstream &results);
  void peer (const std::string &cmd_id, std::ostringstream &results);
  void node (const std::string &cmd_id, std::ostringstream &results);

  bool m_is_running;
  std::thread *m_thread;

  int conn_sockfd, data_sockfd;
  struct sockaddr_un conn_addr, data_addr;

  std::map<std::string, Handler> handlers;
};

} // bote

#endif // PBOTED_SRC_BOTECONTROL_H_
