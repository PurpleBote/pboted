/**
 * Copyright (c) 2019-2022 polistern
 */

#ifndef PBOTED_SRC_BOTECONTROL_H_
#define PBOTED_SRC_BOTECONTROL_H_

#include <map>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>

#include "i2psam.h"

namespace bote {

#define BUFF_SIZE 8192

class BoteControl {
 public:

  BoteControl(const std::string& file_path);
  ~BoteControl();

  void start();
  void stop();

  typedef void (BoteControl::*Handler)(std::ostringstream& results);

 private:
  void run();
  void handle_request();

  void write_data(const std::string &msg);
  std::string read_data();
  int release();
  void close();

  void insert_param(std::ostringstream& ss, const std::string& name, int value) const;
  void insert_param(std::ostringstream& ss, const std::string& name, double value) const;
  void insert_param(std::ostringstream& ss, const std::string& name, const std::string& value) const;

  // info handlers
  void daemon(std::ostringstream& results);
  void identity(std::ostringstream& results);
  void storage(std::ostringstream& results);
  void peer(std::ostringstream& results);
  void node(std::ostringstream& results);

  bool m_is_running;
  std::thread* m_thread;

  int conn_sockfd, data_sockfd;
  //socklen_t sun_size;
  struct sockaddr_un conn_addr, data_addr;

  std::map<std::string, Handler> handlers;
};

} // bote

#endif //PBOTED_SRC_BOTECONTROL_H_
