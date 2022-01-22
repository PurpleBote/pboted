/**
 * Copyright (c) 2019-2022 polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#ifndef NETWORK_WORKER_H__
#define NETWORK_WORKER_H__

#include <algorithm>
#include <ctime>
#include <iostream>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <utility>

#include "BoteContext.h"
#include "Logging.h"
#include "Queue.h"

#include "i2psam.h"

namespace pbote {

const size_t MAX_DATAGRAM_SIZE = 32768;

namespace network {

const std::string SAM_NICKNAME = "pboted";

class udp_client_server_runtime_error : public std::runtime_error {
 public:
  udp_client_server_runtime_error(const char *w) : std::runtime_error(w) {}
};

/**
 * Receive handle class
 */
class UDPReceiver {
 public:
  UDPReceiver(const std::string &address, int port);
  ~UDPReceiver();

  void start();
  void stop();

  void setNickname(const std::string &nickname = SAM_NICKNAME) { m_nickname_ = nickname; };
  void setQueue(const queue_type &recvQueue) { m_recvQueue = recvQueue; };

  int get_socket() const { return f_socket; };
  int get_port() const { return f_port; };
  std::string get_addr() const { return f_addr; };

  bool isRunning() const { return m_IsRunning; };

 private:
  void run();
  long recv();
  // int timed_recv(/*char *msg, size_t max_size,*/ int max_wait_ms);
  void handle_receive();

  bool m_IsRunning;
  std::thread *m_RecvThread;
  std::string m_nickname_;
  int f_socket;
  int f_port;
  std::string f_addr;
  struct addrinfo *f_addrinfo{};

  uint8_t m_DatagramRecvBuffer[MAX_DATAGRAM_SIZE + 1]{};
  queue_type m_recvQueue;
};

/**
 * Send handle class
 */
class UDPSender {
 public:
  UDPSender(const std::string &addr, int port);
  ~UDPSender();

  void start();
  void stop();

  void setNickname(const std::string &nickname = SAM_NICKNAME) { m_nickname_ = nickname; };
  void setSessionID(const std::string &sessionID) { m_sessionID_ = sessionID; };
  void setQueue(const queue_type &sendQueue) { m_sendQueue = sendQueue; };

  int get_socket() const { return f_socket; };
  int get_port() const { return f_port; };
  std::string get_addr() const { return f_addr; };

  bool isRunning() const { return m_IsRunning; };

 private:
  void run();
  void send();
  void handle_send(/*const boost::system::error_code &ec,*/ std::size_t bytes_transferred);

  bool m_IsRunning;
  std::thread *m_SendThread;
  std::string m_nickname_;
  std::string m_sessionID_;

  int f_socket;
  int f_port;
  std::string f_addr;
  struct addrinfo *f_addrinfo{};

  queue_type m_sendQueue;
};

/**
 * Controller class
 * ToDo: Need some optimization
 */
class NetworkWorker {
 public:
  NetworkWorker();
  ~NetworkWorker();

  void init();
  void start();
  void stop();

  std::shared_ptr<i2p::data::PrivateKeys> createSAMSession();

  void createRecvHandler();
  void createSendHandler();

 private:
  /** prevent making copies */
  NetworkWorker(const NetworkWorker &);
  const NetworkWorker &operator=(const NetworkWorker &);

  std::string m_nickname_;

  std::string listenAddress_;
  uint16_t listenPortUDP_;

  std::string routerAddress_;
  uint16_t routerPortTCP_;
  uint16_t routerPortUDP_;

  std::shared_ptr<SAM::DatagramSession> router_session_;

  std::shared_ptr<UDPReceiver> m_RecvHandler;
  std::shared_ptr<UDPSender> m_SendHandler;

  queue_type m_recvQueue;
  queue_type m_sendQueue;
};

extern NetworkWorker network_worker;

} // namespace network
} // namespace pbote

#endif // NETWORK_WORKER_H__
