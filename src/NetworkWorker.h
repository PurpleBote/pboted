/**
 * Copyright (C) 2019-2022, polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#ifndef PBOTED_SRC_NETWORK_WORKER_H_
#define PBOTED_SRC_NETWORK_WORKER_H_

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

namespace pbote
{
namespace network
{

/// Timeout in msec
#define UDP_SEND_TIMEOUT 500

#define MAX_DATAGRAM_SIZE 32768

#define SAM_DEFAULT_NICKNAME "pboted"

class udp_client_server_runtime_error : public std::runtime_error
{
public:
  udp_client_server_runtime_error (const char *w) : std::runtime_error (w) {}
};

class UDPReceiver
{
public:
  UDPReceiver (const std::string &address, int port);
  ~UDPReceiver ();

  void start ();
  void stop ();

  void
  setNickname (const std::string &nickname = SAM_DEFAULT_NICKNAME)
  {
    m_nickname_ = nickname;
  };

  void
  setQueue (const queue_type &recvQueue)
  {
    m_recvQueue = recvQueue;
  };

  int
  get_socket () const
  {
    return f_socket;
  };

  int
  get_port () const
  {
    return f_port;
  };

  std::string
  get_addr () const
  {
    return f_addr;
  };

  bool
  running () const
  {
    return running_;
  };

private:
  void run ();
  long recv ();
  // int timed_recv(/*char *msg, size_t max_size,*/ int max_wait_ms);
  void handle_receive ();

  bool running_;
  std::thread *m_RecvThread;
  std::string m_nickname_;
  int f_socket;
  int f_port;
  std::string f_addr;
  struct addrinfo *f_addrinfo{};

  uint8_t m_DatagramRecvBuffer[MAX_DATAGRAM_SIZE + 1] = {0};
  queue_type m_recvQueue;
};

class UDPSender
{
public:
  UDPSender (const std::string &addr, int port);
  ~UDPSender ();

  void start ();
  void stop ();

  void
  setNickname (const std::string &nickname = SAM_DEFAULT_NICKNAME)
  {
    m_nickname_ = nickname;
  };

  void
  setSessionID (const std::string &sessionID)
  {
    m_sessionID_ = sessionID;
  };

  void
  setQueue (const queue_type &sendQueue)
  {
    m_sendQueue = sendQueue;
  };

  void
  set_sam_session (std::shared_ptr<SAM::DatagramSession> session)
  {
    sam_session = session;
  };

  int
  get_socket () const
  {
    return f_socket;
  };

  int
  get_port () const
  {
    return f_port;
  };

  std::string
  get_addr () const
  {
    return f_addr;
  };

  bool
  running () const
  {
    return running_;
  };

private:
  void run ();
  void send ();
  void handle_send (std::size_t bytes_transferred);

  void check_session();

  bool running_;
  std::thread *m_SendThread;
  std::string m_nickname_;
  std::string m_sessionID_;

  std::shared_ptr<SAM::DatagramSession> sam_session;

  int f_socket;
  int f_port;
  std::string f_addr;
  struct addrinfo *f_addrinfo{};

  queue_type m_sendQueue;
};

class NetworkWorker
{
public:
  NetworkWorker ();
  ~NetworkWorker ();

  void init ();
  void start ();
  void stop ();

  bool is_sick() { return router_session_->isSick (); };

private:
  /** prevent making copies */
  NetworkWorker (const NetworkWorker &);
  const NetworkWorker &operator= (const NetworkWorker &);

  std::shared_ptr<i2p::data::PrivateKeys> createSAMSession ();

  void createRecvHandler ();
  void createSendHandler ();

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

#endif // PBOTED_SRC_NETWORK_WORKER_H_
