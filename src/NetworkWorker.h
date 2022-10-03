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
/// 32 KiB
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
    m_nickname = nickname;
  };

  void
  setQueue (const queue_type &recv_queue)
  {
    m_recv_queue = recv_queue;
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
    return m_running;
  };

private:
  void run ();
  ssize_t recv ();
  void handle_receive ();

  bool m_running;
  std::thread *m_recv_thread;
  std::string m_nickname;
  int f_socket;
  int f_port;
  std::string f_addr;
  struct addrinfo *f_addrinfo{};

  uint8_t UDP_recv_buffer[MAX_DATAGRAM_SIZE + 1] = {0};
  queue_type m_recv_queue;
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
    m_nickname = nickname;
  };

  void
  setSessionID (const std::string &session_id)
  {
    m_session_id = session_id;
  };

  void
  setQueue (const queue_type &send_queue)
  {
    m_send_queue = send_queue;
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
    return m_running;
  };

private:
  void run ();
  void send ();

  void check_session();

  bool m_running;
  std::thread *m_send_thread;
  std::string m_nickname;
  std::string m_session_id;

  std::shared_ptr<SAM::DatagramSession> sam_session;

  int f_socket;
  int f_port;
  std::string f_addr;
  struct addrinfo *f_addrinfo{};

  queue_type m_send_queue;
};

class NetworkWorker
{
public:
  NetworkWorker ();
  ~NetworkWorker ();

  void init ();
  void start ();
  void stop ();

  void running ();
  bool is_sick() { return m_router_session->isSick (); };

private:
  /** prevent making copies */
  NetworkWorker (const NetworkWorker &);
  const NetworkWorker &operator= (const NetworkWorker &);

  std::shared_ptr<i2p::data::PrivateKeys> createSAMSession ();

  void createRecvHandler ();
  void createSendHandler ();

  std::string m_nickname;

  std::string m_listen_address;
  uint16_t m_listen_port_udp;

  std::string m_router_address;
  uint16_t m_router_port_tcp;
  uint16_t m_router_port_udp;

  std::shared_ptr<SAM::DatagramSession> m_router_session;

  std::shared_ptr<UDPReceiver> m_recv_handler;
  std::shared_ptr<UDPSender> m_send_handler;

  queue_type m_recv_queue;
  queue_type m_send_queue;
};

extern NetworkWorker network_worker;

} // namespace network
} // namespace pbote

#endif // PBOTED_SRC_NETWORK_WORKER_H_
