/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#pragma once
#ifndef PBOTED_SRC_NETWORK_WORKER_H
#define PBOTED_SRC_NETWORK_WORKER_H

#include <algorithm>
#include <ctime>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/types.h>
#include <utility>

#include "compat.h"
#include "FileSystem.h"
#include "Logging.h"
#include "Packet.h"
#include "Queue.h"

// libi2pd
#include "Identity.h"

#include "i2psam.hpp"

namespace pbote
{
namespace network
{

/// Timeout in msec
#define UDP_SEND_TIMEOUT 500
/// 32 KiB
#define MAX_DATAGRAM_SIZE 32768

#define SAM_DEFAULT_NICKNAME "pboted"
#define DEFAULT_KEY_FILE_NAME "destination.key"

using queue_type = std::shared_ptr<pbote::util::Queue<sp_queue_pkt>>;
using sp_sam_dg_ses = std::shared_ptr<SAM::DatagramSession>;

class UDPReceiver
{
public:
  UDPReceiver (const std::string &address, int port);
  ~UDPReceiver ();

  void start ();
  void stop ();

  void queue (const queue_type &recv_queue) { m_recv_queue = recv_queue; };

  bool running () const { return m_running; };

  uint64_t bytes_recv() { return m_bytes_recv; }

private:
  void run ();
  void handle_receive ();

  void bytes_recv(uint64_t nbytes) { m_bytes_recv += nbytes; };

  bool m_running;
  std::thread *m_recv_thread;

#ifndef _WIN32
  int server_sockfd;
#else
  SOCKET server_sockfd;
#endif

  int m_port;
  std::string m_address;
  fd_set rset;

  uint8_t *buf;
  queue_type m_recv_queue;

  uint64_t m_bytes_recv = 0;
};

class UDPSender
{
public:
  UDPSender (const std::string &addr, int port);
  ~UDPSender ();

  void start ();
  void stop ();

  void queue (const queue_type &send_queue) { m_send_queue = send_queue; };
  void sam_session (sp_sam_dg_ses session) { m_sam_session = session; };

  bool running () const { return m_running; };

  uint64_t bytes_sent() { return m_bytes_sent; }

private:
  void run ();
  void handle_send ();

  void check_sam_session();

  void bytes_sent(uint64_t nbytes) { m_bytes_sent += nbytes; };

  bool m_running;
  std::thread *m_send_thread;
  std::string m_nickname;
  std::string m_session_id;

  sp_sam_dg_ses m_sam_session;

#ifndef _WIN32
  int m_socket;
#else
  SOCKET m_socket;
#endif

  int m_sam_port = 0;
  std::string m_sam_addr;
  struct addrinfo *m_sam_addrinfo;
  fd_set m_wset;

  queue_type m_send_queue;

  uint64_t m_bytes_sent = 0;
};

class NetworkWorker
{
public:
  NetworkWorker ();
  ~NetworkWorker ();

  void init ();
  void start ();
  void stop ();

  void send(const PacketForQueue& packet);
  void send(const std::shared_ptr<PacketBatch<pbote::CommunicationPacket>>& batch);
  bool receive(const std::shared_ptr<pbote::CommunicationPacket>& packet);
  void remove_batch(const std::shared_ptr<PacketBatch<pbote::CommunicationPacket>>& batch);
  sp_queue_pkt get_pkt_with_timeout(int usec);

  bool running ();
  bool is_sick() { return m_sam_session->isSick (); };

  std::shared_ptr<i2p::data::IdentityEx>
  get_local_destination()
  {
    return m_local_destination;
  }

  std::shared_ptr<i2p::data::PrivateKeys>
  get_local_keys()
  {
    return m_local_keys;
  }

  uint64_t bytes_recv() { return m_receiver->bytes_recv (); }
  uint64_t bytes_sent() { return m_sender->bytes_sent (); }

  //queue_type get_recv_queue() { return m_recv_queue; }
  //queue_type get_send_queue() { return m_send_queue; }

private:
  /** prevent making copies */
  NetworkWorker (const NetworkWorker &);
  const NetworkWorker &operator= (const NetworkWorker &);

  void create_SAM_session ();

  void create_recv_handler ();
  void create_send_handler ();

  int read_keys();
  void save_keys();

  std::string m_nickname;

  std::string m_listen_address;
  uint16_t m_listen_port_udp = 0;

  std::string m_router_address;
  uint16_t m_router_port_tcp = 0;
  uint16_t m_router_port_udp = 0;

  sp_sam_dg_ses m_sam_session;

  std::unique_ptr<UDPReceiver> m_receiver;
  std::unique_ptr<UDPSender> m_sender;

  queue_type m_recv_queue;
  queue_type m_send_queue;

  mutable std::mutex m_batch_mutex;
  std::vector<std::shared_ptr<batch_comm_packet>> m_running_batches;

  /* I2P stuff */
  bool m_keys_loaded = false, m_sam_failed = true;
  std::string m_destination_key_path;
  std::shared_ptr<i2p::data::PrivateKeys> m_local_keys;
  std::shared_ptr<i2p::data::IdentityEx> m_local_destination;
};

extern NetworkWorker network_worker;

} // namespace network
} // namespace pbote

#endif // PBOTED_SRC_NETWORK_WORKER_H
