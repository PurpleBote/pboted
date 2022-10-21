/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <utility>

#include "NetworkWorker.h"

namespace pbote
{
namespace network
{

NetworkWorker network_worker;

UDPReceiver::UDPReceiver (const std::string &address, int port)
  : m_running (false),
    m_recv_thread (nullptr),
    m_port (port),
    m_address (address),
    m_recv_queue (nullptr)
{}

UDPReceiver::~UDPReceiver ()
{
  stop ();

  if (m_recv_thread)
    {
      m_recv_thread->join ();

      delete m_recv_thread;
      m_recv_thread = nullptr;
    }

  if (m_recv_queue)
    m_recv_queue = nullptr;
}

void
UDPReceiver::start ()
{
  if (m_running)
    return;

  LogPrint (eLogInfo, "Network: UDPReceiver: Starting");

  if (m_recv_thread)
    {
      delete m_recv_thread;
      m_recv_thread = nullptr;
    }

  // ToDo: restart on error

  struct addrinfo hints;
  memset(&hints, 0, sizeof(struct addrinfo));

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV | AI_NUMERICHOST;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  struct addrinfo *res;

  char c_port[16];
  sprintf(c_port, "%d", m_port);

  int rc = getaddrinfo (m_address.c_str (), c_port, &hints, &res);
  if (rc != 0 || res == nullptr)
    {
      LogPrint (eLogError, "Network: UDPReceiver: Invalid address or port: ",
                m_address, ":", m_port, ": ", gai_strerror(rc));
      return;
    }

  server_sockfd = socket (res->ai_family, res->ai_socktype, res->ai_protocol);
  if (server_sockfd == (int)INVALID_SOCKET)
    {
      freeaddrinfo (res);
      LogPrint (eLogError, "Network: UDPReceiver: Could not create UDP socket ",
                m_address, ":", m_port, ": ", strerror (errno));
      return;
    }

  rc = bind (server_sockfd, res->ai_addr, res->ai_addrlen);
  if (rc != 0)
    {
      freeaddrinfo (res);
      close (server_sockfd);
      LogPrint (eLogError, "Network: UDPReceiver: Could not bind UDP socket ",
                m_address, ":", m_port, ": ", strerror (errno));
      return;
    }

  freeaddrinfo (res);

  m_running = true;
  m_recv_thread = new std::thread ([this] { run (); });

  LogPrint (eLogInfo, "Network: UDPReceiver: Started");
}

void
UDPReceiver::stop ()
{
  if (!m_running)
    return;

  LogPrint (eLogInfo, "Network: UDPReceiver: Stopping");

  m_running = false;

  FD_CLR (server_sockfd, &rset);
  close (server_sockfd);
  //freeaddrinfo (server_addr);

  LogPrint (eLogInfo, "Network: UDPReceiver: Stopped");
}

void
UDPReceiver::run ()
{
  while (m_running)
    {
      FD_ZERO (&rset);
      FD_SET (server_sockfd, &rset);
      struct timeval tv;

      tv.tv_sec = 10;
      tv.tv_usec = 0;

      int rc = select(server_sockfd + 1, &rset, NULL, NULL, &tv);

      if (rc == -1)
        {
          LogPrint (eLogError, "Network: UDPReceiver: Select error: ",
                    strerror (errno));
          continue;
        }

      if (rc == 0)
        {
          LogPrint (eLogDebug, "Network: UDPReceiver: Select timed out");
          continue;
        }

      //if (!m_running)
      //  break;

      LogPrint (eLogDebug, "Network: UDPReceiver: New data available");

      if (FD_ISSET(server_sockfd, &rset))
        handle_receive ();

      FD_CLR (server_sockfd, &rset);
    }

  LogPrint (eLogInfo, "Network: UDPReceiver: Finished");
}

void
UDPReceiver::handle_receive ()
{
  /* ToDo: recvfrom? */
  ssize_t rc = recv (server_sockfd, UDP_recv_buffer, MAX_DATAGRAM_SIZE, 0);

  if (!m_running)
    return;

  if (rc < 0)
    {
      LogPrint (eLogError, "Network: UDPReceiver: Receive error: ",
                strerror(errno));
      return;
    }

  if (rc == 0)
    {
      LogPrint (eLogWarning, "Network: UDPReceiver: Zero-length datagram");
      return;
    }

  ssize_t len = rc;
  /* Count total receive bytes */
  context.add_recv_byte_count (len);
  /* Terminating array */
  UDP_recv_buffer[len] = 0;
  /* Get newline char position */
  char *eol = strchr ((char *)UDP_recv_buffer, '\n');

  if (!eol)
    {
      LogPrint (eLogWarning, "Network: UDPReceiver: Malformed datagram");
      return;
    }

  *eol = 0;
  eol++;
  size_t payload_len = len - ((uint8_t *)eol - UDP_recv_buffer);
  size_t dest_len = len - payload_len - 1;

  std::string dest (&UDP_recv_buffer[0], &UDP_recv_buffer[dest_len]);

  LogPrint (eLogDebug, "Network: UDPReceiver: Datagram received, dest: ",
            dest, ", size: ", payload_len);

  auto packet = std::make_shared<PacketForQueue> (dest, (uint8_t *)eol,
                                                  payload_len);
  m_recv_queue->Put (packet);
}

///////////////////////////////////////////////////////////////////////////////

UDPSender::UDPSender (const std::string &addr, int port)
  : m_running (false),
    m_send_thread (nullptr),
    m_socket (INVALID_SOCKET),
    m_sam_port (port),
    m_sam_addr (addr),
    m_send_queue (nullptr)
{}

UDPSender::~UDPSender ()
{
  stop ();

  if (m_send_thread)
    {
      m_send_thread->join ();

      delete m_send_thread;
      m_send_thread = nullptr;
    }

  if (m_send_queue)
    m_send_queue = nullptr;
}

void
UDPSender::start ()
{
  if (m_running)
    return;

  LogPrint (eLogInfo, "Network: UDPSender: Starting");

  if (m_send_thread)
    {
      delete m_send_thread;
      m_send_thread = nullptr;
    }

  // ToDo: restart on error
  char c_port[16];
  sprintf(c_port, "%d", m_sam_port);

  struct addrinfo hints;
  memset (&hints, 0, sizeof (hints));

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = 0;
  hints.ai_protocol = 0;
  
  int rc = getaddrinfo (m_sam_addr.c_str (), c_port, &hints, &m_sam_addrinfo);
  if (rc != 0 || m_sam_addrinfo == nullptr)
    {
      LogPrint (eLogError, "Network: UDPSender: Invalid address or port: ",
                m_sam_addr, ":", m_sam_port, ": ", gai_strerror(rc));
      return;
    }

  m_socket = socket (m_sam_addrinfo->ai_family, m_sam_addrinfo->ai_socktype,
                     m_sam_addrinfo->ai_protocol);
  if (m_socket < 0)
    {
      close (m_socket);
      LogPrint (eLogError, "Network: UDPSender: Can't create socket for: ",
                m_sam_addr, ":", m_sam_port);
      return;
    }

  m_running = true;
  m_send_thread = new std::thread ([this] { run (); });
  LogPrint (eLogInfo, "Network: UDPSender: Started");
}

void
UDPSender::stop ()
{
  if (!m_running)
    return;

  LogPrint (eLogInfo, "Network: UDPSender: Stopping");

  m_running = false;

  freeaddrinfo (m_sam_addrinfo);
  FD_CLR (m_socket, &m_wset);
  close (m_socket);

  LogPrint (eLogInfo, "Network: UDPSender: Stopped");
}

void
UDPSender::run ()
{
  while (m_running)
    {
      FD_ZERO (&m_wset);
      FD_SET (m_socket, &m_wset);
      struct timeval tv;

      tv.tv_sec = 10;
      tv.tv_usec = 0;

      int rc = select(m_socket + 1, NULL, &m_wset, NULL, &tv);

      if (!m_running)
        break;

      if (rc == -1)
        {
          LogPrint (eLogError, "Network: UDPSender: Select error: ",
                    strerror (errno));
          continue;
        }

      if (rc == 0)
        {
          LogPrint (eLogDebug, "Network: UDPSender: Select timed out");
          continue;
        }

      if (FD_ISSET(m_socket, &m_wset))
          handle_send ();

      FD_CLR (m_socket, &m_wset);
    }
}

void
UDPSender::handle_send ()
{
  if (!m_running)
    return;

  auto packet = m_send_queue->GetNextWithTimeout (UDP_SEND_TIMEOUT);

  if (!packet)
    return;

  check_session();

  std::string payload (packet->payload.begin (), packet->payload.end ());
  std::string message
      = SAM::Message::datagramSend (m_session_id, packet->destination);
  message.append (payload);

  ssize_t bytes_transferred
      = sendto (m_socket, message.c_str (), message.size (), 0,
                m_sam_addrinfo->ai_addr, m_sam_addrinfo->ai_addrlen);

  if (bytes_transferred == 0)
    {
      LogPrint (eLogWarning, "Network: UDPSender: Zero-length datagram");
      return;
    }

  if (bytes_transferred < 0)
    {
      LogPrint (eLogError, "Network: UDPSender: Send error: ", strerror(errno));
      return;
    }

  context.add_sent_byte_count (bytes_transferred);
}

void
UDPSender::check_session()
{
  /* To prevent log spamming on session issue */
  while (sam_session->isSick ())
    {
      LogPrint (eLogError, "Network: UDPSender: SAM session is sick");
      std::this_thread::sleep_for (std::chrono::seconds (10));
    }
}

///////////////////////////////////////////////////////////////////////////////

NetworkWorker::NetworkWorker ()
  : m_listen_port_udp (0),
    m_router_port_tcp (0),
    m_router_port_udp (0),
    m_sam_session (nullptr),
    m_receiver (nullptr),
    m_sender (nullptr),
    m_recv_queue (nullptr),
    m_send_queue (nullptr)
{}

NetworkWorker::~NetworkWorker ()
{
  stop ();

  m_receiver = nullptr;
  m_sender = nullptr;
  m_sam_session = nullptr;
}

void
NetworkWorker::init ()
{
  m_nickname = context.get_nickname ();

  m_listen_address = context.get_listen_host ();
  m_listen_port_udp = context.get_listen_port_SAM ();

  m_router_address = context.get_router_host ();
  m_router_port_tcp = context.get_router_port_TCP ();
  m_router_port_udp = context.get_router_port_UDP ();

  m_recv_queue = context.getRecvQueue ();
  m_send_queue = context.getSendQueue ();

  createRecvHandler ();
  createSendHandler ();
}

void
NetworkWorker::start ()
{
  LogPrint (eLogInfo, "Network: SAM TCP endpoint: ", m_router_address, ":",
            m_router_port_tcp);
  LogPrint (eLogInfo, "Network: SAM UDP endpoint: ", m_router_address, ":",
            m_router_port_udp);

  // ToDo: we can init with empty listen port for auto port
  //   and use it in SAM init
  bool first_attempt = true;
  do
    {
      m_receiver->start ();

      if (!first_attempt)
        std::this_thread::sleep_for (std::chrono::seconds (10));

    } while (!m_receiver->running ());

  LogPrint (eLogInfo, "Network: Starting SAM session");
  try
    {
      bool success = false;
      first_attempt = true;
      std::shared_ptr<i2p::data::PrivateKeys> key;

      while (!success)
        {
          if (!first_attempt)
            std::this_thread::sleep_for (std::chrono::seconds (10));

          first_attempt = false;

          key = createSAMSession ();

          if (!key)
            continue;

          if (key->ToBase64 ().empty ())
            LogPrint (eLogError, "Network: SAM session failed, reconnecting");
          else
            success = true;
        }

      if (!context.keys_loaded ())
        context.save_new_keys (key);

      LogPrint (eLogInfo, "Network: SAM session created");

      /// Because we get sessionID after SAM initialization
      m_sender->set_sam_session (m_sam_session);
      m_sender->setSessionID (m_sam_session->getSessionID ());
      m_sender->start ();
    }
  catch (std::exception &e)
    {
      LogPrint (eLogError, "Network: Exception in SAM: ", e.what ());
    }
}

void
NetworkWorker::stop ()
{
  if (!running ())
    return;

  LogPrint (eLogInfo, "Network: Stopping");

  m_receiver->stop ();
  m_sender->stop ();
  
  // ToDo: Close SAM session

  LogPrint (eLogInfo, "Network: Stopped");
}

bool
NetworkWorker::running ()
{
  bool recv_run = m_receiver->running ();
  bool send_run = m_sender->running ();
  bool sam_sick = m_sam_session->isSick ();

  /*
  LogPrint (recv_run ? eLogDebug : eLogError, "Network: UDPReceiver: running: ",
            recv_run ? "true" : "false");
  LogPrint (send_run ? eLogDebug : eLogError, "Network: UDPSender: running: ",
            send_run ? "true" : "false");
  */

  return (recv_run && send_run && !sam_sick);
}

std::shared_ptr<i2p::data::PrivateKeys>
NetworkWorker::createSAMSession ()
{
  auto localKeys = context.getlocalKeys ();

  if (context.keys_loaded ())
    {
      m_sam_session = std::make_shared<SAM::DatagramSession> (
              m_nickname, m_router_address, m_router_port_tcp,
              m_router_port_udp, m_listen_address, m_listen_port_udp,
              localKeys->ToBase64 ());
    }
  else
    {
      m_sam_session = std::make_shared<SAM::DatagramSession> (
              m_nickname, m_router_address, m_router_port_tcp,
              m_router_port_udp, m_listen_address, m_listen_port_udp);

      localKeys->FromBase64 (m_sam_session->getMyDestination ().priv);
    }

  if (m_sam_session->getMyDestination ().priv.empty () ||
      m_sam_session->getMyDestination ().pub.empty ())
    {
      LogPrint (eLogError, "Network: SAM session failed");
      return {};
    }

  bool sick = m_sam_session->isSick ();
  LogPrint (sick ? eLogError : eLogInfo, "Network: SAM session: ",
            sick ? "Sick" : "OK");

  LogPrint (eLogInfo, "Network: SAM session created, nickname: ", m_nickname,
            ", sessionID: ", m_sam_session->getSessionID ());

  return localKeys;
}

void
NetworkWorker::createRecvHandler ()
{
  LogPrint (eLogInfo, "Network: Starting UDP receiver with address ",
            m_listen_address, ":", m_listen_port_udp);

  m_receiver = std::make_unique<UDPReceiver> (m_listen_address,
                                              m_listen_port_udp);

  m_receiver->setNickname (m_nickname);
  m_receiver->setQueue (m_recv_queue);
}

void
NetworkWorker::createSendHandler ()
{
  LogPrint (eLogInfo, "Network: Starting UDP sender to address ",
            m_router_address, ":", m_router_port_udp);

  m_sender = std::make_unique<UDPSender> (m_router_address, m_router_port_udp);

  m_sender->setNickname (m_nickname);
  m_sender->setQueue (m_send_queue);
}

} // namespace network
} // namespace pbote
