/**
 * Copyright (C) 2019-2022, polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <errno.h>
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
      f_port (port),
      f_addr (address),
      m_recv_queue (nullptr)
{
  // ToDo: restart on error
  int errcode;
  char decimal_port[16];
  snprintf (decimal_port, sizeof (decimal_port), "%d", f_port);
  decimal_port[sizeof (decimal_port) / sizeof (decimal_port[0]) - 1] = '\0';

  struct addrinfo hints{};
  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;

  errcode = getaddrinfo (address.c_str (), decimal_port, &hints, &f_addrinfo);
  if (errcode != 0 || f_addrinfo == nullptr)
    {
      throw udp_client_server_runtime_error (
          ("Network: UDPReceiver: Invalid address or port: \"" + address + ":"
           + decimal_port + "\", errcode=" + gai_strerror (errcode))
              .c_str ());
    }

  f_socket = socket (f_addrinfo->ai_family, SOCK_DGRAM | SOCK_CLOEXEC,
                     f_addrinfo->ai_protocol);
  if (f_socket == -1)
    {
      freeaddrinfo (f_addrinfo);
      throw udp_client_server_runtime_error (
          ("Network: UDPReceiver: Could not create UDP socket for: \""
           + address + ":" + decimal_port + "\"")
              .c_str ());
    }

  if ((bind (f_socket, f_addrinfo->ai_addr, f_addrinfo->ai_addrlen)) != 0)
    {
      freeaddrinfo (f_addrinfo);
      close (f_socket);
      throw udp_client_server_runtime_error (
          ("Network: UDPReceiver: Could not bind UDP socket with: \"" + address
           + ":" + decimal_port + "\", errcode=" + gai_strerror (errcode))
              .c_str ());
    }
}

UDPReceiver::~UDPReceiver ()
{
  stop ();

  if (m_recv_queue)
    {
      m_recv_queue = nullptr;
    }

  freeaddrinfo (f_addrinfo);
  close (f_socket);
}

void
UDPReceiver::start ()
{
  if (m_recv_thread)
    {
      delete m_recv_thread;
      m_recv_thread = nullptr;
    }

  m_running = true;
  m_recv_thread = new std::thread ([this] { run (); });
}

void
UDPReceiver::stop ()
{
  m_running = false;

  if (m_recv_thread)
    {
      m_recv_thread->join ();

      delete m_recv_thread;
      m_recv_thread = nullptr;
    }

  LogPrint (eLogInfo, "Network: UDPReceiver: Stopped");
}

void
UDPReceiver::run ()
{
  LogPrint (eLogInfo, "Network: UDPReceiver: Started");

  while (m_running)
    {
      handle_receive ();
    }
}

ssize_t
UDPReceiver::recv ()
{
  return ::recv (f_socket, UDP_recv_buffer, MAX_DATAGRAM_SIZE, 0);
}

void
UDPReceiver::handle_receive ()
{
  ssize_t bytes_transferred = recv ();

  if (bytes_transferred < 1)
    {
      if (bytes_transferred == 0)
        {
          LogPrint (eLogWarning, "Network: UDPReceiver: Zero-length datagram");
          return;
        }

      LogPrint (eLogError, "Network: UDPReceiver: Receive error: ", strerror(errno));
      return;
    }

  /// Count total receive bytes
  context.add_recv_byte_count (bytes_transferred);
  /// Terminating array
  UDP_recv_buffer[bytes_transferred] = 0;
  /// Get newline char position
  char *eol = strchr ((char *)UDP_recv_buffer, '\n');

  if (!eol)
    {
      LogPrint (eLogWarning, "Network: UDPReceiver: Malformed datagram");
      return;
    }

  *eol = 0;
  eol++;
  size_t payload_len = bytes_transferred - ((uint8_t *)eol - UDP_recv_buffer);
  size_t dest_len = bytes_transferred - payload_len - 1;

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
      f_port (port),
      f_addr (addr),
      m_send_queue (nullptr)
{
  // ToDo: restart on error
  int errcode;
  char decimal_port[16];
  snprintf (decimal_port, sizeof (decimal_port), "%d", f_port);
  decimal_port[sizeof (decimal_port) / sizeof (decimal_port[0]) - 1] = '\0';

  struct addrinfo hints{};
  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = 0;

  errcode = getaddrinfo (addr.c_str (), decimal_port, &hints, &f_addrinfo);
  if (errcode != 0 || f_addrinfo == nullptr)
    {
      throw udp_client_server_runtime_error (
          ("Network: UDPSender: Invalid address or port " + addr + ":"
           + decimal_port)
              .c_str ());
    }

  f_socket = socket (f_addrinfo->ai_family, f_addrinfo->ai_socktype,
                     f_addrinfo->ai_protocol);
  if (f_socket < 0)
    {
      freeaddrinfo (f_addrinfo);
      close (f_socket);
      throw udp_client_server_runtime_error (
          ("Network: UDPSender: Can't create socket for " + addr + ":"
           + decimal_port)
              .c_str ());
    }
}

UDPSender::~UDPSender ()
{
  stop ();

  if (m_send_queue)
    {
      m_send_queue = nullptr;
    }

  freeaddrinfo (f_addrinfo);
  close (f_socket);
}

void
UDPSender::start ()
{
  if (m_send_thread)
    {
      delete m_send_thread;
      m_send_thread = nullptr;
    }

  m_running = true;
  m_send_thread = new std::thread ([this] { run (); });
}

void
UDPSender::stop ()
{
  m_running = false;

  if (m_send_thread)
    {
      m_send_thread->join ();

      delete m_send_thread;
      m_send_thread = nullptr;
    }

  LogPrint (eLogInfo, "Network: UDPSender: Stopped");
}

void
UDPSender::run ()
{
  LogPrint (eLogInfo, "Network: UDPSender: Started");

  while (m_running)
    {
      send ();
    }
}

void
UDPSender::send ()
{
  auto packet = m_send_queue->GetNextWithTimeout (UDP_SEND_TIMEOUT);

  if (!packet)
    return;

  check_session();

  std::string payload (packet->payload.begin (), packet->payload.end ());
  std::string message
      = SAM::Message::datagramSend (m_session_id, packet->destination);
  message.append (payload);

  ssize_t bytes_transferred
      = sendto (f_socket, message.c_str (), message.size (), 0,
                f_addrinfo->ai_addr, f_addrinfo->ai_addrlen);

  if (bytes_transferred < 1)
    {
      if (bytes_transferred == 0)
        {
          LogPrint (eLogWarning, "Network: UDPSender: Zero-length datagram");
          return;
        }

      LogPrint (eLogError, "Network: UDPSender: Send error: ", strerror(errno));
      return;
    }

  context.add_sent_byte_count (bytes_transferred);
}

void
UDPSender::check_session()
{
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
      m_router_session (nullptr),
      m_recv_handler (nullptr),
      m_send_handler (nullptr),
      m_recv_queue (nullptr),
      m_send_queue (nullptr)
{
}

NetworkWorker::~NetworkWorker ()
{
  stop ();

  m_router_session = nullptr;
  m_recv_handler = nullptr;
  m_send_handler = nullptr;
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
  m_recv_handler->start ();

  LogPrint (eLogInfo, "Network: Starting SAM session");
  try
    {
      bool success = false, first_attempt = true;
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

      /// Because we get sessionID after SAM initialization
      m_send_handler->set_sam_session (m_router_session);
      m_send_handler->setSessionID (
          const_cast<std::string &> (m_router_session->getSessionID ()));
      m_send_handler->start ();

      LogPrint (eLogInfo, "Network: SAM session started");
    }
  catch (std::exception &e)
    {
      LogPrint (eLogError, "Network: Exception in SAM: ", e.what ());
    }
}

void
NetworkWorker::stop ()
{
  m_recv_handler->stop ();
  m_send_handler->stop ();

  // ToDo: Close SAM session

  LogPrint (eLogInfo, "Network: Stopped");
}

void
NetworkWorker::running ()
{
  bool recv_run = m_recv_handler->running ();
  bool send_run = m_send_handler->running ();
  LogPrint (recv_run ? eLogDebug : eLogError, "Network: UDPReceiver: running: ",
            recv_run ? "true" : "false");
  LogPrint (send_run ? eLogDebug : eLogError, "Network: UDPSender: running: ",
            send_run ? "true" : "false");
}

std::shared_ptr<i2p::data::PrivateKeys>
NetworkWorker::createSAMSession ()
{
  auto localKeys = context.getlocalKeys ();

  if (context.keys_loaded ())
    {
      std::shared_ptr<SAM::DatagramSession> new_session
          = std::make_shared<SAM::DatagramSession> (
              m_nickname, m_router_address, m_router_port_tcp, m_router_port_udp,
              m_listen_address, m_listen_port_udp, localKeys->ToBase64 ());

      m_router_session = new_session;
    }
  else
    {
      std::shared_ptr<SAM::DatagramSession> new_session
          = std::make_shared<SAM::DatagramSession> (
              m_nickname, m_router_address, m_router_port_tcp, m_router_port_udp,
              m_listen_address, m_listen_port_udp);

      localKeys->FromBase64 (new_session->getMyDestination ().priv);
      m_router_session = new_session;
    }

  if (m_router_session->getMyDestination ().priv.empty ()
      || m_router_session->getMyDestination ().pub.empty ())
    {
      LogPrint (eLogError, "Network: SAM session failed");
      return {};
    }

  bool sick = m_router_session->isSick ();
  LogPrint (sick ? eLogError : eLogInfo, "Network: SAM session: ",
            sick ? "Sick" : "OK");

  LogPrint (eLogInfo, "Network: SAM session created, nickname: ", m_nickname,
            ", sessionID: ", m_router_session->getSessionID ());

  return localKeys;
}

void
NetworkWorker::createRecvHandler ()
{
  LogPrint (eLogInfo, "Network: Starting UDP receiver with address ",
            m_listen_address, ":", m_listen_port_udp);

  m_recv_handler = std::make_shared<UDPReceiver> (m_listen_address,
                                                  m_listen_port_udp);

  m_recv_handler->setNickname (m_nickname);
  m_recv_handler->setQueue (m_recv_queue);
}

void
NetworkWorker::createSendHandler ()
{
  LogPrint (eLogInfo, "Network: Starting UDP sender to address ",
            m_router_address, ":", m_router_port_udp);

  m_send_handler = std::make_shared<UDPSender> (m_router_address,
                                                m_router_port_udp);

  m_send_handler->setNickname (m_nickname);
  m_send_handler->setQueue (m_send_queue);
}

} // namespace network
} // namespace pbote
