/**
 * Copyright (C) 2019-2022 polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <utility>

#include "NetworkWorker.h"

namespace pbote
{
namespace network
{

NetworkWorker network_worker;

/**
 * Receive handle class
 */
UDPReceiver::UDPReceiver (const std::string &address, int port)
    : m_IsRunning(false),
    m_RecvThread(nullptr),
    f_port(port),
    f_addr(address),
    m_recvQueue(nullptr)
{
  // ToDo: restart on error
  int errcode;
  char decimal_port[16];
  snprintf(decimal_port, sizeof(decimal_port), "%d", f_port);
  decimal_port[sizeof(decimal_port) / sizeof(decimal_port[0]) - 1] = '\0';

  struct addrinfo hints{};
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;

  errcode = getaddrinfo (address.c_str(), decimal_port, &hints, &f_addrinfo);
  if (errcode != 0 || f_addrinfo == nullptr)
    {
      char test[16];
      snprintf(test, sizeof(test), "%d", errcode);
      throw udp_client_server_runtime_error(
          ("Network: UDPReceiver: invalid address or port for UDP socket: \"" +
           address + ":" + decimal_port + "\", errcode=" +
           gai_strerror (errcode)).c_str ());
    }

  if ((f_socket =
         socket (f_addrinfo->ai_family, SOCK_DGRAM | SOCK_CLOEXEC,IPPROTO_UDP)) == -1)
    {
      freeaddrinfo (f_addrinfo);
      throw udp_client_server_runtime_error(
        ("Network: UDPReceiver: could not create UDP socket for: \"" +
         address + ":" + decimal_port + "\"").c_str ());
    }

  if ((bind (f_socket, f_addrinfo->ai_addr, f_addrinfo->ai_addrlen)) != 0)
    {
      freeaddrinfo (f_addrinfo);
      close (f_socket);
      throw udp_client_server_runtime_error(
        ("Network: UDPReceiver: could not bind UDP socket with: \"" +
         address + ":" + decimal_port + "\", errcode=" +
         gai_strerror (errcode)).c_str ());
    }
}

UDPReceiver::~UDPReceiver ()
{
  delete m_RecvThread;
  m_RecvThread = nullptr;
  freeaddrinfo (f_addrinfo);
  close (f_socket);
  m_recvQueue = nullptr;
}

void
UDPReceiver::start ()
{
  if (!m_IsRunning)
    {
      m_IsRunning = true;
      m_RecvThread = new std::thread ([this] { run (); });
    }
}

void
UDPReceiver::stop ()
{
  m_IsRunning = false;

  if (m_RecvThread)
    {
      m_RecvThread->join ();
      delete m_RecvThread;
      m_RecvThread = nullptr;
    }
}

void
UDPReceiver::run ()
{
  LogPrint (eLogInfo,
            "Network: UDPReceiver: run: starting UDP receive thread");

  while (m_IsRunning)
    handle_receive ();
}

long
UDPReceiver::recv ()
{
  return ::recv (f_socket, m_DatagramRecvBuffer, MAX_DATAGRAM_SIZE, 0);
}

void
UDPReceiver::handle_receive ()
{
  std::size_t bytes_transferred = recv ();

  if (bytes_transferred > 0)
    context.add_recv_byte_count (bytes_transferred);

  m_DatagramRecvBuffer[bytes_transferred] = 0;

  // ToDo: bad code! Need rewrite with strchr or memcpy for example
  std::vector<uint8_t> v_destination;
  std::vector<uint8_t> v_data;
  bool isData = false;

  for (u_int i = 0; i < bytes_transferred; i++)
    {
      if (m_DatagramRecvBuffer[i] == 0x0a)
        isData = true;
      else
        {
          if (isData)
            v_data.push_back (m_DatagramRecvBuffer[i]);
          else
            v_destination.push_back (m_DatagramRecvBuffer[i]);
        }
    }

  std::string s_destination(v_destination.begin (), v_destination.end ());
  std::string s_data(v_data.begin (), v_data.end ());

  char *eol = strchr ((char *) m_DatagramRecvBuffer, '\n');

  if (eol)
    {
      *eol = 0;
      eol++;
      size_t payloadLen =
        bytes_transferred - ((uint8_t *) eol - m_DatagramRecvBuffer);

      auto packet =
        std::make_shared<PacketForQueue> (s_destination,
                                          (uint8_t *) eol,
                                          payloadLen);
      m_recvQueue->Put (packet);
    }
  else
    LogPrint (eLogError,
             "Network: UDPReceiver: handle_receive: invalid datagram");

  // immediately recursive accept new datagram
  //if (isRunning()) {
  //  handle_receive();
  //}
}

/**
 * Send handle class
 */
UDPSender::UDPSender (const std::string &addr, int port)
    : m_IsRunning(false),
      m_SendThread(nullptr),
      f_port(port),
      f_addr(addr),
      m_sendQueue(nullptr)
{
  // ToDo: restart on error
  char decimal_port[16];
  snprintf (decimal_port, sizeof(decimal_port), "%d", f_port);
  decimal_port[sizeof(decimal_port) / sizeof(decimal_port[0]) - 1] = '\0';

  struct addrinfo hints{};
  memset (&hints, 0, sizeof(hints));

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;

  int r(getaddrinfo (addr.c_str (), decimal_port, &hints, &f_addrinfo));

  if (r != 0 || f_addrinfo == nullptr)
    {
      throw udp_client_server_runtime_error (
        ("Network: UDPSender: invalid address or port " +
         addr + ":" + decimal_port).c_str ());
    }

  if ((f_socket = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
    {
      close (f_socket);
      throw udp_client_server_runtime_error (
        ("Network: UDPSender: can't create socket for " +
         addr + ":" + decimal_port).c_str ());
    }
}

UDPSender::~UDPSender ()
{
  delete m_SendThread;
  m_SendThread = nullptr;
  freeaddrinfo (f_addrinfo);
  close (f_socket);
  m_sendQueue = nullptr;
}

void
UDPSender::start ()
{
  if (!m_IsRunning)
    {
      m_IsRunning = true;
      m_SendThread = new std::thread ([this] { run (); });
    }
}

void
UDPSender::stop ()
{
  m_IsRunning = false;
  if (m_SendThread) {
    m_SendThread->join ();
    delete m_SendThread;
    m_SendThread = nullptr;
  }
}

void
UDPSender::run ()
{
  LogPrint (eLogInfo, "Network: UDPSender: starting UDP send thread");
  
  while (m_IsRunning)
    send ();
}

void
UDPSender::send ()
{
  auto packet = m_sendQueue->GetNext ();

  std::string payload(packet->payload.begin (), packet->payload.end ());
  std::string message = SAM::Message::datagramSend (m_sessionID_,
                                                    packet->destination);
  message.append (payload);

  size_t bytes_transferred = sendto (f_socket, message.c_str (),
                                     message.size (), 0, f_addrinfo->ai_addr,
                                     f_addrinfo->ai_addrlen);
  //if (m_IsRunning) {
  handle_send (bytes_transferred);
  //}
}

void
UDPSender::handle_send (
/*const boost::system::error_code &error,*/
std::size_t bytes_transferred)
{
  // ToDo: error handler
  // here response has been sent
  if (bytes_transferred > 0)
    context.add_sent_byte_count (bytes_transferred);

  // immediately send new datagrams
  //if (isRunning()) {
  //  send();
  //}
}

/**
 * Controller class
 */
NetworkWorker::NetworkWorker ()
    : listenPortUDP_ (0),
      routerPortTCP_ (0),
      routerPortUDP_ (0),
      router_session_ (nullptr),
      m_RecvHandler (nullptr),
      m_SendHandler (nullptr),
      m_recvQueue (nullptr),
      m_sendQueue (nullptr) {}

NetworkWorker::~NetworkWorker ()
{
  stop ();
  router_session_ = nullptr;
  m_RecvHandler = nullptr;
  m_SendHandler = nullptr;
}

void
NetworkWorker::init ()
{
  m_nickname_ = context.get_nickname ();

  listenAddress_ = context.get_listen_host ();
  listenPortUDP_ = context.get_listen_port_SAM ();

  routerAddress_ = context.get_router_host ();
  routerPortTCP_ = context.get_router_port_TCP ();
  routerPortUDP_ = context.get_router_port_UDP ();

  m_recvQueue = context.getRecvQueue ();
  m_sendQueue = context.getSendQueue ();

  createRecvHandler ();
  createSendHandler ();
}

void
NetworkWorker::start ()
{
  LogPrint (eLogInfo, "Network: SAM TCP endpoint: ",
           routerAddress_, ":", routerPortTCP_);
  LogPrint (eLogInfo, "Network: SAM UDP endpoint: ",
           routerAddress_, ":", routerPortUDP_);

  // we can init with empty listen port for auto port and use it in SAM init
  m_RecvHandler->start ();

  LogPrint (eLogInfo, "Network: starting SAM session");
  try
    {
      bool success = false;
      std::shared_ptr<i2p::data::PrivateKeys> key;
      while (!success)
        {
          std::this_thread::sleep_for (std::chrono::seconds(30));
          key = createSAMSession ();
          if (key)
            {
              if (key->ToBase64 ().empty ())
                LogPrint (eLogError,
                          "Network: SAM session not started, try to reconnect");
              else
                success = true;
            }
        }

      if (!context.keys_loaded ())
        context.save_new_keys (key);

      // Because we get sessionID after SAM initialization
      m_SendHandler->setSessionID (const_cast<std::string &>(router_session_->getSessionID()));
      m_SendHandler->start ();

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
  LogPrint (eLogWarning, "Network: Stopping network worker");
  m_RecvHandler->stop ();
  m_SendHandler->stop ();
}

std::shared_ptr<i2p::data::PrivateKeys>
NetworkWorker::createSAMSession ()
{
  auto localKeys = context.getlocalKeys ();

  if (context.keys_loaded ())
    {
      std::shared_ptr<SAM::DatagramSession> new_session =
        std::make_shared<SAM::DatagramSession> (m_nickname_, routerAddress_,
                                               routerPortTCP_, routerPortUDP_,
                                               listenAddress_, listenPortUDP_,
                                               localKeys->ToBase64 ());
    router_session_ = new_session;
    }
  else
    {
      std::shared_ptr<SAM::DatagramSession> new_session =
        std::make_shared<SAM::DatagramSession> (m_nickname_, routerAddress_,
                                               routerPortTCP_, routerPortUDP_,
                                               listenAddress_, listenPortUDP_);
      localKeys->FromBase64 (new_session->getMyDestination ().priv);
      router_session_ = new_session;
    }

  if (router_session_->getMyDestination ().priv.empty () ||
      router_session_->getMyDestination ().pub.empty ())
    {
      LogPrint (eLogError, "Network: SAM session failed");
      return {};
    }

  if (router_session_->isSick ())
    LogPrint (eLogError, "Network: SAM session is sick");
  else
    LogPrint (eLogDebug, "Network: SAM session is not sick");

  LogPrint (eLogInfo, "Network: SAM session created; nickname: ", m_nickname_,
            ", sessionID: ", router_session_->getSessionID ());

  return localKeys;
}

void
NetworkWorker::createRecvHandler ()
{
  // New receiver
  LogPrint (eLogInfo, "Network: init UDP receiver with address ",
            listenAddress_, ":", listenPortUDP_);

  m_RecvHandler =
    std::make_shared<UDPReceiver> (listenAddress_, listenPortUDP_);
  m_RecvHandler->setNickname (m_nickname_);
  m_RecvHandler->setQueue (m_recvQueue);
}

void
NetworkWorker::createSendHandler ()
{
  LogPrint (eLogInfo, "Network: init UDP sender to address ",
           routerAddress_, ":", routerPortUDP_);
  // New sender
  m_SendHandler = std::make_shared<UDPSender> (routerAddress_, routerPortUDP_);
  m_SendHandler->setNickname (m_nickname_);
  m_SendHandler->setQueue (m_sendQueue);
}

} // namespace network
} // namespace pbote
