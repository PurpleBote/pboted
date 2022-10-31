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

#include "compat.h"
#include "ConfigParser.h"
#include "NetworkWorker.h"

namespace bote
{

NetworkWorker network_worker;

UDPReceiver::UDPReceiver (const std::string &address, int port)
  : m_running (false),
    m_recv_thread (nullptr),
    m_port (port),
    m_address (address),
    m_recv_queue (nullptr)
{
}

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
  /* ToDo: add error handling and restart on error */

  if (m_running)
    return;

  LogPrint (eLogInfo, "Network: UDPReceiver: Starting");

  if (m_recv_thread)
    {
      delete m_recv_thread;
      m_recv_thread = nullptr;
    }

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
  if (rc != RC_SUCCESS || res == nullptr)
    {
      LogPrint (eLogError, "Network: UDPReceiver: Invalid address or port: ",
                m_address, ":", m_port, ": ", gai_strerror(rc));
      return;
    }

  server_sockfd = socket (res->ai_family, res->ai_socktype, res->ai_protocol);
  if (server_sockfd == PB_SOCKET_INVALID)
    {
      freeaddrinfo (res);
      LogPrint (eLogError, "Network: UDPReceiver: Could not create UDP socket ",
                m_address, ":", m_port, ": ", strerror (errno));
      return;
    }

  rc = bind (server_sockfd, res->ai_addr, res->ai_addrlen);
  if (rc == RC_ERROR)
    {
      freeaddrinfo (res);
      PB_SOCKET_CLOSE (server_sockfd);
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
  PB_SOCKET_CLOSE (server_sockfd);

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

      if (!m_running)
        return;

      if (rc == SELECT_ERROR)
        {
          LogPrint (eLogError, "Network: UDPReceiver: Select error: ",
                    strerror (errno));
          continue;
        }

      if (rc == SELECT_TIMEOUT)
        {
          LogPrint (eLogDebug, "Network: UDPReceiver: Select timed out");
          continue;
        }

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
  char *buf = (char *)malloc (MAX_DATAGRAM_SIZE);
  /* ToDo: recvfrom? */
  ssize_t rc = PB_SOCKET_READ (server_sockfd, buf, MAX_DATAGRAM_SIZE - 1);

  if (!m_running)
    {
      free (buf);
      return;
    }

  if (rc == RECV_ERROR)
    {
      LogPrint (eLogError, "Network: UDPReceiver: Receive error: ",
                strerror(errno));
      free (buf);
      return;
    }

  if (rc == RECV_CLOSED)
    {
      LogPrint (eLogWarning, "Network: UDPReceiver: Zero-length datagram");
      free (buf);
      return;
    }

  ssize_t len = rc;
  /* Count total receive bytes */
  bytes_recv (len);
  /* Terminating array */
  buf[len] = 0;
  /* Get newline char position */
  char *eol = strchr (buf, '\n');

  if (!eol)
    {
      LogPrint (eLogWarning, "Network: UDPReceiver: Malformed datagram");
      free (buf);
      return;
    }

  /* Replace newline with zero and go to next pointer (start of payload) */
  *eol = 0;
  eol++;
  /* Desination len ( len - count of items from buf start to payload start) */
  size_t payload_len = len - (eol - buf);
  size_t dest_len = len - payload_len - 1;

  std::string dest (&buf[0], &buf[dest_len]);

  LogPrint (eLogDebug, "Network: UDPReceiver: Datagram received, dest: ",
            dest, ", size: ", payload_len);

  auto packet = std::make_shared<PacketForQueue> (dest, eol, payload_len);
  free (buf);

  m_recv_queue->Put (packet);
}

///////////////////////////////////////////////////////////////////////////////

UDPSender::UDPSender (const std::string &addr, int port)
  : m_running (false),
    m_send_thread (nullptr),
    m_socket (PB_SOCKET_INVALID),
    m_sam_port (port),
    m_sam_addr (addr),
    m_send_queue (nullptr)
{
}

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
  /* ToDo: add error handling and restart on error */

  if (m_running)
    return;

  LogPrint (eLogInfo, "Network: UDPSender: Starting");

  if (m_send_thread)
    {
      delete m_send_thread;
      m_send_thread = nullptr;
    }

  char c_port[16];
  sprintf(c_port, "%d", m_sam_port);

  struct addrinfo hints;
  memset (&hints, 0, sizeof (hints));

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = 0;
  hints.ai_protocol = 0;

  int rc = getaddrinfo (m_sam_addr.c_str (), c_port, &hints, &m_sam_addrinfo);
  if (rc != RC_SUCCESS || m_sam_addrinfo == nullptr)
    {
      LogPrint (eLogError, "Network: UDPSender: Invalid address or port: ",
                m_sam_addr, ":", m_sam_port, ": ", gai_strerror(rc));
      return;
    }

  m_socket = socket (m_sam_addrinfo->ai_family, m_sam_addrinfo->ai_socktype,
                     m_sam_addrinfo->ai_protocol);
  if (m_socket == PB_SOCKET_INVALID)
    {
      PB_SOCKET_CLOSE (m_socket);
      LogPrint (eLogError, "Network: UDPSender: Can't create socket to ",
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
  PB_SOCKET_CLOSE (m_socket);

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

      if (rc == SELECT_ERROR)
        {
          LogPrint (eLogError, "Network: UDPSender: Select error: ",
                    strerror (errno));
          continue;
        }

      if (rc == SELECT_TIMEOUT)
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

  check_sam_session();

  std::string payload (packet->payload.begin (), packet->payload.end ());
  std::string message
      = SAM::Message::datagramSend (m_sam_session->getSessionID (),
                                    packet->destination);
  message.append (payload);

  ssize_t rc = sendto (m_socket, message.c_str (), message.size (), 0,
                       m_sam_addrinfo->ai_addr, m_sam_addrinfo->ai_addrlen);

  if (rc == SEND_ERROR)
    {
      LogPrint (eLogError, "Network: UDPSender: Send error: ", strerror(errno));
      return;
    }

  if (rc == 0)
    {
      LogPrint (eLogWarning, "Network: UDPSender: Zero-length datagram");
      return;
    }

  bytes_sent (rc);
}

void
UDPSender::check_sam_session()
{
  /* To prevent log spamming on session issue */
  while (m_sam_session->isSick ())
    {
      LogPrint (eLogError, "Network: UDPSender: SAM session is sick");
      std::this_thread::sleep_for (std::chrono::seconds (10));
    }
}

///////////////////////////////////////////////////////////////////////////////

NetworkWorker::NetworkWorker ()
  : m_nickname (SAM_DEFAULT_NICKNAME),
    m_listen_port_udp (0),
    m_router_port_tcp (0),
    m_router_port_udp (0),
    m_sam_session (nullptr),
    m_receiver (nullptr),
    m_sender (nullptr),
    m_recv_queue (nullptr),
    m_send_queue (nullptr),
    m_local_destination (nullptr)
{
  m_recv_queue = std::make_shared<bote::Queue<sp_queue_pkt>>();
  m_send_queue = std::make_shared<bote::Queue<sp_queue_pkt>>();

  m_local_keys = std::make_shared<i2p::data::PrivateKeys>();
}

NetworkWorker::~NetworkWorker ()
{
  stop ();

  if (m_receiver)
    m_receiver = nullptr;
  if (m_sender)
    m_sender = nullptr;

  if (m_recv_queue)
    m_recv_queue = nullptr;
  if (m_send_queue)
    m_send_queue = nullptr;

  if (m_sam_session)
    m_sam_session = nullptr;

  m_local_destination = nullptr;
  m_local_keys = nullptr;
}

void
NetworkWorker::init ()
{
  bote::config::GetOption("host", m_listen_address);
  bote::config::GetOption("port", m_listen_port_udp);

  bote::config::GetOption("sam.name", m_nickname);

  bote::config::GetOption("sam.address", m_router_address);
  bote::config::GetOption("sam.tcp", m_router_port_tcp);
  bote::config::GetOption("sam.udp", m_router_port_udp);

  bote::config::GetOption("sam.key", m_destination_key_path);

  LogPrint(eLogInfo, "Network: Config loaded");

  if (m_destination_key_path.empty ())
    {
      m_destination_key_path = bote::fs::DataDirPath (DEFAULT_KEY_FILE_NAME);
      LogPrint(eLogDebug,
        "Network: init: Destination key path empty, try default path: ",
        m_destination_key_path);
    }

  int rc = read_keys ();
  if (rc == RC_ERROR)
    {
      LogPrint(eLogWarning,
               "Network: init: Can't find local destination key, try to create");
    }

  if (rc > 0)
    {
      m_keys_loaded = true;
      LogPrint(eLogInfo,
               "Network: init: Local destination key loaded successfully");
    }

  create_recv_handler ();
  create_send_handler ();
}

void
NetworkWorker::start ()
{
  /* ToDo: add error handling and restart on error */

  LogPrint (eLogInfo, "Network: SAM TCP endpoint: ", m_router_address, ":",
            m_router_port_tcp);
  LogPrint (eLogInfo, "Network: SAM UDP endpoint: ", m_router_address, ":",
            m_router_port_udp);

  // ToDo: we can init with empty listen port for auto port
  //   and use it in SAM init
  bool first_attempt = true;
  do
    {
      if (!first_attempt)
        std::this_thread::sleep_for (std::chrono::seconds (10));

      m_receiver->start ();

    } while (!m_receiver->running ());

  try
    {
      LogPrint (eLogInfo, "Network: Starting SAM session");

      bool success = false;
      first_attempt = true;
      do
        {
          if (!first_attempt)
            std::this_thread::sleep_for (std::chrono::seconds (10));

          first_attempt = false;

          create_SAM_session ();

          if (m_sam_failed)
            LogPrint (eLogError, "Network: SAM session failed, reconnecting");
          else
            success = true;
        } while (!success);

      if (!m_keys_loaded)
        save_keys ();

      LogPrint (eLogInfo, "Network: SAM session created");
    }
  catch (std::exception &e)
    {
      LogPrint (eLogError, "Network: Exception in SAM: ", e.what ());
    }

  // We can get sessionID only after SAM initialization
  m_sender->sam_session (m_sam_session);

  first_attempt = true;
  do
    {
      if (!first_attempt)
        std::this_thread::sleep_for (std::chrono::seconds (10));

      m_sender->start ();

    } while (!m_sender->running ());
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

void
NetworkWorker::send(const PacketForQueue &packet)
{
  m_send_queue->Put(std::make_shared<PacketForQueue>(packet));
}

void
NetworkWorker::send(const std::shared_ptr<batch_comm_packet>& batch)
{
  size_t count = 0;
  m_running_batches.push_back(batch);
  LogPrint(eLogDebug, "Network: send: Running batches: ",
           m_running_batches.size ());

  auto packets = batch->getPackets();
  for (const auto& packet: packets)
    {
      send(packet.second);
      count++;
    }
  LogPrint(eLogDebug, "Network: send: Sent ", count, " packets from batch ",
           batch->owner);
}

bool
NetworkWorker::receive(const sp_comm_pkt& packet)
{
  if (m_running_batches.empty ())
    {
      LogPrint(eLogWarning, "Network: receive: No running batches");
      return false;
    }

  std::vector<uint8_t> v_cid(packet->cid, packet->cid + 32);

  auto batch_itr = m_running_batches.begin ();
  while (batch_itr != m_running_batches.end ())
    {
      if (*batch_itr)
        {
          if ((*batch_itr)->contains (v_cid))
            {
              (*batch_itr)->addResponse (packet);
              LogPrint (eLogDebug, "Network: receive: Response for batch ",
                        (*batch_itr)->owner, ", remain count: ",
                        (*batch_itr)->remain ());
              return true;
            }
        }
      else
        {
          LogPrint(eLogError, "Network: receive: Batch is null");
          m_running_batches.erase (batch_itr);
        }

      ++batch_itr;
    }

  return false;
}

sp_queue_pkt
NetworkWorker::get_pkt_with_timeout(int usec)
{
  return m_recv_queue->GetNextWithTimeout (usec);
}

void
NetworkWorker::remove_batch(const std::shared_ptr<batch_comm_packet>& r_batch)
{
  std::unique_lock<std::mutex> l (m_batch_mutex);

  if (m_running_batches.empty ())
    {
      LogPrint(eLogWarning, "Network: No running batches");
      return;
    }

  // For debug only
  //*
  for (auto batch : m_running_batches)
    {
      if (batch)
        LogPrint(eLogDebug, "Network: Batch: ", batch->owner);
      else
        LogPrint(eLogDebug, "Network: Batch is null");
    }
  //*/

  auto batch_itr = m_running_batches.begin ();
  while (batch_itr != m_running_batches.end ())
    {
      if (*batch_itr)
        {
          LogPrint(eLogDebug, "Network: Batch: ", (*batch_itr)->owner);

          if (r_batch == *batch_itr)
            {
              LogPrint(eLogDebug, "Network: Removing batch ", r_batch->owner);
              m_running_batches.erase (batch_itr);
              LogPrint(eLogDebug, "Network: Running batches: ",
                       m_running_batches.size ());
              break;
            }

          ++batch_itr;
        }
      else
        {
          LogPrint(eLogError, "Network: Batch is null");
          batch_itr = m_running_batches.erase (batch_itr);
        }
    }
}

bool
NetworkWorker::running ()
{
  bool recv_run = false, send_run = false, sam_sick = true;
  if (m_receiver)
    recv_run = m_receiver->running ();

  if (m_sender)
    send_run = m_sender->running ();

  if (m_sam_session)
    sam_sick = m_sam_session->isSick ();

  /*
  LogPrint (recv_run ? eLogDebug : eLogError, "Network: UDPReceiver: running: ",
            recv_run ? "true" : "false");
  LogPrint (send_run ? eLogDebug : eLogError, "Network: UDPSender: running: ",
            send_run ? "true" : "false");
  */

  return (recv_run && send_run && !sam_sick);
}

void
NetworkWorker::create_SAM_session ()
{
  if (m_keys_loaded)
    {
      m_sam_session = std::make_shared<SAM::DatagramSession> (
              m_nickname, m_router_address, m_router_port_tcp,
              m_router_port_udp, m_listen_address, m_listen_port_udp,
              m_local_keys->ToBase64 ());
    }
  else
    {
      m_sam_session = std::make_shared<SAM::DatagramSession> (
              m_nickname, m_router_address, m_router_port_tcp,
              m_router_port_udp, m_listen_address, m_listen_port_udp);
      m_local_keys->FromBase64 (m_sam_session->getMyDestination ().priv);
    }

  if (m_sam_session->getMyDestination ().priv.empty () ||
      m_sam_session->getMyDestination ().pub.empty ())
    {
      LogPrint (eLogError, "Network: SAM session failed");
      m_sam_failed = true;
      return;
    }

  if (m_sam_session->isSick ())
    {
      LogPrint (eLogError, "Network: SAM session: Sick");
      m_sam_failed = true;
      return;
    }

  LogPrint (eLogInfo, "Network: SAM session: OK");
  m_sam_failed = false;

  LogPrint (eLogInfo, "Network: SAM session, nickname: ", m_nickname,
            ", ID: ", m_sam_session->getSessionID ());
}

int
NetworkWorker::read_keys ()
{
  LogPrint(eLogDebug, "Network: read_keys: Reading keys from ",
           m_destination_key_path);

  std::ifstream file(m_destination_key_path, std::ios::binary);
  if (!file)
    return RC_ERROR;

  std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(file)),
                                   (std::istreambuf_iterator<char>()));

  file.close();

  m_local_keys->FromBuffer(bytes.data(), bytes.size());
  m_local_destination
    = std::make_shared<i2p::data::IdentityEx>(*m_local_keys->GetPublic());

  LogPrint(eLogDebug, "Network: read_keys: base64 ",
           m_local_destination->ToBase64().substr (0, 15), "...");
  LogPrint(eLogDebug, "Network: read_keys: hash.base32 ",
           m_local_destination->GetIdentHash().ToBase32());

  return bytes.size();
}

void
NetworkWorker::save_keys()
{
  if (m_destination_key_path.empty ())
    m_destination_key_path = bote::fs::DataDirPath(DEFAULT_KEY_FILE_NAME);

  LogPrint (eLogDebug, "Network: save_keys: Save destination to ",
            m_destination_key_path);

  std::ofstream file (m_destination_key_path,
                   std::ofstream::binary | std::ofstream::out);
  if (!file.is_open ())
    {
      LogPrint (eLogError, "Network: save_keys: Can't open file: ",
                m_destination_key_path);
      return;
    }

  const size_t len = m_local_keys->GetFullLen ();
  uint8_t *buf = (uint8_t *)malloc(len);

  m_local_keys->ToBuffer (buf, len);
  file.write ((char *)buf, len);
  file.close ();

  free(buf);
}

void
NetworkWorker::create_recv_handler ()
{
  LogPrint (eLogInfo, "Network: Starting UDP receiver with address ",
            m_listen_address, ":", m_listen_port_udp);

  m_receiver = std::make_unique<UDPReceiver> (m_listen_address,
                                              m_listen_port_udp);

  m_receiver->queue (m_recv_queue);
}

void
NetworkWorker::create_send_handler ()
{
  LogPrint (eLogInfo, "Network: Starting UDP sender to address ",
            m_router_address, ":", m_router_port_udp);

  m_sender = std::make_unique<UDPSender> (m_router_address, m_router_port_udp);

  m_sender->queue (m_send_queue);
}

} // namespace bote
