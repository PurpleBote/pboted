/**
 * Copyright (c) 2019-2022 polistern
 */

#include "BoteControl.h"
#include "BoteContext.h"
#include "DHTworker.h"
#include "FileSystem.h"
#include "Logging.h"
#include "RelayPeersWorker.h"

namespace bote {

BoteControl::BoteControl(const std::string& sock_path)
  : m_is_running (false),
    m_thread (nullptr)
{
  if (!pbote::fs::Exists(sock_path))
    LogPrint(eLogInfo, "BoteControl: creating new certificate for control connection");
  else
    LogPrint(eLogDebug, "BoteControl: using cert from ", 123);

  int status;

  conn_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (conn_sockfd == -1)
    LogPrint (eLogError, "BoteControl: Invalid socket");

  unlink(sock_path.c_str());

  memset(&conn_addr,0, sizeof conn_addr);

  conn_addr.sun_family = AF_UNIX;
  strncpy(conn_addr.sun_path, sock_path.c_str(), sizeof conn_addr.sun_path-1)
  [sizeof conn_addr.sun_path-1] = 0;

  status =
    bind(conn_sockfd, (const struct sockaddr *) &conn_addr, sizeof(conn_addr));
  
  if ( status == -1 )
    LogPrint(eLogError, "BoteControl: Bind error");

  status = listen(conn_sockfd, 20);
  if (status == -1)
    LogPrint(eLogError, "BoteControl: Listen error");

  // info handlers
  handlers["daemon"] = &BoteControl::daemon;
  handlers["identity"] = &BoteControl::identity;
  handlers["storage"] = &BoteControl::storage;
  handlers["peer"] = &BoteControl::peer;
  handlers["node"] = &BoteControl::node;
}

BoteControl::~BoteControl()
{
  stop();
}

void
BoteControl::start()
{
  if (!m_is_running)
    {
      m_is_running = true;
      m_thread = new std::thread([this] { run(); });
    }
}

void
BoteControl::stop()
{
  if (m_is_running)
    {
      close();
      m_is_running = false;
      if (m_thread)
        {
          m_thread->join ();
          delete m_thread;
          m_thread = nullptr;
        }
    }
}

void
BoteControl::run()
{
  while (m_is_running)
    {
      if ((data_sockfd = accept(conn_sockfd, NULL, NULL)) == -1)
        {
          if (errno != EWOULDBLOCK && errno != EAGAIN)
            {
              LogPrint(eLogError, "BoteControl: run: Accept error: ",
                       strerror(errno));
            }
        }
      else
        {
          LogPrint(eLogInfo, "BoteControl: run: Received new connection");
          handle_request();
        }
    }
}

void
BoteControl::write_data(const std::string &msg)
{
  ssize_t sent_bytes = write(data_sockfd, msg.c_str(), msg.length());
  if (sent_bytes == SOCKET_ERROR)
    {
      LogPrint(eLogError, "BoteControl: write: Failed to send data");
      return;
    }
  if (sent_bytes == 0)
    {
      LogPrint(eLogError, "BoteControl: write: Socket was closed");
      return;
    }
}

std::string
BoteControl::read_data()
{
  char buffer[BUFF_SIZE];
  memset(buffer, 0, BUFF_SIZE);
  
  ssize_t recieved_bytes = read(data_sockfd, buffer, BUFF_SIZE);
  if (recieved_bytes == SOCKET_ERROR)
    {
      LogPrint(eLogError, "BoteControl: write: Failed to read data");
      return std::string();
    }
  if (recieved_bytes == 0)
    {
      LogPrint(eLogError, "BoteControl: write: Socket was closed");
    }
  return std::string(buffer);
}

int
BoteControl::release()
{
  int temp = conn_sockfd;
  conn_sockfd = INVALID_SOCKET;
  return temp;
}

void
BoteControl::close()
{
  if (conn_sockfd != INVALID_SOCKET)
    {
      ::close(conn_sockfd);
      conn_sockfd = INVALID_SOCKET;
    }
}

void
BoteControl::handle_request()
{
  auto request = read_data();
  LogPrint(eLogDebug, "BoteControl: handle_request: Got request: ", request);
  
  // ToDo: parse request and combine response
  std::string response = request;
  
  LogPrint(eLogDebug, "BoteControl: handle_request: Response: ", response);
  write_data(response);
}

void
BoteControl::insert_param(std::ostringstream& ss,
                          const std::string& name,
                          int value) const
{
  ss << "\"" << name << "\":" << value;
}

void
BoteControl::insert_param(std::ostringstream& ss,
                          const std::string& name,
                          double value) const
{
  ss << "\"" << name << "\":" << std::fixed << std::setprecision(2) << value;
}

void
BoteControl::insert_param(std::ostringstream& ss,
                          const std::string& name,
                          const std::string& value) const
{
  ss << "\"" << name << "\":";
  if (value.length() > 0)
    ss << "\"" << value << "\"";
  else
    ss << "null";
}

void
BoteControl::daemon(std::ostringstream& results)
{
  insert_param(results, "daemon.uptime",
               std::to_string(pbote::context.get_uptime()));
}

void
BoteControl::identity(std::ostringstream& results)
{
  insert_param(results, "identity.count",
               std::to_string(pbote::context.get_identities_count()));
}

void
BoteControl::storage(std::ostringstream& results)
{
  insert_param(results, "storage.used",
               std::to_string(pbote::kademlia::DHT_worker.get_storage_usage()));
}

void
BoteControl::peer(std::ostringstream& results)
{
  insert_param(results, "peer.count",
               std::to_string(pbote::relay::relay_peers_worker.getPeersCount()));
}

void
BoteControl::node(std::ostringstream& results)
{
  insert_param(results, "node.count",
               std::to_string(pbote::kademlia::DHT_worker.getNodesCount()));
}

} // bote
