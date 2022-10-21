/**
 * Copyright (C) 2019-2022, polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>

#include "BoteControl.h"
#include "BoteContext.h"
#include "DHTworker.h"
#include "FileSystem.h"
#include "Logging.h"
#include "RelayWorker.h"

namespace bote
{

BoteControl::BoteControl ()
  : m_is_running (false),
    m_control_acceptor_thread (nullptr),
    m_control_handler_thread (nullptr)
{
#if !defined(_WIN32) || !defined(DISABLE_SOCKET)
  pbote::config::GetOption("control.socket", socket_path);
  if (socket_path.empty ())
    {
      socket_path = pbote::fs::DataDirPath (DEFAULT_SOCKET_NAME);
    }

  m_socket_enabled = (socket_path.compare ("false") != 0);

  if (m_socket_enabled)
    {
      if (!pbote::fs::Exists (socket_path))
        {
          LogPrint (eLogInfo, "Control: Control file socket ", socket_path);
        }
      else
        {
          LogPrint (eLogDebug, "Control: Existing socket will be used:",
                    socket_path);
        }
    }
#endif
  pbote::config::GetOption("control.address", m_address);
  pbote::config::GetOption("control.port", m_port);

  LogPrint (eLogInfo, "Control: Control TCP socket ", m_address, ":", m_port);

  /* Fill handlers */
  handlers["all"] = &BoteControl::all;
  handlers["daemon"] = &BoteControl::daemon;
  handlers["identity"] = &BoteControl::identity;
  handlers["storage"] = &BoteControl::storage;
  handlers["peer"] = &BoteControl::peer;
  handlers["node"] = &BoteControl::node;
}

BoteControl::~BoteControl ()
{
  stop ();

  if (m_control_handler_thread)
    {
      m_control_handler_thread->join ();
      delete m_control_handler_thread;
      m_control_handler_thread = nullptr;
    }

  if (m_control_acceptor_thread)
    {
      m_control_acceptor_thread->join ();
      delete m_control_acceptor_thread;
      m_control_acceptor_thread = nullptr;
    }
}

void
BoteControl::start ()
{
  if (m_is_running)
    return;

  LogPrint (eLogInfo, "Control: Starting");

  int cur_sn = 0, rc = 0;
#if !defined(_WIN32) || !defined(DISABLE_SOCKET)
  if (m_socket_enabled)
    {
      conn_sockfd = socket (AF_UNIX, SOCK_STREAM, 0);
      if (conn_sockfd == INVALID_SOCKET)
        {
          LogPrint (eLogError, "Control: File socket: ", strerror (errno));
          return;
        }

      unlink (socket_path.c_str ());

      memset (&file_addr, 0, sizeof file_addr);

      file_addr.sun_family = AF_UNIX;
      strncpy (file_addr.sun_path, socket_path.c_str (),
               sizeof file_addr.sun_path - 1)[sizeof file_addr.sun_path - 1]
          = 0;

      rc = bind (conn_sockfd, (const struct sockaddr *)&file_addr,
                 sizeof (file_addr));
      if (rc == -1)
        {
          // ToDo: add error handling
          LogPrint (eLogError, "Control: File bind error: ", strerror (errno));
        }
      else
        {
          rc = listen (conn_sockfd, CONTROL_MAX_CLIENTS);
          if (rc == -1)
            {
              // ToDo: add error handling
              LogPrint (eLogError, "Control: File listen error: ",
                        strerror (errno));
            }
          else
            {
              memset(fds, 0, sizeof(fds));

              fds[cur_sn].fd = conn_sockfd;
              fds[cur_sn].events = POLLIN;
              ++cur_sn;
            }
        }
    }
#endif
  struct addrinfo hints;
  memset(&hints, 0, sizeof(struct addrinfo));

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV | AI_NUMERICHOST;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  struct addrinfo *res;

  char c_port[16];
  sprintf(c_port, "%d", m_port);

  rc = getaddrinfo (m_address.c_str (), c_port, &hints, &res);
  if (rc != 0 || res == nullptr)
    {
      LogPrint (eLogError, "Control: Invalid address or port: ",
                m_address, ":", m_port, ": ", gai_strerror(rc));
      return;
    }

  tcp_fd = socket (res->ai_family, res->ai_socktype, res->ai_protocol);
  if (tcp_fd == (int)INVALID_SOCKET)
    {
      freeaddrinfo (res);
      LogPrint (eLogError, "Control: TCP socket: ", m_address, ":", m_port,
                ": ", strerror (errno));
      return;
    }

  rc = bind (tcp_fd, res->ai_addr, res->ai_addrlen);
  if (rc == -1)
    {
      // ToDo: add error handling
      freeaddrinfo (res);
      close (tcp_fd);
      LogPrint (eLogError, "Control: TCP bind error: ", strerror (errno));
      return;
    }

  freeaddrinfo (res);

  rc = listen (tcp_fd, CONTROL_MAX_CLIENTS);
  if (rc == -1)
    {
      // ToDo: add error handling
      LogPrint (eLogError, "Control: TCP listen error: ", strerror (errno));
      return;
    }

  if (cur_sn == 0)
    memset(fds, 0, sizeof(fds));
  else
    nfds = 2;

  memset(sessions, 0, sizeof(sessions));

  fds[cur_sn].fd = tcp_fd;
  fds[cur_sn].events = POLLIN;

  m_is_running = true;
  m_control_acceptor_thread = new std::thread ([this] { run (); });
  m_control_handler_thread = new std::thread ([this] { handle (); });

  LogPrint (eLogInfo, "Control: Started");
}

void
BoteControl::stop ()
{
  if (!m_is_running)
    return;

  LogPrint (eLogInfo, "Control: Stopping");

  m_is_running = false;

  /* Clean up all of the sockets that are open */
  for (int sid = 0; sid < nfds; sid++)
    {
      if(fds[sid].fd >= 0)
        {
          close(fds[sid].fd);
          fds[sid].revents = POLLHUP;
        }
    }
  LogPrint (eLogInfo, "Control: Sockets closed");

  LogPrint (eLogInfo, "Control: Stopped");
}

void
BoteControl::run ()
{
  LogPrint (eLogInfo, "Control: Acceptor started");
  sin_size = sizeof (client_addr);

  int rc = 0, current_s = 0;

  do
    {
      rc = poll(fds, nfds, CONTROL_WAIT_TIMEOUT);

      if (!m_is_running)
        return;

      /* Check to see if the poll call failed */
      if (rc < 0)
        {
          LogPrint(eLogError, "Control: Poll error: ", strerror (errno));
          continue;
        }

      if (rc == 0)
        {
          LogPrint(eLogDebug, "Control: Poll timed out");
          continue;
        }

      current_s = nfds;
      for (int sid = 0; sid < current_s; sid++)
        {
          if(fds[sid].revents == 0)
            continue;

          if(fds[sid].revents != POLLIN)
            {
              LogPrint(eLogError, "Control: Revents: ", fds[sid].revents);
              continue;
            }

          if (fds[sid].fd != tcp_fd
#if !defined(_WIN32) || !defined(DISABLE_SOCKET)
              || fds[sid].fd != conn_sockfd
#endif
              )
            continue;

          LogPrint (eLogDebug, "Control: Server socket readable");
          do
            {
              LogPrint (eLogDebug, "Control: New accept");
              client_sockfd = accept(fds[sid].fd,
                                     (struct sockaddr *)&client_addr,
                                     &sin_size);

              if (client_sockfd < 0)
              {
                if (m_is_running && errno != EWOULDBLOCK && errno != EAGAIN)
                {
                  LogPrint (eLogError, "Control: Accept error: ",
                            strerror (errno));
                }
                break;
              }

              LogPrint (eLogInfo, "Control: Received connection from ",
                        inet_ntoa (client_addr.sin_addr));

              fds[nfds].fd = client_sockfd;
              fds[nfds].events = POLLIN;
              sessions[nfds].state = STATE_INIT;

              nfds++;
            } while (client_sockfd != -1);
        }
    } while (m_is_running);

  LogPrint (eLogInfo, "Control: Acceptor stopped");
}

void
BoteControl::handle ()
{
  LogPrint (eLogInfo, "Control: Handler started");

  bool compress_array = false;
  do
    {
      int current_sc = nfds, closed_fd = 0;;

      for (int sid = 0; sid < current_sc; sid++)
        {
          if (fds[sid].fd == tcp_fd
#if !defined(_WIN32) || !defined(DISABLE_SOCKET)
              || fds[sid].fd == conn_sockfd
#endif
              )
            continue;

          LogPrint (eLogDebug, "ControlSession: New data");
          bool close_conn = false;
          /* Receive all incoming data on this socket */
          /* until the recv fails with EWOULDBLOCK */
          do
          {
            if (fds[sid].fd < 0)
            {
              LogPrint (eLogWarning, "ControlSession: Socket already closed");
              break;
            }

            memset (sessions[sid].buf, 0, sizeof (sessions[sid].buf));
            //ssize_t rc = recv (fds[sid].fd, sessions[sid].buf,
            //                   sizeof (sessions[sid].buf), 0);
            ssize_t rc = read (fds[sid].fd, sessions[sid].buf,
                               sizeof(sessions[sid].buf));
            if (rc < 0)
            {
              LogPrint (eLogError, "ControlSession: Can't receive data, close");
              close_conn = true;
              break;
            }

            if (rc == 0)
            {
              LogPrint (eLogDebug, "ControlSession: Connection closed");
              close_conn = true;
              break;
            }

            /* Data was received  */
            std::string str_buf (sessions[sid].buf);
            str_buf = str_buf.substr (0, str_buf.size () - 2);

            LogPrint (eLogDebug, "ControlSession: Request stream: ", str_buf);
            handle_request (sid);
          } while (m_is_running);

          if (close_conn)
            {
              close(fds[sid].fd);
              fds[sid].fd = -1;
              compress_array = true;
              ++closed_fd;
            }
        }
      //LogPrint (eLogDebug, "Control: Closed connections: ", closed_fd);

      /* we need to squeeze together the array and */
      /* decrement the number of file descriptors and sessions*/
      if (!compress_array)
        continue;

      compress_array = false;
      for (int sid = 0; sid < nfds; sid++)
        {
          if (fds[sid].fd != (int)INVALID_SOCKET)
            continue;

          for(int j = sid; j < nfds; j++)
            {
              fds[j].fd = fds[j + 1].fd;
              sessions[j] = sessions[j + 1];
            }
          sid--;
          nfds--;
        }
    } while (m_is_running);

  LogPrint (eLogInfo, "Control: Handler stopped");
}

void
BoteControl::reply (int sid, const std::string &msg)
{
  //ssize_t rc = send (fds[sid].fd, msg.c_str (), msg.length (), 0);
  ssize_t rc = write (fds[sid].fd, msg.c_str (), msg.length ());
  if (rc == SOCKET_ERROR)
    {
      LogPrint (eLogError, "Control: reply: Failed to send data");
      return;
    }

  if (rc == 0)
    {
      LogPrint (eLogError, "Control: reply: Socket was closed");
      return;
    }
}

void
BoteControl::handle_request (int sid)
{
  std::string str_req (sessions[sid].buf);
  LogPrint (eLogDebug, "Control: handle_request: Got request: ", str_req);

  // ToDo: parse request and combine response
  std::ostringstream result;

  size_t pos = str_req.find (".");
  std::string cmd_prefix = str_req.substr (0, pos);
  std::string cmd_id = str_req.substr (pos + 1);

  LogPrint (eLogDebug, "Control: handle_request: cmd_prefix: ", cmd_prefix,
            ", cmd_id: ", cmd_id);

  auto it = handlers.find (cmd_prefix);
  if (it != handlers.end ())
    {
      result << "{\"id\": null,\"result\": {";
      (this->*(it->second)) (cmd_id, result);
      result << "}, \"jsonrpc\": 2.0}";
    }
  else
    {
      LogPrint (eLogWarning, "Control: handle_request: Unknown cmd prefix: ",
                cmd_prefix);
      unknown_cmd (str_req, result);
    }

  reply (sid, result.str ());
}

void
BoteControl::insert_param (std::ostringstream &ss, const std::string &name,
                           int value) const
{
  ss << "\"" << name << "\": " << value;
}

void
BoteControl::insert_param (std::ostringstream &ss, const std::string &name,
                           double value) const
{
  ss << "\"" << name << "\": " << std::fixed << std::setprecision (2) << value;
}

void
BoteControl::insert_param (std::ostringstream &ss, const std::string &name,
                           const std::string &value) const
{
  ss << "\"" << name << "\": ";
  if (value.length () > 0)
    ss << "\"" << value << "\"";
  else
    ss << "null";
}

void
BoteControl::all (const std::string &cmd_id, std::ostringstream &results)
{
  std::string empty;
  daemon (empty, results);
  results << ", ";
  identity (empty, results);
  results << ", ";
  storage (empty, results);
  results << ", ";
  peer (empty, results);
  results << ", ";
  node (empty, results);
}
  
void
BoteControl::daemon (const std::string &cmd_id, std::ostringstream &results)
{
  results << "\"daemon\": {";
  insert_param (results, "uptime", (int)pbote::context.get_uptime ());
  results << ", ";
  results << "\"bytes\": {";
  insert_param (results, "recived", (int)pbote::context.get_bytes_recv ());
  results << ", ";
  insert_param (results, "sent", (int)pbote::context.get_bytes_sent ());
  results << "}}";
}

void
BoteControl::identity (const std::string &cmd_id, std::ostringstream &results)
{
  results << "\"identity\": {";
  insert_param (results, "count", (int)pbote::context.get_identities_count ());
  results << "}";
}

void
BoteControl::storage (const std::string &cmd_id, std::ostringstream &results)
{
  results << "\"storage\": {";
  insert_param (results, "used",
                (double)pbote::kademlia::DHT_worker.get_storage_usage ());
  results << "}";
}

void
BoteControl::peer (const std::string &cmd_id, std::ostringstream &results)
{
  results << "\"peers\": {";
  results << "\"count\": {";
  insert_param (results, "total",
                (int)pbote::relay::relay_worker.getPeersCount ());
  results << ", ";
  insert_param (results, "good",
                (int)pbote::relay::relay_worker.get_good_peer_count ());
  results << "}}";
}

void
BoteControl::node (const std::string &cmd_id, std::ostringstream &results)
{
  results << "\"nodes\": {";
  results << "\"count\": {";
  insert_param (results, "total",
                (int)pbote::kademlia::DHT_worker.getNodesCount ());
  results << ", ";
  insert_param (results, "unlocked",
                (int)pbote::kademlia::DHT_worker.get_unlocked_nodes_count ());
  results << "}}";
}

void
BoteControl::unknown_cmd (const std::string &cmd, std::ostringstream &results)
{
  results << "{\"id\": null, \"error\": ";
  results << "{\"code\": 404,";
  results << "\"message\": \"Command not found: " << cmd << "\"},";
  results << "\"jsonrpc\": 2.0}";
}

} // bote
