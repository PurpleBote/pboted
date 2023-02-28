/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022-2023, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <errno.h>
#include <string.h>
#include <sys/types.h>

#include "BoteControl.h"
#include "BoteContext.h"
#include "DHTworker.h"
#include "FileSystem.h"
#include "Logging.h"
#include "RelayWorker.h"

namespace bote
{
namespace module
{

BoteControl::BoteControl ()
  : m_is_running (false),
    m_control_thread (nullptr)
{
#if !defined(DISABLE_SOCKET)
  bote::config::GetOption("control.socket", socket_path);
  if (socket_path.empty ())
    {
      socket_path = bote::fs::DataDirPath (CONTROL_DEFAULT_SOCKET_NAME);
    }

  m_socket_enabled = (socket_path.compare ("false") != 0);

  if (m_socket_enabled)
    {
      if (!bote::fs::Exists (socket_path))
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
  bote::config::GetOption("control.address", m_address);
  bote::config::GetOption("control.port", m_port);

  LogPrint (eLogInfo, "Control: Control TCP socket ", m_address, ":", m_port);

  /* Fill handlers */
  handlers["all"] = &BoteControl::all;
  handlers["addressbook"] = &BoteControl::addressbook;
  handlers["daemon"] = &BoteControl::daemon;
  handlers["identity"] = &BoteControl::identity;
  handlers["storage"] = &BoteControl::storage;
  handlers["peer"] = &BoteControl::peer;
  handlers["node"] = &BoteControl::node;
}

BoteControl::~BoteControl ()
{
  stop ();

  if (m_control_thread)
    {
      m_control_thread->join ();
      delete m_control_thread;
      m_control_thread = nullptr;
    }
}

void
BoteControl::start ()
{
  /* ToDo: add error handling */

  if (m_is_running)
    return;

  LogPrint (eLogInfo, "Control: Starting");

  int cur_sn = 0, rc = 0;
  PB_INT_OR_DWORD enabled = 1;

#if !defined(DISABLE_SOCKET)
  if (m_socket_enabled)
    {
      conn_sockfd = socket (AF_UNIX, SOCK_STREAM, 0);
      if (conn_sockfd == PB_SOCKET_INVALID)
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

      rc = PB_SOCKET_IOCTL(conn_sockfd, FIONBIO, enabled);
      if (rc == PB_SOCKET_ERROR)
      {
        LogPrint (eLogError, "Control: ioctl() failed: ", strerror (errno));
        PB_SOCKET_CLOSE (conn_sockfd);
        return;
      }

      rc = bind (conn_sockfd, (const struct sockaddr *)&file_addr,
                 sizeof (file_addr));
      if (rc == PB_SOCKET_ERROR)
        {
          LogPrint (eLogError, "Control: File bind error: ", strerror (errno));
        }
      else
        {
          rc = listen (conn_sockfd, CONTROL_MAX_CLIENTS);
          if (rc == PB_SOCKET_ERROR)
            {
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
  if (rc != RC_SUCCESS || res == nullptr)
    {
      LogPrint (eLogError, "Control: Invalid address or port: ",
                m_address, ":", m_port, ": ", gai_strerror(rc));
      return;
    }

  tcp_fd = socket (res->ai_family, res->ai_socktype, res->ai_protocol);
  if (tcp_fd == PB_SOCKET_INVALID)
    {
      freeaddrinfo (res);
      LogPrint (eLogError, "Control: TCP socket: ", m_address, ":", m_port,
                ": ", strerror (errno));
      return;
    }

  enabled = 1;

  rc = PB_SOCKET_IOCTL(tcp_fd, FIONBIO, enabled);
  if (rc == RC_ERROR)
  {
    LogPrint (eLogError, "Control: ioctl(FIONBIO) failed: ", strerror (errno));
    PB_SOCKET_CLOSE (tcp_fd);
    freeaddrinfo (res);
    return;
  }

  rc = bind (tcp_fd, res->ai_addr, res->ai_addrlen);
  if (rc == RC_ERROR)
    {
      freeaddrinfo (res);
      PB_SOCKET_CLOSE (tcp_fd);
      LogPrint (eLogError, "Control: TCP bind error: ", strerror (errno));
      return;
    }

  freeaddrinfo (res);

  rc = listen (tcp_fd, CONTROL_MAX_CLIENTS);
  if (rc == RC_ERROR)
    {
      LogPrint (eLogError, "Control: TCP listen error: ", strerror (errno));
      return;
    }

  /*
   * If UNIX socket code disabled we need to init file descriptors set
   * If enabled - just increase used socket count to 2
   */
  if (cur_sn == 0)
    memset(fds, 0, sizeof(fds));
  else
    nfds = 2;

  fds[cur_sn].fd = tcp_fd;
  fds[cur_sn].events = POLLIN;

  m_is_running = true;
  m_control_thread = new std::thread ([this] { run (); });

  LogPrint (eLogInfo, "Control: Started");
}

void
BoteControl::stop ()
{
  if (!m_is_running)
    return;

  LogPrint (eLogInfo, "Control: Stopping");

  m_is_running = false;

  for (int sid = 0; sid < nfds; sid++)
    {
      /* Clean up all of the sockets that are open */
      if (fds[sid].fd != PB_SOCKET_INVALID)
        {
          PB_SOCKET_CLOSE (fds[sid].fd);
          fds[sid].revents = POLLHUP;
        }

      /* Free allocated session buffer */
      if (session.need_clean)
        {
          free (session.buf);
          session.need_clean = false;
        }
    }
  LogPrint (eLogInfo, "Control: Sockets closed");

  LogPrint (eLogInfo, "Control: Stopped");
}

void
BoteControl::run ()
{
  LogPrint (eLogInfo, "Control: run: Started");

  int rc = 0, current_sc = 0;
  bool compress_array = false;

  while (m_is_running)
    {
      LogPrint(eLogDebug, "Control: run: Waiting on poll");
      rc = PB_SOCKET_POLL(fds, nfds, CONTROL_POLL_TIMEOUT);

      if (!m_is_running)
        return;

      /* Check to see if the poll call failed */
      if (rc == POLL_ERROR)
        {
          if (errno == EINTR) continue;

          LogPrint(eLogError, "Control: run: Poll error: ", strerror (errno));
          break;
        }

      if (rc == POLL_TIMEOUT)
        {
          LogPrint(eLogDebug, "Control: run: Poll timed out");
          continue;
        }
      current_sc = nfds;
      for (int sid = 0; sid < current_sc; sid++)
        {
          LogPrint(eLogDebug, "Control: run: FD #", sid, " revents ",
                   fds[sid].revents);
          if (fds[sid].revents == 0)
            continue;

          if (fds[sid].revents != POLLIN)
            {
              LogPrint(eLogError, "Control: run: FD #", sid,
                       " revents ", fds[sid].revents);
              continue;
            }

#if !defined(DISABLE_SOCKET)
          if ((fds[sid].fd == tcp_fd || fds[sid].fd == conn_sockfd) &&
              fds[sid].revents & POLLIN)
#else
          if (fds[sid].fd == tcp_fd && fds[sid].revents & POLLIN)
#endif
            {
              LogPrint(eLogDebug, "Control: run: Checking server socket");
              do
                {
                  struct sockaddr_in client_addr;
                  memset(&client_addr, 0, sizeof(struct sockaddr_in));
                  socklen_t sin_size = sizeof (client_addr);

                  client_sockfd = accept(fds[sid].fd, (struct sockaddr *)&client_addr,
                                         &sin_size);

                  if (client_sockfd == PB_SOCKET_INVALID)
                  {
                    /*
                     * EWOULDBLOCK and EAGAIN - socket is marked nonblocking
                     * and no connections are present to be accepted
                     */
                    if (m_is_running && errno != EWOULDBLOCK && errno != EAGAIN)
                    {
                      LogPrint (eLogError, "Control: run: Accept error: ",
                                strerror (errno));
                    }
                    break;
                  }

                  LogPrint (eLogInfo, "Control: run: Received connection #",
                            nfds, " from ", inet_ntoa (client_addr.sin_addr));

                  if (nfds >= CONTROL_MAX_CLIENTS)
                    {
                      LogPrint(eLogWarning, "Control: run: Session limit");
                      PB_SOCKET_CLOSE (client_sockfd);
                      continue;
                    }

                  fds[nfds].fd = client_sockfd;
                  fds[nfds].events = POLLIN;

                  session.state = CONTROL_STATE_INIT;

                  nfds++;
                } while (client_sockfd != PB_SOCKET_INVALID);
              LogPrint (eLogDebug, "Control: run: End of accepting");
            }
        }

      LogPrint(eLogDebug, "Control: run: Checking clients");
      current_sc = nfds;
      for (int sid = 0; sid < current_sc; sid++)
        {
          LogPrint(eLogDebug, "Control: run: FD #", sid,
                   " revents: ", fds[sid].revents);

#if !defined(DISABLE_SOCKET)
          if (fds[sid].fd != tcp_fd && fds[sid].fd != conn_sockfd)
#else
          if (fds[sid].fd != tcp_fd)
#endif
            {
              if (session.state == CONTROL_STATE_INIT)
                {
                  //reply (sid, reply_ok[OK_HELO]);
                  session.state = CONTROL_STATE_AUTH;
                }

              LogPrint (eLogDebug, "ControlSession: run: FD #", sid,
                        ": New data");
              bool close_conn = false;
              /* Receive all incoming data on this socket */
              /* until the recv fails with EWOULDBLOCK */
              do
                {
                  if (fds[sid].fd == PB_SOCKET_INVALID)
                    {
                      LogPrint (eLogError, "ControlSession: run: FD #", sid,
                           " closed");
                        close_conn = true;
                        break;
                    }

                  if (session.need_clean)
                    {
                      free (session.buf);
                      session.need_clean = false;
                    }

                  session.buf = (char *)malloc (CONTROL_BUFF_SIZE);
                  session.need_clean = true;
                  memset (session.buf, 0, CONTROL_BUFF_SIZE);
                  ssize_t rc = PB_SOCKET_READ (fds[sid].fd, session.buf,
                                     CONTROL_BUFF_SIZE - 1);
                  if (rc == PB_SOCKET_ERROR)
                  {
                    /*
                     * EWOULDBLOCK and EAGAIN - socket is marked nonblocking
                     * and no connections are present to be accepted
                     */
                    if (m_is_running && errno != EWOULDBLOCK && errno != EAGAIN)
                      {
                        LogPrint (eLogError, "ControlSession: run: FD #",
                                  sid, ": Can't receive data, close");
                        close_conn = true;
                      }
                    break;
                  }

                  if (rc == 0)
                    {
                      LogPrint (eLogDebug, "ControlSession: run: FD #",
                                sid, " closed");
                      close_conn = true;
                      break;
                    }

                  /* Data was received  */
                  try
                    {
                      handle_request (sid);
                    }
                  catch (const std::exception& ex)
                    {
                      LogPrint (eLogError, "ControlSession: run: FD #", sid, " ",
                        ex.what());
                    }
                } while (m_is_running);

              if (close_conn)
                {
                  fds[sid].revents = POLLHUP;
                  if (fds[sid].fd != PB_SOCKET_INVALID)
                    {
                      PB_SOCKET_CLOSE (fds[sid].fd);
                      fds[sid].fd = PB_SOCKET_INVALID;
                    }
                  compress_array = true;

                  if (session.need_clean)
                    {
                      free (session.buf);
                      session.need_clean = false;
                    }

                  LogPrint (eLogDebug, "ControlSession: run: FD #", sid,
                            " closed");
                }
            }
        }

      if (!compress_array)
        continue;

      /*
       * We need to squeeze together the array and
       * decrement the number of file descriptors
       */
      compress_array = false;
      for (int sid = 0; sid < nfds; sid++)
        {
          LogPrint (eLogDebug, "ControlSession: run: FD #", sid,
                    ", total count: ", nfds);
          /* Skip good FD */
          if (fds[sid].fd != PB_SOCKET_INVALID)
            continue;

          LogPrint (eLogDebug, "ControlSession: run: FD #", sid,
                    " with invalid socket");

          for(int j = sid; j < nfds; j++)
            {
              LogPrint (eLogDebug, "ControlSession: run: FD #", j + 1,
                        " moved to #", j);
              fds[j].fd = fds[j + 1].fd;
            }
          sid--;
          nfds--;
        }
    }

  LogPrint (eLogInfo, "Control: Stopped");
}

void
BoteControl::reply (int sid, const std::string &msg)
{
  ssize_t rc = PB_SOCKET_WRITE (fds[sid].fd, msg.c_str (), msg.length ());
  if (rc == PB_SOCKET_ERROR)
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
  std::string str_req (session.buf);
  LogPrint (eLogDebug, "Control: handle_request: Got request: ", str_req);

  if (!jsonrpcpp::Parser::is_request(str_req))
    {
      LogPrint (eLogWarning, "Control: handle_request: Invalid request");
      jsonrpcpp::Error err("Invalid request", -32600);
      json response = {{"jsonrpc", "2.0"}, {"error", err.to_json()}, {"id", nullptr}};
      reply (sid, response.dump());
      return;
    }

  jsonrpcpp::request_ptr req = nullptr;

  try
    {
      req = std::dynamic_pointer_cast<jsonrpcpp::Request>(jsonrpcpp::Parser::do_parse(str_req));
    }
  catch (const std::exception& ex)
    {
      LogPrint (eLogWarning, "Control: handle_request: Invalid request: ", ex.what());
      jsonrpcpp::Error err("Invalid request", -32600);
      json response = {{"jsonrpc", "2.0"}, {"error", err.to_json()}, {"id", nullptr}};
      reply (sid, response.dump());
      return;
    }

  if (!req)
    {
      LogPrint (eLogWarning, "Control: handle_request: Can't parse");
      jsonrpcpp::Error err("Invalid request", -32600);
      json response = {{"jsonrpc", "2.0"}, {"error", err.to_json()}, {"id", nullptr}};
      reply (sid, response.dump());
      return;
    }

  LogPrint (eLogDebug, "Control: handle_request: json req: ", req->to_json().dump());

  json results;
  auto it = handlers.find (req->method());
  if (it != handlers.end ())
    {
      (this->*(it->second)) (req, results);
    }
  else
    {
      LogPrint (eLogWarning, "Control: handle_request: Method not found");
      jsonrpcpp::Error err("Method not found", -32601);
      json response = {
        {"jsonrpc", "2.0"},
        {"result", nullptr},
        {"error", err.to_json()},
        {"id", req->id ().to_json ()}
      };
      reply (sid, response.dump());
      return;
    }

  json res = {
    {"jsonrpc", "2.0"},
    {"result", nullptr},
    {"error", nullptr},
    {"id", req->id ().to_json ()}
  };

  if (session.is_error || results.contains("error"))
    res["error"] = results.at ("error");
  else
    res["result"] = results;

  session.is_error = false;

  LogPrint (eLogDebug, "Control: handle_request: json res: ", res.dump());

  reply (sid, res.dump());
}

void
BoteControl::all (const jsonrpcpp::request_ptr req, json& results)
{
  if (session.is_error)
    return;

  if (req->method ().compare ("all") != 0)
    {
      unknown_method (req, results);
      return;
    }

  if (!req->params ().has ("subcommand"))
    {
      unknown_param (req, results);
      return;
    }

  auto subcmd = req->params ().get<std::string>("subcommand");

  LogPrint (eLogDebug, "Control: all: subcmd: ", subcmd);

  if (subcmd.compare("show") == 0)
    {
      daemon (req, results);
      addressbook (req, results);
      identity (req, results);
      storage (req, results);
      peer (req, results);
      node (req, results);
    }
  else
    unknown_param (req, results);
}

void
BoteControl::addressbook (const jsonrpcpp::request_ptr req, json& results)
{
  if (session.is_error)
    return;

  if (req->method ().compare ("all") != 0 && req->method ().compare ("addressbook") != 0)
    {
      unknown_method (req, results);
      return;
    }

  if (!req->params ().has ("subcommand"))
    {
      unknown_param (req, results);
      return;
    }

  auto subcmd = req->params ().get<std::string>("subcommand");

  LogPrint (eLogDebug, "Control: addressbook: subcmd: ", subcmd);

  if (subcmd.compare("show") == 0)
    {
      results["addressbook"] = {
        { "size", bote::context.contacts_size () }
      };
    }
  else
    unknown_param (req, results);
}

void
BoteControl::daemon (const jsonrpcpp::request_ptr req, json& results)
{
  if (session.is_error)
    return;

  if (req->method ().compare ("all") != 0 && req->method ().compare ("daemon") != 0)
    {
      unknown_method (req, results);
      return;
    }

  if (!req->params ().has ("subcommand"))
    {
      unknown_param (req, results);
      return;
    }

  auto subcmd = req->params ().get<std::string>("subcommand");

  LogPrint (eLogDebug, "Control: daemon: subcmd: ", subcmd);

  if (subcmd.compare("show") == 0)
    {
      results["daemon"] = {
        { "uptime", bote::context.get_uptime () },
        { "bytes",
          {
            { "recived", bote::network_worker.bytes_recv () },
            { "sent", bote::network_worker.bytes_sent () }
          }
        }
      };
    }
  else
    unknown_param (req, results);
}

void
BoteControl::identity (const jsonrpcpp::request_ptr req, json& results)
{
  if (session.is_error)
    return;

  if (req->method ().compare ("all") != 0 && req->method ().compare ("identity") != 0)
    {
      unknown_method (req, results);
      return;
    }

  if (!req->params ().has ("subcommand"))
    {
      unknown_param (req, results);
      return;
    }

  auto subcmd = req->params ().get<std::string>("subcommand");

  LogPrint (eLogDebug, "Control: identity: subcmd: ", subcmd);

  if (req->method ().compare ("all") == 0 && subcmd.compare("show") == 0)
    {
      results["identity"] = {
        { "count", bote::context.get_identities_count () }
      };
    }
  else if (req->method ().compare ("identity") == 0 && subcmd.compare("show") == 0)
    {
      results["identity"] = json::array();
      auto identities = bote::context.getEmailIdentities ();
      for (const auto &identity : identities)
        {
          json jident = {
            { "name", identity->publicName },
            { "address", identity->identity.ToBase64v1 () },
            { "hash", identity->identity.GetIdentHash ().ToBase64 () },
            { "type", identity->identity.GetKeyType () }
          };
          results["identity"].push_back(jident);
        }
    }
  else
    unknown_param (req, results);
}

void
BoteControl::storage (const jsonrpcpp::request_ptr req, json& results)
{
  if (session.is_error)
    return;

  if (req->method ().compare ("all") != 0 && req->method ().compare ("storage") != 0)
    {
      unknown_method (req, results);
      return;
    }

  if (!req->params ().has ("subcommand"))
    {
      unknown_param (req, results);
      return;
    }

  auto subcmd = req->params ().get<std::string>("subcommand");

  LogPrint (eLogDebug, "Control: storage: subcmd: ", subcmd);

  if (subcmd.compare("show") == 0)
    {
      results["storage"] = {
        { "used", bote::DHT_worker.get_storage_usage () }
      };
    }
  else
    unknown_param (req, results);
}

void
BoteControl::peer (const jsonrpcpp::request_ptr req, json& results)
{
  if (session.is_error)
    return;

  if (req->method ().compare ("all") != 0 && req->method ().compare ("peer") != 0)
    {
      unknown_method (req, results);
      return;
    }

  if (!req->params ().has ("subcommand"))
    {
      unknown_param (req, results);
      return;
    }

  auto subcmd = req->params ().get<std::string>("subcommand");

  LogPrint (eLogDebug, "Control: peer: subcmd: ", subcmd);

  if (subcmd.compare("show") == 0)
    {
      results["peers"] = {
        { "count",
          {
            { "total", bote::relay_worker.getPeersCount () },
            { "good", bote::relay_worker.get_good_peer_count () }
          }
        }
      };
    }
  else
    unknown_param (req, results);
}

void
BoteControl::node (const jsonrpcpp::request_ptr req, json& results)
{
  if (session.is_error)
    return;

  if (req->method ().compare ("all") != 0 && req->method ().compare ("node") != 0)
    {
      unknown_method (req, results);
      return;
    }

  if (!req->params ().has ("subcommand"))
    {
      unknown_param (req, results);
      return;
    }

  auto subcmd = req->params ().get<std::string>("subcommand");

  LogPrint (eLogDebug, "Control: node: subcmd: ", subcmd);

  if (subcmd.compare("show") == 0)
    {
      results["nodes"] = {
        {"count",
          {
            { "total", bote::DHT_worker.getNodesCount () },
            { "unlocked", bote::DHT_worker.get_unlocked_nodes_count () }
          }
        }
      };
    }
  else
    unknown_param (req, results);
}

void
BoteControl::unknown_method (const jsonrpcpp::request_ptr req, json& results)
{
  if (session.is_error)
    return;

  LogPrint (eLogWarning, "Control: unknown_method: ", req->to_json ().dump ());

  jsonrpcpp::Error err("Method not found", -32601);
  results["error"] = err.to_json();

  session.is_error = true;
}

void
BoteControl::unknown_param (const jsonrpcpp::request_ptr req, json& results)
{
  if (session.is_error)
    return;

  LogPrint (eLogWarning, "Control: unknown_param: ", req->to_json ().dump ());

  jsonrpcpp::Error err("Invalid params", -32602);
  results["error"] = err.to_json();

  session.is_error = true;
}

} /* namespace module */
} /* namespace bote */
