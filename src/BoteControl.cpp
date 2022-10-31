/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022, The PurpleBote Team
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

/*
#ifndef _WIN32 // brokes socket binding on Windows
      rc = setsockopt(conn_sockfd, SOL_SOCKET, SO_REUSEADDR,
                      (char *)&enabled, sizeof(enabled));
      if (rc == PB_SOCKET_ERROR)
      {
        LogPrint (eLogError, "Control: setsockopt() failed: ", strerror (errno));
        PB_SOCKET_CLOSE (conn_sockfd);
        return;
      }
#endif
*/
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
                  handle_request (sid);
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

      /* We need to squeeze together the array and */
      /* decrement the number of file descriptors */
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
  //ssize_t rc = send (fds[sid].fd, msg.c_str (), msg.length (), 0);
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
  ss << "\"" << name << "\": " << std::fixed << std::setprecision (6) << value;
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
  LogPrint (eLogDebug, "Control: all: cmd_id: ", cmd_id);

  if (0 == cmd_id.compare ("show"))
    {
      daemon (cmd_id, results);
      results << ", ";
      addressbook (cmd_id, results);
      results << ", ";
      identity (cmd_id, results);
      results << ", ";
      storage (cmd_id, results);
      results << ", ";
      peer (cmd_id, results);
      results << ", ";
      node (cmd_id, results);
    }
  else
    unknown_cmd (cmd_id, results);
}

void
BoteControl::addressbook (const std::string &cmd_id, std::ostringstream &results)
{
  LogPrint (eLogDebug, "Control: addressbook: cmd_id: ", cmd_id);

  if (0 == cmd_id.compare ("show"))
    {
      results << "\"addressbook\": {";
      insert_param (results, "size", (int)bote::context.contacts_size ());
      results << "}";
    }
  else
    unknown_cmd (cmd_id, results);
}

void
BoteControl::daemon (const std::string &cmd_id, std::ostringstream &results)
{
  LogPrint (eLogDebug, "Control: daemon: cmd_id: ", cmd_id);

  if (0 == cmd_id.compare ("show"))
    {
      results << "\"daemon\": {";
      insert_param (results, "uptime", (int)bote::context.get_uptime ());
      results << ", ";
      results << "\"bytes\": {";
      insert_param (results, "recived", (int)bote::network_worker.bytes_recv ());
      results << ", ";
      insert_param (results, "sent", (int)bote::network_worker.bytes_sent ());
      results << "}}";
    }
  else
    unknown_cmd (cmd_id, results);
}

void
BoteControl::identity (const std::string &cmd_id, std::ostringstream &results)
{
  LogPrint (eLogDebug, "Control: daemon: cmd_id: ", cmd_id);

  if (0 == cmd_id.compare ("show"))
    {
      results << "\"identity\": {";
      insert_param (results, "count", (int)bote::context.get_identities_count ());
      results << "}";
    }
  else
    unknown_cmd (cmd_id, results);
}

void
BoteControl::storage (const std::string &cmd_id, std::ostringstream &results)
{
  LogPrint (eLogDebug, "Control: storage: cmd_id: ", cmd_id);

  if (0 == cmd_id.compare ("show"))
    {
      results << "\"storage\": {";
      insert_param (results, "used",
                    (double)bote::DHT_worker.get_storage_usage ());
      results << "}";
    }
  else
    unknown_cmd (cmd_id, results);
}

void
BoteControl::peer (const std::string &cmd_id, std::ostringstream &results)
{
  LogPrint (eLogDebug, "Control: peer: cmd_id: ", cmd_id);

  if (0 == cmd_id.compare ("show"))
    {
      results << "\"peers\": {";
      results << "\"count\": {";
      insert_param (results, "total",
                    (int)bote::relay_worker.getPeersCount ());
      results << ", ";
      insert_param (results, "good",
                    (int)bote::relay_worker.get_good_peer_count ());
      results << "}}";
    }
  else
    unknown_cmd (cmd_id, results);
}

void
BoteControl::node (const std::string &cmd_id, std::ostringstream &results)
{
  LogPrint (eLogDebug, "Control: node: cmd_id: ", cmd_id);

  if (0 == cmd_id.compare ("show"))
    {
      results << "\"nodes\": {";
      results << "\"count\": {";
      insert_param (results, "total",
                    (int)bote::DHT_worker.getNodesCount ());
      results << ", ";
      insert_param (results, "unlocked",
                    (int)bote::DHT_worker.get_unlocked_nodes_count ());
      results << "}}";
    }
  else
    unknown_cmd (cmd_id, results);
}

void
BoteControl::unknown_cmd (const std::string &cmd, std::ostringstream &results)
{
  LogPrint (eLogWarning, "Control: node: unknown_cmd: ", cmd);

  results << "{\"id\": null, \"error\": ";
  results << "{\"code\": 404,";
  results << "\"message\": \"Command not found: " << cmd << "\"},";
  results << "\"jsonrpc\": 2.0}";
}

} /* namespace module */
} /* namespace bote */
