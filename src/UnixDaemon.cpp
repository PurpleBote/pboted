/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#ifndef _WIN32

#include <fcntl.h>
#include <csignal>
#include <cstdlib>
#include <sys/resource.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

#include "BoteContext.h"
#include "BoteDaemon.h"
#include "ConfigParser.h"
#include "DHTworker.h"
#include "FileSystem.h"
#include "Logging.h"
#include "RelayWorker.h"

namespace bote
{

void handle_signal(int sig)
{
  switch (sig)
    {
      case SIGHUP:
        LogPrint(eLogInfo, "Daemon: Got SIGHUP, reload configuration...");
        // ToDo: reload_config ();
        break;
      case SIGUSR1:
        LogPrint(eLogInfo, "Daemon: Got SIGUSR1, reopening logs...");
        bote::log::Logger().Reopen();
        break;
      case SIGINT:
        if (sig == SIGINT)
          LogPrint (eLogInfo, "Daemon: Got SIGINT, stopping");
      case SIGABRT:
        if (sig == SIGABRT)
          LogPrint (eLogInfo, "Daemon: Got SIGABRT, stopping");
      case SIGTERM:        
        if (sig == SIGTERM)
          LogPrint (eLogInfo, "Daemon: Got SIGTERM, stopping");
        else
          LogPrint(eLogError, "Daemon: Got unknown signal: ", sig);
        Daemon.stop ();
        break;
      case SIGPIPE:
        LogPrint(eLogInfo, "Daemon: Got SIGPIPE");
        break;
      default:
        LogPrint(eLogWarning, "Daemon: Got unknown signal: ", sig);
        break;
    }
}

int DaemonLinux::start ()
{
  /* Demonization */
  if (isDaemon)
  {
    LogPrint(eLogDebug, "Daemon: Run as daemon");

    if (daemon(true, false) == -1)
      {
        LogPrint (eLogError, "Daemon: Daemonization failed");
        return EXIT_FAILURE;
      }

    const std::string& d = bote::fs::GetDataDir();
    if (chdir(d.c_str()) != 0)
      {
        LogPrint(eLogError, "Daemon: Could not chdir: ", strerror(errno));
        return EXIT_FAILURE;
      }
  }

  /* Set proc limits */
  struct rlimit limit = {};
  uint16_t nfiles = 0;
  bote::config::GetOption("openfiles", nfiles);
  getrlimit(RLIMIT_NOFILE, &limit);
  if (nfiles == 0)
    {
      LogPrint(eLogInfo, "Daemon: Using system limit in ", limit.rlim_cur,
               " max open files");
    }
  else if (nfiles <= limit.rlim_max)
    {
      limit.rlim_cur = nfiles;
      if (setrlimit(RLIMIT_NOFILE, &limit) == 0)
        {
          LogPrint(eLogInfo, "Daemon: Set max number of open files to ",
                   nfiles, " (system limit is ", limit.rlim_max, ")");
        }
      else
        {
          LogPrint(eLogError,"Daemon: Can't set max number of open files: ",
                   strerror(errno));
        }
    }
  else
    {
      LogPrint(eLogError,"Daemon: limits.openfiles exceeds system limit: ",
               limit.rlim_max);
    }

  /* Set core file size */
  uint32_t cfsize = 0;
  bote::config::GetOption("coresize", cfsize);
  if (cfsize)
  {
    cfsize *= 1024;
    getrlimit(RLIMIT_CORE, &limit);
    if (cfsize <= limit.rlim_max)
      {
        limit.rlim_cur = cfsize;
        if (setrlimit(RLIMIT_CORE, &limit) != 0)
          {
            LogPrint(eLogError,"Daemon: Can't set max size of coredump: ",
              strerror(errno));
          }
        else if (cfsize == 0)
          LogPrint(eLogInfo, "Daemon: Coredumps disabled");
        else
          {
            LogPrint(eLogInfo, "Daemon: Set max size of core files to ",
                     cfsize / 1024, "KiB");
          }
      }
    else
      {
        LogPrint(eLogError, "Daemon: limits.coresize exceeds system limit: ",
                 limit.rlim_max);
      }
  }

  /* Pidfile */
  bote::config::GetOption("pidfile", pidfile);
  if (pidfile.empty())
    {
      pidfile = bote::fs::DataDirPath("pboted.pid");
    }

  if (!pidfile.empty())
    {
      pidFH = open(pidfile.c_str(), O_RDWR | O_CREAT, 0600);
      if (pidFH < 0)
        {
          LogPrint(eLogError, "Daemon: Could not create pidfile ", pidfile,
                   ": ", strerror(errno));
          return EXIT_FAILURE;
        }

      char pid[10];
      sprintf(pid, "%d\n", getpid());
      int trcd = ftruncate (pidFH, 0);

      if (trcd < 0)
        {
          LogPrint(eLogError, "Daemon: Can't truncate pidfile: ",
                   strerror(errno));
          return EXIT_FAILURE;
        }

      if (write(pidFH, pid, strlen(pid)) < 0)
        {
          LogPrint(eLogError, "Daemon: Can't write pidfile: ",
                   strerror(errno));
          return EXIT_FAILURE;
        }
    }

  /* Signal handler */
  struct sigaction sa;
  sa.sa_handler = handle_signal;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  sigaction (SIGHUP, &sa, 0);
  sigaction (SIGUSR1, &sa, 0);
  sigaction (SIGABRT, &sa, 0);
  sigaction (SIGTERM, &sa, 0);
  sigaction (SIGINT, &sa, 0);
  sigaction (SIGPIPE, &sa, 0);

  return Daemon_Singleton::start ();
}

bool DaemonLinux::stop ()
{
  if (!running)
    return true;

  running = false;

  m_check_cv.notify_one ();

  bool rc = Daemon_Singleton::stop ();

  close (pidFH);
  bote::fs::Remove (pidfile);

  return rc;
}

void DaemonLinux::run ()
{
  auto check_timeout = std::chrono::seconds (10);

  while (running)
    {
      {
        std::unique_lock<std::mutex> lk (m_cv_mutex);
        auto rc = m_check_cv.wait_for (lk, check_timeout);

        if (rc == std::cv_status::no_timeout)
          LogPrint (eLogDebug, "Daemon: Got notification");

        lk.unlock ();
      }

      /* ToDo: check status of network, DHT, relay, etc. */
      /* and try restart on error */

      if (bote::network_worker.is_sick ())
        {
          LogPrint(eLogError, "Daemon: SAM session is sick, try to re-connect");
          bote::network_worker.init ();
          bote::network_worker.start ();
        }
    }
}

} // namespace bote

#endif /* _WIN32 */
