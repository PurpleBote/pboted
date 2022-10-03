/**
 * Copyright (C) 2019-2022, polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <fcntl.h>
#include <csignal>
#include <cstdlib>
#include <sys/resource.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

#include "BoteContext.h"
#include "ConfigParser.h"
#include "BoteDaemon.h"
#include "DHTworker.h"
#include "FileSystem.h"
#include "Logging.h"
#include "RelayWorker.h"

void handle_signal(int sig)
{
  switch (sig)
    {
      case SIGHUP:
        LogPrint(eLogInfo, "Daemon: Got SIGHUP, reload configuration...");
        // pbote::context.ReloadConfig();
        break;
      case SIGUSR1:
        LogPrint(eLogInfo, "Daemon: Got SIGUSR1, reopening logs...");
        pbote::log::Logger().Reopen();
        break;
      case SIGINT:
      case SIGABRT:
      case SIGTERM:
        Daemon.running = false; // Exit loop
        break;
      case SIGPIPE:
        LogPrint(eLogInfo, "Daemon: Got SIGPIPE received");
        break;
      default:
        LogPrint(eLogWarning, "Daemon: Unknown signal received: ", sig);
        break;
    }
}

namespace pbote
{
namespace util
{

int DaemonLinux::start()
{
  if (isDaemon)
  {
    LogPrint(eLogDebug, "Daemon: Run as daemon");

    if (daemon(true, false) == -1)
      {
        return EXIT_FAILURE;
      }

    const std::string& d = pbote::fs::GetDataDir();
    if (chdir(d.c_str()) != 0)
      {
        LogPrint(eLogError, "Daemon: Could not chdir: ", strerror(errno));
        return EXIT_FAILURE;
      }
  }

  // set proc limits
  struct rlimit limit = {};
  uint16_t nfiles = 0;
  pbote::config::GetOption("limits.openfiles", nfiles);
  getrlimit(RLIMIT_NOFILE, &limit);
  if (nfiles == 0)
    LogPrint(eLogInfo, "Daemon: Using system limit in ", limit.rlim_cur," max open files");
  else if (nfiles <= limit.rlim_max)
    {
      limit.rlim_cur = nfiles;
      if (setrlimit(RLIMIT_NOFILE, &limit) == 0)
        LogPrint(eLogInfo, "Daemon: Set max number of open files to ", nfiles, " (system limit is ", limit.rlim_max, ")");
      else
        LogPrint(eLogError,"Daemon: Can't set max number of open files: ", strerror(errno));
    }
  else
    LogPrint(eLogError,"Daemon: limits.openfiles exceeds system limit: ", limit.rlim_max);

  uint32_t cfsize = 0;
  pbote::config::GetOption("limits.coresize", cfsize);
  if (cfsize) // core file size set
  {
    cfsize *= 1024;
    getrlimit(RLIMIT_CORE, &limit);
    if (cfsize <= limit.rlim_max)
      {
        limit.rlim_cur = cfsize;
        if (setrlimit(RLIMIT_CORE, &limit) != 0)
          LogPrint(eLogError,"Daemon: Can't set max size of coredump: ", strerror(errno));
        else if (cfsize == 0)
          LogPrint(eLogInfo, "Daemon: Coredumps disabled");
        else
          LogPrint(eLogInfo, "Daemon: Set max size of core files to ", cfsize / 1024, "KiB");
      }
    else
      LogPrint(eLogError, "Daemon: limits.coresize exceeds system limit: ", limit.rlim_max);
  }

  // Pidfile
  // this code is c-styled and a bit ugly, but we need fd for locking pidfile
  pbote::config::GetOption("pidfile", pidfile);
  if (pidfile.empty())
    {
      pidfile = pbote::fs::DataDirPath("pbote.pid");
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
          LogPrint(eLogError, "Daemon: Can't truncate pidfile: ", strerror(errno));
          return EXIT_FAILURE;
        }

      if (write(pidFH, pid, strlen(pid)) < 0)
        {
          LogPrint(eLogError, "Daemon: Can't write pidfile: ", strerror(errno));
          return EXIT_FAILURE;
        }
    }

  gracefulShutdownInterval = 0; // not specified

  // Signal handler
  struct sigaction sa;
  sa.sa_handler = handle_signal;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  sigaction(SIGHUP, &sa, 0);
  sigaction(SIGUSR1, &sa, 0);
  sigaction(SIGABRT, &sa, 0);
  sigaction(SIGTERM, &sa, 0);
  sigaction(SIGINT, &sa, 0);
  sigaction(SIGPIPE, &sa, 0);

  return Daemon_Singleton::start();
}

bool DaemonLinux::stop()
{
  if (running)
    running = false;

  pbote::fs::Remove(pidfile);

  return Daemon_Singleton::stop();
}

void DaemonLinux::run()
{
  while (running)
    {
      // ToDo: check status of network, DHT, relay, etc. and try restart on error
      std::this_thread::sleep_for(std::chrono::seconds(10));

      if (pbote::network::network_worker.is_sick ())
        {
          LogPrint(eLogError, "Daemon: SAM session is sick, try to re-connect");
          pbote::network::network_worker.init ();
          pbote::network::network_worker.start ();
        }
    }
}

} // namespace util
} // namespace pbote
