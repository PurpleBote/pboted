/**
 * Copyright (c) 2019-2021 polistern
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
#include "Daemon.h"
#include "DHTworker.h"
#include "FS.h"
#include "Log.h"
#include "RelayPeersWorker.h"

void handle_signal(int sig) {
  switch (sig) {
    case SIGHUP:LogPrint(eLogInfo, "Daemon: Got SIGHUP, reload configuration...");
      // pbote::context.ReloadConfig();
      break;
    case SIGUSR1:LogPrint(eLogInfo, "Daemon: Got SIGUSR1, reopening logs...");
      pbote::log::Logger().Reopen();
      break;
    case SIGINT:
    case SIGABRT:
    case SIGTERM:
      Daemon.running = false; // Exit loop
      break;
    case SIGPIPE:LogPrint(eLogInfo, "Daemon: Got SIGPIPE received");
      break;
    default:LogPrint(eLogWarning, "Daemon: Unknown signal received: ", sig);
      break;
  }
}

namespace pbote {
namespace util {

int DaemonLinux::start() {
  if (isDaemon) {
    LogPrint(eLogDebug, "Daemon: Run as daemon");

    if (daemon(true, false) == -1) {
      return EXIT_FAILURE;
    }

    /*pid_t pid, sid;
    pid = fork();

    if (pid > 0) {
      LogPrint(eLogDebug, "Daemon: Exit parent process");
      //::exit(EXIT_SUCCESS); // Exit parent
      return pid;
    }

    // On error
    if (pid < 0) {
      LogPrint(eLogError, "Daemon: could not fork: ", strerror(errno));
      return EXIT_FAILURE;
    }

    // child
    umask(S_IWGRP | S_IRWXO); // 0027

    sid = setsid();
    if (sid < 0) {
      LogPrint(eLogError, "Daemon: could not create process group: ", strerror(errno));
      return EXIT_FAILURE;
    }*/

    const std::string& d = pbote::fs::GetDataDir();
    if (chdir(d.c_str()) != 0) {
      LogPrint(eLogError, "Daemon: could not chdir: ", strerror(errno));
      return EXIT_FAILURE;
    }

    // point std{in,out,err} descriptors to /dev/null
    /*freopen("/dev/null", "r", stdin);
    freopen("/dev/null", "w", stdout);
    freopen("/dev/null", "w", stderr);*/
  }

  // set proc limits
  struct rlimit limit;
  uint16_t nfiles;
  pbote::config::GetOption("limits.openfiles", nfiles);
  getrlimit(RLIMIT_NOFILE, &limit);
  if (nfiles == 0) {
    LogPrint(eLogInfo, "Daemon: using system limit in ", limit.rlim_cur," max open files");
  } else if (nfiles <= limit.rlim_max) {
    limit.rlim_cur = nfiles;
    if (setrlimit(RLIMIT_NOFILE, &limit) == 0) {
      LogPrint(eLogInfo, "Daemon: set max number of open files to ", nfiles, " (system limit is ", limit.rlim_max, ")");
    } else {
      LogPrint(eLogError,"Daemon: can't set max number of open files: ", strerror(errno));
    }
  } else {
    LogPrint(eLogError,"Daemon: limits.openfiles exceeds system limit: ", limit.rlim_max);
  }
  uint32_t cfsize;
  pbote::config::GetOption("limits.coresize", cfsize);
  if (cfsize) // core file size set
  {
    cfsize *= 1024;
    getrlimit(RLIMIT_CORE, &limit);
    if (cfsize <= limit.rlim_max) {
      limit.rlim_cur = cfsize;
      if (setrlimit(RLIMIT_CORE, &limit) != 0) {
        LogPrint(eLogError,"Daemon: can't set max size of coredump: ", strerror(errno));
      } else if (cfsize == 0) {
        LogPrint(eLogInfo, "Daemon: coredumps disabled");
      } else {
        LogPrint(eLogInfo, "Daemon: set max size of core files to ", cfsize / 1024, "Kb");
      }
    } else {
      LogPrint(eLogError, "Daemon: limits.coresize exceeds system limit: ", limit.rlim_max);
    }
  }

  // Pidfile
  // this code is c-styled and a bit ugly, but we need fd for locking pidfile
  //std::string pidfile;
  pbote::config::GetOption("pidfile", pidfile);
  if (pidfile.empty()) {
    pidfile = pbote::fs::DataDirPath("pbote.pid");
  }
  if (!pidfile.empty()) {
    pidFH = open(pidfile.c_str(), O_RDWR | O_CREAT, 0600);
    if (pidFH < 0) {
      LogPrint(eLogError, "Daemon: could not create pid file ", pidfile, ": ", strerror(errno));
      return EXIT_FAILURE;
    }

    char pid[10];
    sprintf(pid, "%d\n", getpid());
    ftruncate(pidFH, 0);
    if (write(pidFH, pid, strlen(pid)) < 0) {
      LogPrint(eLogError, "Daemon: could not write pidfile: ", strerror(errno));
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

bool DaemonLinux::stop() {
  pbote::fs::Remove(pidfile);

  return Daemon_Singleton::stop();
}

void DaemonLinux::run() {
  while (running) {
    auto uptime = context.get_uptime();

    LogPrint(eLogDebug, "Daemon: uptime: ", uptime / 60, "m ", uptime % 60, "s",
             ", bytes received: ", context.get_bytes_recv(),
             ", bytes sent: ", context.get_bytes_sent(),
             ", DHT nodes: ", pbote::kademlia::DHT_worker.getNodesCount(),
             ", Relay peers: ", pbote::relay::relay_peers_worker.getPeersCount());

    /*if (pbote::context::context.isHeathy()) {
      LogPrint(eLogDebug, "Context: is healthy!");
    }*/
    /*if (gracefulShutdownInterval)
            {
                    gracefulShutdownInterval--; // - 1 second
                    if (gracefulShutdownInterval <= 0 ||
       i2p::tunnel::tunnels.CountTransitTunnels() <= 0)
                    {
                            LogPrint(eLogInfo, "Graceful shutdown");
                            return;
                    }
            }*/
    std::this_thread::sleep_for(std::chrono::seconds(60));
  }
}

} // namespace util
} // namespace pbote
