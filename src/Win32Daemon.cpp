/**
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#ifdef _WIN32 // Windows-only

#ifndef UNICODE
#define UNICODE
#endif

#include <signal.h>
#include <thread>

#include "BoteContext.h"
#include "BoteDaemon.h"
#include "DHTworker.h"
#include "Logging.h"

#include "win32/Resource.h"
#include "win32/Service.h"

/// Windows Service block

class Service : public WindowsService {
  using WindowsService::WindowsService;

protected:
  virtual DWORD WINAPI worker(LPVOID)
  {
    Daemon.run();
    return ERROR_SUCCESS;
  }
  virtual void on_startup()
  {
    Daemon.start();
  }
  virtual void on_stop()
  {
    Daemon.stop();
  }
};

void SignalHandler(int sig)
{
  switch (sig)
    {
      case SIGINT:
      case SIGABRT:
      case SIGTERM:
        LogPrint(eLogWarning, "Daemon: signal received");
        Daemon.running = false;
        break;
      default:
        LogPrint(eLogWarning, "Daemon: Unknown signal received: ", sig);
        break;
    }
}

/// Windows Daemon block

namespace pbote
{
namespace util
{

bool DaemonWin32::init(int argc, char* argv[])
{
  bool ret = Daemon_Singleton::init(argc, argv);

  if (ret && isDaemon)
  {
    Service pboted("pboted service", false);
    pboted.run();
    return false; // Application terminated, no need to continue it more
  }
  else if (ret)
  {
    pbote::log::SetThrowFunction ([](const std::string& s)
    {
      std::wstring ws = std::wstring(s.begin(), s.end());
      const wchar_t* str = ws.c_str();
      MessageBox(0, str, L"pboted", MB_ICONERROR | MB_TASKMODAL | MB_OK );
    });
  }
  return ret;
}

int DaemonWin32::start()
{
  signal(SIGINT, SignalHandler);
  signal(SIGABRT, SignalHandler);
  signal(SIGTERM, SignalHandler);

  WSADATA wsaData;
  WSAStartup(MAKEWORD(2, 2), &wsaData);

  return Daemon_Singleton::start();
}

bool DaemonWin32::stop()
{
  if (!running)
    return true;

  running = false;

  m_check_cv.notify_one ();

  return Daemon_Singleton::stop();
}

void DaemonWin32::run()
{
  auto check_timeout = std::chrono::seconds (1);

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

#endif // _WIN32
