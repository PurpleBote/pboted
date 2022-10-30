/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <memory>
#include <unordered_map>

#include "BoteContext.h"
#include "BoteControl.h"
#include "BoteDaemon.h"
#include "compat.h"
#include "ConfigParser.h"
#include "DHTworker.h"
#include "EmailWorker.h"
#include "FileSystem.h"
#include "Logging.h"
#include "POP3.h"
#include "RelayWorker.h"
#include "SMTP.h"
#include "version.h"

namespace bote
{

class Daemon_Singleton::Daemon_Singleton_Private
{
 public:
  Daemon_Singleton_Private() {};
  ~Daemon_Singleton_Private() {};

  std::unique_ptr<bote::smtp::SMTP> SMTP_server;
  std::unique_ptr<bote::pop3::POP3> POP3_server;
  std::unique_ptr<bote::module::BoteControl> control_server;
};

Daemon_Singleton::Daemon_Singleton()
  : isDaemon(false),
    running(true),
    d(*new Daemon_Singleton_Private())
{}

Daemon_Singleton::~Daemon_Singleton()
{
  delete &d;
}

bool
Daemon_Singleton::IsService() const
{
  bool service = false;
  bote::config::GetOption("service", service);
  return service;
}

bool
Daemon_Singleton::init(int argc, char *argv[])
{
  return init(argc, argv, nullptr);
}

bool
Daemon_Singleton::init(int argc, char *argv[],
                       std::shared_ptr<std::ostream> logstream)
{
  bote::config::Init();
  bote::config::ParseCmdline(argc, argv);

  std::string config;
  bote::config::GetOption("conf", config);
  std::string datadir;
  bote::config::GetOption("datadir", datadir);
  bote::fs::DetectDataDir(datadir, IsService());
  bote::fs::Init();

  datadir = bote::fs::GetDataDir();
  if (config.empty())
    {
      config = bote::fs::DataDirPath("pboted.conf");
      if (!bote::fs::Exists(config))
        config = "";
    }

  bote::config::ParseConfig(config);
  bote::config::Finalize();

  bote::config::GetOption("daemon", isDaemon);

  std::string logs;
  bote::config::GetOption("log", logs);
  std::string logfile;
  bote::config::GetOption("logfile", logfile);
  std::string loglevel;
  bote::config::GetOption("loglevel", loglevel);
  bool logclftime;
  bote::config::GetOption("logclftime", logclftime);

  // Setup logging
  if (logclftime)
    bote::log::Logger().SetTimeFormat("[%d/%b/%Y:%H:%M:%S %z]");

  if (isDaemon && (logs.empty() || logs == "stdout"))
    logs = "file";

  bote::log::Logger().SetLogLevel(loglevel);
  if (logstream)
    {
      LogPrint(eLogInfo, "Log: Will send messages to std::ostream");
      bote::log::Logger().SendTo(logstream);
    }
  else if (logs == "file")
    {
      if (logfile.empty())
        logfile = bote::fs::DataDirPath("pboted.log");
      LogPrint(eLogInfo, "Log: Will send messages to ", logfile);
      bote::log::Logger().SendTo(logfile);
    }
#ifndef _WIN32
  else if (logs == "syslog")
    {
      LogPrint(eLogInfo, "Log: Will send messages to syslog");
      bote::log::Logger().SendTo("pboted", LOG_DAEMON);
    }
#endif
  else
    {
      // use stdout -- default
    }

#ifdef NDEBUG
  LogPrint(eLogInfo, CODENAME, " v", VERSION, " R starting");
#else
  LogPrint(eLogInfo, CODENAME, " v", VERSION, " D starting");
#endif // NDEBUG

  LogPrint(eLogDebug, "FS: Data directory: ", datadir);
  LogPrint(eLogDebug, "FS: Main config file: ", config);

  LogPrint(eLogInfo, "Daemon: Init network");
  bote::network_worker.init();

  LogPrint(eLogInfo, "Daemon: Init context");
  bote::context.init();

  LogPrint(eLogDebug, "Daemon: Init done");
  return true;
}

int
Daemon_Singleton::start()
{
  LogPrint(eLogDebug, "Daemon: Start services");
  bote::log::Logger().Start();

  LogPrint(eLogInfo, "Daemon: Starting network");
  bote::network_worker.start();

  LogPrint(eLogInfo, "Daemon: Starting relay");
  bote::relay_worker.start();

  LogPrint(eLogInfo, "Daemon: Starting DHT");
  bote::DHT_worker.start();

  LogPrint(eLogInfo, "Daemon: Starting packet handler");
  bote::packet_handler.start();

  LogPrint(eLogInfo, "Daemon: Starting Email");
  bote::email_worker.start();

  bool control_enabled = false;
  bote::config::GetOption("control.enabled", control_enabled);
  if (control_enabled)
    {
      LogPrint(eLogInfo, "Daemon: Starting control socket");
      d.control_server = std::make_unique<bote::module::BoteControl>();
      d.control_server->start();
    }

  bool smtp_enabled = false;
  bote::config::GetOption("smtp.enabled", smtp_enabled);
  if (smtp_enabled)
    {
      std::string SMTPaddr;
      uint16_t SMTPport;
      bote::config::GetOption("smtp.address", SMTPaddr);
      bote::config::GetOption("smtp.port", SMTPport);
      LogPrint(eLogInfo, "Daemon: Starting SMTP server at ",
               SMTPaddr, ":", SMTPport);

      try
        {
          d.SMTP_server = std::make_unique<bote::smtp::SMTP>(SMTPaddr, SMTPport);
          d.SMTP_server->start();
        }
      catch (std::exception &ex)
        {
          LogPrint(eLogError, "Daemon: Failed to start SMTP server: ",
                   ex.what());
          ThrowFatal("Unable to start SMTP server at ",
                     SMTPaddr, ":", SMTPport, ": ", ex.what());
        }
    }

  bool pop3_enabled = false;
  bote::config::GetOption("pop3.enabled", pop3_enabled);
  if (pop3_enabled)
    {
      std::string POP3addr;
      uint16_t POP3port;
      bote::config::GetOption("pop3.address", POP3addr);
      bote::config::GetOption("pop3.port", POP3port);
      LogPrint(eLogInfo, "Daemon: Starting POP3 server at ",
               POP3addr, ":", POP3port);

      try
        {
          d.POP3_server = std::make_unique<bote::pop3::POP3>(POP3addr, POP3port);
          d.POP3_server->start();
        }
      catch (std::exception &ex)
        {
          LogPrint(eLogError, "Daemon: Failed to start POP3 server: ",
                   ex.what());
          ThrowFatal("Unable to start POP3 server at ",
                     POP3addr, ":", POP3port, ": ", ex.what());
        }
    }

  LogPrint(eLogInfo, "Daemon: Started");

  return EXIT_SUCCESS;
}

bool
Daemon_Singleton::stop()
{
  LogPrint(eLogInfo, "Daemon: Start shutting down");

  /* First we need to stop easy stopable stuff */
  if (d.SMTP_server)
    {
      LogPrint(eLogInfo, "Daemon: Stopping SMTP server");
      d.SMTP_server->stop();
      d.SMTP_server = nullptr;
      LogPrint(eLogInfo, "Daemon: SMTP server stopped");
    }

  if (d.POP3_server)
    {
      LogPrint(eLogInfo, "Daemon: Stopping POP3 server");
      d.POP3_server->stop();
      d.POP3_server = nullptr;
      LogPrint(eLogInfo, "Daemon: POP3 server stopped");
    }

  if (d.control_server)
    {
      LogPrint(eLogInfo, "Daemon: Stopping control socket");
      d.control_server->stop();
      d.control_server = nullptr;
      LogPrint(eLogInfo, "Daemon: Control socket stopped");
    }

  /* Next we need to stop main network stuff */
  LogPrint(eLogInfo, "Daemon: Stopping packet handler");
  bote::packet_handler.stop();
  LogPrint(eLogInfo, "Daemon: Packet handler stopped");

  LogPrint(eLogInfo, "Daemon: Stopping network worker");
  bote::network_worker.stop();
  LogPrint(eLogInfo, "Daemon: Network worker stopped");

  /* And last we stop bote stuff */
  LogPrint(eLogInfo, "Daemon: Stopping DHT worker");
  bote::DHT_worker.stop();
  LogPrint(eLogInfo, "Daemon: DHT worker stopped");

  LogPrint(eLogInfo, "Daemon: Stopping relay worker");
  bote::relay_worker.stop();
  LogPrint(eLogInfo, "Daemon: Relay worker stopped");

  LogPrint(eLogInfo, "Daemon: Stopping Email worker");
  bote::email_worker.stop();
  LogPrint(eLogInfo, "Daemon: Email worker stopped");

  LogPrint(eLogInfo, "Daemon: Stopped");

  bote::log::Logger().Stop();

  return true;
}

} // namespace bote
