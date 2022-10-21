/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <memory>

#include "BoteContext.h"
#include "BoteControl.h"
#include "BoteDaemon.h"
#include "ConfigParser.h"
#include "DHTworker.h"
#include "EmailWorker.h"
#include "FileSystem.h"
#include "Logging.h"
#include "POP3.h"
#include "RelayWorker.h"
#include "SMTP.h"
#include "version.h"

namespace pbote
{
namespace util
{

class Daemon_Singleton::Daemon_Singleton_Private
{
 public:
  Daemon_Singleton_Private() {};
  ~Daemon_Singleton_Private() {};

  std::unique_ptr<bote::smtp::SMTP> SMTPserver;
  std::unique_ptr<bote::pop3::POP3> POP3server;
  std::unique_ptr<bote::BoteControl> control_server;
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
  pbote::config::GetOption("service", service);
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
  pbote::config::Init();
  pbote::config::ParseCmdline(argc, argv);

  std::string config;
  pbote::config::GetOption("conf", config);
  std::string datadir;
  pbote::config::GetOption("datadir", datadir);
  pbote::fs::DetectDataDir(datadir, IsService());
  pbote::fs::Init();

  datadir = pbote::fs::GetDataDir();
  if (config.empty())
    {
      config = pbote::fs::DataDirPath("pboted.conf");
      if (!pbote::fs::Exists(config))
        config = "";
    }

  pbote::config::ParseConfig(config);
  pbote::config::Finalize();

  pbote::config::GetOption("daemon", isDaemon);

  std::string logs;
  pbote::config::GetOption("log", logs);
  std::string logfile;
  pbote::config::GetOption("logfile", logfile);
  std::string loglevel;
  pbote::config::GetOption("loglevel", loglevel);
  bool logclftime;
  pbote::config::GetOption("logclftime", logclftime);

  // Setup logging
  if (logclftime)
    pbote::log::Logger().SetTimeFormat("[%d/%b/%Y:%H:%M:%S %z]");

  if (isDaemon &&(logs.empty() || logs == "stdout"))
    logs = "file";

  pbote::log::Logger().SetLogLevel(loglevel);
  if (logstream)
    {
      LogPrint(eLogInfo, "Log: Will send messages to std::ostream");
      pbote::log::Logger().SendTo(logstream);
    }
  else if (logs == "file")
    {
      if (logfile.empty())
        logfile = pbote::fs::DataDirPath("pboted.log");
      LogPrint(eLogInfo, "Log: Will send messages to ", logfile);
      pbote::log::Logger().SendTo(logfile);
    }
  else if (logs == "syslog")
    {
      LogPrint(eLogInfo, "Log: Will send messages to syslog");
      pbote::log::Logger().SendTo("pboted", LOG_DAEMON);
    }
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

  LogPrint(eLogInfo, "Daemon: Init context");
  pbote::context.init();

  LogPrint(eLogInfo, "Daemon: Init network");
  pbote::network::network_worker.init();

  LogPrint(eLogDebug, "Daemon: Init done");
  return true;
}

int
Daemon_Singleton::start()
{
  LogPrint(eLogDebug, "Daemon: Start services");
  pbote::log::Logger().Start();

  LogPrint(eLogInfo, "Daemon: Starting network worker");
  pbote::network::network_worker.start();

  LogPrint(eLogInfo, "Daemon: Starting relay");
  pbote::relay::relay_worker.start();

  LogPrint(eLogInfo, "Daemon: Starting DHT");
  pbote::kademlia::DHT_worker.start();

  LogPrint(eLogInfo, "Daemon: Starting packet handler");
  pbote::packet::packet_handler.start();

  LogPrint(eLogInfo, "Daemon: Starting Email");
  pbote::kademlia::email_worker.start();

  bool control = false;
  pbote::config::GetOption("control.enabled", control);
  if (control)
    {
      LogPrint(eLogInfo, "Daemon: Starting control socket");
      d.control_server = std::make_unique<bote::BoteControl>();
      d.control_server->start();
    }

  bool smtp = false;
  pbote::config::GetOption("smtp.enabled", smtp);
  if (smtp)
    {
      std::string SMTPaddr;
      uint16_t SMTPport;
      pbote::config::GetOption("smtp.address", SMTPaddr);
      pbote::config::GetOption("smtp.port", SMTPport);
      LogPrint(eLogInfo, "Daemon: Starting SMTP server at ",
               SMTPaddr, ":", SMTPport);

      try
        {
          d.SMTPserver = std::make_unique<bote::smtp::SMTP>(SMTPaddr, SMTPport);
          d.SMTPserver->start();
        }
      catch (std::exception &ex)
        {
          LogPrint(eLogError, "Daemon: Failed to start SMTP server: ",
                   ex.what());
          ThrowFatal("Unable to start SMTP server at ",
                     SMTPaddr, ":", SMTPport, ": ", ex.what());
        }
    }

  bool pop3 = false;
  pbote::config::GetOption("pop3.enabled", pop3);
  if (pop3)
    {
      std::string POP3addr;
      uint16_t POP3port;
      pbote::config::GetOption("pop3.address", POP3addr);
      pbote::config::GetOption("pop3.port", POP3port);
      LogPrint(eLogInfo, "Daemon: Starting POP3 server at ",
               POP3addr, ":", POP3port);

      try
        {
          d.POP3server = std::make_unique<bote::pop3::POP3>(POP3addr, POP3port);
          d.POP3server->start();
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
  if (d.SMTPserver)
    {
      LogPrint(eLogInfo, "Daemon: Stopping SMTP server");
      d.SMTPserver->stop();
      d.SMTPserver = nullptr;
      LogPrint(eLogInfo, "Daemon: SMTP server stopped");
    }

  if (d.POP3server)
    {
      LogPrint(eLogInfo, "Daemon: Stopping POP3 server");
      d.POP3server->stop();
      d.POP3server = nullptr;
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
  pbote::packet::packet_handler.stop();
  LogPrint(eLogInfo, "Daemon: Packet handler stopped");

  LogPrint(eLogInfo, "Daemon: Stopping network worker");
  pbote::network::network_worker.stop();
  LogPrint(eLogInfo, "Daemon: Network worker stopped");

  /* And last we stop bote stuff */
  LogPrint(eLogInfo, "Daemon: Stopping DHT worker");
  pbote::kademlia::DHT_worker.stop();
  LogPrint(eLogInfo, "Daemon: DHT worker stopped");

  LogPrint(eLogInfo, "Daemon: Stopping relay worker");
  pbote::relay::relay_worker.stop();
  LogPrint(eLogInfo, "Daemon: Relay worker stopped");

  LogPrint(eLogInfo, "Daemon: Stopping Email worker");
  pbote::kademlia::email_worker.stop();
  LogPrint(eLogInfo, "Daemon: Email worker stopped");

  LogPrint(eLogInfo, "Daemon: Stopped");

  pbote::log::Logger().Stop();

  return true;
}

} // namespace util
} // namespace pbote
