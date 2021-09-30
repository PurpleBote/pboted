/**
 * Copyright (c) 2019-2020 polistern
 */

#include "BoteContext.h"
#include "ConfigParser.h"
#include "Daemon.h"
#include "DHTworker.h"
#include "EmailWorker.h"
#include "FS.h"
#include "Log.h"
#include "RelayPeersWorker.h"
#include "version.h"

namespace pbote {
namespace util {
class Daemon_Singleton::Daemon_Singleton_Private {
 public:
  Daemon_Singleton_Private() {};
  ~Daemon_Singleton_Private() {};
};

Daemon_Singleton::Daemon_Singleton()
    : isDaemon(false), running(true), d(*new Daemon_Singleton_Private()) {}
Daemon_Singleton::~Daemon_Singleton() { delete &d; }

bool Daemon_Singleton::IsService() const {
  bool service = false;
  return service;
}

bool Daemon_Singleton::init(int argc, char *argv[]) {
  return init(argc, argv, nullptr);
}

bool Daemon_Singleton::init(int argc, char *argv[],
                            std::shared_ptr<std::ostream> logstream) {
  pbote::config::Init();
  pbote::config::ParseCmdline(argc, argv);

  std::string config;
  pbote::config::GetOption("conf", config);
  std::string datadir;
  pbote::config::GetOption("datadir", datadir);
  pbote::fs::DetectDataDir(datadir, IsService());
  pbote::fs::Init();

  datadir = pbote::fs::GetDataDir();
  if (config == "") {
    config = pbote::fs::DataDirPath("pbote.conf");
    if (!pbote::fs::Exists(config))
      config = "";
  }

  pbote::config::ParseConfig(config);
  pbote::config::Finalize();

  pbote::config::GetOption("daemon", isDaemon);

  std::string logs = "";
  pbote::config::GetOption("log", logs);
  std::string logfile = "";
  pbote::config::GetOption("logfile", logfile);
  std::string loglevel = "";
  pbote::config::GetOption("loglevel", loglevel);
  bool logclftime;
  pbote::config::GetOption("logclftime", logclftime);

  /* setup logging */
  if (logclftime)
    pbote::log::Logger().SetTimeFormat("[%d/%b/%Y:%H:%M:%S %z]");

  if (isDaemon && (logs == "" || logs == "stdout"))
    logs = "file";

  pbote::log::Logger().SetLogLevel(loglevel);
  if (logstream) {
    LogPrint(eLogInfo, "Log: will send messages to std::ostream");
    pbote::log::Logger().SendTo(logstream);
  } else if (logs == "file") {
    if (logfile == "")
      logfile = pbote::fs::DataDirPath("pbote.log");
    LogPrint(eLogInfo, "Log: will send messages to ", logfile);
    pbote::log::Logger().SendTo(logfile);
  } else {
    // use stdout -- default
  }

  LogPrint(eLogInfo, "pBote v", VERSION, " starting");
  LogPrint(eLogDebug, "FS: data directory: ", datadir);
  LogPrint(eLogDebug, "FS: main config file: ", config);

  LogPrint(eLogInfo, "Daemon: load context");
  pbote::context.init();

  LogPrint(eLogInfo, "Daemon: setup network");
  pbote::network::worker.init();

  /*bool ipv6;
  pbote::config::GetOption("ipv6", ipv6);
  bool ipv4;
  pbote::config::GetOption("ipv4", ipv4);*/
  /*#ifdef MESHNET
                  // manual override for meshnet
                  ipv4 = false;
                  ipv6 = true;
#endif*/
  /*uint16_t port;
  pbote::config::GetOption("port", port);
  if (!pbote::config::IsDefault("port")) {
    LogPrint(eLogInfo, "Daemon: accepting incoming connections at port ", port);
    pbote::context.UpdatePort (port);
  }*/
  // pbote::context.SetSupportsV6		 (ipv6);
  // pbote::context.SetSupportsV4		 (ipv4);

  /*bool ntcp;   pbote::config::GetOption("ntcp", ntcp);
  pbote::context.PublishNTCPAddress (ntcp, !ipv6);
  bool ntcp2; pbote::config::GetOption("ntcp2.enabled", ntcp2);
  if (ntcp2)
  {
  bool published;
  pbote::config::GetOption("ntcp2.published", published);
   if (published)
  {
    uint16_t ntcp2port;
    pbote::config::GetOption("ntcp2.port", ntcp2port); if (!ntcp && !ntcp2port)
     ntcp2port = port; // use standard port pbote::context.PublishNTCP2Address
     (ntcp2port, true); // publish
     if (ipv6)
  {
  std::string ipv6Addr;
     pbote::config::GetOption("ntcp2.addressv6", ipv6Addr); auto addr =
     boost::asio::ip::address_v6::from_string (ipv6Addr); if
     (!addr.is_unspecified () && addr != boost::asio::ip::address_v6::any ())
  pbote::context.UpdateNTCP2V6Address(addr); // set ipv6 address if configured
  }
  }
  else
  pbote::context.PublishNTCP2Address (port, false); // unpublish
  }*/

  /*bool transit; pbote::config::GetOption("notransit", transit);
                  pbote::context.SetAcceptsTunnels (!transit);
                  uint16_t transitTunnels;
     pbote::config::GetOption("limits.transittunnels", transitTunnels);
                  SetMaxNumTransitTunnels (transitTunnels);

                  bool isFloodfill; pbote::config::GetOption("floodfill",
     isFloodfill); if (isFloodfill) { LogPrint(eLogInfo, "Daemon: router will be
     floodfill"); i2p::context.SetFloodfill (true); }	else {
                          i2p::context.SetFloodfill (false);
                  }*/

  /// this section also honors 'floodfill' flag, if set above
  /*std::string bandwidth; i2p::config::GetOption("bandwidth", bandwidth);
                  if (bandwidth.length () > 0)
                  {
                          if (bandwidth[0] >= 'K' && bandwidth[0] <= 'X')
                          {
                                  i2p::context.SetBandwidth (bandwidth[0]);
                                  LogPrint(eLogInfo, "Daemon: bandwidth set to
     ", i2p::context.GetBandwidthLimit (), "KBps");
                          }
                          else
                          {
                                  auto value = std::atoi(bandwidth.c_str());
                                  if (value > 0)
                                  {
                                          i2p::context.SetBandwidth (value);
                                          LogPrint(eLogInfo, "Daemon: bandwidth
     set to ", i2p::context.GetBandwidthLimit (), " KBps");
                                  }
                                  else
                                  {
                                          LogPrint(eLogInfo, "Daemon: unexpected
     bandwidth ", bandwidth, ". Set to 'low'"); i2p::context.SetBandwidth
     (i2p::data::CAPS_FLAG_LOW_BANDWIDTH2);
                                  }
                          }
                  }
                  else if (isFloodfill)
                  {
                          LogPrint(eLogInfo, "Daemon: floodfill bandwidth set to
     'extra'"); i2p::context.SetBandwidth
     (i2p::data::CAPS_FLAG_EXTRA_BANDWIDTH1);
                  }
                  else
                  {
                          LogPrint(eLogInfo, "Daemon: bandwidth set to 'low'");
                          i2p::context.SetBandwidth
     (i2p::data::CAPS_FLAG_LOW_BANDWIDTH2);
                  }*/

  /*int shareRatio; i2p::config::GetOption("share", shareRatio);
                  i2p::context.SetShareRatio (shareRatio);*/

  /*std::string family; i2p::config::GetOption("family", family);
                  i2p::context.SetFamily (family);
                  if (family.length () > 0)
                          LogPrint(eLogInfo, "Daemon: family set to ",
     family);*/

  /*bool trust; i2p::config::GetOption("trust.enabled", trust);
      if (trust)
      {
          LogPrint(eLogInfo, "Daemon: explicit trust enabled");
          std::string fam; i2p::config::GetOption("trust.family", fam);
                          std::string routers;
     i2p::config::GetOption("trust.routers", routers); bool restricted = false;
          if (fam.length() > 0)
          {
                                  std::set<std::string> fams;
                                  size_t pos = 0, comma;
                                  do
                                  {
                                          comma = fam.find (',', pos);
                                          fams.insert (fam.substr (pos, comma !=
     std::string::npos ? comma - pos : std::string::npos)); pos = comma + 1;
                                  }
                                  while (comma != std::string::npos);
                                  i2p::transport::transports.RestrictRoutesToFamilies(fams);
                                  restricted  = fams.size() > 0;
          }
                          if (routers.length() > 0) {
                                  std::set<i2p::data::IdentHash> idents;
                                  size_t pos = 0, comma;
                                  do
                                  {
                                          comma = routers.find (',', pos);
                                          i2p::data::IdentHash ident;
                                          ident.FromBase64 (routers.substr (pos,
     comma != std::string::npos ? comma - pos : std::string::npos));
                                          idents.insert (ident);
                                          pos = comma + 1;
                                  }
                                  while (comma != std::string::npos);
                                  LogPrint(eLogInfo, "Daemon: setting restricted
     routes to use ", idents.size(), " trusted routers");
                                  i2p::transport::transports.RestrictRoutesToRouters(idents);
                                  restricted = idents.size() > 0;
                          }
                          if(!restricted)
                                  LogPrint(eLogError, "Daemon: no trusted
     routers of families specififed");
      }*/
  /*bool hidden; i2p::config::GetOption("trust.hidden", hidden);
      if (hidden)
      {
          LogPrint(eLogInfo, "Daemon: using hidden mode");
          i2p::data::netdb.SetHidden(true);
      }*/
  // std::cout << "Daemon_Singleton::init Done" << std::endl;
  return true;
}

bool Daemon_Singleton::start() {
  pbote::log::Logger().Start();

  LogPrint(eLogInfo, "Daemon: starting network worker");
  pbote::network::worker.start();

  LogPrint(eLogInfo, "Daemon: starting packet handler");
  pbote::packet::handler.start();

  LogPrint(eLogInfo, "Daemon: starting relay peers");
  pbote::relay::relay_peers_worker.start();

  LogPrint(eLogInfo, "Daemon: starting DHT");
  pbote::kademlia::DHT_worker.start();

  LogPrint(eLogInfo, "Daemon: starting Email");
  pbote::kademlia::email_worker.start();

  /** shut down netdb right away */
  /*pbote::transport::transports.Stop();
                          pbote::data::netdb.Stop();
                          return false;
                  }*/

  /*bool http; pbote::config::GetOption("http.enabled", http);
                  if (http) {
                          std::string httpAddr;
     pbote::config::GetOption("http.address", httpAddr); uint16_t
     httpPort; pbote::config::GetOption("http.port",		 httpPort);
                          LogPrint(eLogInfo, "Daemon: starting HTTP Server at ",
     httpAddr, ":", httpPort); d.httpServer =
     std::unique_ptr<pbote::http::HTTPServer>(new
     pbote::http::HTTPServer(httpAddr, httpPort)); d.httpServer->Start();
                  }*/

  /*LogPrint(eLogInfo, "Daemon: starting Tunnels");
                  pbote::tunnel::tunnels.Start();*/

  /*LogPrint(eLogInfo, "Daemon: starting Client");
                  pbote::client::context.Start ();*/

  return true;
}

bool Daemon_Singleton::stop() {
  /*#ifdef WITH_EVENTS
                  i2p::event::core.SetListener(nullptr);
#endif*/
  LogPrint(eLogInfo, "Daemon: shutting down");
  /*LogPrint(eLogInfo, "Daemon: stopping Client");
                  pbote::client::context.Stop();
                  LogPrint(eLogInfo, "Daemon: stopping Tunnels");
                  pbote::tunnel::tunnels.Stop();*/

  /*if (d.UPnP)
                  {
                          d.UPnP->Stop ();
                          d.UPnP = nullptr;
                  }

                  if (d.m_NTPSync)
                  {
                          d.m_NTPSync->Stop ();
                          d.m_NTPSync = nullptr;
                  }*/

  /*LogPrint(eLogInfo, "Daemon: stopping Transports");
                  pbote::transport::transports.Stop();*/
  /*LogPrint(eLogInfo, "Daemon: stopping NetDB");
                  pbote::data::netdb.Stop();*/
  /*if (d.httpServer) {
                          LogPrint(eLogInfo, "Daemon: stopping HTTP Server");
                          d.httpServer->Stop();
                          d.httpServer = nullptr;
                  }
                  if (d.m_I2PControlService)
                  {
                          LogPrint(eLogInfo, "Daemon: stopping I2PControl");
                          d.m_I2PControlService->Stop ();
                          d.m_I2PControlService = nullptr;
                  }*/
  /*#ifdef WITH_EVENTS
                  if (d.m_WebsocketServer) {
                          LogPrint(eLogInfo, "Daemon: stopping Websocket
server"); d.m_WebsocketServer->Stop(); d.m_WebsocketServer = nullptr;
                  }
#endif*/
  // pbote::crypto::TerminateCrypto ();
  pbote::log::Logger().Stop();

  return true;
}
} // namespace util
} // namespace pbote
