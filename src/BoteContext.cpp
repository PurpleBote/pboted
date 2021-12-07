/**
 * Copyright (c) 2019-2021 polistern
 */

#include <utility>

#include "BoteContext.h"

namespace pbote {

BoteContext context;

BoteContext::BoteContext()
    : keys_loaded_(false),
      listenPortSAM(0),
      routerPortTCP(0),
      routerPortUDP(0),
      bytes_recv_(0),
      bytes_sent_(0),
      m_recvQueue(std::make_shared<pbote::util::Queue<std::shared_ptr<PacketForQueue>>>()),
      m_sendQueue(std::make_shared<pbote::util::Queue<std::shared_ptr<PacketForQueue>>>()),
      localDestination(std::make_shared<i2p::data::IdentityEx>()),
      local_keys_(std::make_shared<i2p::data::PrivateKeys>()) {
  start_time_ = std::chrono::system_clock::now().time_since_epoch().count();
  //identities_storage_.init();
  std::chrono::high_resolution_clock::duration
      d = std::chrono::high_resolution_clock::now() - std::chrono::high_resolution_clock::now();
  unsigned seed2 = d.count();
  rbe.seed(seed2);
}

BoteContext::~BoteContext() {
  m_recvQueue = nullptr;
  m_sendQueue = nullptr;
}

void BoteContext::init() {
  pbote::config::GetOption("host", listenHost);
  pbote::config::GetOption("port", listenPortSAM);

  pbote::config::GetOption("sam.name", nickname);

  pbote::config::GetOption("sam.address", routerHost);
  pbote::config::GetOption("sam.tcp", routerPortTCP);
  pbote::config::GetOption("sam.udp", routerPortUDP);

  LogPrint(eLogInfo, "Context: config loaded");

  std::string localDestinationPath = pbote::fs::DataDirPath("destination.key");
  int size = readLocalIdentity(localDestinationPath);
  if (size > 0) {
    keys_loaded_ = true;
    LogPrint(eLogInfo, "Context: Local destination loaded successfully");
    LogPrint(eLogDebug, "Context: localDestination: ", local_keys_->ToBase64());
  } else {
    keys_loaded_ = false;
    LogPrint(eLogWarning, "Context: Can't find local destination, try to create");
  }
  identities_storage_ = new pbote::identitiesStorage();
  identities_storage_->init();

  auto ident_test = identities_storage_->getIdentities();
  LogPrint(eLogInfo, "Context: Loaded identities: ", ident_test.size());

  address_book_.load();
  LogPrint(eLogInfo, "Context: Loaded contacts: ", address_book_.size());
}

void BoteContext::send(const PacketForQueue &packet) {
  m_sendQueue->Put(std::make_shared<PacketForQueue>(packet));
}

void BoteContext::send(const std::shared_ptr<PacketBatch<pbote::CommunicationPacket>>& batch) {
  size_t count = 0;
  runningBatches.push_back(batch);
  auto packets = batch->getPackets();
  for (const auto& packet: packets) {
    send(packet.second);
    count++;
  }
  LogPrint(eLogDebug, "Context: send ", count, " packets from batch ", batch->owner);
}

bool BoteContext::receive(const std::shared_ptr<pbote::CommunicationPacket>& packet) {
  std::vector<uint8_t> v_cid(packet->cid, packet->cid + 32);
  for (const auto& batch: runningBatches) {
    if (batch->contains(v_cid)) {
      batch->addResponse(packet);
      LogPrint(eLogDebug,
               "Context: response received for batch ",
               batch->owner,
               ", remain response count: ",
               batch->packetCount() - batch->responseCount());
      return true;
    }
  }
  return false;
}

void BoteContext::removeBatch(const std::shared_ptr<PacketBatch<pbote::CommunicationPacket>>& r_batch) {
  for (auto batch_it = runningBatches.begin(); batch_it != runningBatches.end(); batch_it++) {
    if (r_batch == *batch_it) {
      runningBatches.erase(batch_it);
      break;
    }
  }
}

std::shared_ptr<pbote::BoteIdentityFull> BoteContext::identityByName(const std::string &name) {
  // ToDo: well is it really better?
  //return std::find_if(email_identities.begin(), email_identities.end(), [&name](std::shared_ptr<pbote::EmailIdentityFull> i){ return i->publicName == name; }).operator*();

  for (auto identity : identities_storage_->getIdentities()) {
    LogPrint(eLogDebug, "BoteContext: identityByName: name: ", name,
             ", now: ", identity->publicName);
    if (identity->publicName == name)
      return identity;
  }
  return nullptr;
}

unsigned long BoteContext::get_uptime() {
  unsigned long raw_uptime = std::chrono::system_clock::now().time_since_epoch().count() - start_time_;
  return raw_uptime * std::chrono::system_clock::period::num / std::chrono::system_clock::period::den;
}

void BoteContext::save_new_keys(std::shared_ptr<i2p::data::PrivateKeys> localKeys) {
  local_keys_ = std::move(localKeys);
  if (!keys_loaded_)
    saveLocalIdentity(pbote::fs::DataDirPath("destination.key"));
}

int BoteContext::readLocalIdentity(const std::string &path) {
  LogPrint(eLogDebug, "Context: load destination from file ", path);
  std::ifstream f(path, std::ios::binary);
  if (!f) return -1;

  std::vector<unsigned char> bytes(
      (std::istreambuf_iterator<char>(f)),
      (std::istreambuf_iterator<char>()));

  f.close();
  local_keys_->FromBuffer(bytes.data(), bytes.size());
  localDestination = std::make_shared<i2p::data::IdentityEx>(*local_keys_->GetPublic());
  LogPrint(eLogDebug, "Context: localDestination.base64 ", localDestination->ToBase64());
  LogPrint(eLogDebug, "Context: localDestination.hash.base32 ", localDestination->GetIdentHash().ToBase32());
  return bytes.size();
}

void BoteContext::saveLocalIdentity(const std::string &path) {
  LogPrint(eLogDebug, "Context: save destination to file ", path);
  std::ofstream f(path, std::ofstream::binary | std::ofstream::out);
  if (!f.is_open()) {
    LogPrint(eLogError, "Context: can't open file ", path);
    return;
  }
  size_t len = local_keys_->GetFullLen();
  uint8_t *buf = new uint8_t[len];
  local_keys_->ToBuffer(buf, len);
  f.write((char *) buf, len);
  f.close();
  delete[] buf;
}

void BoteContext::random_cid(uint8_t *buf, size_t len) {
  std::vector<uint8_t> cid_data(len);
  std::generate(cid_data.begin(), cid_data.end(), std::ref(rbe));
  memcpy(buf, cid_data.data(), len);
}

} // namespace pbote