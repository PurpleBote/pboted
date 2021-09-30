/**
 * Copyright (c) 2019-2021 polistern
 */

#include <cstring>

#include "DHTStorage.h"

namespace pbote {
namespace kademlia {

void DHTStorage::update() {
  loadLocalIndexPackets();
  loadLocalEmailPackets();
  loadLocalContactPackets();
}

void DHTStorage::safe(uint8_t* key, std::vector<uint8_t> data) {

  update();
}

bool DHTStorage::deleteIndex(uint8_t* key) {
  if(exist(pbote::type::DataI, key)) {

  }
  return false;
}

bool DHTStorage::deleteEmail(uint8_t* key) {
  if(exist(pbote::type::DataE, key)) {

  }
  return false;
}

std::vector<uint8_t> DHTStorage::getIndex(uint8_t* key) {
  if(exist(pbote::type::DataI, key)) {
    return getPacket(pbote::type::DataI, key);
  }
  return {};
}

std::vector<uint8_t> DHTStorage::getEmail(uint8_t* key) {
  if(exist(pbote::type::DataE, key)) {
    return getPacket(pbote::type::DataE, key);
  }
  return {};
}

std::vector<uint8_t> DHTStorage::getContact(uint8_t* key) {
  if(exist(pbote::type::DataC, key)) {
    return getPacket(pbote::type::DataC, key);
  }
  return {};
}

std::vector<uint8_t> DHTStorage::getPacket(pbote::type type, uint8_t* key) {
  std::string packet_path;

  switch(type) {
    case pbote::type::DataI:
      packet_path = pbote::fs::DataDirPath("DHTindex");
      break;
    case pbote::type::DataE:
      packet_path = pbote::fs::DataDirPath("DHTemail");
      break;
    case pbote::type::DataC:
      packet_path = pbote::fs::DataDirPath("DHTdirectory");
      break;
    default:
      return {};
  }

  i2p::data::Tag<32> t_key(key);
  std::vector<std::string> packets_path;
  auto result = pbote::fs::ReadDir(packet_path, packets_path);

  if (result) {
    LogPrint(eLogDebug, "DHTStorage: getPacket: packets paths:");
    for (const auto &path : packets_path) {
      LogPrint(eLogDebug, "DHTStorage: getPacket: ", path);
      //std::ifstream file(path, std::ios::binary);
      //std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(file)), (std::istreambuf_iterator<char>()));
      //file.close();
    }
    LogPrint(eLogDebug, "DHTStorage: getPacket: found packet with key: ", t_key.ToBase64());
    return {};
  } else {
    LogPrint(eLogWarning, "DHTStorage: getPacket: have no file with key: ", t_key.ToBase64());
    return {};
  }
}

bool DHTStorage::exist(pbote::type type, uint8_t* key) {
  switch(type) {
    case pbote::type::DataI:
      return find(local_index_packets, key);
    case pbote::type::DataE:
      return find(local_email_packets, key);
    case pbote::type::DataC:
      return find(local_contact_packets, key);
    default:
      return false;
  }
}

bool DHTStorage::find(const std::vector<std::string>& list, uint8_t* key) {
  //for (const auto& item : list) {
  //  if (memcmp(item.data(), key, 32))
  //    return true;
  //}

  if(std::any_of(list.cbegin(), list.cend(), [key](const std::string& y) { return memcmp(y.data(), key, 32); }))
    return true;
  return false;
}

void DHTStorage::safeIndex(uint8_t* key, std::vector<uint8_t> data) {

}

void DHTStorage::safeEmail(uint8_t* key, std::vector<uint8_t> data) {

}

void DHTStorage::safeContact(uint8_t* key, std::vector<uint8_t> data) {

}

void DHTStorage::loadLocalIndexPackets() {
  std::string indexPacketPath = pbote::fs::DataDirPath("DHTindex");
  std::vector<std::string> packets_path;
  auto result = pbote::fs::ReadDir(indexPacketPath, packets_path);
  if (result) {
    for (const auto &path : packets_path) {
      LogPrint(eLogDebug, "DHTStorage: loadLocalIndexPackets: ", path);
      local_index_packets.push_back(path);
    }

    LogPrint(eLogDebug, "DHTStorage: loadLocalIndexPackets: index loaded: ", local_index_packets.size());
  }
  LogPrint(eLogWarning, "DHTStorage: loadLocalIndexPackets: have no index files");
}

void DHTStorage::loadLocalEmailPackets() {
  std::string email_packet_path = pbote::fs::DataDirPath("DHTemail");
  std::vector<std::string> packets_path;
  auto result = pbote::fs::ReadDir(email_packet_path, packets_path);
  if (result) {
    for (const auto &path : packets_path) {
      LogPrint(eLogDebug, "DHTStorage: loadLocalEmailPackets: ", path);
      local_email_packets.push_back(path);
    }

    LogPrint(eLogDebug, "DHTStorage: loadLocalEmailPackets: mails loaded: ", local_email_packets.size());
  }
  LogPrint(eLogWarning, "DHTStorage: loadLocalEmailPackets: have no mail files");
}

void DHTStorage::loadLocalContactPackets() {
  std::string email_packet_path = pbote::fs::DataDirPath("DHTdirectory");
  std::vector<std::string> packets_path;
  auto result = pbote::fs::ReadDir(email_packet_path, packets_path);
  if (result) {
    for (const auto &path : packets_path) {
      LogPrint(eLogDebug, "DHTStorage: loadLocalContactPackets: ", path);
      local_contact_packets.push_back(path);
    }

    LogPrint(eLogDebug, "DHTStorage: loadLocalContactPackets: contacts loaded: ", local_contact_packets.size());
  }
  LogPrint(eLogWarning, "DHTStorage: loadLocalContactPackets: have no contact files");
}

}
}
