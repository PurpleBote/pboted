/**
 * Copyright (c) 2019-2021 polistern
 */

#include <cstring>
#include <fstream>
#include <iterator>

#include "DHTStorage.h"

namespace pbote {
namespace kademlia {

void DHTStorage::update() {
  loadLocalIndexPackets();
  loadLocalEmailPackets();
  loadLocalContactPackets();

  LogPrint(eLogDebug, "DHTStorage: loaded index: ", local_index_packets.size(),
           ", emails: ", local_email_packets.size(), ", contacts: ", local_contact_packets.size());
}

bool DHTStorage::safe(std::vector<uint8_t> data) {
  uint8_t dataType = data[0];
  bool success = false;
  uint8_t key[32];
  memcpy(key, data.data() + 2, 32);
  i2p::data::Tag<32> dht_key(key);

  switch (dataType) {
    case ((uint8_t) 'I'):
      success = safeIndex(dht_key, data);
      break;
    case ((uint8_t) 'E'):
      success = safeEmail(dht_key, data);
      break;
    case ((uint8_t) 'C'):
      success = safeContact(dht_key, data);
      break;
    default:
      break;
  }

  update();
  return success;
}

bool DHTStorage::deleteIndex(i2p::data::Tag<32> key) {
  if(exist(pbote::type::DataI, key)) {
    return true;
  }
  return false;
}

bool DHTStorage::deleteEmail(i2p::data::Tag<32> key) {
  if(exist(pbote::type::DataE, key)) {
    return true;
  }
  return false;
}

std::vector<uint8_t> DHTStorage::getIndex(i2p::data::Tag<32> key) {
  if(exist(pbote::type::DataI, key)) {
    return getPacket(pbote::type::DataI, key);
  }
  return {};
}

std::vector<uint8_t> DHTStorage::getEmail(i2p::data::Tag<32> key) {
  if(exist(pbote::type::DataE, key)) {
    return getPacket(pbote::type::DataE, key);
  }
  return {};
}

std::vector<uint8_t> DHTStorage::getContact(i2p::data::Tag<32> key) {
  if(exist(pbote::type::DataC, key)) {
    return getPacket(pbote::type::DataC, key);
  }
  return {};
}

std::vector<uint8_t> DHTStorage::getPacket(pbote::type type, i2p::data::Tag<32> key) {
  std::string dir_path;
  std::vector<std::string> local_list;

  switch(type) {
    case pbote::type::DataI:
      dir_path = pbote::fs::DataDirPath("DHTindex");
      local_list = local_index_packets;
      break;
    case pbote::type::DataE:
      dir_path = pbote::fs::DataDirPath("DHTemail");
      local_list = local_email_packets;
      break;
    case pbote::type::DataC:
      dir_path = pbote::fs::DataDirPath("DHTdirectory");
      local_list = local_contact_packets;
      break;
    default:
      return {};
  }

  if (!local_list.empty()) {
    LogPrint(eLogDebug, "DHTStorage: getPacket: try to find packet");
    for (const auto& filename : local_list) {
      i2p::data::Tag<32> filekey = {};
      filekey.FromBase64(filename);
      if ( filekey == key) {
        LogPrint(eLogDebug, "DHTStorage: getPacket: found packet with key: ", key.ToBase64());

        std::string filepath(dir_path);
        filepath.append("/");
        filepath.append(filename);
        filepath.append(DEFAULT_FILE_EXTENSION);

        std::ifstream file(filepath, std::ios::binary);

        if (!file.is_open()) {
          LogPrint(eLogError, "DHTStorage: getPacket: can't open file ", filepath);
          return {};
        }

        std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(file)), (std::istreambuf_iterator<char>()));
        file.close();

        return bytes;
      }
    }
    LogPrint(eLogWarning, "DHTStorage: getPacket: have no file with key: ", key.ToBase64());
    return {};
  } else {
    LogPrint(eLogWarning, "DHTStorage: getPacket: have no files for search");
    return {};
  }
}

bool DHTStorage::exist(pbote::type type, i2p::data::Tag<32> key) {
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

bool DHTStorage::find(const std::vector<std::string>& list, i2p::data::Tag<32> key) {
  if(std::any_of(list.cbegin(), list.cend(), [key](const std::string& y) { return memcmp(y.data(), key.data(), 32); }))
    return true;
  return false;
}

bool DHTStorage::safeIndex(i2p::data::Tag<32> key, std::vector<uint8_t> data) {
  std::string packetPath = pbote::fs::DataDirPath("DHTindex", key.ToBase64() + ".dat");

  if (pbote::fs::Exists(packetPath)) {
    LogPrint(eLogDebug, "DHTStorage: safeIndex: packet already exist: ", packetPath);
    return false;
  }

  LogPrint(eLogDebug, "DHTStorage: safeIndex: save packet to ", packetPath);
  std::ofstream file(packetPath, std::ofstream::binary | std::ofstream::out);
  if (!file.is_open()) {
    LogPrint(eLogError, "DHTStorage: safeIndex: can't open file ", packetPath);
    return false;
  }

  std::ostream_iterator<uint8_t> output_iterator(file, "\n");
  std::copy(data.begin(), data.end(), output_iterator);

  file.close();
  return true;
}

bool DHTStorage::safeEmail(i2p::data::Tag<32> key, std::vector<uint8_t> data) {
  std::string packetPath = pbote::fs::DataDirPath("DHTemail", key.ToBase64() + ".dat");

  if (pbote::fs::Exists(packetPath)) {
    LogPrint(eLogDebug, "DHTStorage: safeEmail: packet already exist: ", packetPath);
    return false;
  }

  LogPrint(eLogDebug, "DHTStorage: safeEmail: save packet to ", packetPath);
  std::ofstream file(packetPath, std::ofstream::binary | std::ofstream::out);
  if (!file.is_open()) {
    LogPrint(eLogError, "DHTStorage: safeEmail: can't open file ", packetPath);
    return false;
  }

  std::ostream_iterator<uint8_t> output_iterator(file, "\n");
  std::copy(data.begin(), data.end(), output_iterator);

  file.close();
  return true;
}

bool DHTStorage::safeContact(i2p::data::Tag<32> key, std::vector<uint8_t> data) {
  std::string packetPath = pbote::fs::DataDirPath("DHTdirectory", key.ToBase64() + ".dat");

  if (pbote::fs::Exists(packetPath)) {
    LogPrint(eLogDebug, "DHTStorage: safeContact: packet already exist: ", packetPath);
    return false;
  }

  LogPrint(eLogDebug, "DHTStorage: safeContact: save packet to ", packetPath);
  std::ofstream file(packetPath, std::ofstream::binary | std::ofstream::out);
  if (!file.is_open()) {
    LogPrint(eLogError, "DHTStorage: safeContact: can't open file ", packetPath);
    return false;
  }

  std::ostream_iterator<uint8_t> output_iterator(file, "\n");
  std::copy(data.begin(), data.end(), output_iterator);

  file.close();
  return true;
}

void DHTStorage::loadLocalIndexPackets() {
  local_index_packets = std::vector<std::string>();
  std::string indexPacketPath = pbote::fs::DataDirPath("DHTindex");
  std::vector<std::string> packets_path;
  auto result = pbote::fs::ReadDir(indexPacketPath, packets_path);
  if (result) {
    for (const auto &path : packets_path) {
      auto filename = remove_extension(base_name(path));
      local_index_packets.push_back(filename);
    }

    LogPrint(eLogDebug, "DHTStorage: loadLocalIndexPackets: index loaded: ", local_index_packets.size());
  } else {
    LogPrint(eLogWarning, "DHTStorage: loadLocalIndexPackets: have no index files");
  }
}

void DHTStorage::loadLocalEmailPackets() {
  local_email_packets = std::vector<std::string>();
  std::string email_packet_path = pbote::fs::DataDirPath("DHTemail");
  std::vector<std::string> packets_path;
  auto result = pbote::fs::ReadDir(email_packet_path, packets_path);
  if (result) {
    for (const auto &path : packets_path) {
      auto filename = remove_extension(base_name(path));
      local_email_packets.push_back(filename);
    }

    LogPrint(eLogDebug, "DHTStorage: loadLocalEmailPackets: mails loaded: ", local_email_packets.size());
  } else {
    LogPrint(eLogWarning, "DHTStorage: loadLocalEmailPackets: have no mail files");
  }
}

void DHTStorage::loadLocalContactPackets() {
  local_contact_packets = std::vector<std::string>();
  std::string email_packet_path = pbote::fs::DataDirPath("DHTdirectory");
  std::vector<std::string> packets_path;
  auto result = pbote::fs::ReadDir(email_packet_path, packets_path);
  if (result) {
    for (const auto &path : packets_path) {
      auto filename = remove_extension(base_name(path));
      local_contact_packets.push_back(filename);
    }

    LogPrint(eLogDebug, "DHTStorage: loadLocalContactPackets: contacts loaded: ", local_contact_packets.size());
  } else {
    LogPrint(eLogWarning, "DHTStorage: loadLocalContactPackets: have no contact files");
  }
}

} // kademlia
} // pbote
