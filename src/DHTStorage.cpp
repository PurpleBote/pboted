/**
 * Copyright (C) 2019-2022 polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <boost/filesystem.hpp>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iterator>
#include <cstdio>

#include "ConfigParser.h"
#include "DHTStorage.h"

namespace pbote
{
namespace kademlia
{

void
DHTStorage::update ()
{
  loadLocalIndexPackets ();
  loadLocalEmailPackets ();
  loadLocalContactPackets ();

  update_storage_usage ();

  /// There is no need to check this too often
  if (update_counter > 20)
  {
    remove_old_packets ();
    update_counter = 0;

    LogPrint (eLogDebug, "DHTStorage: update: ",
             " index: ", local_index_packets.size (),
             ", emails: ", local_email_packets.size (),
             ", contacts: ", local_contact_packets.size ());
  }

  update_counter++;
}

int
DHTStorage::safe(const std::vector<uint8_t>& data)
{
  uint8_t dataType = data[0];
  int success = 0;
  uint8_t key[32];
  memcpy(key, data.data () + 2, 32);
  i2p::data::Tag<32> dht_key (key);

  switch (dataType) {
    case ((uint8_t) 'I'):
      success = safeIndex (dht_key, data);
      break;
    case ((uint8_t) 'E'):
      success = safeEmail (dht_key, data);
      break;
    case ((uint8_t) 'C'):
      success = safeContact (dht_key, data);
      break;
    default:
      break;
  }

  update ();
  return success;
}

bool
DHTStorage::deleteIndex(i2p::data::Tag<32> key)
{
  if(exist(pbote::type::DataI, key)) {
    std::string packet_path = pbote::fs::DataDirPath("DHTindex", key.ToBase64() + ".dat");

    int status = std::remove(packet_path.c_str());

    if (status == 0) {
      LogPrint(eLogInfo, "DHTStorage: deleteIndex: File ", packet_path, " removed");
      update_storage_usage();
      return true;
    } else {
      LogPrint(eLogError, "DHTStorage: deleteIndex: Can't remove file ", packet_path);
      return false;
    }
  }
  return false;
}

bool
DHTStorage::deleteEmail (i2p::data::Tag<32> key)
{
  if(exist(pbote::type::DataE, key))
    {
      std::string packet_path = pbote::fs::DataDirPath("DHTemail", key.ToBase64() + ".dat");

      int status = std::remove(packet_path.c_str());

      if (status == 0)
        {
          LogPrint(eLogInfo, "DHTStorage: deleteEmail: File ", packet_path, " removed");
          update_storage_usage();
          return true;
        }
      else
        {
          LogPrint(eLogError, "DHTStorage: deleteEmail: Can't remove file ", packet_path);
          return false;
        }
    }
  return false;
}

std::vector<uint8_t>
DHTStorage::getIndex(i2p::data::Tag<32> key)
{
  if(exist(pbote::type::DataI, key))
    {
      return getPacket(pbote::type::DataI, key);
    }
  return {};
}

std::vector<uint8_t>
DHTStorage::getEmail(i2p::data::Tag<32> key)
{
  if(exist(pbote::type::DataE, key))
    {
      return getPacket(pbote::type::DataE, key);
    }
  return {};
}

std::vector<uint8_t>
DHTStorage::getContact(i2p::data::Tag<32> key)
{
  if(exist(pbote::type::DataC, key))
    {
      return getPacket(pbote::type::DataC, key);
    }
  return {};
}

bool
DHTStorage::limit_reached(size_t data_size)
{
  LogPrint(eLogDebug, "DHTStorage: limit_reached: ",
           (limit < (used + data_size)) ? "true" : "false");
  return limit <= (used + data_size);
}

std::vector<uint8_t>
DHTStorage::getPacket(pbote::type type, i2p::data::Tag<32> key)
{
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

  if (!local_list.empty())
    {
      LogPrint(eLogDebug, "DHTStorage: getPacket: try to find packet");
      for (const auto& filename : local_list)
        {
          i2p::data::Tag<32> filekey = {};
          filekey.FromBase64(filename);
          if ( filekey == key)
            {
              LogPrint(eLogDebug, "DHTStorage: getPacket: found packet with key: ", key.ToBase64());

              std::string filepath(dir_path);
              filepath.append("/");
              filepath.append(filename);
              filepath.append(DEFAULT_FILE_EXTENSION);

              std::ifstream file(filepath, std::ios::binary);

              if (!file.is_open())
                {
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
    }
  else
    {
      LogPrint(eLogWarning, "DHTStorage: getPacket: have no files for search");
      return {};
    }
}

bool
DHTStorage::exist(pbote::type type, i2p::data::Tag<32> key)
{
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

bool
DHTStorage::find(const std::vector<std::string>& list, i2p::data::Tag<32> key)
{
  if(std::any_of(list.cbegin(), list.cend(), [key](const std::string& y) { return memcmp(y.data(), key.data(), 32); }))
    return true;
  return false;
}

int
DHTStorage::safeIndex(i2p::data::Tag<32> key, const std::vector<uint8_t>& data)
{
  std::string packetPath = pbote::fs::DataDirPath("DHTindex", key.ToBase64() + ".dat");

  if (pbote::fs::Exists(packetPath))
    {
      int status = update_index(key, data);
      if (status == STORE_FILE_EXIST)
        {
          LogPrint(eLogDebug, "DHTStorage: safeIndex: packet already exist: ", packetPath);
          return STORE_FILE_EXIST;
        }
      if (status == STORE_FILE_OPEN_ERROR)
        {
          LogPrint(eLogWarning, "DHTStorage: safeIndex: packet can't open file ", packetPath);
          return STORE_FILE_OPEN_ERROR;
        }
      LogPrint(eLogDebug, "DHTStorage: safeIndex: saved: ", packetPath);
      return STORE_SUCCESS;
    }

  LogPrint(eLogDebug, "DHTStorage: safeIndex: save packet to ", packetPath);
  std::ofstream file(packetPath, std::ofstream::binary | std::ofstream::out);
  if (!file.is_open())
    {
      LogPrint(eLogError, "DHTStorage: safeIndex: can't open file ", packetPath);
      return STORE_FILE_OPEN_ERROR;
    }

  file.write(reinterpret_cast<const char *>(data.data()), data.size());
  file.close();

  update_storage_usage();

  return STORE_SUCCESS;
}

int
DHTStorage::safeEmail(i2p::data::Tag<32> key, const std::vector<uint8_t>& data)
{
  std::string packetPath = pbote::fs::DataDirPath("DHTemail", key.ToBase64() + ".dat");

  if (pbote::fs::Exists(packetPath))
    {
      LogPrint(eLogDebug, "DHTStorage: safeEmail: packet already exist: ", packetPath);
      return STORE_FILE_EXIST;
    }

  LogPrint(eLogDebug, "DHTStorage: safeEmail: save packet to ", packetPath);
  std::ofstream file(packetPath, std::ofstream::binary | std::ofstream::out);
  if (!file.is_open())
    {
      LogPrint(eLogError, "DHTStorage: safeEmail: can't open file ", packetPath);
      return STORE_FILE_OPEN_ERROR;
    }

  EmailEncryptedPacket email_packet = {};
  email_packet.fromBuffer(const_cast<uint8_t *>(data.data()), data.size(), true);
  const auto time_now = std::chrono::system_clock::now();
  email_packet.stored_time = (int32_t)std::chrono::duration_cast<std::chrono::seconds>(time_now.time_since_epoch()).count();
  auto packet_bytes = email_packet.toByte();

  file.write(reinterpret_cast<const char *>(packet_bytes.data()), (long)packet_bytes.size());
  file.close();

  update_storage_usage();

  return STORE_SUCCESS;
}

int
DHTStorage::safeContact(i2p::data::Tag<32> key, const std::vector<uint8_t>& data)
{
  std::string packetPath = pbote::fs::DataDirPath("DHTdirectory", key.ToBase64() + ".dat");

  if (pbote::fs::Exists(packetPath))
    {
      LogPrint(eLogDebug, "DHTStorage: safeContact: packet already exist: ", packetPath);
      return STORE_FILE_EXIST;
    }

  LogPrint(eLogDebug, "DHTStorage: safeContact: save packet to ", packetPath);
  std::ofstream file(packetPath, std::ofstream::binary | std::ofstream::out);
  if (!file.is_open())
    {
      LogPrint(eLogError, "DHTStorage: safeContact: can't open file ", packetPath);
      return STORE_FILE_OPEN_ERROR;
    }

  file.write(reinterpret_cast<const char *>(data.data()), data.size());
  file.close();

  update_storage_usage();

  return STORE_SUCCESS;
}

int
DHTStorage::update_index(i2p::data::Tag<32> key, const std::vector<uint8_t>& data)
{
  IndexPacket new_packet, old_packet;
  new_packet.fromBuffer(data, true);

  auto old_data = getIndex(key);
  if (old_data.empty())
    {
      LogPrint(eLogError, "DHTStorage: update_index: can't open old index ", key.ToBase64());
      return -1;
    }

  old_packet.fromBuffer(old_data, true);
  size_t duplicated = 0, added = 0;

  for (auto entry : new_packet.data)
    {
      if (std::find(old_packet.data.begin(), old_packet.data.end(), entry) != old_packet.data.end())
        {
          duplicated++;
        }
      else
        {
          old_packet.data.push_back(entry);
          added++;
        }
    }

  LogPrint(eLogDebug, "DHTStorage: update_index: new entries: ",
           new_packet.data.size(), ", duplicated :", duplicated,
           ", added: ", added);

  if (duplicated == new_packet.data.size())
    return -2;

  return 0;
}

void
DHTStorage::loadLocalIndexPackets()
{
  local_index_packets = std::vector<std::string>();
  std::string indexPacketPath = pbote::fs::DataDirPath("DHTindex");
  std::vector<std::string> packets_path;
  auto result = pbote::fs::ReadDir(indexPacketPath, packets_path);

  if (result)
    {
      for (const auto &path : packets_path)
        {
          auto filename = remove_extension(base_name(path));
          local_index_packets.push_back(filename);
        }

      LogPrint(eLogDebug, "DHTStorage: loadLocalIndexPackets: index loaded: ", local_index_packets.size());
    }
  else
    {
      LogPrint(eLogWarning, "DHTStorage: loadLocalIndexPackets: have no index files");
    }
}

void
DHTStorage::loadLocalEmailPackets()
{
  local_email_packets = std::vector<std::string>();
  std::string email_packet_path = pbote::fs::DataDirPath("DHTemail");
  std::vector<std::string> packets_path;
  auto result = pbote::fs::ReadDir(email_packet_path, packets_path);

  if (result)
    {
      for (const auto &path : packets_path)
        {
          auto filename = remove_extension(base_name(path));
          local_email_packets.push_back(filename);
        }

      LogPrint(eLogDebug, "DHTStorage: loadLocalEmailPackets: mails loaded: ", local_email_packets.size());
    }
  else
    {
      LogPrint(eLogWarning, "DHTStorage: loadLocalEmailPackets: have no mail files");
    }
}

void
DHTStorage::loadLocalContactPackets()
{
  local_contact_packets = std::vector<std::string>();
  std::string email_packet_path = pbote::fs::DataDirPath("DHTdirectory");
  std::vector<std::string> packets_path;
  auto result = pbote::fs::ReadDir(email_packet_path, packets_path);

  if (result)
    {
      for (const auto &path : packets_path)
        {
          auto filename = remove_extension(base_name(path));
          local_contact_packets.push_back(filename);
        }

      LogPrint(eLogDebug, "DHTStorage: loadLocalContactPackets: contacts loaded: ", local_contact_packets.size());
    }
  else
    {
      LogPrint(eLogWarning, "DHTStorage: loadLocalContactPackets: have no contact files");
    }
}

size_t
DHTStorage::suffix_to_multiplier(const std::string &size_str)
{
  std::vector<std::string> sizes = { "B", "KB", "MB", "GB", "TB" };
  std::string suffix = size_str;
  std::size_t pos = suffix.find(' ');

  if (pos != std::string::npos)
    {
      suffix.erase(0, pos + 1);
    }
  else
    {
      LogPrint(eLogError,
               "DHTStorage: suffix_to_multiplier: can't parse data size suffix: ",
               size_str);
      suffix = "MB";
    }

  size_t iexp = 0;

  for (size_t i = 0; i < sizes.size(); i++)
    {
      if (sizes[i] == suffix)
        {
          /// Because first element is 0
          iexp = i;
          break;
      }
    }

  return (size_t)std::pow(1024, iexp);
}

void
DHTStorage::set_storage_limit()
{
  std::string limit_str;
  pbote::config::GetOption("storage", limit_str);

  size_t multiplier = suffix_to_multiplier(limit_str);

  std::size_t pos = limit_str.find(' ');
  limit_str.erase(pos, limit_str.size() - pos);

  size_t base = std::stoi(limit_str);
  limit = base * multiplier;
  LogPrint(eLogDebug, "DHTStorage: set_storage_limit: limit: ", limit);
}

void
DHTStorage::update_storage_usage()
{
  std::vector<std::string> dirs = {"DHTindex", "DHTemail", "DHTdirectory"};
  used = 0;

  for (const auto& dir : dirs)
    {
      std::string dir_path = pbote::fs::DataDirPath(dir);
      for (boost::filesystem::recursive_directory_iterator it(dir_path);
           it != boost::filesystem::recursive_directory_iterator(); ++it)
        {
          if (!boost::filesystem::is_directory(*it))
            used += boost::filesystem::file_size(*it);
        }
      /*LogPrint(eLogDebug, "DHTStorage: update_storage_usage: directory: ",
             dir, ", used: ", used);*/
    }
}

void
DHTStorage::remove_old_packets()
{
  size_t removed_count = 0;

  const auto time_now = std::chrono::system_clock::now();
  const auto current_timestamp =
    (int32_t)std::chrono::duration_cast<std::chrono::seconds>(time_now.time_since_epoch()).count();

  std::string dir_path = pbote::fs::DataDirPath("DHTemail");

  if (boost::filesystem::is_empty(dir_path.c_str()))
    {
      LogPrint(eLogDebug, "DHTStorage: remove_old_packets: DHTemail directory is empty");
      return;
    }

  for (auto& entry : boost::filesystem::recursive_directory_iterator(dir_path))
    {
      if (boost::filesystem::is_directory(entry))
        continue;

      LogPrint(eLogDebug, "DHTStorage: remove_old_packets: checking file: ", entry.path());

      std::ifstream file(entry.path(), std::ios::binary);
      if (!file.is_open())
        {
          LogPrint(eLogError, "DHTStorage: remove_old_packets: can't open file ", entry.path());
          continue;
        }

      uint8_t * bytes = (uint8_t *) malloc(38);

      file.read(reinterpret_cast<char*>(bytes), 38);
      file.close();

      uint8_t type;
      uint8_t version;
      uint8_t key[32]{};
      int32_t stored_time{};

      size_t offset = 0;
      memcpy(&type, bytes, 1);
      offset += 1;
      memcpy(&version, bytes + offset, 1);
      offset += 1;
      memcpy(&key, bytes + offset, 32);
      offset += 32;
      memcpy(&stored_time, bytes + offset, 4);

      stored_time = (int32_t)ntohl((uint32_t)stored_time);

      LogPrint(eLogDebug, "DHTStorage: remove_old_packets: current_timestamp: ", current_timestamp);
      LogPrint(eLogDebug, "DHTStorage: remove_old_packets: packet_timestamp:  ", stored_time + store_duration);

      if (stored_time + store_duration < current_timestamp)
        {
          LogPrint(eLogInfo, "DHTStorage: remove_old_packets: remove: ", entry.path());
          if (deleteEmail(i2p::data::Tag<32>(key)))
            removed_count++;
          else
            LogPrint(eLogError, "DHTStorage: remove_old_packets: can't remove file: ", entry.path());
        }
      else
        {
          LogPrint(eLogDebug, "DHTStorage: remove_old_packets: packet ", entry.path(), " is too young to die.");
        }
    }

  LogPrint(eLogDebug, "DHTStorage: remove_old_packets: packets removed: ", removed_count);
}

} // kademlia
} // pbote
