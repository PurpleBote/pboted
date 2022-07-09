/**
 * Copyright (C) 2019-2022, polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <boost/filesystem.hpp>
#include <chrono>
#include <cstring>
#include <filesystem>
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
  /// There is no need to check it too often
  if (update_counter > 20)
  {
    update_counter = 0;

    /// Only in case if we have less than 10 MiB of free space
    if (limit_reached (10485760))
      {
        LogPrint (eLogDebug, "DHTStorage: update: Cleanup started");

        remove_old_packets ();
        remove_old_entries ();

        LogPrint (eLogDebug, "DHTStorage: update: Cleanup finished");
      }

    LogPrint (eLogDebug, "DHTStorage: update: ",
              " index: ", local_index_packets.size (),
              ", emails: ", local_email_packets.size (),
              ", contacts: ", local_contact_packets.size ());
  }

  update_storage_usage ();

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

  return success;
}

bool
DHTStorage::Delete(pbote::type type, const i2p::data::Tag<32>& key)
{
  if (!exist(type, key))
    return false;

  std::string packet_path;

  switch (type)
    {
      case (type::DataI):
        packet_path = pbote::fs::DataDirPath("DHTindex", key.ToBase64() + DEFAULT_FILE_EXTENSION);
        break;
      case (type::DataE):
        packet_path = pbote::fs::DataDirPath("DHTemail", key.ToBase64() + DEFAULT_FILE_EXTENSION);
        break;
      default:
        return false;
    }

  if (pbote::fs::Remove(packet_path))
    {
      LogPrint(eLogInfo, "DHTStorage: remove: File ", packet_path, " removed");
      update_storage_usage();
      return true;
    }
  else
    {
      LogPrint(eLogError, "DHTStorage: remove: Can't remove file ", packet_path);
      return false;
    }
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
DHTStorage::getPacket (pbote::type type, i2p::data::Tag<32> key)
{
  std::string dir_path;
  std::set<std::string> local_list;

  switch(type) {
    case type::DataI:
      dir_path = "DHTindex";
      local_list = local_index_packets;
      break;
    case type::DataE:
      dir_path = "DHTemail";
      local_list = local_email_packets;
      break;
    case type::DataC:
      dir_path = "DHTdirectory";
      local_list = local_contact_packets;
      break;
    default:
      LogPrint(eLogError, "DHTStorage: getPacket: Unsupported type: ", type);
      return {};
  }

  if (local_list.empty ())
    {
      LogPrint(eLogWarning, "DHTStorage: getPacket: Have no files for search");
      return {};
    }

  if (local_list.find(key.ToBase64 ()) == local_list.end ())
    {
      LogPrint(eLogDebug, "DHTStorage: getPacket: Have no file, type: ",
               uint8_t(type), ", key: ", key.ToBase64 ());
      return {};
    }

  std::string filepath = pbote::fs::DataDirPath(dir_path, key.ToBase64 () + DEFAULT_FILE_EXTENSION);
  std::ifstream file(filepath, std::ios::binary);

  if (!file.is_open())
    {
      LogPrint(eLogError, "DHTStorage: getPacket: Can't open file ", filepath);
      return {};
    }

  std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(file)), (std::istreambuf_iterator<char>()));
  file.close();

  return bytes;
}

bool
DHTStorage::exist(pbote::type type, i2p::data::Tag<32> key)
{
  std::string packet_path;

  switch(type)
    {
      case pbote::type::DataI:
        packet_path = pbote::fs::DataDirPath("DHTindex", key.ToBase64() + DEFAULT_FILE_EXTENSION);
        break;
      case pbote::type::DataE:
        packet_path = pbote::fs::DataDirPath("DHTemail", key.ToBase64() + DEFAULT_FILE_EXTENSION);
        break;
      case pbote::type::DataC:
        packet_path = pbote::fs::DataDirPath("DHTdirectory", key.ToBase64() + DEFAULT_FILE_EXTENSION);
        break;
      default:
        return false;
    }

  return boost::filesystem::exists(packet_path);
}

int
DHTStorage::safeIndex(i2p::data::Tag<32> key, const std::vector<uint8_t>& data)
{
  std::string packetPath = pbote::fs::DataDirPath("DHTindex", key.ToBase64() + DEFAULT_FILE_EXTENSION);

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
          LogPrint(eLogWarning, "DHTStorage: safeIndex: can't open file ", packetPath);
          return STORE_FILE_OPEN_ERROR;
        }
      LogPrint(eLogDebug, "DHTStorage: safeIndex: saved: ", packetPath);
      return STORE_SUCCESS;
    }

  LogPrint(eLogDebug, "DHTStorage: safeIndex: save packet to ", packetPath);
  std::ofstream file(packetPath, std::ofstream::binary | std::ofstream::out);
  if (file.is_open())
    {
      file.write(reinterpret_cast<const char *>(data.data()), data.size());
      file.close();
    }
  else
    {
      LogPrint(eLogError, "DHTStorage: safeIndex: can't open file ", packetPath);
      return STORE_FILE_OPEN_ERROR;
    }

  update_storage_usage();

  return STORE_SUCCESS;
}

int
DHTStorage::safeEmail(i2p::data::Tag<32> key, const std::vector<uint8_t>& data)
{
  std::string packetPath = pbote::fs::DataDirPath("DHTemail", key.ToBase64() + DEFAULT_FILE_EXTENSION);

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

  EmailEncryptedPacket email_packet;
  email_packet.fromBuffer(const_cast<uint8_t *>(data.data()), data.size(), true);
  email_packet.stored_time = ts_now ();
  auto packet_bytes = email_packet.toByte();

  file.write(reinterpret_cast<const char *>(packet_bytes.data()), (long)packet_bytes.size());
  file.close();

  update_storage_usage();

  return STORE_SUCCESS;
}

int
DHTStorage::safeContact(i2p::data::Tag<32> key, const std::vector<uint8_t>& data)
{
  std::string packetPath = pbote::fs::DataDirPath("DHTdirectory", key.ToBase64() + DEFAULT_FILE_EXTENSION);

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
  std::unique_lock<std::mutex> l (index_mutex);
  IndexPacket new_pkt, old_pkt;
  new_pkt.fromBuffer(data, true);

  auto old_data = getIndex(key);
  if (old_data.empty())
    {
      LogPrint(eLogError, "DHTStorage: update_index: can't open old index ", key.ToBase64());
      return STORE_FILE_OPEN_ERROR;
    }

  old_pkt.fromBuffer(old_data, true);
  size_t duplicated = 0, added = 0;

  for (auto entry : new_pkt.data)
    {
      if (std::find(old_pkt.data.begin(), old_pkt.data.end(), entry) != old_pkt.data.end())
        {
          duplicated++;
        }
      else
        {
          entry.time = ts_now ();
          old_pkt.data.push_back(entry);
          added++;
        }
    }

  LogPrint(eLogDebug, "DHTStorage: update_index: new entries: ",
           new_pkt.data.size(), ", duplicated: ", duplicated,
           ", added: ", added);

  Delete(type::DataI, key);

  std::string pkt_path = pbote::fs::DataDirPath("DHTindex", key.ToBase64() + DEFAULT_FILE_EXTENSION);

  LogPrint(eLogDebug, "DHTStorage: update_index: save packet to ", pkt_path);
  std::ofstream file(pkt_path, std::ofstream::binary | std::ofstream::out);
  if (file.is_open())
    {
      file.write(reinterpret_cast<const char *>(data.data()), data.size());
      file.close();
    }
  else
    {
      LogPrint(eLogError, "DHTStorage: update_index: can't open file ", pkt_path);
      return STORE_FILE_OPEN_ERROR;
    }

  update_storage_usage ();

  return STORE_SUCCESS;
}

int
DHTStorage::clean_index (i2p::data::Tag<32> key, int32_t ts_now)
{
  std::unique_lock<std::mutex> l (index_mutex);
  IndexPacket index_packet;
  auto index_data = getIndex(key);

  if (index_data.empty())
    {
      LogPrint(eLogError, "DHTStorage: clean_index: can't open old index ", key.ToBase64());
      return -1;
    }

  index_packet.fromBuffer(index_data, true);
  size_t removed = 0;

  for (auto it = index_packet.data.begin(); it != index_packet.data.end(); )
    {
      LogPrint(eLogDebug, "DHTStorage: clean_index: current_timestamp:   ", ts_now);
      LogPrint(eLogDebug, "DHTStorage: clean_index: record_timestamp:    ", it->time + store_duration);

      if (it->time + store_duration > ts_now)
        {
          LogPrint(eLogDebug, "DHTStorage: clean_index: Record is too young to die");
          ++it;
          continue;
        }

      i2p::data::Tag<32> entry_key(it->key);
      it = index_packet.data.erase(it);
      LogPrint(eLogDebug, "DHTStorage: clean_index: Old record removed: ", entry_key.ToBase64());
      removed++;
    }

  Delete(type::DataI, key);

  index_packet.nump = index_packet.data.size();

  if (index_packet.data.empty())
    {
      LogPrint(eLogDebug, "DHTStorage: clean_index: Empty packet removed: ", key.ToBase64());
      return -1;
    }

  safeIndex(key, index_packet.toByte());

  return removed;
}

void
DHTStorage::loadLocalIndexPackets()
{
  local_index_packets = std::set<std::string>();
  std::vector<std::string> packets_path;

  if (!pbote::fs::ReadDir(pbote::fs::DataDirPath("DHTindex"), packets_path))
    {
      LogPrint(eLogWarning, "DHTStorage: loadLocalIndexPackets: have no index files");
      return;
    }

  for (const auto &path : packets_path)
    {
      auto filename = remove_extension(base_name(path));
      local_index_packets.insert(filename);
    }

  LogPrint(eLogDebug, "DHTStorage: loadLocalIndexPackets: index loaded: ",
           local_index_packets.size());
}

void
DHTStorage::loadLocalEmailPackets()
{
  local_email_packets = std::set<std::string>();
  std::vector<std::string> packets_path;

  if (!pbote::fs::ReadDir(pbote::fs::DataDirPath("DHTemail"), packets_path))
    {
      LogPrint(eLogWarning, "DHTStorage: loadLocalEmailPackets: have no mail files");
      return;
    }

  for (const auto &path : packets_path)
    {
      auto filename = remove_extension(base_name(path));
      local_email_packets.insert(filename);
    }

  LogPrint(eLogDebug, "DHTStorage: loadLocalEmailPackets: mails loaded: ",
           local_email_packets.size());
}

void
DHTStorage::loadLocalContactPackets()
{
  local_contact_packets = std::set<std::string>();
  std::vector<std::string> packets_path;

  if (!pbote::fs::ReadDir(pbote::fs::DataDirPath("DHTdirectory"), packets_path))
    {
      LogPrint(eLogWarning, "DHTStorage: loadLocalContactPackets: have no contact files");
      return;
    }

  for (const auto &path : packets_path)
    {
      auto filename = remove_extension(base_name(path));
      local_contact_packets.insert(filename);
    }

  LogPrint(eLogDebug, "DHTStorage: loadLocalContactPackets: contacts loaded: ",
           local_contact_packets.size());
}

size_t
DHTStorage::suffix_to_multiplier(const std::string &size_str)
{
  std::vector<std::string> sizes = { "B", "KiB", "MiB", "GiB", "TiB" };
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
      suffix = "MiB";
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
  size_t new_used = 0;

  try
    {
      std::string dir_path = pbote::fs::DataDirPath("DHTindex");
      for (boost::filesystem::recursive_directory_iterator it(dir_path);
           it != boost::filesystem::recursive_directory_iterator(); ++it)
        {
          if (boost::filesystem::is_regular_file(*it))
            new_used += boost::filesystem::file_size(*it);
        }

      dir_path = pbote::fs::DataDirPath("DHTemail");
      for (boost::filesystem::recursive_directory_iterator it(dir_path);
           it != boost::filesystem::recursive_directory_iterator(); ++it)
        {
          if (boost::filesystem::is_regular_file(*it))
            new_used += boost::filesystem::file_size(*it);
        }

      dir_path = pbote::fs::DataDirPath("DHTdirectory");
      for (boost::filesystem::recursive_directory_iterator it(dir_path);
           it != boost::filesystem::recursive_directory_iterator(); ++it)
        {
          if (boost::filesystem::is_regular_file(*it))
            new_used += boost::filesystem::file_size(*it);
        }

      used = new_used;
    }
  catch (const std::exception& e)
    {
      std::string e_what(e.what());
      LogPrint(eLogError, "DHTStorage: update_storage_usage: ", e_what);
    }

  loadLocalIndexPackets ();
  loadLocalEmailPackets ();
  loadLocalContactPackets ();
}

void
DHTStorage::remove_old_packets()
{
  size_t removed_count = 0;
  const int32_t ts = ts_now ();

  if (boost::filesystem::is_empty(pbote::fs::DataDirPath("DHTemail").c_str()))
    {
      LogPrint(eLogDebug, "DHTStorage: remove_old_packets: DHTemail directory is empty");
      return;
    }

  {
    std::unique_lock<std::mutex> l (email_mutex);
    for (const auto& pkt : local_email_packets)
      {
        i2p::data::Tag<32> key;
        key.FromBase64(pkt);
        auto data = getPacket(type::DataE, key);
        EmailEncryptedPacket email_pkt;
        email_pkt.fromBuffer (data.data (), data.size (), true);
        int32_t store_ts = email_pkt.stored_time + store_duration;

        LogPrint(eLogDebug, "DHTStorage: remove_old_packets: current_ts: ", ts);
        LogPrint(eLogDebug, "DHTStorage: remove_old_packets: packet_ts:  ", store_ts);

        if (store_ts > ts)
          {
            LogPrint(eLogDebug, "DHTStorage: remove_old_packets: packet ", pkt, " is too young to die.");
            continue;
          }

        LogPrint(eLogDebug, "DHTStorage: remove_old_packets: remove: ", pkt);

        if (Delete(type::DataE, key))
          removed_count++;
        else
          LogPrint(eLogError, "DHTStorage: remove_old_packets: can't remove file: ", pkt);
      }
  }

  LogPrint(eLogDebug, "DHTStorage: remove_old_packets: packets removed: ", removed_count);
}

void
DHTStorage::remove_old_entries()
{
  size_t removed_entries = 0, removed_packets = 0;

  if (boost::filesystem::is_empty(pbote::fs::DataDirPath("DHTindex").c_str()))
    {
      LogPrint(eLogDebug, "DHTStorage: remove_old_entries: DHTindex directory is empty");
      return;
    }

  const int32_t ts = ts_now ();
  for (const auto& pkt : local_index_packets)
    {
      i2p::data::Tag<32> key;
      key.FromBase64(pkt);
      int result = clean_index(key, ts);

      if (result > 0)
        removed_entries += result;

      if (result == -1)
        removed_packets++;
    }

  LogPrint(eLogDebug, "DHTStorage: remove_old_entries: Records removed: ", removed_entries);
  LogPrint(eLogDebug, "DHTStorage: remove_old_entries: Packets removed: ", removed_packets);
}

int32_t
DHTStorage::ts_now ()
{
  const auto ts = std::chrono::system_clock::now ();
  const auto epoch = ts.time_since_epoch ();
  return std::chrono::duration_cast<std::chrono::seconds> (epoch).count ();
}

} // kademlia
} // pbote
