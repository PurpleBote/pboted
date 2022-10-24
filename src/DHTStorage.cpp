/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <chrono>
#include <cstring>
#include <fstream>
#include <iterator>
#include <cstdio>

#include "BoteContext.h"
#include "compat.h"
#include "ConfigParser.h"
#include "DHTStorage.h"
#include "Packet.h"

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
DHTStorage::safe (const std::vector<uint8_t>& data)
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

int
DHTStorage::safe_deleted (pbote::type type, const i2p::data::Tag<32>& key, const std::vector<uint8_t>& data)
{
  int success = 0;

  switch (type)
    {
      case (DataI):
        success = safe_deleted_index (key, data);
        break;
      case (DataE):
        success = safe_deleted_email (key, data);
        break;
      default:
        break;
    }

  return success;
}

bool
DHTStorage::Delete (pbote::type type, const i2p::data::Tag<32>& key, const char *ext)
{
  if (!exist (type, key))
    return false;

  std::string packet_path;

  switch (type)
    {
      case (DataI):
        packet_path = pbote::fs::DataDirPath("DHTindex", key.ToBase64() + ext);
        break;
      case (DataE):
        packet_path = pbote::fs::DataDirPath("DHTemail", key.ToBase64() + ext);
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

bool
DHTStorage::remove_index (const i2p::data::Tag<32>& index_dht_key,
                          const i2p::data::Tag<32>& email_dht_key,
                          const i2p::data::Tag<32>& del_auth)
{
  std::unique_lock<std::recursive_mutex> l (index_mutex);

  pbote::DeletionInfoPacket::item deletion_item;
  memcpy(deletion_item.DA, del_auth.data (), 32);
  memcpy(deletion_item.key, email_dht_key.data (), 32);
  deletion_item.time = context.ts_now ();

  pbote::DeletionInfoPacket deletion_pkt;
  deletion_pkt.data.push_back (deletion_item);
  deletion_pkt.count = 1;

  (void)safe_deleted (DataI, index_dht_key, deletion_pkt.toByte ());

  IndexPacket index_pkt;

  auto index_data = getIndex (index_dht_key);
  if (index_data.empty ())
    {
      LogPrint (eLogError, "DHTStorage: remove_index: Can't open old index ",
                index_dht_key.ToBase64 ());
      return false;
    }

  bool parsed = index_pkt.fromBuffer (index_data, true);
  if (!parsed)
    {
      LogPrint (eLogError, "DHTStorage: remove_index: Can't parse index ",
                index_dht_key.ToBase64 ());
      return false;
    }

  int32_t removed = index_pkt.erase_entry (email_dht_key.data (),
                                           del_auth.data ());

  if (removed == 0)
    {
      LogPrint (eLogDebug, "DHTStorage: remove_index: Index without key: ",
                index_dht_key.ToBase64 ());
      return false;
    }

  LogPrint (eLogDebug, "DHTStorage: remove_index: Index entry removed, key: ",
            index_dht_key.ToBase64 ());

  Delete (DataI, index_dht_key);

  std::string pkt_path = pbote::fs::DataDirPath ("DHTindex",
      index_dht_key.ToBase64 () + DEFAULT_FILE_EXTENSION);

  LogPrint (eLogDebug, "DHTStorage: remove_index: Save packet to ", pkt_path);
  auto index_bytes = index_pkt.toByte ();
  std::ofstream file(pkt_path, std::ofstream::binary | std::ofstream::out);
  if (file.is_open ())
    {
      file.write (reinterpret_cast<const char *> (index_bytes.data ()),
                                                  index_bytes.size ());
      file.close ();
    }
  else
    {
      LogPrint (eLogError, "DHTStorage: remove_index: Can't open file ",
                pkt_path);
      return STORE_FILE_OPEN_ERROR;
    }

  update_storage_usage ();

  return STORE_SUCCESS;
}

size_t
DHTStorage::remove_indices (const i2p::data::Tag<32>& index_dht_key,
                            const IndexDeleteRequestPacket& packet)
{
  size_t counter = 0;
  for (auto item : packet.data)
  {
    i2p::data::Tag<32> mail_key(item.key);
    i2p::data::Tag<32> mail_da(item.da);

    bool removed = remove_index (index_dht_key, mail_key, mail_da);
    if (removed)
      counter++;
  }
  return counter;
}

std::vector<uint8_t>
DHTStorage::getIndex(i2p::data::Tag<32> key)
{
  if(exist(DataI, key))
    {
      return getPacket(DataI, key);
    }

  return {};
}

std::vector<uint8_t>
DHTStorage::getEmail(i2p::data::Tag<32> key)
{
  if(exist(DataE, key))
    {
      return getPacket(DataE, key);
    }

  return {};
}

std::vector<uint8_t>
DHTStorage::getContact(i2p::data::Tag<32> key)
{
  if(exist(DataC, key))
    {
      return getPacket(DataC, key);
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
DHTStorage::getPacket (pbote::type type, i2p::data::Tag<32> key,
                       const char *ext)
{
  std::string dir_path;
  std::set<std::string> local_list;

  switch(type) {
    case DataI:
      dir_path = "DHTindex";
      local_list = local_index_packets;
      break;
    case DataE:
      dir_path = "DHTemail";
      local_list = local_email_packets;
      break;
    case DataC:
      dir_path = "DHTdirectory";
      local_list = local_contact_packets;
      break;
    default:
      LogPrint(eLogError, "DHTStorage: getPacket: Unsupported type: ", type);
      return {};
  }

  std::string filepath = pbote::fs::DataDirPath(dir_path, key.ToBase64 () + ext);
  if (!pbote::fs::Exists(filepath))
    {
      LogPrint(eLogDebug, "DHTStorage: getPacket: Have no file, type: ",
               uint8_t(type), ", path: ", filepath);
      return {};
    }

  LogPrint(eLogDebug, "DHTStorage: getPacket: Found packet: ", filepath);

  std::ifstream file(filepath, std::ios::binary);

  if (!file.is_open())
    {
      LogPrint(eLogError, "DHTStorage: getPacket: Can't open file ", filepath);
      return {};
    }

  std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(file)),
                             (std::istreambuf_iterator<char>()));
  file.close();

  return bytes;
}

bool
DHTStorage::exist (pbote::type type, i2p::data::Tag<32> key)
{
  std::string packet_path;

  switch (type)
    {
      case DataI:
        packet_path = pbote::fs::DataDirPath ("DHTindex", key.ToBase64 () + DEFAULT_FILE_EXTENSION);
        break;
      case DataE:
        packet_path = pbote::fs::DataDirPath ("DHTemail", key.ToBase64 () + DEFAULT_FILE_EXTENSION);
        break;
      case DataC:
        packet_path = pbote::fs::DataDirPath ("DHTdirectory", key.ToBase64 () + DEFAULT_FILE_EXTENSION);
        break;
      default:
        return false;
    }

  return pbote::fs::Exists(packet_path);
}

int
DHTStorage::safeIndex (i2p::data::Tag<32> key,
                       const std::vector<uint8_t>& data)
{
  std::string packetPath = pbote::fs::DataDirPath("DHTindex", key.ToBase64() + DEFAULT_FILE_EXTENSION);

  LogPrint(eLogDebug, "DHTStorage: safeIndex: Path: ", packetPath);

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
DHTStorage::safe_deleted_index (i2p::data::Tag<32> key,
                                const std::vector<uint8_t>& data)
{
  std::string packetPath = pbote::fs::DataDirPath("DHTindex", key.ToBase64() + DELETED_FILE_EXTENSION);

  if (pbote::fs::Exists(packetPath))
    {
      int status = update_deletion_info(DataI, key, data);
      if (status == STORE_FILE_EXIST)
        {
          LogPrint(eLogDebug, "DHTStorage: update_deleted_index: packet already exist: ", packetPath);
          return STORE_FILE_EXIST;
        }
      if (status == STORE_FILE_OPEN_ERROR)
        {
          LogPrint(eLogWarning, "DHTStorage: update_deleted_index: can't open file ", packetPath);
          return STORE_FILE_OPEN_ERROR;
        }
      LogPrint(eLogDebug, "DHTStorage: update_deleted_index: saved: ", packetPath);
      return STORE_SUCCESS;
    }

  LogPrint(eLogDebug, "DHTStorage: update_deleted_index: save packet to ", packetPath);
  std::ofstream file(packetPath, std::ofstream::binary | std::ofstream::out);
  if (file.is_open())
    {
      file.write(reinterpret_cast<const char *>(data.data()), data.size());
      file.close();
    }
  else
    {
      LogPrint(eLogError, "DHTStorage: update_deleted_index: can't open file ", packetPath);
      return STORE_FILE_OPEN_ERROR;
    }

  update_storage_usage();

  return STORE_SUCCESS;
}

int
DHTStorage::safeEmail (i2p::data::Tag<32> key,
                       const std::vector<uint8_t>& data)
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
  email_packet.stored_time = context.ts_now ();
  auto packet_bytes = email_packet.toByte();

  file.write(reinterpret_cast<const char *>(packet_bytes.data()), (long)packet_bytes.size());
  file.close();

  update_storage_usage();

  return STORE_SUCCESS;
}

int
DHTStorage::safe_deleted_email (i2p::data::Tag<32> key,
                                const std::vector<uint8_t>& data)
{
  std::string packetPath = pbote::fs::DataDirPath("DHTemail", key.ToBase64() + DELETED_FILE_EXTENSION);

  if (pbote::fs::Exists(packetPath))
    {
      LogPrint(eLogDebug, "DHTStorage: safe_deleted_email: packet already exist: ", packetPath);
      return STORE_FILE_EXIST;
    }

  LogPrint(eLogDebug, "DHTStorage: safe_deleted_email: save packet to ", packetPath);
  std::ofstream file(packetPath, std::ofstream::binary | std::ofstream::out);
  if (!file.is_open())
    {
      LogPrint(eLogError, "DHTStorage: safe_deleted_email: can't open file ", packetPath);
      return STORE_FILE_OPEN_ERROR;
    }

  file.write(reinterpret_cast<const char *>(data.data()), (long)data.size());
  file.close();

  update_storage_usage();

  return STORE_SUCCESS;
}

int
DHTStorage::safeContact (i2p::data::Tag<32> key,
                         const std::vector<uint8_t>& data)
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
DHTStorage::update_index (i2p::data::Tag<32> key,
                          const std::vector<uint8_t>& data)
{
  std::unique_lock<std::recursive_mutex> l (index_mutex);
  IndexPacket new_pkt, old_pkt;
  new_pkt.fromBuffer (data, true);

  auto old_data = getIndex (key);
  if (old_data.empty ())
    {
      LogPrint (eLogError, "DHTStorage: update_index: Can't open old index ",
                key.ToBase64 ());
      return STORE_FILE_OPEN_ERROR;
    }

  old_pkt.fromBuffer (old_data, true);
  size_t duplicated = 0, added = 0;

  for (auto entry : new_pkt.data)
    {
      if (std::find (old_pkt.data.begin (), old_pkt.data.end (),entry)
            != old_pkt.data.end())
        {
          duplicated++;
        }
      else
        {
          entry.time = context.ts_now ();
          old_pkt.data.push_back (entry);
          added++;
        }
    }

  LogPrint (eLogDebug, "DHTStorage: update_index: New entries: ",
            new_pkt.data.size (), ", duplicated: ", duplicated,
            ", added: ", added);

  Delete (DataI, key);

  std::string pkt_path = pbote::fs::DataDirPath ("DHTindex", key.ToBase64 () + DEFAULT_FILE_EXTENSION);

  LogPrint (eLogDebug, "DHTStorage: update_index: Save packet to ", pkt_path);
  std::ofstream file(pkt_path, std::ofstream::binary | std::ofstream::out);
  if (file.is_open ())
    {
      file.write (reinterpret_cast<const char *>(data.data ()), data.size ());
      file.close ();
    }
  else
    {
      LogPrint (eLogError, "DHTStorage: update_index: Can't open file ",
                pkt_path);
      return STORE_FILE_OPEN_ERROR;
    }

  LogPrint (eLogDebug, "DHTStorage: update_index: Packet saved to ", pkt_path);

  update_storage_usage ();

  return STORE_SUCCESS;
}

int
DHTStorage::update_deletion_info (pbote::type type, i2p::data::Tag<32> key,
                                  const std::vector<uint8_t>& data)
{
  if (type == DataI)
    std::unique_lock<std::recursive_mutex> l (index_mutex);
  if (type == DataE)
    std::unique_lock<std::recursive_mutex> l (email_mutex);

  DeletionInfoPacket new_pkt, old_pkt;
  new_pkt.fromBuffer(data, true);

  auto old_data = getPacket(type, key, DELETED_FILE_EXTENSION);
  if (old_data.empty())
    {
      LogPrint(eLogError, "DHTStorage: update_deletion_info: can't open file ",
               key.ToBase64());
      return STORE_FILE_OPEN_ERROR;
    }

  old_pkt.fromBuffer(old_data, true);
  size_t duplicated = 0, added = 0;

  for (auto item : new_pkt.data)
    {
      if (std::find(old_pkt.data.begin(), old_pkt.data.end(), item) != old_pkt.data.end())
        {
          duplicated++;
        }
      else
        {
          item.time = context.ts_now ();
          old_pkt.data.push_back(item);
          added++;
        }
    }

  LogPrint(eLogDebug, "DHTStorage: update_deletion_info: New entries: ",
           new_pkt.data.size(), ", duplicated: ", duplicated,
           ", added: ", added);

  Delete(type, key, DELETED_FILE_EXTENSION);

  std::string dir_path;

  switch(type) {
    case DataI:
      dir_path = "DHTindex";
      break;
    case DataE:
      dir_path = "DHTemail";
      break;
    default:
      LogPrint(eLogError, "DHTStorage: update_deletion_info: Unsupported type: ", type);
      return STORE_FILE_OPEN_ERROR;
  }

  std::string pkt_path = pbote::fs::DataDirPath(dir_path, key.ToBase64() + DELETED_FILE_EXTENSION);

  LogPrint(eLogDebug, "DHTStorage: update_deletion_info: Save packet to ", pkt_path);
  std::ofstream file(pkt_path, std::ofstream::binary | std::ofstream::out);
  if (file.is_open())
    {
      file.write(reinterpret_cast<const char *>(data.data()), data.size());
      file.close();
    }
  else
    {
      LogPrint(eLogError, "DHTStorage: update_deletion_info: Can't open file ",
               pkt_path);
      return STORE_FILE_OPEN_ERROR;
    }

  update_storage_usage ();

  return STORE_SUCCESS;
}

int
DHTStorage::clean_index (i2p::data::Tag<32> key, int32_t ts_now)
{
  std::unique_lock<std::recursive_mutex> l (index_mutex);
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
      LogPrint(eLogDebug, "DHTStorage: clean_index: current_timestamp: ", ts_now);
      LogPrint(eLogDebug, "DHTStorage: clean_index: record_timestamp:  ", it->time + store_duration);

      if (it->time + store_duration > ts_now)
        {
          LogPrint(eLogDebug, "DHTStorage: clean_index: Record is too young to die");
          ++it;
          continue;
        }

      i2p::data::Tag<32> entry_key(it->key);
      it = index_packet.data.erase(it);
      LogPrint(eLogDebug, "DHTStorage: clean_index: Old record removed: ",
               entry_key.ToBase64());
      removed++;
    }

  Delete(DataI, key);

  index_packet.nump = index_packet.data.size();

  if (index_packet.data.empty())
    {
      LogPrint(eLogDebug, "DHTStorage: clean_index: Empty packet removed: ",
               key.ToBase64());
      return -1;
    }

  safeIndex(key, index_packet.toByte());

  return removed;
}

int
DHTStorage::clean_deletion_info (pbote::type type, i2p::data::Tag<32> key,
                                 int32_t ts_now)
{
  if (type == DataI)
    std::unique_lock<std::recursive_mutex> l (index_mutex);
  if (type == DataE)
    std::unique_lock<std::recursive_mutex> l (email_mutex);

  DeletionInfoPacket deletion_info;
  auto deletion_data = getPacket(type, key, DELETED_FILE_EXTENSION);

  if (deletion_data.empty())
    {
      LogPrint(eLogError, "DHTStorage: clean_deletion_info: Can't open old file for key",
               key.ToBase64());
      return -1;
    }

  deletion_info.fromBuffer(deletion_data, true);
  size_t removed = 0;

  for (auto it = deletion_info.data.begin(); it != deletion_info.data.end(); )
    {
      LogPrint(eLogDebug, "DHTStorage: clean_deletion_info: current_timestamp: ",
               ts_now);
      LogPrint(eLogDebug, "DHTStorage: clean_deletion_info: record_timestamp:  ",
               it->time + store_duration);

      if (it->time + store_duration > ts_now)
        {
          LogPrint(eLogDebug, "DHTStorage: clean_deletion_info: Record is too young to die");
          ++it;
          continue;
        }

      i2p::data::Tag<32> entry_key(it->key);
      it = deletion_info.data.erase(it);
      LogPrint(eLogDebug, "DHTStorage: clean_deletion_info: Old record removed: ",
               entry_key.ToBase64 ());
      removed++;
    }

  Delete(type, key, DELETED_FILE_EXTENSION);

  deletion_info.count = deletion_info.data.size ();

  if (deletion_info.data.empty ())
    {
      LogPrint(eLogDebug, "DHTStorage: clean_deletion_info: Empty packet removed: ",
               key.ToBase64 ());
      return -1;
    }

  safe_deleted (type, key, deletion_info.toByte ());

  return removed;
}

void
DHTStorage::loadLocalIndexPackets ()
{
  std::set<std::string> temp_index_packets;
  std::vector<std::string> packets_path;

  if (!pbote::fs::ReadDir(pbote::fs::DataDirPath("DHTindex"), packets_path))
    {
      LogPrint(eLogWarning, "DHTStorage: loadLocalIndexPackets: have no index files");
      return;
    }

  for (const auto &path : packets_path)
    {
      if (path.compare (path.size () - 4, 4, DELETED_FILE_EXTENSION) != 0)
        continue;

      auto filename = remove_extension(base_name(path));
      temp_index_packets.insert(filename);
    }

  LogPrint(eLogDebug, "DHTStorage: loadLocalIndexPackets: index loaded: ",
           temp_index_packets.size());
  local_index_packets = temp_index_packets;
}

void
DHTStorage::loadLocalEmailPackets ()
{
  std::set<std::string> temp_email_packets;
  std::vector<std::string> packets_path;

  if (!pbote::fs::ReadDir(pbote::fs::DataDirPath("DHTemail"), packets_path))
    {
      LogPrint(eLogWarning, "DHTStorage: loadLocalEmailPackets: have no mail files");
      return;
    }

  for (const auto &path : packets_path)
    {
      if (path.compare (path.size () - 4, 4, DELETED_FILE_EXTENSION) != 0)
        continue;

      auto filename = remove_extension(base_name(path));
      temp_email_packets.insert(filename);
    }

  LogPrint(eLogDebug, "DHTStorage: loadLocalEmailPackets: mails loaded: ",
           temp_email_packets.size());
  local_email_packets = temp_email_packets;
}

void
DHTStorage::loadLocalContactPackets ()
{
  std::set<std::string> temp_contact_packets;
  std::vector<std::string> packets_path;

  if (!pbote::fs::ReadDir(pbote::fs::DataDirPath("DHTdirectory"), packets_path))
    {
      LogPrint(eLogWarning, "DHTStorage: loadLocalContactPackets: have no contact files");
      return;
    }

  for (const auto &path : packets_path)
    {
      auto filename = remove_extension(base_name(path));
      temp_contact_packets.insert(filename);
    }

  LogPrint(eLogDebug, "DHTStorage: loadLocalContactPackets: contacts loaded: ",
           temp_contact_packets.size());
  local_contact_packets = temp_contact_packets;
}

size_t
DHTStorage::suffix_to_multiplier (const std::string &size_str)
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
DHTStorage::set_storage_limit ()
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
DHTStorage::update_storage_usage ()
{
  size_t new_used = 0;

  try
    {
      std::string dir_path = pbote::fs::DataDirPath("DHTindex");
      for (nsfs::recursive_directory_iterator it(dir_path);
           it != nsfs::recursive_directory_iterator(); ++it)
        {
          if (nsfs::is_regular_file(*it))
            new_used += nsfs::file_size(*it);
        }

      dir_path = pbote::fs::DataDirPath("DHTemail");
      for (nsfs::recursive_directory_iterator it(dir_path);
           it != nsfs::recursive_directory_iterator(); ++it)
        {
          if (nsfs::is_regular_file(*it))
            new_used += nsfs::file_size(*it);
        }

      dir_path = pbote::fs::DataDirPath("DHTdirectory");
      for (nsfs::recursive_directory_iterator it(dir_path);
           it != nsfs::recursive_directory_iterator(); ++it)
        {
          if (nsfs::is_regular_file(*it))
            new_used += nsfs::file_size(*it);
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
DHTStorage::remove_old_packets ()
{
  size_t removed_count = 0;
  const int32_t ts = context.ts_now ();

  if (nsfs::is_empty(pbote::fs::DataDirPath("DHTemail").c_str()))
    {
      LogPrint(eLogDebug, "DHTStorage: remove_old_packets: DHTemail directory is empty");
      return;
    }

  {
    std::unique_lock<std::recursive_mutex> l (email_mutex);
    for (const auto& pkt : local_email_packets)
      {
        i2p::data::Tag<32> key;
        key.FromBase64(pkt);
        auto data = getPacket(DataE, key);
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

        if (Delete(DataE, key))
          removed_count++;
        else
          LogPrint(eLogError, "DHTStorage: remove_old_packets: can't remove file: ", pkt);
      }
  }

  LogPrint(eLogDebug, "DHTStorage: remove_old_packets: packets removed: ", removed_count);
}

void
DHTStorage::remove_old_entries ()
{
  size_t removed_entries = 0, removed_packets = 0;

  if (nsfs::is_empty(pbote::fs::DataDirPath("DHTindex").c_str()))
    {
      LogPrint(eLogDebug, "DHTStorage: remove_old_entries: DHTindex directory is empty");
      return;
    }

  const int32_t ts = context.ts_now ();
  std::set<std::string> index_copy = local_index_packets;
  for (const auto& pkt : index_copy)
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

} // kademlia
} // pbote
