/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <cassert>
#include <cstdio>
#include <fstream>
#include <iostream>

#include "BoteContext.h"
#include "compat.h"
#include "Email.h"

// libi2pd
#include "Gzip.h"

namespace bote
{

void *
_lzmaAlloc (ISzAllocPtr, size_t size)
{
  return new uint8_t[size];
}

void
_lzmaFree (ISzAllocPtr, void *addr)
{
  if (!addr)
    return;

  delete[] reinterpret_cast<uint8_t *> (addr);
}

ISzAlloc _allocFuncs
= {
   _lzmaAlloc, _lzmaFree
};

EmailMetadata::EmailMetadata ()
  : m_path(),
    m_dht(),
    m_message_id(),
    m_full_received(0),
    m_fr_count(0),
    m_deleted(false)
{
  m_parts = std::make_shared<std::map<uint16_t, EmailMetadata::Part> >();
}

bool
EmailMetadata::load (const std::string &path)
{
  if (!bote::fs::Exists (path))
  {
    LogPrint (eLogWarning, "EmailMetadata: load: Have no file ", path);
    return false;
  }

  m_path = path;

  char value_delimiter = '=';
  char dot_delimiter = '.';

  std::map<std::string, std::string> kv_lines;
  std::vector<std::string> parts;
  std::ifstream is_file(path);

  /// Read lines and parse by key=value
  std::string line;
  while (std::getline (is_file, line))
    {
      std::istringstream is_line(line);
      std::string key;

      if (std::getline (is_line, key, value_delimiter))
        {
          std::string value;
          if (std::getline (is_line, value)) 
            kv_lines.insert (std::pair<std::string, std::string>(key, value));
        }
    }

  size_t found;
  for (auto l : kv_lines)
    {
      size_t dot_pos = l.first.find (dot_delimiter);
      found = l.first.find (PREFIX_PART);

      /// Add only unique parts prefix like "part0", "part1", etc.
      if (dot_pos != std::string::npos && found != std::string::npos)
        {
          std::string p = l.first.substr (0, dot_pos);
          if (std::find(parts.begin(), parts.end(), p) == parts.end())
            {
              parts.push_back(p);
              LogPrint (eLogDebug, "EmailMetadata: load: ", p);
              continue;
            }
        }

      if (l.first.find (PREFIX_MESSAGE_ID_) != std::string::npos)
        {
          message_id(l.second);
          set_message_id_bytes ();
          continue;
        }

      if (l.first.find (PREFIX_DHT_KEY) != std::string::npos)
        {
          m_dht.FromBase64 (l.second);
          continue;
        }

      if (l.first.find (PREFIX_RECEIVED) != std::string::npos)
        {
          m_full_received = std::stoul(l.second);
          continue;
        }

      if (l.first.find (PREFIX_DELETED) != std::string::npos)
        {
          m_deleted = (std::stoi(l.second) ? true : false);
          continue;
        }

      if (l.first.find (PREFIX_FRAGMENTS) != std::string::npos)
        {
          m_fr_count = std::stoul(l.second);
          continue;
        }

    }

  if (parts.empty ())
    {
      // Not an error, first packet not received for example
      LogPrint (eLogDebug, "EmailMetadata: load: Meta without parts");
    }

  is_file.close();

  LogPrint(eLogDebug, "EmailMetadata: load: mid: ", m_message_id);
  LogPrint(eLogDebug, "EmailMetadata: load: dht_key: ", m_dht.ToBase64 ());
  LogPrint(eLogDebug, "EmailMetadata: load: received: ", m_full_received);
  LogPrint(eLogDebug, "EmailMetadata: load: count: ", m_fr_count);

  /// Now we can start parse values by parts ID's
  for (auto p : parts)
    {
      EmailMetadata::Part temp_part;

      for (auto l : kv_lines)
        {
          // Skipping non-part lines
          if (l.first.find (p) == std::string::npos)
            continue;

          if (l.first.find (PART_ID) != std::string::npos)
            {
              temp_part.id = static_cast<uint16_t>(std::stoul (l.second));
              continue;
            }

          if (l.first.find (PART_DHT_KEY) != std::string::npos)
            {
              temp_part.key.FromBase64 (l.second);
              continue;
            }

          if (l.first.find (PART_DA) != std::string::npos)
            {
              temp_part.DA.FromBase64 (l.second);
              continue;
            }

          if (l.first.find (PART_RECEIVED) != std::string::npos)
            {
              temp_part.received = static_cast<int32_t>(std::stol(l.second));
              continue;
            }

          if (l.first.find (PART_DELETED) != std::string::npos)
            {
              temp_part.deleted = (std::stoi(l.second) ? true : false);
              continue;
            }

          if (l.first.find (PART_DELIVERED) != std::string::npos)
            {
              temp_part.delivered = (std::stoi(l.second) ? true : false);
              continue;
            }
        }
      LogPrint(eLogDebug, "EmailMetadata: load: id: ", temp_part.id);
      LogPrint(eLogDebug, "EmailMetadata: load: dht: ", temp_part.key.ToBase64 ());
      LogPrint(eLogDebug, "EmailMetadata: load: DA: ", temp_part.DA.ToBase64 ());

      m_parts->insert(std::pair<uint16_t, EmailMetadata::Part>(temp_part.id, temp_part));
    }

  // ToDo: Check if malformed

  return true;
}

bool
EmailMetadata::save (const std::string& dir)
{
  if (!dir.empty ())
    LogPrint (eLogDebug, "EmailMetadata: save: dir: ", dir);

  std::string meta_path;
  // If metadata not loaded from file system, and we need to save it first time
  if (!dir.empty () && filename ().empty ())
    {
      meta_path = bote::fs::DataDirPath (dir, message_id () + ".meta");
    }
  else
    meta_path = filename ();

  std::ofstream file (meta_path, std::ofstream::out | std::ofstream::trunc);

  if (!file.is_open ())
    {
      LogPrint(eLogError, "EmailMetadata: save: Can't open file ", meta_path);
      return false;
    }

  /**
   * mid=157d8603-f12d-4d17-93de-02a62cb21111@bote.i2p
   * dht_key=v2424v24hb
   * received=123124125125
   * deleted=0
   * fragments=3
   * part0.id=0
   * part0.key=12315fq234f1
   * part0.DA=1325gw42g344
   * part0.received=123452341234
   * part0.deleted=0
   * part0.delivered=1
   * part1.id=1
   * part1.key=vedrfgvf34tfga
   * part1.DA=sdvfvf2345v
   * part1.received=123423413
   * part1.deleted=1
   * part1.delivered=1
   * part2.id=2
   * part2.key=12d31f134f
   * part2.DA=g1345gq34
   * part2.received=1312341234
   * part2.deleted=0
   * part2.delivered=1
   */

  file << "mid=" << m_message_id << "\n";
  file << "dht_key=" << m_dht.ToBase64 () << "\n";
  file << "received=" << m_full_received << "\n";
  file << "deleted=" << (m_deleted ? "1" : "0") << "\n";
  file << "fragments=" << m_fr_count << "\n";

  for (auto part : (*m_parts))
    {
      file << "part" << part.first <<".id=" << part.second.id << "\n";
      file << "part" << part.first <<".key=" << part.second.key.ToBase64 () << "\n";
      file << "part" << part.first <<".DA=" << part.second.DA.ToBase64 () << "\n";
      file << "part" << part.first <<".received=" << part.second.received << "\n";
      file << "part" << part.first <<".deleted=" << (part.second.deleted ? "1" : "0") << "\n";
      file << "part" << part.first <<".delivered=" << (part.second.delivered ? "1" : "0") << "\n";
    }

  file.close ();

  filename (meta_path);
  LogPrint (eLogDebug, "EmailMetadata: save: Saved to ", meta_path);

  return true;
}

bool
EmailMetadata::move (const std::string& dir)
{
  std::string new_path = bote::fs::DataDirPath (dir, message_id () + ".meta");

  LogPrint (eLogDebug, "EmailMetadata: move: old path: ", filename ());
  LogPrint (eLogDebug, "EmailMetadata: move: new path: ", new_path);

  std::ifstream ifs (filename (), std::ios::in | std::ios::binary);
  std::ofstream ofs (new_path, std::ios::out | std::ios::binary);

  ofs << ifs.rdbuf ();

  int status = std::remove (filename ().c_str ());

  if (status != 0)
    {
      LogPrint (eLogError, "EmailMetadata: move: Can't move file ", filename (),
            " to ", new_path);
      return false;
    }

  
  LogPrint (eLogInfo, "EmailMetadata: move: File ", filename (),
            " moved to ", new_path);
  filename (new_path);

  return true;
}

void
EmailMetadata::message_id (std::string id)
{
  m_message_id = id;
  set_message_id_bytes ();
}

void
EmailMetadata::set_message_id_bytes ()
{
  std::vector<uint8_t> res;
  /// Example: 27d92c57-0503-4dd6-9bb3-fa2d0613855f
  for (int i = 0; i < 36; i++)
    {
      if (!MESSAGE_ID_TEMPLATE[i])
        res.push_back (m_message_id.c_str ()[i]);
    }

  m_message_id_bytes = res;
}

void
EmailMetadata::message_id_bytes (const std::vector<uint8_t> &bytes)
{
  i2p::data::Tag<32> mid(bytes.data ());
  LogPrint (eLogDebug, "EmailMetadata: message_id_bytes: mid: ", mid.ToBase64 ());

  m_message_id_bytes = bytes;
  set_message_id_string ();
}

void
EmailMetadata::set_message_id_string ()
{
  if (m_message_id_bytes.size () < 32)
    {
      LogPrint (eLogError, "EmailMetadata: set_message_id_string: Too short: ",
                m_message_id_bytes.size ());
      return;
    }

  std::stringstream ss;
  /// Example: 27d92c57-0503-4dd6-9bb3-fa2d0613855f
  int counter = 0;
  for (int i = 0; i < 36; i++)
    {
      if (MESSAGE_ID_TEMPLATE[i])
        ss << "-";
      else
        {
          ss << m_message_id_bytes[counter];
          counter++;
        }
    }

  ss << "@bote.i2p";

  LogPrint (eLogDebug, "EmailMetadata: set_message_id_string: ", ss.str ());

  m_message_id = ss.str ();
}

bool
EmailMetadata::is_full ()
{
  LogPrint (eLogDebug, "EmailMetadata: m_parts: ", m_parts->size ());
  LogPrint (eLogDebug, "EmailMetadata: m_fr_count: ", m_fr_count);
  return m_parts->size () == m_fr_count;
}

bool
EmailMetadata::delivered ()
{
  for (auto p : (*m_parts))
    {
      if (!p.second.delivered)
        {
          LogPrint (eLogDebug, "EmailMetadata: delivered: part ",
                p.second.key.ToBase64 (), " not delivered");
          return false;
        }
    }

  return true;
}

void
EmailMetadata::add_part (EmailMetadata::Part p)
{
  LogPrint (eLogDebug, "EmailMetadata: add_part, id: ", p.id);
  LogPrint (eLogDebug, "EmailMetadata: add_part, key: ", p.key.ToBase64 ());
  LogPrint (eLogDebug, "EmailMetadata: add_part, DA: ", p.DA.ToBase64 ());
  m_parts->insert(std::pair<uint16_t, Part>(p.id, p));
}

size_t
EmailMetadata::fill (std::shared_ptr<bote::DeletionInfoPacket> packet)
{
  size_t valid = 0;
  for (uint16_t id = 0; id < m_parts->size (); id++)
    {
      if ((*m_parts)[id].deleted || (*m_parts)[id].delivered)
        continue;

      if (packet->item_exist ((*m_parts)[id].key.data (),
                             (*m_parts)[id].DA.data ()))
        {
          LogPrint (eLogDebug, "EmailMetadata: fill: Mark delivered part: ",
                id, ", key: ", (*m_parts)[id].key.ToBase64 ());
          (*m_parts)[id].delivered = true;
          (*m_parts)[id].received = context.ts_now ();
          valid++;
        }
    }

  return valid;
}

///////////////////////////////////////////////////////////////////////////////

Email::Email ()
  : m_incomplete (false),
    m_empty (true),
    m_skip (false),
    sender (nullptr),
    recipient (nullptr)
{
  m_metadata = std::make_shared<EmailMetadata>();
}

void
Email::fromMIME (const std::vector<uint8_t> &email_data)
{
  std::string message(email_data.begin(), email_data.end());
  mail.load(message.begin(), message.end());

  for (const auto &entity : mail.header())
    {
      auto it = std::find(HEADER_WHITELIST.begin(), HEADER_WHITELIST.end(),
                          entity.name());
      if (it != HEADER_WHITELIST.end())
        {
          LogPrint(eLogDebug, "Email: fromMIME: ", entity.name(), ": ",
                   entity.value());
        }
      else
        {
          mail.header().field(entity.name()).value("");
          LogPrint(eLogDebug, "Email: fromMIME: Forbidden header ",
                   entity.name(), " removed");
        }
    }

  m_empty = false;
  compose ();
}

void
Email::set_message_id ()
{
  std::string meta_mid = m_metadata->message_id ();
  if (!meta_mid.empty ())
    {
      LogPrint (eLogDebug, "Email: set_message_id: Meta Message-ID: ", meta_mid);
      return;
    }

  std::string mail_mid = field ("Message-ID");
  if (!mail_mid.empty ())
    {
      char chars[] = "<>";

      for (size_t i = 0; i < strlen(chars); ++i)
        {
          mail_mid.erase (std::remove(mail_mid.begin(),
                                      mail_mid.end(),
                                      chars[i]),
                          mail_mid.end());
        }

      m_metadata->message_id (mail_mid);
      LogPrint (eLogDebug, "Email: set_message_id: Mail Message-ID: ", mail_mid);
      return;
    }

  mail_mid = generate_uuid_v4 ();
  mail_mid.append ("@bote.i2p");

  LogPrint (eLogDebug, "Email: set_message_id: New Message-ID: ", mail_mid);

  setField ("Message-ID", mail_mid);
  m_metadata->message_id (mail_mid);
}

std::string
Email::get_message_id ()
{
  std::string mail_mid = field ("Message-ID");

  if (mail_mid.empty ())
    {
      LogPrint (eLogDebug, "Email: get_message_id: Message-ID is empty");
      set_message_id ();
    }
  else if (mail_mid.size () == 36 && mail_mid.c_str ()[14] != 4)
    {
      LogPrint (eLogDebug, "Email: get_message_id: Message-ID is not V4");
      set_message_id ();
    }

  return m_metadata->message_id ();
}

void
Email::set_message_id_bytes ()
{
  std::string message_id = get_message_id ();
  std::vector<uint8_t> res;
  /// Example: 27d92c57-0503-4dd6-9bb3-fa2d0613855f
  for (int i = 0; i < 36; i++)
    {
      if (!MESSAGE_ID_TEMPLATE[i])
        res.push_back (message_id.c_str ()[i]);
    }

  m_metadata->message_id_bytes (res);
}

std::string
Email::hashcash ()
{
  /**
   * Format:
   * version: currently 1
   * bits: the number of leading bits that are 0
   * timestamp: a date/time stamp (time is optional)
   * resource: the data string being transmitted, for example, an IP address, email address, or other data
   * extension: ignored in version 1
   * random seed: base-64 encoded random set of characters
   * counter: base-64 encoded binary counter between 0 and 220, (1,048,576)
   *
   * Example:
   * 1:20:1303030600:admin@example.com::McMybZIhxKXu57jd:FOvXX
   */

  /*
  uint8_t version = 1;
  uint8_t bits = 20;
  std::string resource ("admin@example.com"), extension, seed, counter;

  const int32_t ts_now = context.ts_now ();
  // ToDo: think about it
  seed = std::string("McMybZIhxKXu57jd");
  counter = std::string("FOvXX");

  std::string hc_s;
  hc_s.append ("" + version);
  hc_s.append (":" + bits);
  hc_s.append (":" + ts_now);
  hc_s.append (":" + resource);
  hc_s.append (":" + extension);
  hc_s.append (":" + seed);
  hc_s.append (":" + counter);
  */

  // ToDo: temp, TBD
  std::string hc_s ("1:20:1303030600:admin@example.com::McMybZIhxKXu57jd:FOvXX");
  LogPrint (eLogDebug, "Email: hashcash: hashcash: ", hc_s);
  //std::vector<uint8_t> result (hc_s.begin(), hc_s.end());

  //return result;
  return hc_s;
}

std::string
Email::get_from_label ()
{
  return mail.header().from().begin()->label();
}

std::string
Email::get_from_mailbox ()
{
  return mail.header().from().begin()->mailbox();
}

std::string
Email::get_from_address ()
{
  auto mailbox = mail.header().from().begin()->mailbox();
  auto domain = mail.header().from().begin()->domain();
  return mailbox + "@" + domain;
}

std::string
Email::get_to_label ()
{
  return mail.header().to().begin()->mailbox().label();
}

std::string
Email::get_to_mailbox ()
{
  return mail.header().to().begin()->mailbox().mailbox();
}

std::string
Email::get_to_addresses ()
{
  auto mailbox = mail.header().to().begin()->mailbox().mailbox();
  auto domain = mail.header().to().begin()->mailbox().domain();
  return mailbox + "@" + domain;
}

bool
Email::verify ()
{
  // ToDo: verify signature
  return true;
}

void
Email::compose ()
{
  if (m_composed)
    return;

  set_message_id ();
  set_message_id_bytes ();

  LogPrint (eLogDebug, "Email: compose: Message-ID: ", get_message_id ());
  LogPrint (eLogDebug, "Email: compose: Message-ID bytes: ",
            get_message_id_bytes ().ToBase64 ());

  setField ("X-HashCash", hashcash ());

  std::stringstream buffer;
  buffer << mail;
  std::string str_buf = buffer.str ();

  // For debug only
  //*
  if (str_buf.size () > 1000)
    {
      std::string mess_begin = str_buf.substr (0, 1000);
      std::string mess_end = str_buf.substr (str_buf.size ()-1000,
                                             str_buf.size ());
      LogPrint (eLogDebug, "Email: compose: content:\n", mess_begin,
                "\n\n...\n\n", mess_end, "\n");
    }
  else
    LogPrint (eLogDebug, "Email: compose: content:\n", str_buf);
  //*/

  full_bytes = std::vector<uint8_t> (str_buf.begin (), str_buf.end ());

  m_empty = false;
  m_incomplete = false;
  m_composed = true;
}

bool
Email::split ()
{
  if (skip ())
    return false;

  if (m_splitted)
    return true;

  size_t full_parts = full_bytes.size () / (MAX_DATAGRAM_LEN - PACKET_MAX_OVERHEAD);
  size_t remainder_parts = full_bytes.size () % (MAX_DATAGRAM_LEN - PACKET_MAX_OVERHEAD);
  m_metadata->fr_count (remainder_parts > 0 ? full_parts + 1 : full_parts);
  size_t full_size = full_bytes.size ();
  size_t offset = 0;
  size_t part_max_size = MAX_DATAGRAM_LEN - PACKET_MAX_OVERHEAD;

  LogPrint (eLogDebug, "Email: split: Email parts: ", m_metadata->fr_count ());

  while ((offset + remainder_parts) < full_size)
    {
      bote::EmailUnencryptedPacket packet;
      memcpy (packet.mes_id, m_metadata->message_id_bytes ().data (), 32);
      packet.data = std::vector<uint8_t>(full_bytes.begin () + offset,
                                         full_bytes.begin () + offset + part_max_size);
      packet.length = packet.data.size ();

      m_plain_parts.push_back (std::make_shared<bote::EmailUnencryptedPacket>(packet));

      offset += part_max_size;
    }

  /// Remain part
  bote::EmailUnencryptedPacket packet;
  memcpy (packet.mes_id, m_metadata->message_id_bytes ().data (), 32);
  packet.data = std::vector<uint8_t>(full_bytes.begin () + offset,
                                     full_bytes.begin () + offset + remainder_parts);
  packet.length = packet.data.size ();

  m_plain_parts.push_back (std::make_shared<bote::EmailUnencryptedPacket>(packet));

  if (offset + remainder_parts < full_size)
    {
      LogPrint (eLogError, "Email: split: Can't split MIME message, parsed: ",
                offset + remainder_parts, ", full: ", full_size);
      skip (true);
      return false;
    }

  if (m_plain_parts.size () != m_metadata->fr_count ())
    {
      LogPrint (eLogError, "Email: split: Parts count unequal, plain: ",
                m_plain_parts.size (), ", metadata: ", m_metadata->fr_count ());
      skip (true);
      return false;
    }

  /// Filling metadata from plain part
  for (uint16_t id = 0; id < m_metadata->fr_count (); id++)
    {
      if (memcmp(m_plain_parts[id]->DA, zero_array, 32) == 0)
        context.random_cid (m_plain_parts[id]->DA, 32);

      i2p::data::Tag<32> del_auth (m_plain_parts[id]->DA);
      LogPrint (eLogDebug, "Email: split: ", id, ": Message DA: ",
                del_auth.ToBase64 ());

      auto meta_parts = m_metadata->get_parts ();

      auto found = meta_parts->find(id);
      if (found != meta_parts->end ())
        {
          found->second.id = id;
          found->second.DA = m_plain_parts[id]->DA;
        }
      else
        {
          EmailMetadata::Part new_part;

          new_part.id = id;
          new_part.DA = m_plain_parts[id]->DA;

          meta_parts->insert (std::pair<uint16_t, bote::EmailMetadata::Part>(id, new_part));
        }

      m_plain_parts[id]->fr_id = id;
      m_plain_parts[id]->fr_count = m_metadata->fr_count ();
      m_plain_parts[id]->length = m_plain_parts[id]->data.size ();
    }

  m_splitted = true;

  return true;
}

bool
Email::fill_storable ()
{
  if (skip ())
    return false;

  for (uint16_t id = 0; id < m_metadata->fr_count (); id++)
    {
      StoreRequestPacket storable_part;

      auto part_hashcash = hashcash ();
      LogPrint (eLogDebug, "Email: fill_storable: ", id, ": hashcash: ",
                part_hashcash);

      storable_part.hashcash = std::vector<uint8_t> (part_hashcash.begin(),
                                                     part_hashcash.end());

      storable_part.hc_length = storable_part.hashcash.size ();
      LogPrint (eLogDebug, "Email: fill_storable: ", id,
                ": storable_part.hc_length: ", storable_part.hc_length);

      storable_part.data = m_enc_parts[id]->toByte ();
      storable_part.length = storable_part.data.size ();

      i2p::data::Tag<32> email_dht_key (m_enc_parts[id]->key);

      m_storable_parts.insert (std::pair<i2p::data::Tag<32>, StoreRequestPacket> (email_dht_key, storable_part));
    }

  auto recipient = get_recipient ();
  memcpy (&m_index.hash, recipient->GetIdentHash ().data (), 32);

  for (const auto &enc_part : m_enc_parts)
    {
      IndexPacket::Entry entry;
      memcpy (entry.key, enc_part->key, 32);
      memcpy (entry.dv, enc_part->delete_hash, 32);
      entry.time = context.ts_now ();

      m_index.data.push_back (entry);
    }

  m_index.nump = m_index.data.size ();

  /// For now it's not checking from Java-Bote side
  auto index_hashcash = hashcash ();
  LogPrint (eLogDebug, "Email: split: hashcash: ", index_hashcash);

  m_storable_index.hashcash = std::vector<uint8_t> (index_hashcash.begin(),
                                                 index_hashcash.end());
  m_storable_index.hc_length = m_storable_index.hashcash.size ();
  LogPrint (eLogDebug, "EmailWorker: Send: store_index.hc_length: ",
            m_storable_index.hc_length);

  m_storable_index.data = m_index.toByte ();
  m_storable_index.length = m_storable_index.data.size ();

  return true;
}

bool
Email::restore ()
{
  if (!m_metadata->is_full ())
    {
      LogPrint(eLogInfo, "Email: restore: Mail not complete");
      return false;
    }

  full_bytes = std::vector<uint8_t>();

  auto meta_parts = m_metadata-> get_parts();
  for (size_t i = 0; i < meta_parts->size (); i++)
    {
      auto meta_part = meta_parts->find (i);
      if (meta_part == meta_parts->end ())
        {
          LogPrint(eLogInfo, "Email: restore: Mail not complete");
          return false;
        }

      i2p::data::Tag<32> part_dht_key((*meta_part).second.key);

      std::string plain_part_path
          = bote::fs::DataDirPath ("incomplete",
                                   part_dht_key.ToBase64 () + ".pkt");

      if (!bote::fs::Exists(plain_part_path))
        {
          LogPrint(eLogWarning, "Email: restore: Have no file ", plain_part_path);
          return false;
        }

      std::ifstream file (plain_part_path, std::ios::binary);
      std::vector<uint8_t> data ((std::istreambuf_iterator<char> (file)),
                                 (std::istreambuf_iterator<char> ()));
      file.close ();

      if (data.empty ())
        return false;

      EmailUnencryptedPacket packet;
      bool parsed = packet.fromBuffer (data, true);
      if (!parsed)
        {
          LogPrint(eLogWarning, "Email: restore: Can't parse ", plain_part_path);
          return false;
        }

      full_bytes.insert (full_bytes.end (),
                         packet.data.begin (),
                         packet.data.end ());
    }

  decompress (full_bytes);

  return true;
}

bool
Email::save (const std::string &dir)
{
  std::string emailPacketPath;
  // If email not loaded from file system, and we need to save it first time
  if (!dir.empty () && filename ().empty ())
    {
      emailPacketPath = bote::fs::DataDirPath (dir, get_message_id () + ".mail");

      if (bote::fs::Exists (emailPacketPath))
        {
          return false;
        }
    }
  else
    {
      emailPacketPath = filename ();
    }

  std::ofstream file (emailPacketPath, std::ofstream::binary | std::ofstream::out);

  if (!file.is_open ())
    {
      LogPrint(eLogError, "Email: save: Can't open file ", emailPacketPath);
      return false;
    }

  file.write (reinterpret_cast<const char *> (full_bytes.data ()),
                                              full_bytes.size ());
  file.close ();

  LogPrint (eLogDebug, "Email: save: Saved to ", emailPacketPath);

  nsfs::path p = emailPacketPath;
  std::string p_dir = p.parent_path ().string ();
  std::string subdir = p_dir.substr (bote::fs::GetDataDir ().size () + 1);
  LogPrint (eLogDebug, "Email: save: Subdir: ", subdir);
  m_metadata->save (subdir);

  return true;
}

bool
Email::move (const std::string &dir)
{
  if (skip ())
    return false;

  std::string new_path
      = bote::fs::DataDirPath (dir, m_metadata->message_id () + ".mail");

  LogPrint (eLogDebug, "Email: move: old path: ", filename ());
  LogPrint (eLogDebug, "Email: move: new path: ", new_path);

  std::ifstream ifs (filename (), std::ios::in | std::ios::binary);
  std::ofstream ofs (new_path, std::ios::out | std::ios::binary);

  ofs << ifs.rdbuf ();

  int status = std::remove (filename ().c_str ());

  if (status != 0)
    {
      LogPrint (eLogError, "Email: move: Can't move file ", filename (), " to ", new_path);
      return false;
    }

  LogPrint (eLogInfo, "Email: move: File ", filename (), " moved to ", new_path);

  filename (new_path);
  m_metadata->move (dir);

  return true;
}

void
Email::encrypt ()
{
  if (skip ())
    return;

  if (m_encrypted)
    return;

  for (uint16_t id = 0; id < m_metadata->fr_count (); id++)
    {
      bote::EmailEncryptedPacket encrypted;

      SHA256 (m_plain_parts[id]->DA, 32, encrypted.delete_hash);

      //* For debug only
      i2p::data::Tag<32> del_hash (encrypted.delete_hash),
                         del_auth (m_plain_parts[id]->DA);
      LogPrint (eLogDebug, "Email: encrypt: ", id,
                ": del_auth: ", del_auth.ToBase64 ());
      LogPrint (eLogDebug, "Email: encrypt: ", id,
                ": del_hash: ", del_hash.ToBase64 ());
      //*/

      LogPrint (eLogDebug, "Email: encrypt: ", id,
                ": plain_part.data.size: ", m_plain_parts[id]->data.size ());

      auto part_bytes = m_plain_parts[id]->toByte ();

      if (!sender)
        {
          LogPrint (eLogError, "Email: encrypt: ", id,
                    ": Sender error");
          skip (true);
          return;
        }

      encrypted.edata = sender->GetPublicIdentity ()->Encrypt (
              part_bytes.data (), part_bytes.size (),
              recipient->GetCryptoPublicKey ());

      if (encrypted.edata.empty ())
        {
          LogPrint (eLogError, "Email: encrypt: ", id,
                    ": Encrypted data is empty, skipped");
          skip (true);
          return;
        }

      encrypted.length = encrypted.edata.size ();
      encrypted.alg = sender->GetKeyType ();
      encrypted.stored_time = 0;

      LogPrint (eLogDebug, "Email: encrypt: ", id,
                ": encrypted.edata.size(): ", encrypted.edata.size ());

      /// Get hash of data + length for DHT key
      const size_t data_for_hash_len = 2 + encrypted.edata.size ();
      std::vector<uint8_t> data_for_hash
          = { static_cast<uint8_t> (encrypted.length >> 8),
              static_cast<uint8_t> (encrypted.length & 0xff) };
      data_for_hash.insert (data_for_hash.end (), encrypted.edata.begin (), encrypted.edata.end ());

      SHA256 (data_for_hash.data (), data_for_hash_len, encrypted.key);

      i2p::data::Tag<32> dht_key (encrypted.key);
      LogPrint (eLogDebug, "Email: encrypt: ", id,
                ": dht_key: ", dht_key.ToBase64 ());
      LogPrint (eLogDebug, "Email: encrypt: ", id,
                ": encrypted.length : ", encrypted.length);

      m_enc_parts.push_back (std::make_shared<bote::EmailEncryptedPacket>(encrypted));

      /// Set DHT key to metadata
      auto meta_parts = m_metadata->get_parts ();

      auto found = meta_parts->find(id);
      if (found != meta_parts->end ())
        {
          found->second.key = dht_key;
        }
      else
        {
          LogPrint (eLogError, "Email: encrypt: ", id,
                    ": No metadata for part, skipped");
          skip (true);
          return;
        }
    }

  m_encrypted = true;
}

bool
Email::compress (CompressionAlgorithm type)
{
  LogPrint (eLogDebug, "Email: compress: alg: ", unsigned (type));

  if (type == CompressionAlgorithm::LZMA)
    {
      LogPrint (eLogWarning, "Email: compress: We not support compression LZMA, will be uncompressed");
      type = CompressionAlgorithm::UNCOMPRESSED;
    }

  if (type == CompressionAlgorithm::ZLIB)
    {
      LogPrint (eLogDebug, "Email: compress: ZLIB, start compress");

      std::vector<uint8_t> output;
      zlibCompress (output, full_bytes);

      full_bytes.push_back (uint8_t (CompressionAlgorithm::ZLIB));
      full_bytes.insert (full_bytes.end (), output.begin (), output.end ());
      LogPrint (eLogDebug, "Email: compress: ZLIB compressed");

      return true;
    }

  LogPrint (eLogDebug, "Email: compress: Data uncompressed, save as is");

  full_bytes.insert (full_bytes.begin (),
                     (uint8_t) CompressionAlgorithm::UNCOMPRESSED);

  return true;
}

void
Email::decompress (std::vector<uint8_t> v_mail)
{
  size_t offset = 0;
  uint8_t compress_alg;
  memcpy (&compress_alg, v_mail.data () + offset, 1);
  offset += 1;

  LogPrint (eLogDebug, "Email: decompress: compress alg: ", unsigned (compress_alg));

  if (compress_alg == CompressionAlgorithm::LZMA)
    {
      LogPrint (eLogDebug, "Email: decompress: LZMA compressed, start decompress");
      std::vector<uint8_t> output;
      lzmaDecompress (output,
                      std::vector<uint8_t>(v_mail.data() + offset,
                                           v_mail.data() + v_mail.size()));
      full_bytes = output;
      LogPrint (eLogDebug, "Email: compress: LZMA decompressed");
      return;
    }

  if (compress_alg == CompressionAlgorithm::ZLIB)
    {
      LogPrint (eLogDebug, "Email: decompress: ZLIB compressed, start decompress");
      std::vector<uint8_t> output;
      zlibDecompress (output,
                      std::vector<uint8_t>(v_mail.data() + offset,
                                           v_mail.data() + v_mail.size()));
      full_bytes = output;
      LogPrint (eLogDebug, "Email: compress: ZLIB decompressed");
      return;
    }

  if (compress_alg == CompressionAlgorithm::UNCOMPRESSED)
    {
      LogPrint (eLogDebug, "Email: decompress: data uncompressed, save as is");
      full_bytes = std::vector<uint8_t> (v_mail.begin () + 1, v_mail.end ());
      return;
    }

  LogPrint(eLogWarning, "Email: decompress: Unknown compress algorithm, try to save as is");
  full_bytes = std::vector<uint8_t>(v_mail.begin() + 1, v_mail.end());
}

std::string
Email::generate_uuid_v4 ()
{
  static std::random_device              rd;
  static std::mt19937                    gen (rd ());
  static std::uniform_int_distribution<> dis (0, 15);
  static std::uniform_int_distribution<> dis2 (8, 11); // variant 1

  std::stringstream ss;
  int i;

  ss << std::hex;
  for (i = 0; i < 8; i++)
    ss << dis (gen);

  ss << "-";
  for (i = 0; i < 4; i++)
    ss << dis (gen);

  ss << "-4";
  for (i = 0; i < 3; i++)
    ss << dis (gen);

  ss << "-";
  ss << dis2 (gen);
  for (i = 0; i < 3; i++)
    ss << dis (gen);

  ss << "-";
  for (i = 0; i < 12; i++)
    ss << dis (gen);

  return ss.str ();
}

void
Email::lzmaDecompress (std::vector<uint8_t> &outBuf,
                       const std::vector<uint8_t> &inBuf)
{
  CLzmaDec dec;

  LzmaDec_Construct (&dec);
  SRes res = LzmaDec_Allocate (&dec, &inBuf[0], LZMA_PROPS_SIZE, &_allocFuncs);
  assert (res == SZ_OK);

  if (res == SZ_OK)
    LogPrint (eLogDebug, "Email: lzmaDecompress: Assert passed");

  LzmaDec_Init (&dec);

  unsigned outPos = 0, inPos = LZMA_PROPS_SIZE;
  ELzmaStatus status;
  const size_t BUF_SIZE = 10240;
  outBuf.resize (25 * 1024 * 1024);

  while (outPos < outBuf.size ())
    {
      SizeT destLen = std::min (BUF_SIZE, outBuf.size () - outPos);
      SizeT srcLen = std::min (BUF_SIZE, inBuf.size () - inPos);

      res = LzmaDec_DecodeToBuf (&dec,
                                 &outBuf[outPos], &destLen,
                                 &inBuf[inPos], &srcLen,
                                 (outPos + destLen == outBuf.size ())
                                 ? LZMA_FINISH_END : LZMA_FINISH_ANY, &status);
      assert (res == SZ_OK);
      inPos += srcLen;
      outPos += destLen;
      if (status == LZMA_STATUS_FINISHED_WITH_MARK)
        {
          LogPrint (eLogDebug, "Email: lzmaDecompress: Finished with mark");
          break;
        }
    }

  LzmaDec_Free (&dec, &_allocFuncs);
  outBuf.resize (outPos);
}

void
Email::zlibCompress (std::vector<uint8_t> &outBuf,
                     const std::vector<uint8_t> &inBuf)
{
  i2p::data::GzipInflator inflator;
  inflator.Inflate (inBuf.data (), inBuf.size (),
                    outBuf.data (), outBuf.size ());
}

void
Email::zlibDecompress (std::vector<uint8_t> &outBuf,
                       const std::vector<uint8_t> &inBuf)
{
  i2p::data::GzipDeflator deflator;
  deflator.Deflate (inBuf.data (), inBuf.size (),
                    outBuf.data (), outBuf.size ());
}

void
Email::set_sender_identity (sp_id_full identity)
{
  if (!identity)
    {
      LogPrint (eLogWarning, "Email: set_sender: Can't set "
                "sender identity, skipped");
      skip (true);
      return;
    }

  sender = std::make_shared<BoteIdentityPrivate>(identity->identity);
  std::string addr = sender->GetPublicIdentity ()->ToBase64v1 ();

  std::string old_from_address = field("From");
  std::string new_from;
  new_from.append (identity->publicName + " <b64." + addr + ">");

  set_from (new_from);
  set_sender (new_from);

  LogPrint (eLogDebug, "EmailWorker: set_sender: FROM replaced, old: ",
                old_from_address, ", new: ", new_from);

  LogPrint (eLogDebug, "Email: set_sender: sender: ", sender->ToBase64 ());
  LogPrint (eLogDebug, "Email: set_sender: email: sender hash: ",
            sender->GetIdentHash ().ToBase64 ());
}

void
Email::set_recipient_identity (std::string to_address)
{
  LogPrint (eLogDebug, "Email: set_recipient: to_address: ", to_address);

  std::string format_prefix = to_address.substr(0, to_address.find(".") + 1);

  if (format_prefix.compare(ADDRESS_B32_PREFIX) == 0)
    recipient = parse_address_v1(to_address);
  else if (format_prefix.compare(ADDRESS_B64_PREFIX) == 0)
    recipient = parse_address_v1(to_address);
  else
    recipient = parse_address_v0(to_address);

  if (recipient == nullptr)
    {
      LogPrint (eLogWarning, "Email: set_recipient: Can't create "
                "recipient from \"TO\" header, skip mail");
      skip (true);

      return;
    }

  m_metadata->dht (recipient->GetIdentHash ());

  LogPrint (eLogDebug, "Email: set_recipient: recipient: ",
            recipient->ToBase64 ());
  LogPrint (eLogDebug, "Email: set_recipient: recipient hash: ",
            recipient->GetIdentHash ().ToBase64 ());
}

sp_id_public
Email::parse_address_v0(std::string address)
{
  BoteIdentityPublic identity;
  size_t base64_key_len = 0, offset = 0;

  if (address.length() == ECDH256_ECDSA256_PUBLIC_BASE64_LENGTH)
    {
      identity = BoteIdentityPublic(KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC);
      base64_key_len = ECDH256_ECDSA256_PUBLIC_BASE64_LENGTH / 2;
    }
  else if (address.length() == ECDH521_ECDSA521_PUBLIC_BASE64_LENGTH)
    {
      identity = BoteIdentityPublic(KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC);
      base64_key_len = ECDH521_ECDSA521_PUBLIC_BASE64_LENGTH / 2;
    }
  else
    {
      LogPrint(eLogWarning, "EmailWorker: parse_address_v0: Unsupported identity type");
      return nullptr;
    }

  // Restore keys
  std::string cryptoPublicKey = "A" + address.substr(offset, (base64_key_len));
  offset += (base64_key_len);
  std::string signingPublicKey = "A" + address.substr(offset, (base64_key_len));

  std::string restored_identity_str;
  restored_identity_str.append(cryptoPublicKey);
  restored_identity_str.append(signingPublicKey);

  identity.FromBase64(restored_identity_str);

  LogPrint(eLogDebug, "EmailWorker: parse_address_v0: identity.ToBase64: ",
           identity.ToBase64());
  LogPrint(eLogDebug, "EmailWorker: parse_address_v0: idenhash.ToBase64: ",
           identity.GetIdentHash().ToBase64());

  return std::make_shared<BoteIdentityPublic>(identity);
}

sp_id_public
Email::parse_address_v1(std::string address)
{
  BoteIdentityPublic identity;
  std::string format_prefix = address.substr (0, address.find (".") + 1);
  std::string base_str = address.substr (format_prefix.length ());
  // ToDo: Define length from base32/64
  uint8_t identity_bytes[2048];
  size_t identity_len = 0;

  if (format_prefix.compare (ADDRESS_B32_PREFIX) == 0)
    identity_len = i2p::data::Base32ToByteStream (base_str.c_str (), base_str.length (), identity_bytes, 2048);
  else if (format_prefix.compare (ADDRESS_B64_PREFIX) == 0)
    identity_len = i2p::data::Base64ToByteStream (base_str.c_str (), base_str.length (), identity_bytes, 2048);
  else
    return nullptr;

  if (identity_len < 5)
    {
      LogPrint (eLogError, "identitiesStorage: parse_identity_v1: Malformed address");
      return nullptr;
    }

  if (identity_bytes[0] != ADDRESS_FORMAT_V1)
    {
      LogPrint (eLogError, "identitiesStorage: parse_identity_v1: Unsupported address format");
      return nullptr;
    }

  if (identity_bytes[1] == CRYP_TYPE_ECDH256 &&
      identity_bytes[2] == SIGN_TYPE_ECDSA256 &&
      identity_bytes[3] == SYMM_TYPE_AES_256 &&
      identity_bytes[4] == HASH_TYPE_SHA_256)
    {
      identity = BoteIdentityPublic(KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC);
    }
  else if (identity_bytes[1] == CRYP_TYPE_ECDH521 &&
           identity_bytes[2] == SIGN_TYPE_ECDSA521 &&
           identity_bytes[3] == SYMM_TYPE_AES_256 &&
           identity_bytes[4] == HASH_TYPE_SHA_512)
    {
      identity = BoteIdentityPublic(KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC);
    }
  else if (identity_bytes[1] == CRYP_TYPE_X25519 &&
           identity_bytes[2] == SIGN_TYPE_ED25519 &&
           identity_bytes[3] == SYMM_TYPE_AES_256 &&
           identity_bytes[4] == HASH_TYPE_SHA_512)
    {
      identity = BoteIdentityPublic(KEY_TYPE_X25519_ED25519_SHA512_AES256CBC);
    }

  size_t len = identity.FromBuffer(identity_bytes + 5, identity_len);

  if (len == 0)
    return nullptr;

  LogPrint(eLogDebug, "identitiesStorage: parse_identity_v1: identity.ToBase64: ",
           identity.ToBase64());
  LogPrint(eLogDebug, "identitiesStorage: parse_identity_v1: idenhash.ToBase64: ",
           identity.GetIdentHash().ToBase64());

  return std::make_shared<BoteIdentityPublic>(identity);
}

} // bote
