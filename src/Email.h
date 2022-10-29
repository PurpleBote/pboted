/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#pragma once
#ifndef PBOTED_SRC_EMAIL_H
#define PBOTED_SRC_EMAIL_H

#include <map>
#include <mimetic/mimetic.h>
#include <string>
#include <vector>

#include "LzmaDec.h"
#include "LzmaEnc.h"
#include "7zTypes.h"

#include "BoteIdentity.h"
#include "Packet.h"

namespace pbote
{

#define MAX_HEADER_LENGTH 998

/** The maximum number of bytes by which EncryptedEmailPacket
 *  can be bigger than the UnencryptedEmailPacket
 *  ToDo: need to verify
 */
//const size_t PACKET_MAX_OVERHEAD = 641;
const size_t PACKET_MAX_OVERHEAD = 4000; // FOR TESTS
const size_t MAX_DATAGRAM_LEN = 32768;

const uint8_t zero_array[32] = {0};

const bool MESSAGE_ID_TEMPLATE[]
    = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

using sp_id_full = std::shared_ptr<pbote::BoteIdentityFull>;
using sp_id_private = std::shared_ptr<pbote::BoteIdentityPrivate>;
using sp_id_public = std::shared_ptr<pbote::BoteIdentityPublic>;
using v_sp_plain_email = std::vector<std::shared_ptr<pbote::EmailUnencryptedPacket> >;

// contains the sender's base64-encoded signature
const std::string SIGNATURE_HEADER = "X-I2PBote-Signature";
// contains the string "true" or "false"
const std::string SIGNATURE_VALID_HEADER = "X-I2PBote-Sig-Valid";
const std::vector<std::string> HEADER_WHITELIST
= {
   "From",
   "Sender",
   "Reply-To",
   "In-Reply-To",
   "To",
   "CC",
   "BCC",
   "Date",
   "Subject",
   "Content-Type",
   "Content-Transfer-Encoding",
   "MIME-Version",
   "Message-ID",
   "X-HashCash",
   "X-Priority",
   SIGNATURE_HEADER
};

const std::string PREFIX_MESSAGE_ID_ = "mid";
const std::string PREFIX_DHT_KEY = "dht_key";
const std::string PREFIX_RECEIVED = "received";
const std::string PREFIX_DELETED = "deleted";
const std::string PREFIX_FRAGMENTS = "fragments";
const std::string PREFIX_PART = "part";

const std::string PART_ID = "id";
const std::string PART_DHT_KEY = "key";
const std::string PART_DA = "DA";
const std::string PART_RECEIVED = "received";
const std::string PART_DELETED = "deleted";
const std::string PART_DELIVERED = "delivered";

const std::string META_FILE_EXTENSION = ".meta";

class EmailMetadata
{
 public:
  struct Part
    {
      uint16_t id = 0;
      i2p::data::Tag<32> key = {};
      i2p::data::Tag<32> DA = {};
      int32_t received = 0;
      bool deleted = false, delivered = false;
    };

  EmailMetadata ();
  ~EmailMetadata () = default;

  bool load (const std::string &path);
  bool save (const std::string& dir = "");
  bool move (const std::string& dir);

  std::string filename () { return m_path; }
  void filename (std::string path) { m_path = path; }

  i2p::data::Tag<32> dht() { return m_dht; }
  void dht (i2p::data::Tag<32> key) { m_dht = key; }

  std::string message_id () { return m_message_id; }
  void message_id (std::string id);
  void set_message_id_bytes ();

  std::vector<uint8_t> message_id_bytes () { return m_message_id_bytes; }
  void message_id_bytes (const std::vector<uint8_t> &bytes);
  void set_message_id_string ();

  void fr_count (uint16_t count) { m_fr_count = count; }
  uint16_t fr_count () { return m_fr_count; }

  int32_t received () { return m_full_received; }
  void received (int32_t time) { m_full_received = time; }

  bool is_full ();

  bool delivered ();

  bool deleted () { return m_deleted; }
  void deleted (bool del) { m_deleted = del; }

  void add_part (EmailMetadata::Part p);

  std::shared_ptr<std::map<uint16_t, EmailMetadata::Part> >
  get_parts()
  {
    return m_parts;
  }

  size_t fill (std::shared_ptr<pbote::DeletionInfoPacket> packet);

 private:
  std::string m_path;

  i2p::data::Tag<32> m_dht;

  std::string m_message_id;
  std::vector<uint8_t> m_message_id_bytes;

  int32_t m_full_received = 0;
  uint16_t m_fr_count = 0;

  bool m_deleted;
  std::shared_ptr<std::map<uint16_t, Part> > m_parts;
};

class Email
{
 public:
  enum CompressionAlgorithm
    {
     UNCOMPRESSED,
     LZMA,
     ZLIB
    };

  enum Header
    {
     FROM,
     SENDER,
     REPLY_TO,
     IN_REPLY_TO,
     TO,
     CC,
     BCC,
     DATE,
     SUBJECT,
     CONTENT_TYPE,
     CONTENT_TRANSFER_ENCODING,
     MIME_VERSION,
     MESSAGE_ID,
     X_HASH_CASH,
     X_PRIORITY,
     X_I2PBBOTE_SIGNATURE
  };

  Email ();
  ~Email () = default;

  //void fromUnencryptedPacket(const pbote::EmailUnencryptedPacket &email_packet);
  //bool from_buffer (const std::vector<uint8_t> &data, bool from_net);
  void fromMIME (const std::vector<uint8_t> &email);

  void set_message_id ();
  std::string get_message_id ();
  void set_message_id_bytes ();

  i2p::data::Tag<32>
  get_message_id_bytes ()
  {
    return i2p::data::Tag<32>(m_metadata->message_id_bytes ().data ());
  }

  std::string hashcash ();

  //std::map<std::string, std::string> getAllRecipients ();

  std::string get_from_label ();
  std::string get_from_mailbox ();
  std::string get_from_address ();

  //std::string getRecipients (const std::string &type);

  std::string get_to_label ();
  std::string get_to_mailbox ();
  std::string get_to_addresses ();

  /*std::string
  getCCAddresses ()
  {
    return mail.header().cc().begin()->mailbox().mailbox();
  }*/
  /*std::string
  getBCCAddresses ()
  {
    return mail.header().bcc().begin()->mailbox().mailbox();
  }*/
  /*std::string
  getReplyAddress ()
  {
    return mail.header().replyto().begin()->mailbox().mailbox();
  }*/

  void
  set_from (const std::string& value)
  {
    mail.header ().from (value);
  }

  void
  set_sender (const std::string& value)
  {
    mail.header ().sender (value);
  }

  void
  set_to (const std::string& value)
  {
    mail.header ().to (value);
  }

  void
  setField (const std::string& type, const std::string& value)
  {
    mail.header().field(type).value(value);
  }

  std::string
  field(const std::string& type)
  {
    return mail.header().field(type).value();
  }

  bool empty () const { return m_empty; };
  bool incomplete () const { return m_incomplete; };
  void skip (bool skip) { m_skip = skip; };
  bool skip () const { return m_skip; };
  bool verify ();
  bool check (uint8_t *hash);

  std::string filename () { return filename_; }
  void filename (const std::string& fn) { filename_ = fn; }

  bool deleted () { return m_deleted; }
  void deleted (bool del) { m_deleted = del; }

  std::shared_ptr<EmailMetadata> metadata () { return m_metadata; }
  void metadata(std::shared_ptr<EmailMetadata> meta) { m_metadata = meta; }

  void compose ();
  bool split ();
  bool fill_storable ();

  bool restore ();

  bool compress (CompressionAlgorithm type);
  void decompress (std::vector<uint8_t> data);

  bool save (const std::string& dir = "");
  bool move (const std::string& dir);

  std::vector<uint8_t> bytes () { return full_bytes; }

  size_t length () { return mail.size(); }

  void set_sender_identity(sp_id_full identity);
  void set_recipient_identity(std::string to_address);
  sp_id_private get_sender () { return sender; };
  sp_id_public get_recipient () { return recipient; };
  pbote::IndexPacket get_index () { return m_index; }
  pbote::StoreRequestPacket get_storable_index () { return m_storable_index; }

  std::shared_ptr<EmailMetadata> get_metadata() { return m_metadata; }

  std::map<i2p::data::Tag<32>, pbote::StoreRequestPacket>
  get_storable ()
  {
    return m_storable_parts;
  }

  v_sp_plain_email decrypted () { return m_plain_parts;};

  std::vector<std::shared_ptr<pbote::EmailEncryptedPacket>>
  encrypted ()
  {
    return m_enc_parts;
  };

  void encrypt ();

 private:
  std::string generate_uuid_v4 ();

  static void lzmaDecompress (std::vector<uint8_t> &outBuf, const std::vector<uint8_t> &inBuf);

  static void zlibCompress (std::vector<uint8_t> &outBuf, const std::vector<uint8_t> &inBuf);
  static void zlibDecompress (std::vector<uint8_t> &outBuf, const std::vector<uint8_t> &inBuf);

  sp_id_public parse_address_v0(std::string address);
  sp_id_public parse_address_v1(std::string address);

  bool m_incomplete;
  bool m_empty;
  bool m_deleted;
  bool m_skip;
  bool m_encrypted = false;
  bool m_composed = false;
  bool m_splitted= false;

  std::string filename_;
  mimetic::MimeEntity mail;
  std::shared_ptr<EmailMetadata> m_metadata;

  sp_id_private sender;
  sp_id_public recipient;

  std::vector<uint8_t> full_bytes;

  pbote::IndexPacket m_index;
  pbote::StoreRequestPacket m_storable_index;

  v_sp_plain_email m_plain_parts;
  std::vector<std::shared_ptr<pbote::EmailEncryptedPacket>> m_enc_parts;
  std::map<i2p::data::Tag<32>, pbote::StoreRequestPacket> m_storable_parts;
};

} // pbote

#endif // PBOTED_SRC_EMAIL_H
