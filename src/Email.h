/**
 * Copyright (C) 2019-2022 polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#ifndef PBOTED_SRC_EMAIL_H_
#define PBOTED_SRC_EMAIL_H_

#include <map>
#include <mimetic/mimetic.h>
#include <string>
#include <vector>

#include "LzmaDec.h"
#include "LzmaEnc.h"
#include "7zTypes.h"

#include "BoteIdentity.h"
#include "Packet.h"

namespace pbote {

#define MAX_HEADER_LENGTH 998

using sp_id_full = std::shared_ptr<pbote::BoteIdentityFull>;
using sp_id_private = std::shared_ptr<pbote::BoteIdentityPrivate>;
using sp_id_public = std::shared_ptr<pbote::BoteIdentityPublic>;

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
  Email (const std::vector<uint8_t> &data, bool from_net);
  ~Email () = default;

  //void fromUnencryptedPacket(const pbote::EmailUnencryptedPacket &email_packet);
  void fromMIME (const std::vector<uint8_t> &email);

  void set_message_id ();
  std::string get_message_id ();
  void set_message_id_bytes ();

  i2p::data::Tag<32>
  get_message_id_bytes ()
  {
    return i2p::data::Tag<32>(packet.mes_id);
  }

  std::vector<uint8_t> hashcash ();

  //std::map<std::string, std::string> getAllRecipients ();

  std::string get_from_label ();
  std::string get_from_mailbox ();
  std::string get_from_address ();

  //std::string getRecipients (const std::string &type);

  std::string get_to_label ();
  std::string get_to_mailbox ();
  std::string get_to_addresses ();

  //std::string getCCAddresses () { return mail.header().cc().begin()->mailbox().mailbox(); }
  //std::string getBCCAddresses () { return mail.header().bcc().begin()->mailbox().mailbox(); }
  //std::string getReplyAddress () { return mail.header().replyto().begin()->mailbox().mailbox(); }

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
    //mail.header().setField(type, value);
  }

  std::string
  field(const std::string& type)
  {
    return mail.header().field(type).value();
  }

  bool empty () const { return empty_; };
  bool incomplete () const { return incomplete_; };
  void skip (bool s) { skip_ = s; };
  bool skip () const { return skip_; };
  void deleted (bool s) { deleted_ = s; };
  bool deleted () const { return deleted_; };
  bool verify (uint8_t *hash);

  std::string filename () { return filename_; }
  void filename (const std::string& fn) { filename_ = fn; }
  std::vector<uint8_t> bytes ();
  bool save (const std::string& dir);
  bool move (const std::string& dir);

  size_t length () { return mail.size(); }

  void compose ();

  void set_sender_identity(sp_id_full identity);
  void set_recipient_identity(std::string to_address);
  sp_id_private get_sender () { return sender; };
  sp_id_public get_recipient () { return recipient; };

  pbote::EmailEncryptedPacket getEncrypted () { return encrypted; };
  void setEncrypted (const pbote::EmailEncryptedPacket &data) { encrypted = data; };
  void encrypt ();

  pbote::EmailUnencryptedPacket getDecrypted () { return packet;};
  void setDecrypted (const pbote::EmailUnencryptedPacket &data) { packet = data; };

  bool compress (CompressionAlgorithm type);
  void decompress (std::vector<uint8_t> data);

 private:
  std::string generate_uuid_v4 ();

  static void lzmaDecompress (std::vector<uint8_t> &outBuf, const std::vector<uint8_t> &inBuf);

  static void zlibCompress (std::vector<uint8_t> &outBuf, const std::vector<uint8_t> &inBuf);
  static void zlibDecompress (std::vector<uint8_t> &outBuf, const std::vector<uint8_t> &inBuf);

  sp_id_public parse_address_v0(std::string address);
  sp_id_public parse_address_v1(std::string address);

  bool incomplete_;
  bool empty_;
  bool skip_;
  bool deleted_;
  bool encrypted_ = false;
  bool composed_ = false;
  // metadata?
  // sendtime
  std::string filename_;
  mimetic::MimeEntity mail;
  sp_id_private sender;
  sp_id_public recipient;

  pbote::EmailEncryptedPacket encrypted;
  pbote::EmailUnencryptedPacket packet;
};

} // pbote

#endif //PBOTED_SRC_EMAIL_H_
