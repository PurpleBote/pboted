/**
 * Copyright (c) 2019-2021 polistern
 */

#ifndef PBOTE_EMAIL_H_
#define PBOTE_EMAIL_H_

#include <map>
#include <string>
#include <vector>
#include "lib/lzma/LzmaDec.h"
#include "lib/lzma/LzmaEnc.h"
#include "lib/lzma/7zTypes.h"

#include "EmailIdentity.h"
#include "Packet.h"

namespace pbote {

static void *_lzmaAlloc(ISzAllocPtr, size_t size) {
  return new uint8_t[size];
}
static void _lzmaFree(ISzAllocPtr, void *addr) {
  if (!addr)
    return;

  delete[] reinterpret_cast<uint8_t *>(addr);
}

static ISzAlloc _allocFuncs = {
    _lzmaAlloc, _lzmaFree
};

const std::string SIGNATURE_HEADER = "X-I2PBote-Signature"; // contains the sender's base64-encoded signature
const std::string SIGNATURE_VALID_HEADER = "X-I2PBote-Sig-Valid"; // contains the string "true" or "false"
const std::vector<std::string> HEADER_WHITELIST = {
    "From", "Sender", "Reply-To", "In-Reply-To", "To", "CC", "BCC", "Date", "Subject", "Content-Type", "Content-Transfer-Encoding",
    "MIME-Version", "Message-ID", "X-HashCash", "X-Priority", SIGNATURE_HEADER};
const uint16_t MAX_HEADER_LENGTH = 998;

class Email {
 public:
  enum CompressionAlgorithm {
    UNCOMPRESSED,
    LZMA,
    ZIP,
    GZIP
  };
  enum Header {
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

  Email();
  Email(const std::vector<uint8_t> &data, bool from_net);

  ~Email();

  //void fromUnencryptedPacket(const pbote::EmailUnencryptedPacket &email_packet);
  void fromMIME(const std::vector<uint8_t> &email);

  i2p::data::Tag<32> getID();
  std::vector<uint8_t> getHashCash();

  std::string getHeader(const std::string &name);
  void setHeader(Header type, const std::string &value);

  std::map<std::string, std::string> getAllRecipients();
  std::string getRecipients(const std::string &type);

  std::string getToAddresses();
  std::string getCCAddresses();
  std::string getBCCAddresses();
  std::string getReplyAddress();

  bool empty() const { return empty_; };
  bool incomplete() const { return incomplete_; };
  void setSkiped() { skip_ = true; };
  bool skip() { return skip_; };
  bool verify(uint8_t *hash);
  std::vector<uint8_t> bytes();
  void setPacket();

  pbote::EmailEncryptedPacket getEncrypted() { return encrypted; };
  void setEncrypted(const pbote::EmailEncryptedPacket &data) { encrypted = data; };

  pbote::EmailUnencryptedPacket getDecrypted() { return packet;};
  void setDecrypted(const pbote::EmailUnencryptedPacket &data) { packet = data; };

  void compress(CompressionAlgorithm type);
  void decompress(std::vector<uint8_t> data);

 private:
  static void lzmaCompress(std::vector<unsigned char> &outBuf, const std::vector<unsigned char> &inBuf);
  static void lzmaDecompress(std::vector<unsigned char> &outBuf, const std::vector<unsigned char> &inBuf);

  std::string getValue(std::string line, Header type);

  bool incomplete_;
  bool empty_;
  bool skip_;
  // i2p::data::Tag<32> messageId;
  // metadata?
  // sendtime
  std::map<Header, std::string> headers;
  //std::string body;
  std::vector<uint8_t> body;

  pbote::EmailEncryptedPacket encrypted;
  pbote::EmailUnencryptedPacket packet;
};

}
#endif //PBOTE_EMAIL_H_
