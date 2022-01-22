/**
 * Copyright (c) 2019-2022 polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#ifndef BOTE_IDENTITY_H_
#define BOTE_IDENTITY_H_

#include <algorithm>
#include <openssl/sha.h>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "Cryptography.h"
#include "FileSystem.h"
#include "Logging.h"

#include "Signature.h"
#include "Tag.h"

namespace pbote {
/// Identity types
const uint8_t KEY_TYPE_ELG2048_DSA1024_SHA256_AES256CBC = 1; /// UNSUPPORTED
const uint8_t KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC = 2;
const uint8_t KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC = 3;
const uint8_t KEY_TYPE_NTRUE1087_GMSS512_AES256_SHA512 = 4;  /// UNSUPPORTED
const uint8_t KEY_TYPE_X25519_ED25519_SHA512_AES256CBC = 5;

/// Format: <crypt> / <sign> / <symmetric> / <hash>
/// ECDH-256 / ECDSA-256 / AES-256 / SHA-256
const std::string ECDH256_ECDSA256_NAME = "ECDH-256 / ECDSA-256";
const size_t ECDH256_ECDSA256_COMPLETE_BASE64_LENGTH = 172;
const size_t ECDH256_ECDSA256_PUBLIC_BASE64_LENGTH = 86;
const size_t ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH = 33;
const size_t ECDH256_ECDSA256_BYTE_PRIVATE_KEY_LENGTH = 33;

/// ECDH-512 / ECDSA-521 / AES-256 / SHA-512
const std::string ECDH521_ECDSA521_NAME = "ECDH-521 / ECDSA-521";
//const size_t ECDH521_ECDSA521_COMPLETE_BASE64_LENGTH = 348;
//const size_t ECDH521_ECDSA521_PUBLIC_BASE64_LENGTH = 174;
//const size_t ECDH521_ECDSA521_BYTE_PUBLIC_KEY_LENGTH = 66;
//const size_t ECDH521_ECDSA521_BYTE_PRIVATE_KEY_LENGTH = 66;

/// X25519 / ED25519 / AES-256 / SHA-512
const std::string X25519_ED25519_NAME = "X25519 / ED25519";
//const size_t X25519_ED25519_COMPLETE_BASE64_LENGTH = 176;
//const size_t X25519_ED25519_PUBLIC_BASE64_LENGTH = 88;
//const size_t X25519_ED25519_PUBLIC_KEY_LENGTH = 32;
//const size_t X25519_ED25519_PRIVATE_KEY_LENGTH = 32;

typedef i2p::data::Tag<32> IdentHash;
typedef uint16_t KeyType;

inline std::string keyTypeToString(KeyType keyType) {
  switch (keyType) {
    case KEY_TYPE_ELG2048_DSA1024_SHA256_AES256CBC:
      return {"ElGamal-2048 / DSA-1024"};
    case KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC:
      return {ECDH256_ECDSA256_NAME};
    case KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC:
      return {ECDH521_ECDSA521_NAME};
    case KEY_TYPE_NTRUE1087_GMSS512_AES256_SHA512:
      return {"NTRUE-1087 / GMSS-512"};
    case KEY_TYPE_X25519_ED25519_SHA512_AES256CBC:
      return {X25519_ED25519_NAME};
    default:
      return {"UNKNOWN"};
  }
}

class I_BoteIdentity {
 public:
  virtual ~I_BoteIdentity() = default;

  virtual size_t from_buffer(const uint8_t *buf, size_t len) = 0;
  virtual size_t to_buffer(uint8_t *buf, size_t len) = 0;

  virtual uint8_t *getCryptoPrivateKey() = 0;
  virtual uint8_t *getSigningPrivateKey() = 0;
  virtual uint8_t *getCryptoPublicKey() = 0;
  virtual uint8_t *getSigningPublicKey() = 0;

  virtual void setCryptoPrivateKey(const uint8_t *buf, size_t len) = 0;
  virtual void setSigningPrivateKey(const uint8_t *buf, size_t len) = 0;
  virtual void setCryptoPublicKey(const uint8_t *buf, size_t len) = 0;
  virtual void setSigningPublicKey(const uint8_t *buf, size_t len) = 0;

  virtual size_t get_crypto_private_len() const = 0;
  virtual size_t get_crypto_public_len() const = 0;
  virtual size_t get_singing_private_len() const = 0;
  virtual size_t get_singing_public_len() const = 0;

  virtual size_t get_identity_size() const = 0;
  virtual size_t get_identity_full_size() const = 0;
  virtual size_t get_identity_type() const = 0;

  virtual IdentHash hash() const = 0;
};

class ECDHP256Identity : public I_BoteIdentity {
 public:
  ECDHP256Identity() = default;

  size_t from_buffer(const uint8_t *buf, size_t len) override {
    if (len < get_identity_size())
      return 0;

    memcpy(cryptoPublicKey, buf, ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH);
    memcpy(signingPublicKey, buf + ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH, ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH);
    return get_identity_size();
  }

  size_t to_buffer(uint8_t *buf, size_t len) override {
    if (len < get_identity_size())
      return 0;

    memcpy(buf, cryptoPublicKey, get_identity_size());
    return get_identity_size();
  }

  uint8_t *getCryptoPrivateKey() override { return cryptoPrivateKey; };
  uint8_t *getSigningPrivateKey() override { return signingPrivateKey; };
  uint8_t *getCryptoPublicKey() override { return cryptoPublicKey; };
  uint8_t *getSigningPublicKey() override { return signingPublicKey; };

  void setCryptoPrivateKey(const uint8_t *buf, size_t len) override { memcpy(cryptoPrivateKey, buf, len); };
  void setSigningPrivateKey(const uint8_t *buf, size_t len) override { memcpy(signingPrivateKey, buf, len); };
  void setCryptoPublicKey(const uint8_t *buf, size_t len) override { memcpy(cryptoPublicKey, buf, len); };
  void setSigningPublicKey(const uint8_t *buf, size_t len) override { memcpy(signingPublicKey, buf, len); };

  size_t get_crypto_private_len() const override { return ECDH256_ECDSA256_BYTE_PRIVATE_KEY_LENGTH; };
  size_t get_crypto_public_len() const override { return ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH; };
  size_t get_singing_private_len() const override { return ECDH256_ECDSA256_BYTE_PRIVATE_KEY_LENGTH; };
  size_t get_singing_public_len() const override { return ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH; };

  size_t get_identity_size() const override {
    return (ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH * 2);
  };

  size_t get_identity_full_size() const override {
    return ((ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH + ECDH256_ECDSA256_BYTE_PRIVATE_KEY_LENGTH) * 2);
  };

  size_t get_identity_type() const override { return KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC; };

  IdentHash hash() const override {
    IdentHash hash;
    SHA256(cryptoPublicKey, get_identity_size(), hash);
    return hash;
  }

 private:
  uint8_t cryptoPrivateKey[ECDH256_ECDSA256_BYTE_PRIVATE_KEY_LENGTH]{};
  uint8_t signingPrivateKey[ECDH256_ECDSA256_BYTE_PRIVATE_KEY_LENGTH]{};
  uint8_t cryptoPublicKey[ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH]{};
  uint8_t signingPublicKey[ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH]{};
};

class BoteIdentityPublic {
 public:
  BoteIdentityPublic(KeyType type = KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC);
  BoteIdentityPublic(const uint8_t *cryptoPublicKey, const uint8_t *signingPublicKey,
                     KeyType type = KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC);
  BoteIdentityPublic(const uint8_t *buf, size_t len) { FromBuffer(buf, len); };
  BoteIdentityPublic(const BoteIdentityPublic &other) { *this = other; };
  ~BoteIdentityPublic() { delete m_Verifier; };

  BoteIdentityPublic &operator=(const BoteIdentityPublic &other);
  bool operator==(const BoteIdentityPublic &other) const { return GetIdentHash() == other.GetIdentHash(); }

  size_t FromBuffer(const uint8_t *buf, size_t len);
  size_t ToBuffer(uint8_t *buf, size_t len) const;
  size_t FromBase64(const std::string &s);
  std::string ToBase64() const;

  std::shared_ptr<I_BoteIdentity> GetIdentity() const { return m_Identity; };
  const IdentHash &GetIdentHash() const { return m_IdentHash; };
  void RecalculateIdentHash();
  size_t GetFullLen() const { return m_Identity->get_identity_size(); };
  KeyType GetKeyType() const { return m_Identity->get_identity_type(); }

  size_t getCryptoPublicKeyLen() const { return m_Identity->get_crypto_public_len(); };
  const uint8_t *GetCryptoPublicKey() const { return m_Identity->getCryptoPublicKey(); };
  uint8_t *GetCryptoPublicKeyBuffer() { return m_Identity->getCryptoPublicKey(); };

  size_t getSigningPublicKeyLen() const { return m_Identity->get_singing_public_len(); };
  size_t GetSignatureLen() const;
  const uint8_t *GetSigningPublicKeyBuffer() const { return m_Identity->getSigningPublicKey(); };

  std::vector<uint8_t> Encrypt(const uint8_t *data, int len, const uint8_t *pubKey) const;
  std::shared_ptr<pbote::CryptoKeyEncryptor> CreateEncryptor(const uint8_t *key) const;
  static std::shared_ptr<pbote::CryptoKeyEncryptor> CreateEncryptor(KeyType keyType, const uint8_t *key);

  static i2p::crypto::Verifier *CreateVerifier(KeyType keyType);
  bool Verify(const uint8_t *buf, size_t len, const uint8_t *signature) const;
  void DropVerifier() const;

 private:
  void CreateVerifier() const;
  void UpdateVerifier(i2p::crypto::Verifier *verifier) const;

 private:
  mutable std::shared_ptr<I_BoteIdentity> m_Identity;
  IdentHash m_IdentHash{};
  mutable i2p::crypto::Verifier *m_Verifier = nullptr;
  mutable std::mutex m_VerifierMutex;
};

class BoteIdentityPrivate {
 public:
  BoteIdentityPrivate(KeyType type = KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC);
  BoteIdentityPrivate(const BoteIdentityPrivate &other) { *this = other; };
  ~BoteIdentityPrivate() = default;

  BoteIdentityPrivate &operator=(const BoteIdentityPrivate &other);

  size_t FromBuffer(const uint8_t *buf, size_t len);
  size_t ToBuffer(uint8_t *buf, size_t len) const;
  size_t FromBase64(const std::string &s);
  std::string ToBase64() const;

  std::shared_ptr<const BoteIdentityPublic> GetPublicIdentity() const { return m_Public; };
  const IdentHash &GetIdentHash() const { return m_Public->GetIdentHash(); };
  void RecalculateIdentHash() { m_Public->RecalculateIdentHash(); }
  size_t GetFullLen() const { return m_Public->GetIdentity()->get_identity_full_size(); };
  KeyType GetKeyType() const { return m_Public->GetKeyType(); }

  size_t getCryptoPrivateKeyLen() const { return m_Public->GetIdentity()->get_crypto_private_len(); };
  const uint8_t *GetCryptoPrivateKey() const { return m_Public->GetIdentity()->getCryptoPrivateKey(); };
  void setCryptoPrivateKey(const uint8_t *buf, size_t len) { m_Public->GetIdentity()->setCryptoPrivateKey(buf, len); };

  size_t getSigningPrivateKeyLen() const { return m_Public->GetIdentity()->get_singing_private_len(); };
  const uint8_t *GetSigningPrivateKey() const { return m_Public->GetIdentity()->getSigningPrivateKey(); };
  void setSigningPrivateKey(const uint8_t *buf, size_t len) {
    m_Public->GetIdentity()->setSigningPrivateKey(buf, len);
  };
  size_t GetSignatureLen() const { return m_Public->GetSignatureLen(); };

  std::vector<uint8_t> Decrypt(const uint8_t *encrypted, size_t elen);
  std::shared_ptr<pbote::CryptoKeyDecryptor> CreateDecryptor() const;

  void Sign(const uint8_t *buf, int len, uint8_t *signature) const;
  static i2p::crypto::Signer *CreateSigner(KeyType keyType, const uint8_t *priv);

 private:
  void CreateSigner() const { CreateSigner(GetKeyType()); };
  void CreateSigner(KeyType keyType) const;

  std::shared_ptr<BoteIdentityPublic> m_Public;
  mutable std::unique_ptr<i2p::crypto::Signer> m_Signer;
};

/// Identity string format:
///   <crypto public><signing public><crypto private><signing private>

const std::string DEFAULT_IDENTITY_FILE_NAME = "identities.txt";

const std::string IDENTITY_PREFIX = "identity";
const std::string IDENTITY_PREFIX_KEY = "key";
const std::string IDENTITY_PREFIX_PUBLIC_NAME = "publicName";
const std::string IDENTITY_PREFIX_DESCRIPTION = "description";
const std::string IDENTITY_PREFIX_SALT = "salt";
const std::string IDENTITY_PREFIX_PICTURE = "picture";
const std::string IDENTITY_PREFIX_TEXT = "text";
const std::string IDENTITY_PREFIX_PUBLISHED = "published";
const std::string IDENTITY_PREFIX_DEFAULT = "default";
const std::string CONFIGURATION_PREFIX = "configuration.";

struct BoteIdentityFull {
  uint16_t id;
  std::string salt;
  std::string publicName;
  std::string full_key;
  std::string description;
  std::string picture;
  std::string text;
  KeyType type;
  bool isPublished;
  bool isEncrypted;
  bool isDefault;
  BoteIdentityPrivate identity;
};

class identitiesStorage {
 public:
  identitiesStorage() = default;

  void init();
  long loadIdentities(const std::string &path);
  //void saveIdentities();
  //void importIdentities();
  //void exportIdentities();
  void addIdentityToStorage(const BoteIdentityFull& ident) { identities_.push_back(std::make_shared<BoteIdentityFull>(ident)); }

  //BoteIdentityFull createIdentity();
  std::vector<std::shared_ptr<BoteIdentityFull>> getIdentities() { return identities_; };
  //BoteIdentityFull getIdentityByName(std::string name);
  //BoteIdentityFull getIdentityByKey(std::string key);
  //BoteIdentityFull getDefaultIdentity();

  static std::string getParam(std::string line, const std::string &prefix0, const std::string& prefix1);

 private:
  std::vector<std::shared_ptr<BoteIdentityFull>> identities_;
  std::string default_identity_;
};

} // namespace pbote

#endif // BOTE_IDENTITY_H_
