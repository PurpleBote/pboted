/**
 * Copyright (c) 2019-2021 polistern
 */

#ifndef EMAIL_IDENTITIY_H__
#define EMAIL_IDENTITIY_H__

#include <algorithm>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "Cryptography.h"
#include "FileSystem.h"
#include "Logging.h"

#include "CryptoKey.h"
#include "Signature.h"
#include "Tag.h"

namespace pbote {

/// ECDH-256 / ECDSA-256 / AES-256 / SHA-256 params
#define ECDH256_ECDSA256_NAME "ECDH-256 / ECDSA-256"
#define ECDH256_ECDSA256_COMPLETE_BASE64_LENGTH 172
#define ECDH256_ECDSA256_PUBLIC_BASE64_LENGTH 86
#define ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH 33
#define ECDH256_ECDSA256_BYTE_PRIVATE_KEY_LENGTH 32

#define CRYPTO_KEY_TYPE_ECDH_P256_SHA256_AES256CBC 2
#define SIGNING_KEY_TYPE_ECDSA_P256_SHA256 2

/// ECIES-256 / ED25519 / AES-256 / SHA-256 params
#define CRYPTO_KEY_TYPE_ECIES_X25519_AES256 5
#define SIGNING_KEY_TYPE_ECIES_X25519_AES256 5

typedef i2p::data::Tag<32> IdentHash;
typedef uint16_t SigningKeyType;
typedef uint16_t CryptoKeyType;

struct IBoteIdentity {
  virtual ~IBoteIdentity() {};

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

  virtual size_t get_identity_size() const = 0;
  virtual size_t get_identity_type() const = 0;

  virtual IdentHash hash() const = 0;
};

struct ECDHP256Identity : IBoteIdentity {
  uint8_t cryptoPrivKey[ECDH256_ECDSA256_BYTE_PRIVATE_KEY_LENGTH];
  uint8_t signingPrivKey[ECDH256_ECDSA256_BYTE_PRIVATE_KEY_LENGTH];
  uint8_t cryptoPubKey[ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH];
  uint8_t signingPubKey[ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH];

  ECDHP256Identity() = default;

  size_t from_buffer(const uint8_t *buf, size_t len) override {
    if (len < get_identity_size())
      return 0;

    memcpy(cryptoPubKey, buf, get_identity_size());
    return get_identity_size();
  }

  size_t to_buffer(uint8_t *buf, size_t len) override {
    if (len < get_identity_size())
      return 0;

    memcpy(buf, cryptoPubKey, get_identity_size());
    return get_identity_size();
  }

  uint8_t *getCryptoPrivateKey() override { return cryptoPrivKey; };
  uint8_t *getSigningPrivateKey() override { return signingPrivKey; };
  uint8_t *getCryptoPublicKey() override { return cryptoPubKey; };
  uint8_t *getSigningPublicKey() override { return signingPubKey; };

  void setCryptoPrivateKey(const uint8_t *buf, size_t len) override { memcpy(cryptoPrivKey, buf, len); };
  void setSigningPrivateKey(const uint8_t *buf, size_t len) override { memcpy(signingPrivKey, buf, len); };
  void setCryptoPublicKey(const uint8_t *buf, size_t len) override { memcpy(cryptoPubKey, buf, len); };
  void setSigningPublicKey(const uint8_t *buf, size_t len) override { memcpy(signingPubKey, buf, len); };

  size_t get_identity_size() const override { return (ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH * 2); };
  size_t get_identity_type() const override { return CRYPTO_KEY_TYPE_ECDH_P256_SHA256_AES256CBC; };

  IdentHash hash() const override {
    IdentHash hash;
    SHA256(cryptoPubKey, get_identity_size(), hash);
    return hash;
  }
};

class EmailIdentityPublic {
 public:
  EmailIdentityPublic();
  EmailIdentityPublic(const uint8_t *publicKey,
                      const uint8_t *signingKey,
                      SigningKeyType type = SIGNING_KEY_TYPE_ECDSA_P256_SHA256,
                      CryptoKeyType cryptoType = CRYPTO_KEY_TYPE_ECDH_P256_SHA256_AES256CBC);
  EmailIdentityPublic(const uint8_t *buf, size_t len);
  EmailIdentityPublic(const EmailIdentityPublic &other);
  ~EmailIdentityPublic();

  EmailIdentityPublic &operator=(const EmailIdentityPublic &other);
  bool operator==(const EmailIdentityPublic &other) const { return GetIdentHash() == other.GetIdentHash(); }

  size_t FromBuffer(const uint8_t *buf, size_t len);
  size_t ToBuffer(uint8_t *buf, size_t len) const;

  size_t FromBase64(const std::string &s);
  std::string ToBase64() const;

  const std::shared_ptr<IBoteIdentity> GetStandardIdentity() const { return m_StandardIdentity; };
  const IdentHash &GetIdentHash() const { return m_IdentHash; };
  void RecalculateIdentHash(uint8_t *buff = nullptr);
  size_t GetFullLen() const;

  CryptoKeyType GetCryptoKeyType() const;
  const uint8_t *GetEncryptionPublicKey() const { return m_StandardIdentity->getCryptoPublicKey(); };

  uint8_t *GetEncryptionPublicKeyBuffer() { return m_StandardIdentity->getCryptoPublicKey(); };
  SigningKeyType GetSigningKeyType() const;
  size_t GetSigningPublicKeyLen() const;
  const uint8_t *GetSigningPublicKeyBuffer() const;
  size_t GetSigningPrivateKeyLen() const;
  size_t GetSignatureLen() const;

  void DropVerifier() const; // to save memory
  static i2p::crypto::Verifier *CreateVerifier(SigningKeyType keyType);
  bool Verify(const uint8_t *buf, size_t len, const uint8_t *signature) const;

 private:
  void CreateVerifier() const;
  void UpdateVerifier(i2p::crypto::Verifier *verifier) const;

 private:
  std::shared_ptr<IBoteIdentity> m_StandardIdentity;
  IdentHash m_IdentHash;
  mutable i2p::crypto::Verifier *m_Verifier = nullptr;
  mutable std::mutex m_VerifierMutex;
};

class EmailIdentityPrivate {
 public:
  EmailIdentityPrivate() = default;
  EmailIdentityPrivate(const EmailIdentityPrivate &other) { *this = other; };
  EmailIdentityPrivate &operator=(const EmailIdentityPrivate &other);
  ~EmailIdentityPrivate() = default;

  size_t FromBuffer(const uint8_t *buf, size_t len);
  size_t ToBuffer(uint8_t *buf, size_t len) const;
  size_t FromBase64(const std::string &s);
  std::string ToBase64() const;

  std::shared_ptr<const EmailIdentityPublic> GetPublicIdentity() const { return m_Public; };

  const uint8_t *GetCryptoPrivateKey() const { return m_Public->GetStandardIdentity()->getCryptoPrivateKey(); };
  const uint8_t *GetSigningPrivateKey() const { return m_Public->GetStandardIdentity()->getSigningPrivateKey(); };
  size_t GetSignatureLen() const; // might not match identity
  void RecalculateIdentHash(uint8_t *buf = nullptr) { m_Public->RecalculateIdentHash(buf); }
  size_t GetFullLen() const;

  std::vector<uint8_t> Decrypt(const uint8_t *encrypted, size_t elen);
  std::shared_ptr<pbote::ECDHP256Decryptor> CreateDecryptor(const uint8_t *key) const;
  static std::shared_ptr<pbote::ECDHP256Decryptor> CreateDecryptor(CryptoKeyType cryptoType, const uint8_t *key);

  std::vector<uint8_t> Encrypt(const uint8_t *data, int dlen, const uint8_t *pubKey) const;
  std::shared_ptr<pbote::CryptoKeyEncryptor> CreateEncryptor(const uint8_t *key) const;
  static std::shared_ptr<pbote::ECDHP256Encryptor> CreateEncryptor(const CryptoKeyType keyType, const uint8_t *key);

  void Sign(const uint8_t *buf, int len, uint8_t *signature) const;
  static void GenerateSigningKeyPair(SigningKeyType type, uint8_t *priv, uint8_t *pub);
  static void GenerateCryptoKeyPair(CryptoKeyType type, uint8_t *priv, uint8_t *pub);
  static i2p::crypto::Signer *CreateSigner(SigningKeyType keyType, const uint8_t *priv);

 private:
  void CreateSigner() const;
  void CreateSigner(SigningKeyType keyType) const;
  size_t GetPrivateKeyLen() const;

 private:
  std::shared_ptr<EmailIdentityPublic> m_Public;
  uint8_t m_CryptoPrivateKey[33];
  uint8_t m_SigningPrivateKey[33];

  mutable std::unique_ptr<i2p::crypto::Signer> m_Signer;
  std::shared_ptr<i2p::crypto::CryptoKeyDecryptor> m_Decryptor;
};

#define IDENTITY_PREFIX "identity"
#define IDENTITY_PREFIX_KEY "key"
#define IDENTITY_PREFIX_PUBLIC_NAME "publicName"
#define IDENTITY_PREFIX_DESCRIPTION "description"
#define IDENTITY_PREFIX_SALT "salt"
#define IDENTITY_PREFIX_PICTURE "picture"
#define IDENTITY_PREFIX_TEXT "text"
#define IDENTITY_PREFIX_PUBLISHED "published"
#define IDENTITY_PREFIX_DEFAULT "default"
#define CONFIGURATION_PREFIX "configuration."

struct EmailIdentityFull {
  uint16_t id;
  std::string salt;
  std::string publicName;
  std::string full_key;
  std::string description;
  std::string picture;
  std::string text;
  SigningKeyType type;
  bool isPublished;
  bool isEncrypted;
  bool isDefault;
  EmailIdentityPrivate identity;
};

class identitiesStorage {
 public:
  identitiesStorage()
      : default_identity_("") {}

  void init();
  size_t loadIdentities(const std::string &path);
  void saveIdentities();
  void importIdentities();
  void exportIdentities();
  void addIdentityToStorage(EmailIdentityFull ident);

  EmailIdentityFull createIdentitie();
  std::vector<std::shared_ptr<EmailIdentityFull>> getIdentities() { return identities_; };
  EmailIdentityFull getIdentitieByName(std::string name);
  EmailIdentityFull getIdentitieByKey(std::string key);
  EmailIdentityFull getDefaultIdentitie();

  static std::string getParam(std::string line, const std::string &prefix0, std::string prefix1);

 private:
  std::vector<std::shared_ptr<EmailIdentityFull>> identities_;
  std::string default_identity_;
};

} // namespace pbote

#endif // EMAIL_IDENTITIY_H__
