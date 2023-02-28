/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022-2023, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#pragma once
#ifndef PBOTED_SRC_IDENTITY_H
#define PBOTED_SRC_IDENTITY_H

#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "Cryptography.h"
#include "FileSystem.h"
#include "Logging.h"

// libi2pd
#include "Signature.h"
#include "Tag.h"

namespace i2p
{
namespace crypto
{

/// ECDSA_SHA256_P256 for I2P-Bote
const size_t ECDSAP256_BOTE_KEY_LENGTH = 66;
typedef ECDSAVerifier<SHA256Hash, NID_X9_62_prime256v1, ECDSAP256_BOTE_KEY_LENGTH> ECDSAP256BVerifier;
typedef ECDSASigner<SHA256Hash, NID_X9_62_prime256v1, ECDSAP256_BOTE_KEY_LENGTH> ECDSAP256BSigner;

inline void CreateECDSAP256BRandomKeys (uint8_t * signingPrivateKey, uint8_t * signingPublicKey)
{
  CreateECDSARandomKeys (NID_X9_62_prime256v1, ECDSAP256_BOTE_KEY_LENGTH, signingPrivateKey, signingPublicKey);
}

} /* namespace crypto */
} /* namespace i2p */

namespace bote
{

const size_t MAX_IDENTITY_SIZE = 2048;

/// Identity types
const uint8_t KEY_TYPE_ELG2048_DSA1024_SHA256_AES256CBC = 1; /// UNSUPPORTED
const uint8_t KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC = 2;
const uint8_t KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC = 3;
const uint8_t KEY_TYPE_NTRUE1087_GMSS512_SHA512_AES256CBC = 4;  /// UNSUPPORTED
const uint8_t KEY_TYPE_X25519_ED25519_SHA512_AES256CBC = 5;

const std::string ADDRESS_B32_PREFIX = "b32.";
const std::string ADDRESS_B64_PREFIX = "b64.";

const uint8_t ADDRESS_FORMAT_V1 = 0x01;

// Crypto key ID's
const uint8_t CRYP_TYPE_ECDH256 = 0x02;
const uint8_t CRYP_TYPE_ECDH521 = 0x03;
const uint8_t CRYP_TYPE_X25519 = 0x05;
// Signing key ID's
const uint8_t SIGN_TYPE_ECDSA256 = 0x02;
const uint8_t SIGN_TYPE_ECDSA521 = 0x03;
const uint8_t SIGN_TYPE_ED25519 = 0x05;
// Symmetric alg ID's
const uint8_t SYMM_TYPE_AES_256 = 0x02;
// Hash alg ID's
const uint8_t HASH_TYPE_SHA_256 = 0x01;
const uint8_t HASH_TYPE_SHA_512 = 0x02;

/// Format: <crypt> / <sign> / <symmetric> / <hash>
/// ECDH-256 / ECDSA-256 / AES-256 / SHA-256
const std::string ECDH256_ECDSA256_NAME = "ECDH-256 / ECDSA-256";
const size_t ECDH256_ECDSA256_COMPLETE_BASE64_LENGTH = 172;
const size_t ECDH256_ECDSA256_PUBLIC_BASE64_LENGTH = 86;
const size_t ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH = 33;
const size_t ECDH256_ECDSA256_BYTE_PRIVATE_KEY_LENGTH = 33;

/// ECDH-512 / ECDSA-521 / AES-256 / SHA-512
const std::string ECDH521_ECDSA521_NAME = "ECDH-521 / ECDSA-521";
const size_t ECDH521_ECDSA521_COMPLETE_BASE64_LENGTH = 348;
const size_t ECDH521_ECDSA521_PUBLIC_BASE64_LENGTH = 174;
const size_t ECDH521_ECDSA521_BYTE_PUBLIC_KEY_LENGTH = 66;
const size_t ECDH521_ECDSA521_BYTE_PRIVATE_KEY_LENGTH = 66;

/// X25519 / ED25519 / AES-256 / SHA-512
const std::string X25519_ED25519_NAME = "X25519 / ED25519";
const size_t X25519_ED25519_BYTE_PUBLIC_KEY_LENGTH = 32;
const size_t X25519_ED25519_BYTE_PRIVATE_KEY_LENGTH = 32;

typedef i2p::data::Tag<32> IdentHash;
typedef uint16_t KeyType;

inline std::string keyTypeToString(KeyType keyType)
{
  switch (keyType)
    {
      case KEY_TYPE_ELG2048_DSA1024_SHA256_AES256CBC:
        return {"ElGamal-2048 / DSA-1024"};
      case KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC:
        return {ECDH256_ECDSA256_NAME};
      case KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC:
        return {ECDH521_ECDSA521_NAME};
      case KEY_TYPE_NTRUE1087_GMSS512_SHA512_AES256CBC:
        return {"NTRUE-1087 / GMSS-512"};
      case KEY_TYPE_X25519_ED25519_SHA512_AES256CBC:
        return {X25519_ED25519_NAME};
      default:
        return {"UNKNOWN"};
    }
}

class I_BoteIdentity
{
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

class ECDHP256Identity : public I_BoteIdentity
{
 public:
  ECDHP256Identity() = default;

  size_t from_buffer(const uint8_t *buf, size_t len) override
  {
    if (len < get_identity_size())
      return 0;

    memcpy(cryptoPublicKey, buf, ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH);
    memcpy(signingPublicKey, buf + ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH, ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH);
    return get_identity_size();
  }

  size_t to_buffer(uint8_t *buf, size_t len) override
  {
    if (len < get_identity_size())
      return 0;

    memcpy(buf, cryptoPublicKey, get_identity_size());
    return get_identity_size();
  }

  uint8_t *getCryptoPrivateKey() override { return cryptoPrivateKey; };
  uint8_t *getSigningPrivateKey() override { return signingPrivateKey; };
  uint8_t *getCryptoPublicKey() override { return cryptoPublicKey; };
  uint8_t *getSigningPublicKey() override { return signingPublicKey; };

  void setCryptoPrivateKey(const uint8_t *buf, size_t len) override
  {
    memcpy(cryptoPrivateKey, buf, len);
  };

  void setSigningPrivateKey(const uint8_t *buf, size_t len) override
  {
    memcpy(signingPrivateKey, buf, len);
  };

  void setCryptoPublicKey(const uint8_t *buf, size_t len) override
  {
    memcpy(cryptoPublicKey, buf, len);
  };

  void setSigningPublicKey(const uint8_t *buf, size_t len) override
  {
    memcpy(signingPublicKey, buf, len);
  };

  size_t get_crypto_private_len() const override
  {
    return ECDH256_ECDSA256_BYTE_PRIVATE_KEY_LENGTH;
  };

  size_t get_crypto_public_len() const override
  {
    return ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH;
  };

  size_t get_singing_private_len() const override
  {
    return ECDH256_ECDSA256_BYTE_PRIVATE_KEY_LENGTH;
  };

  size_t get_singing_public_len() const override
  {
    return ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH;
  };

  size_t get_identity_size() const override
  {
    return (ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH * 2);
  };

  size_t get_identity_full_size() const override
  {
    return ((ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH + ECDH256_ECDSA256_BYTE_PRIVATE_KEY_LENGTH) * 2);
  };

  size_t get_identity_type() const override
  {
    return KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC;
  };

  IdentHash hash() const override
  {
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

class ECDHP521Identity : public I_BoteIdentity
{
 public:
  ECDHP521Identity() = default;

  size_t from_buffer(const uint8_t *buf, size_t len) override
  {
    if (len < get_identity_size())
      return 0;

    memcpy(cryptoPublicKey, buf, ECDH521_ECDSA521_BYTE_PUBLIC_KEY_LENGTH);
    memcpy(signingPublicKey, buf + ECDH521_ECDSA521_BYTE_PUBLIC_KEY_LENGTH, ECDH521_ECDSA521_BYTE_PUBLIC_KEY_LENGTH);
    return get_identity_size();
  }

  size_t to_buffer(uint8_t *buf, size_t len) override
  {
    if (len < get_identity_size())
      return 0;

    memcpy(buf, cryptoPublicKey, get_identity_size());
    return get_identity_size();
  }

  uint8_t *getCryptoPrivateKey() override { return cryptoPrivateKey; };
  uint8_t *getSigningPrivateKey() override { return signingPrivateKey; };
  uint8_t *getCryptoPublicKey() override { return cryptoPublicKey; };
  uint8_t *getSigningPublicKey() override { return signingPublicKey; };

  void setCryptoPrivateKey(const uint8_t *buf, size_t len) override
  {
    memcpy(cryptoPrivateKey, buf, len);
  };

  void setSigningPrivateKey(const uint8_t *buf, size_t len) override
  {
    memcpy(signingPrivateKey, buf, len);
  };

  void setCryptoPublicKey(const uint8_t *buf, size_t len) override
  {
    memcpy(cryptoPublicKey, buf, len);
  };

  void setSigningPublicKey(const uint8_t *buf, size_t len) override
  {
    memcpy(signingPublicKey, buf, len);
  };

  size_t get_crypto_private_len() const override
  {
    return ECDH521_ECDSA521_BYTE_PRIVATE_KEY_LENGTH;
  };

  size_t get_crypto_public_len() const override
  {
    return ECDH521_ECDSA521_BYTE_PUBLIC_KEY_LENGTH;
  };

  size_t get_singing_private_len() const override
  {
    return ECDH521_ECDSA521_BYTE_PRIVATE_KEY_LENGTH;
  };

  size_t get_singing_public_len() const override
  {
    return ECDH521_ECDSA521_BYTE_PUBLIC_KEY_LENGTH;
  };

  size_t get_identity_size() const override
  {
    return (ECDH521_ECDSA521_BYTE_PUBLIC_KEY_LENGTH * 2);
  };

  size_t get_identity_full_size() const override
  {
    return ((ECDH521_ECDSA521_BYTE_PUBLIC_KEY_LENGTH + ECDH521_ECDSA521_BYTE_PRIVATE_KEY_LENGTH) * 2);
  };

  size_t get_identity_type() const override
  {
    return KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC;
  };

  IdentHash hash() const override
  {
    IdentHash hash;
    SHA256(cryptoPublicKey, get_identity_size(), hash);
    return hash;
  }

 private:
  uint8_t cryptoPrivateKey[ECDH521_ECDSA521_BYTE_PRIVATE_KEY_LENGTH]{};
  uint8_t signingPrivateKey[ECDH521_ECDSA521_BYTE_PRIVATE_KEY_LENGTH]{};
  uint8_t cryptoPublicKey[ECDH521_ECDSA521_BYTE_PUBLIC_KEY_LENGTH]{};
  uint8_t signingPublicKey[ECDH521_ECDSA521_BYTE_PUBLIC_KEY_LENGTH]{};
};

class X25519Identity : public I_BoteIdentity
{
 public:
  X25519Identity() = default;

  size_t from_buffer(const uint8_t *buf, size_t len) override
  {
    if (len < get_identity_size())
      return 0;

    memcpy(cryptoPublicKey, buf, X25519_ED25519_BYTE_PUBLIC_KEY_LENGTH);
    memcpy(signingPublicKey, buf + X25519_ED25519_BYTE_PUBLIC_KEY_LENGTH, X25519_ED25519_BYTE_PUBLIC_KEY_LENGTH);
    return get_identity_size();
  }

  size_t to_buffer(uint8_t *buf, size_t len) override
  {
    if (len < get_identity_size())
      return 0;

    memcpy(buf, cryptoPublicKey, get_identity_size());
    return get_identity_size();
  }

  uint8_t *getCryptoPrivateKey() override { return cryptoPrivateKey; };
  uint8_t *getSigningPrivateKey() override { return signingPrivateKey; };
  uint8_t *getCryptoPublicKey() override { return cryptoPublicKey; };
  uint8_t *getSigningPublicKey() override { return signingPublicKey; };

  void setCryptoPrivateKey(const uint8_t *buf, size_t len) override
  {
    memcpy(cryptoPrivateKey, buf, len);
  };

  void setSigningPrivateKey(const uint8_t *buf, size_t len) override
  {
    memcpy(signingPrivateKey, buf, len);
  };

  void setCryptoPublicKey(const uint8_t *buf, size_t len) override
  {
    memcpy(cryptoPublicKey, buf, len);
  };

  void setSigningPublicKey(const uint8_t *buf, size_t len) override
  {
    memcpy(signingPublicKey, buf, len);
  };

  size_t get_crypto_private_len() const override
  {
    return X25519_ED25519_BYTE_PRIVATE_KEY_LENGTH;
  };

  size_t get_crypto_public_len() const override
  {
    return X25519_ED25519_BYTE_PUBLIC_KEY_LENGTH;
  };

  size_t get_singing_private_len() const override
  {
    return X25519_ED25519_BYTE_PRIVATE_KEY_LENGTH;
  };

  size_t get_singing_public_len() const override
  {
    return X25519_ED25519_BYTE_PUBLIC_KEY_LENGTH;
  };

  size_t get_identity_size() const override
  {
    return (X25519_ED25519_BYTE_PUBLIC_KEY_LENGTH * 2);
  };

  size_t get_identity_full_size() const override
  {
    return ((X25519_ED25519_BYTE_PUBLIC_KEY_LENGTH + X25519_ED25519_BYTE_PRIVATE_KEY_LENGTH) * 2);
  };

  size_t get_identity_type() const override
  {
    return KEY_TYPE_X25519_ED25519_SHA512_AES256CBC;
  };

  IdentHash hash() const override
  {
    IdentHash hash;
    SHA256(cryptoPublicKey, get_identity_size(), hash);
    return hash;
  }

 private:
  uint8_t cryptoPrivateKey[X25519_ED25519_BYTE_PRIVATE_KEY_LENGTH]{};
  uint8_t signingPrivateKey[X25519_ED25519_BYTE_PRIVATE_KEY_LENGTH]{};
  uint8_t cryptoPublicKey[X25519_ED25519_BYTE_PUBLIC_KEY_LENGTH]{};
  uint8_t signingPublicKey[X25519_ED25519_BYTE_PUBLIC_KEY_LENGTH]{};
};

class BoteIdentityPublic
{
 public:
  BoteIdentityPublic(KeyType type = KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC);
  BoteIdentityPublic(const uint8_t *cryptoPublicKey,
                     const uint8_t *signingPublicKey,
                     KeyType type = KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC);
  BoteIdentityPublic(const uint8_t *buf, size_t len) { FromBuffer(buf, len); };
  BoteIdentityPublic(const BoteIdentityPublic &other) { *this = other; };

  ~BoteIdentityPublic() { delete m_Verifier; };

  BoteIdentityPublic &operator= (const BoteIdentityPublic &other);
  bool operator== (const BoteIdentityPublic &other) const;

  size_t FromBuffer(const uint8_t *buf, size_t len);
  size_t ToBuffer(uint8_t *buf, size_t len) const;
  size_t FromBase64(const std::string &s);
  std::string ToBase64() const;
  std::string ToBase64v1() const;

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
  std::shared_ptr<bote::CryptoKeyEncryptor> CreateEncryptor(const uint8_t *key) const;
  static std::shared_ptr<bote::CryptoKeyEncryptor> CreateEncryptor(KeyType keyType, const uint8_t *key);

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

class BoteIdentityPrivate
{
 public:
  BoteIdentityPrivate(KeyType type = KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC);
  BoteIdentityPrivate(const BoteIdentityPrivate &other) { *this = other; };
  ~BoteIdentityPrivate() = default;

  BoteIdentityPrivate &operator= (const BoteIdentityPrivate &other);
  bool operator== (const BoteIdentityPrivate &other) const;

  size_t FromBuffer(const uint8_t *buf, size_t len);
  size_t ToBuffer(uint8_t *buf, size_t len) const;
  size_t FromBase64(const std::string &s);
  std::string ToBase64() const;
  std::string ToBase64v1() const { return m_Public->ToBase64v1 (); };

  std::shared_ptr<const BoteIdentityPublic> GetPublicIdentity() const { return m_Public; };
  const IdentHash &GetIdentHash() const { return m_Public->GetIdentHash(); };
  void RecalculateIdentHash() { m_Public->RecalculateIdentHash(); }
  size_t GetFullLen() const { return m_Public->GetIdentity()->get_identity_full_size(); };
  KeyType GetKeyType() const { return m_Public->GetKeyType(); }

  size_t getCryptoPrivateKeyLen() const
  {
    return m_Public->GetIdentity()->get_crypto_private_len();
  };

  const uint8_t *GetCryptoPrivateKey() const
  {
    return m_Public->GetIdentity()->getCryptoPrivateKey();
  };

  void setCryptoPrivateKey(const uint8_t *buf, size_t len)
  {
    m_Public->GetIdentity()->setCryptoPrivateKey(buf, len);
  };

  size_t getSigningPrivateKeyLen() const
  {
    return m_Public->GetIdentity()->get_singing_private_len();
  };

  const uint8_t *GetSigningPrivateKey() const
  {
    return m_Public->GetIdentity()->getSigningPrivateKey();
  };

  void setSigningPrivateKey(const uint8_t *buf, size_t len)
  {
    m_Public->GetIdentity()->setSigningPrivateKey(buf, len);
  };

  size_t GetSignatureLen() const { return m_Public->GetSignatureLen(); };

  std::vector<uint8_t> Decrypt(const uint8_t *encrypted, size_t elen);
  std::shared_ptr<bote::CryptoKeyDecryptor> CreateDecryptor() const;

  void Sign(const uint8_t *buf, int len, uint8_t *signature) const;
  static i2p::crypto::Signer *CreateSigner(KeyType keyType, const uint8_t *priv);

 private:
  void CreateSigner() const { CreateSigner(GetKeyType()); };
  void CreateSigner(KeyType keyType) const;

  std::shared_ptr<BoteIdentityPublic> m_Public;
  mutable std::unique_ptr<i2p::crypto::Signer> m_Signer;
};

} // namespace bote

#endif // PBOTED_SRC_IDENTITY_H
