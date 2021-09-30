/**
 * Copyright (c) 2019-2020 polistern
 */

#ifndef EMAIL_IDENTITIY_H__
#define EMAIL_IDENTITIY_H__

#include <algorithm>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "Crypto.h"
#include "FS.h"
#include "Log.h"

#include "lib/libi2pd/Tag.h"
#include "lib/libi2pd/Signature.h"
#include "lib/libi2pd/CryptoKey.h"

namespace pbote {

typedef i2p::data::Tag<32> IdentHash;

const uint8_t CERTIFICATE_TYPE_NULL = 0;
const uint8_t CERTIFICATE_TYPE_HASHCASH = 1;
const uint8_t CERTIFICATE_TYPE_HIDDEN = 2;
const uint8_t CERTIFICATE_TYPE_SIGNED = 3;
const uint8_t CERTIFICATE_TYPE_MULTIPLE = 4;
const uint8_t CERTIFICATE_TYPE_KEY = 5;

const uint8_t PRIVATE_KEY_LEN = 33;

struct Keys {
  uint8_t cryptoPrivKey[33];
  uint8_t signingPrivKey[33];
  uint8_t cryptoPubKey[33];
  uint8_t signingPubKey[33];
};

struct EmailIdentity {
  uint8_t cryptoPubKey[33];
  uint8_t signingPubKey[33];
  //uint8_t certificate[3];    // byte 1 - type, bytes 2-3 - length

  EmailIdentity() = default;
  EmailIdentity(const Keys &keys) { *this = keys; };
  EmailIdentity &operator=(const Keys &keys);
  size_t FromBuffer(const uint8_t *buf, size_t len);
  IdentHash Hash() const;
};

Keys CreateRandomKeys();

const size_t IDENTITY_SIZE_DEFAULT = sizeof(EmailIdentity);
const uint16_t CRYPTO_KEY_TYPE_ECDH_P256_SHA256_AES256CBC = 2;
const uint16_t SIGNING_KEY_TYPE_ECDSA_SHA256_P256 = 2;
typedef uint16_t SigningKeyType;
typedef uint16_t CryptoKeyType;

class EmailIdentityPublic {
 public:
  EmailIdentityPublic();
  EmailIdentityPublic(const uint8_t *publicKey,
                  const uint8_t *signingKey,
                  SigningKeyType type = SIGNING_KEY_TYPE_ECDSA_SHA256_P256,
                  CryptoKeyType cryptoType = CRYPTO_KEY_TYPE_ECDH_P256_SHA256_AES256CBC);
  EmailIdentityPublic(const uint8_t *buf, size_t len);
  EmailIdentityPublic(const EmailIdentityPublic &other);
  EmailIdentityPublic(const EmailIdentity &standard);
  ~EmailIdentityPublic();

  EmailIdentityPublic &operator=(const EmailIdentityPublic &other);
  EmailIdentityPublic &operator=(const EmailIdentity &standard);
  bool operator==(const EmailIdentityPublic &other) const { return GetIdentHash() == other.GetIdentHash(); }

  size_t FromBuffer(const uint8_t *buf, size_t len);
  size_t ToBuffer(uint8_t *buf, size_t len) const;
  size_t FromBase64(const std::string &s);
  std::string ToBase64() const;

  const EmailIdentity &GetStandardIdentity() const { return m_StandardIdentity; };
  const IdentHash &GetIdentHash() const { return m_IdentHash; };
  const uint8_t *GetEncryptionPublicKey() const { return m_StandardIdentity.cryptoPubKey; };
  uint8_t *GetEncryptionPublicKeyBuffer() { return m_StandardIdentity.cryptoPubKey; };
  size_t GetFullLen() const;
  size_t GetSigningPublicKeyLen() const;
  const uint8_t *GetSigningPublicKeyBuffer() const; // returns NULL for P521
  size_t GetSigningPrivateKeyLen() const;
  size_t GetSignatureLen() const;
  SigningKeyType GetSigningKeyType() const;
  CryptoKeyType GetCryptoKeyType() const;
  void RecalculateIdentHash(uint8_t *buff = nullptr);

  void DropVerifier() const; // to save memory
  static i2p::crypto::Verifier *CreateVerifier(SigningKeyType keyType);
  bool Verify(const uint8_t *buf, size_t len, const uint8_t *signature) const;

 private:
  void CreateVerifier() const;
  void UpdateVerifier(i2p::crypto::Verifier *verifier) const;

 private:
  EmailIdentity m_StandardIdentity;
  SigningKeyType m_signing_type;
  CryptoKeyType m_crypto_type;
  IdentHash m_IdentHash;
  mutable i2p::crypto::Verifier *m_Verifier = nullptr;
  mutable std::mutex m_VerifierMutex;
};

class EmailIdentityPrivate {
 public:
  EmailIdentityPrivate() = default;
  EmailIdentityPrivate(const EmailIdentityPrivate& other) { *this = other; };
  EmailIdentityPrivate(const Keys& keys) { *this = keys; };
  EmailIdentityPrivate& operator=(const Keys& keys);
  EmailIdentityPrivate& operator=(const EmailIdentityPrivate& other);
  ~EmailIdentityPrivate() = default;

  size_t FromBuffer(const uint8_t * buf, size_t len);
  size_t ToBuffer(uint8_t * buf, size_t len) const;
  size_t FromBase64(const std::string& s);
  std::string ToBase64() const;

  std::shared_ptr<const EmailIdentityPublic> GetPublic() const { return m_Public; };
  const uint8_t * GetPrivateKey() const { return m_CryptoPrivateKey; };
  const uint8_t * GetSigningPrivateKey() const { return m_SigningPrivateKey; };
  size_t GetSignatureLen() const; // might not match identity
  bool IsOfflineSignature() const { return m_TransientSignatureLen > 0; };
  uint8_t * GetPadding();
  void RecalculateIdentHash(uint8_t * buf=nullptr) { m_Public->RecalculateIdentHash(buf); }
  size_t GetFullLen() const;

  void Sign(const uint8_t * buf, int len, uint8_t * signature) const;

  //void Decrypt(const uint8_t * encrypted, uint8_t * data, CryptoKeyType preferredCrypto = CRYPTO_KEY_TYPE_ECDH_P256_SHA256_AES256CBC);
  std::vector<uint8_t> Decrypt(const uint8_t * encrypted, size_t elen);
  std::shared_ptr<pbote::ECDHP256Decryptor> CreateDecryptor(const uint8_t * key) const;
  static std::shared_ptr<pbote::ECDHP256Decryptor> CreateDecryptor(CryptoKeyType cryptoType, const uint8_t * key);

  std::vector<uint8_t> Encrypt (const uint8_t * data, int dlen, const uint8_t *pubKey) const;
  std::shared_ptr<pbote::CryptoKeyEncryptor> CreateEncryptor(const uint8_t *key) const;
  static std::shared_ptr<pbote::ECDHP256Encryptor> CreateEncryptor(const uint8_t *priv, const uint8_t *key);

  static EmailIdentityPrivate CreateRandomKeys(SigningKeyType type = SIGNING_KEY_TYPE_ECDSA_SHA256_P256, CryptoKeyType cryptoType = CRYPTO_KEY_TYPE_ECDH_P256_SHA256_AES256CBC);
  static void GenerateSigningKeyPair(SigningKeyType type, uint8_t * priv, uint8_t * pub);
  static void GenerateCryptoKeyPair(CryptoKeyType type, uint8_t * priv, uint8_t * pub);
  static i2p::crypto::Signer * CreateSigner(SigningKeyType keyType, const uint8_t * priv);

  // offline keys
  EmailIdentityPrivate CreateOfflineKeys(SigningKeyType type, uint32_t expires) const;
  const std::vector<uint8_t>& GetOfflineSignature() const { return m_OfflineSignature; };

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
  std::vector<uint8_t> m_OfflineSignature; // non zero length, if applicable
  size_t m_TransientSignatureLen = 0;
  size_t m_TransientSigningPrivateKeyLen = 0;
};

/// ECDH-256 / ECDSA-256 / AES-256 / SHA-256 params
const std::string ECDH256_ECDSA256_NAME = "ECDH-256 / ECDSA-256";
const size_t ECDH256_ECDSA256_COMPLETE_BASE64_LENGTH = 172;
const size_t ECDH256_ECDSA256_COMPLETE_BASE64_PUBLIC_LENGTH = 86;
const size_t ECDH256_ECDSA256_COMPLETE_BYTE_ARRAY_KEY_LENGTH = 33;

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

/**
 * Identities file
 *
 * Stores all email identities the local user has created. The file uses the
 * Java Properties format, and can be read into / written out from a Java
 * Properties object.
 *
 * The following property keys are currently stored and recognized:
 *    identity#.publicName  - The public name of the identity, included in
 *        emails.
 *    identity#.key         - Base64 of the identity keys.
 *    identity#.salt        - Salt used to generate a fingerprint.
 *    identity#.description - Description of the identity, only displayed
 *        locally.
 *    identity#.picture     - Base64 of byte[] containing picture data
 *    identity#.text        - Text associated with the identity.
 *    identity#.published   - Has the identity been published to the public
 *        addressbook?
 *    (# is an integer index)
 *
 * The base64 key contains two public keys (encryption+signing) and two private
 * keys.
 *
 * The identities file can optionally contain the property key "default", with
 * its value set to an Email Destination (i.e. two public keys). If the
 * Email Destination matches one of the identities, that identity is used as
 * the default.
 */

struct EmailIdentityFull {
  uint16_t id;
  std::string salt;
  std::string publicName;
  std::string full_key;
  Keys keys;
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

  static std::string getParam(std::string line, const std::string& prefix0, std::string prefix1);

 private:
  std::vector<std::shared_ptr<EmailIdentityFull>> identities_;
  std::string default_identity_;
};

} // namespace pbote

#endif // EMAIL_IDENTITIY_H__
