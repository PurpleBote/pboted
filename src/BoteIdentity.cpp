/**
 * Copyright (c) 2019-2021 polistern
 */

#include "BoteIdentity.h"

namespace pbote {

/// Public Identity

BoteIdentityPublic::BoteIdentityPublic(KeyType keyType) {
  LogPrint(eLogDebug, "EmailIdentityPublic: Key type: ", keyTypeToString(keyType));

  switch (keyType) {
    case KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC:
      m_Identity.reset(new ECDHP256Identity());
      break;
    case KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC:
      //m_Identity.reset(new ECDHP256Identity());
      break;
    case KEY_TYPE_X25519_ED25519_SHA512_AES256CBC:
      //m_Identity.reset(new ECDHP256Identity());
      break;
    default:
      LogPrint(eLogError, "EmailIdentityPublic: Unsupported key type: ", keyTypeToString(keyType));
  }

  RecalculateIdentHash();
  CreateVerifier();
}

BoteIdentityPublic::BoteIdentityPublic(const uint8_t *cryptoPublicKey, const uint8_t *signingPublicKey, KeyType keyType) {
  size_t cryptoPublicKeyLen, signingPublicKeyLen;
  LogPrint(eLogDebug, "BoteIdentityPublic: Key type: ", keyTypeToString(keyType));

  if (keyType == KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC) {
    cryptoPublicKeyLen = ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH;
    signingPublicKeyLen = ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH;

    m_Identity.reset(new ECDHP256Identity());

    m_Identity->setCryptoPublicKey(cryptoPublicKey, cryptoPublicKeyLen);
    m_Identity->setSigningPublicKey(signingPublicKey, signingPublicKeyLen);
  } else if (keyType == KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC) {
    // ToDo
  } else if (keyType == KEY_TYPE_X25519_ED25519_SHA512_AES256CBC) {
    // ToDo
  } else {
    LogPrint(eLogError, "BoteIdentityPublic: Unsupported key type: ", keyTypeToString(keyType));
  }

  RecalculateIdentHash();
  CreateVerifier();
}

void BoteIdentityPublic::RecalculateIdentHash() {
  size_t sz = GetFullLen();
  uint8_t *buf = new uint8_t[sz];

  ToBuffer(buf, sz);
  SHA256(buf, sz, m_IdentHash);

  delete[] buf;
}

BoteIdentityPublic &BoteIdentityPublic::operator=(const BoteIdentityPublic &other) {
  m_Identity = other.m_Identity;
  m_IdentHash = other.m_IdentHash;

  delete m_Verifier;
  m_Verifier = nullptr;

  return *this;
}

size_t BoteIdentityPublic::FromBuffer(const uint8_t *buf, size_t len) {
  if (len < m_Identity->get_identity_size()) {
    LogPrint(eLogError, "BoteIdentityPublic: FromBuffer: Buffer length ", len, " is too small");
    return 0;
  }

  m_Identity->from_buffer(buf, len);
  RecalculateIdentHash();

  delete m_Verifier;
  m_Verifier = nullptr;

  return GetFullLen();
}

size_t BoteIdentityPublic::ToBuffer(uint8_t *buf, size_t len) const {
  const size_t fullLen = GetFullLen();

  if (fullLen > len)
    return 0; // buffer is too small and may overflow somewhere else

  return m_Identity->to_buffer(buf, len);
}

size_t BoteIdentityPublic::FromBase64(const std::string &s) {
  const size_t slen = s.length();
  std::vector<uint8_t> buf(slen); // binary data can't exceed base64

  const size_t l = i2p::data::Base64ToByteStream(s.c_str(), s.length(), buf.data(), slen);

  return FromBuffer(buf.data(), l);
}

std::string BoteIdentityPublic::ToBase64() const {
  const size_t bufLen = GetFullLen();
  const size_t strLen = i2p::data::Base64EncodingBufferSize(bufLen);
  std::vector<uint8_t> buf(bufLen);
  std::vector<char> str(strLen);
  size_t l = ToBuffer(buf.data(), bufLen);
  size_t l1 = i2p::data::ByteStreamToBase64(buf.data(), l, str.data(), strLen);

  return std::string(str.data(), l1);
}

size_t BoteIdentityPublic::GetSignatureLen() const {
  if (!m_Verifier)
    CreateVerifier();

  if (m_Verifier)
    return m_Verifier->GetSignatureLen();
  return 0; // ToDo
}

std::vector<uint8_t> BoteIdentityPublic::Encrypt(const uint8_t *data, int len, const uint8_t *pubKey) const {
  auto encryptor = CreateEncryptor(pubKey);
  if (encryptor)
    return encryptor->Encrypt(data, len);
  return {};
}

std::shared_ptr<pbote::CryptoKeyEncryptor> BoteIdentityPublic::CreateEncryptor(const uint8_t *key) const {
  if (!key)
    key = GetCryptoPublicKey(); // use publicKey
  return CreateEncryptor(GetKeyType(), key);
}

std::shared_ptr<pbote::CryptoKeyEncryptor> BoteIdentityPublic::CreateEncryptor(const KeyType keyType, const uint8_t *key) {
  LogPrint (eLogDebug, "BoteIdentityPublic: CreateEncryptor: Crypto key type: ", keyTypeToString(keyType));
  switch (keyType){
    case KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC:
      return std::make_shared<pbote::ECDHP256Encryptor>(key);
    case KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC:
      return nullptr; // ToDo
    case KEY_TYPE_X25519_ED25519_SHA512_AES256CBC:
      return nullptr; // ToDo
    default:
      LogPrint (eLogError, "BoteIdentityPublic: CreateEncryptor: Unsupported crypto key type ",
                keyTypeToString(keyType));
  }
  return nullptr;
}

bool BoteIdentityPublic::Verify(const uint8_t *buf, size_t len, const uint8_t *signature) const {
  if (!m_Verifier)
    CreateVerifier();

  if (m_Verifier)
    return m_Verifier->Verify(buf, len, signature);
  return false;
}

i2p::crypto::Verifier *BoteIdentityPublic::CreateVerifier(KeyType keyType) {
  switch (keyType) {
    case KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC:
      return new i2p::crypto::ECDSAP256Verifier();
    case KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC:
      return nullptr; // ToDo
    case KEY_TYPE_X25519_ED25519_SHA512_AES256CBC:
      return nullptr; // ToDo
    default:
      LogPrint (eLogError, "BoteIdentityPublic: CreateVerifier: Unsupported signing key type ", keyTypeToString(keyType));
  }
  return nullptr;
}

void BoteIdentityPublic::DropVerifier() const {
  i2p::crypto::Verifier *verifier;
  {
    std::lock_guard<std::mutex> l(m_VerifierMutex);
    verifier = m_Verifier;
    m_Verifier = nullptr;
  }
  delete verifier;
}

void BoteIdentityPublic::CreateVerifier() const {
  if (m_Verifier)
    return; // don't create again

  auto verifier = CreateVerifier(GetKeyType());
  if (verifier)
    verifier->SetPublicKey(m_Identity->getSigningPublicKey());

  UpdateVerifier(verifier);
}

void BoteIdentityPublic::UpdateVerifier(i2p::crypto::Verifier *verifier) const {
  bool del = false;
  {
    std::lock_guard<std::mutex> l(m_VerifierMutex);
    if (!m_Verifier)
      m_Verifier = verifier;
    else
      del = true;
  }
  if (del)
    delete verifier;
}

/// Private Identity

BoteIdentityPrivate::BoteIdentityPrivate(KeyType type) {
  m_Public.reset(new BoteIdentityPublic(type));
}

BoteIdentityPrivate &BoteIdentityPrivate::operator=(const BoteIdentityPrivate &other) {
  m_Public = std::make_shared<BoteIdentityPublic>(*other.m_Public);

  setCryptoPrivateKey(other.GetCryptoPrivateKey(), other.getCryptoPrivateKeyLen());
  setSigningPrivateKey(other.GetSigningPrivateKey(), other.getSigningPrivateKeyLen());

  m_Signer = nullptr;
  CreateSigner();

  return *this;
}

size_t BoteIdentityPrivate::FromBuffer(const uint8_t *buf, size_t len) {
  m_Public = std::make_shared<BoteIdentityPublic>(GetKeyType());
  size_t ret = m_Public->FromBuffer(buf, len);

  auto cryptoKeyLen = getCryptoPrivateKeyLen();

  if (!ret || ret + cryptoKeyLen > len)
    return 0; // overflow

  setCryptoPrivateKey(buf + ret, cryptoKeyLen);
  ret += cryptoKeyLen;

  size_t signingPrivateKeySize = getSigningPrivateKeyLen();
  if (signingPrivateKeySize + ret > len || signingPrivateKeySize > 33)
    return 0; // overflow

  setSigningPrivateKey(buf + ret, signingPrivateKeySize);
  ret += signingPrivateKeySize;

  m_Signer = nullptr;
  // check if signing private key is all zeros
  bool allzeros = true;
  for (size_t i = 0; i < signingPrivateKeySize; i++)
    if (GetSigningPrivateKey()[i]) {
      allzeros = false;
      break;
    }

  if (allzeros) {
    std::unique_ptr<i2p::crypto::Verifier> transientVerifier(BoteIdentityPublic::CreateVerifier(m_Public->GetKeyType()));
    if (!transientVerifier)
      return 0;

    auto keyLen = transientVerifier->GetPublicKeyLen();
    if (keyLen + ret > len)
      return 0;

    transientVerifier->SetPublicKey(buf + ret);
    ret += keyLen;

    if (m_Public->GetSignatureLen() + ret > len)
      return 0;

    ret += m_Public->GetSignatureLen();
    CreateSigner(m_Public->GetKeyType());
  } else
    CreateSigner(m_Public->GetKeyType());

  return ret;
}

size_t BoteIdentityPrivate::ToBuffer(uint8_t *buf, size_t len) const {
  if (m_Public->GetIdentity()->get_identity_full_size() > len)
    return 0; // overflow

  size_t ret = m_Public->ToBuffer(buf, len);

  size_t cryptoKeyLen = getCryptoPrivateKeyLen();
  memcpy(buf + ret, GetCryptoPrivateKey(), cryptoKeyLen);
  ret += cryptoKeyLen;

  size_t signingKeyLen = getSigningPrivateKeyLen();
  memcpy(buf + ret, GetSigningPrivateKey(), signingKeyLen);
  ret += signingKeyLen;

  return ret;
}

size_t BoteIdentityPrivate::FromBase64(const std::string &s) {
  uint8_t *buf = new uint8_t[s.length()];
  size_t l = i2p::data::Base64ToByteStream(s.c_str(), s.length(), buf, s.length());
  LogPrint(eLogDebug, "BoteIdentityPrivate: FromBase64: l: ", l);
  size_t ret = FromBuffer(buf, l);
  delete[] buf;
  return ret;
}

std::string BoteIdentityPrivate::ToBase64() const {
  uint8_t *buf = new uint8_t[GetFullLen()];
  char *str = new char[GetFullLen() * 2];
  size_t l = ToBuffer(buf, GetFullLen());
  size_t l1 = i2p::data::ByteStreamToBase64(buf, l, str, GetFullLen() * 2);
  str[l1] = 0;
  delete[] buf;
  std::string ret(str);
  delete[] str;
  return ret;
}

void BoteIdentityPrivate::Sign(const uint8_t *buf, int len, uint8_t *signature) const {
  if (!m_Signer)
    CreateSigner();

  m_Signer->Sign(buf, len, signature);
}

i2p::crypto::Signer *BoteIdentityPrivate::CreateSigner(KeyType keyType, const uint8_t *priv) {
  switch (keyType) {
    case KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC:
      return new i2p::crypto::ECDSAP256Signer(priv);
    case KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC:
      return nullptr; // ToDo
    case KEY_TYPE_X25519_ED25519_SHA512_AES256CBC:
      return nullptr; // ToDo
    default:LogPrint(eLogError, "BoteIdentityPrivate: CreateSigner: Unsupported signing key type ", keyTypeToString(keyType));
  }
  return nullptr;
}

std::vector<uint8_t> BoteIdentityPrivate::Decrypt(const uint8_t * encrypted, size_t len) {
  auto decryptor = CreateDecryptor();
  if (decryptor)
    return decryptor->Decrypt(encrypted, len);
  return {};
}

std::shared_ptr<pbote::CryptoKeyDecryptor> BoteIdentityPrivate::CreateDecryptor() const {
  switch (GetKeyType()) {
    case KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC:
      return std::make_shared<pbote::ECDHP256Decryptor>(GetCryptoPrivateKey());
    case KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC:
      return nullptr; // ToDo
    case KEY_TYPE_X25519_ED25519_SHA512_AES256CBC:
      return nullptr; // ToDo
    default:
      LogPrint(eLogError, "BoteIdentityPrivate: CreateDecryptor: Unsupported crypto key type ",
               keyTypeToString(GetKeyType()));
  };
  return nullptr;
}

void BoteIdentityPrivate::CreateSigner(KeyType keyType) const {
  if (m_Signer)
    return;

  // public key is not required
  auto signer = CreateSigner(keyType, GetSigningPrivateKey());
  if (signer)
    m_Signer.reset(signer);
}

/// Identities Storage

void identitiesStorage::init() {
  //ToDo: add file encryption/decryption
  std::string identitiesPath = pbote::fs::DataDirPath(DEFAULT_IDENTITY_FILE_NAME);

  LogPrint(eLogInfo, "identitiesStorage: init: Try load identities from file: ", identitiesPath);

  long identities_count = loadIdentities(identitiesPath);
  if (identities_count == 0)
    LogPrint(eLogWarning, "identitiesStorage: init: Can't load identities from file: ", identitiesPath);
  else if (identities_count < 0)
    LogPrint(eLogWarning, "identitiesStorage: init: Identities file does not exist: ", identitiesPath);
  else
    LogPrint(eLogInfo, "identitiesStorage: init: Load ", identities_count, " identities.");
}

long identitiesStorage::loadIdentities(const std::string &path) {
  // ToDo: bad code, need to rethink
  // ToDo: move load to context
  LogPrint(eLogDebug, "identitiesStorage: loadIdentities: load identity from file ", path);

  std::string value_delimiter = "=";
  char ident_delimiter = '.';

  // Check if file exist
  std::ifstream f(path);
  if (!f.good())
    return -1;
  f.close();

  std::vector<std::string> lines;
  std::vector<std::string> identities;
  std::ifstream infile(path);

  // read lines
  for (std::string line; getline(infile, line);) {
    // if start with "identity" - add to parsing
    if (line.rfind(IDENTITY_PREFIX, 0) == 0) {
      lines.push_back(line);

      std::string token = line.substr(0, line.find(value_delimiter));
      std::string ident = token.substr(0, line.find(ident_delimiter));

      // add only unique identity prefix like "identity0", "identity1", etc.
      if (std::find(identities.begin(), identities.end(), ident) == identities.end())
        identities.push_back(ident);
    }

    // if start with "default" - save to default_identity_
    if (!line.find(IDENTITY_PREFIX_DEFAULT))
      default_identity_ = line;
  }
  infile.close();

  // now we can start parse values to identities
  for (std::string ident: identities) {
    BoteIdentityFull temp_ident;
    temp_ident.id = std::atoi(&ident.back());
    for (const std::string& line : lines) {
      std::string t_ident = ident;
      t_ident.append(".");
      if (!line.find(t_ident.append(IDENTITY_PREFIX_KEY)))
        temp_ident.full_key = getParam(line, ident, IDENTITY_PREFIX_KEY);

      t_ident = ident;
      t_ident.append(".");

      if (!line.find(t_ident.append(IDENTITY_PREFIX_PUBLIC_NAME)))
        temp_ident.publicName = getParam(line, ident, IDENTITY_PREFIX_PUBLIC_NAME);

      if (!line.find(t_ident.append(IDENTITY_PREFIX_DESCRIPTION)))
        temp_ident.description = getParam(line, ident, IDENTITY_PREFIX_DESCRIPTION);

      if (!line.find(t_ident.append(IDENTITY_PREFIX_PICTURE)))
        temp_ident.picture = getParam(line, ident, IDENTITY_PREFIX_PICTURE);

      if (!line.find(t_ident.append(IDENTITY_PREFIX_TEXT)))
        temp_ident.text = getParam(line, ident, IDENTITY_PREFIX_TEXT);
    }

    LogPrint(eLogDebug, "identitiesStorage: loadIdentities: name: ", temp_ident.publicName);
    LogPrint(eLogDebug, "identitiesStorage: loadIdentities: full_key: ", temp_ident.full_key);
    LogPrint(eLogDebug, "identitiesStorage: loadIdentities: description: ", temp_ident.description);
    LogPrint(eLogDebug, "identitiesStorage: loadIdentities: picture: ", temp_ident.picture);
    LogPrint(eLogDebug, "identitiesStorage: loadIdentities: text: ", temp_ident.text);
    LogPrint(eLogDebug, "identitiesStorage: loadIdentities: size: ", temp_ident.full_key.size());


    if (temp_ident.full_key.size() == ECDH256_ECDSA256_COMPLETE_BASE64_LENGTH) {
      temp_ident.identity = BoteIdentityPrivate(KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC);
      temp_ident.type = temp_ident.identity.GetKeyType();
      temp_ident.isDefault = false;
      temp_ident.isEncrypted = false;
      temp_ident.isPublished = false;

      // Parse keys
      size_t offset = 0;
      std::string cryptoPublicKey = "A" + temp_ident.full_key.substr(0, (ECDH256_ECDSA256_PUBLIC_BASE64_LENGTH / 2));
      offset += (ECDH256_ECDSA256_PUBLIC_BASE64_LENGTH / 2);
      std::string signingPublicKey = "A" + temp_ident.full_key.substr(offset, (ECDH256_ECDSA256_PUBLIC_BASE64_LENGTH / 2));
      offset += (ECDH256_ECDSA256_PUBLIC_BASE64_LENGTH / 2);
      std::string cryptoPrivateKey = "A" + temp_ident.full_key.substr(offset, (ECDH256_ECDSA256_PUBLIC_BASE64_LENGTH / 2));
      offset += (ECDH256_ECDSA256_PUBLIC_BASE64_LENGTH / 2);
      std::string signingPrivateKey = "A" + temp_ident.full_key.substr(offset, (ECDH256_ECDSA256_PUBLIC_BASE64_LENGTH / 2));

      std::string restored_identity_str;
      restored_identity_str.append(cryptoPublicKey);
      restored_identity_str.append(signingPublicKey);
      restored_identity_str.append(cryptoPrivateKey);
      restored_identity_str.append(signingPrivateKey);

      temp_ident.identity.FromBase64(restored_identity_str);

      LogPrint(eLogDebug,"identitiesStorage: loadIdentities: identity.ToBase64: ", temp_ident.identity.ToBase64());
      LogPrint(eLogDebug,"identitiesStorage: loadIdentities: idenhash.ToBase64: ",
               temp_ident.identity.GetIdentHash().ToBase64());
      LogPrint(eLogDebug,"identitiesStorage: loadIdentities: idenhash.ToBase32: ",
               temp_ident.identity.GetIdentHash().ToBase32());
      LogPrint(eLogDebug, "identitiesStorage: loadIdentities: email identity added: ", temp_ident.publicName);
    } else
      LogPrint(eLogWarning, "identitiesStorage: loadIdentities: Unsupported identity type");

    addIdentityToStorage(temp_ident);
  }
  return (long)identities.size();
}

std::string identitiesStorage::getParam(std::string line, const std::string& prefix0, const std::string& prefix1) {
  std::string value_delimiter = "=";
  std::string prefix = prefix0 + "." + prefix1;
  if (!line.find(prefix)) {
    size_t pos = 0;
    std::string token;
    while (pos != std::string::npos) {
      pos = line.find(value_delimiter);
      token = line.substr(0, pos);
      line.erase(0, pos + value_delimiter.length());
    }
    return line;
  } else {
    return {};
  }
}

} // namespace pbote
