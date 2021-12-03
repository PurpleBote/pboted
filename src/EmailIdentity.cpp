/**
 * Copyright (c) 2019-2021 polistern
 */

#include <string>
#include <string_view>

#include "EmailIdentity.h"

#include "I2PEndian.h"

namespace pbote {

EmailIdentityPublic::EmailIdentityPublic() {}

EmailIdentityPublic::EmailIdentityPublic(const uint8_t *publicKey,
                                         const uint8_t *signingKey,
                                         SigningKeyType signingType,
                                         CryptoKeyType cryptoType) {
  size_t cryptoPublicKeyLen, signingPublicKeyLen;
  if (signingType == SIGNING_KEY_TYPE_ECDSA_P256_SHA256 && cryptoType == CRYPTO_KEY_TYPE_ECDH_P256_SHA256_AES256CBC) {
    cryptoPublicKeyLen = ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH;
    signingPublicKeyLen = ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH;
    m_StandardIdentity = std::make_shared<ECDHP256Identity>();
  } else {
    cryptoPublicKeyLen = 0;
    signingPublicKeyLen = 0;
  }

  m_StandardIdentity->setCryptoPublicKey(publicKey, cryptoPublicKeyLen);
  m_StandardIdentity->setSigningPublicKey(signingKey, signingPublicKeyLen);

  RecalculateIdentHash();
  CreateVerifier();
}

void EmailIdentityPublic::RecalculateIdentHash(uint8_t *buf) {
  bool dofree = buf == nullptr;
  size_t sz = GetFullLen();
  if (!buf)
    buf = new uint8_t[sz];
  ToBuffer(buf, sz);
  SHA256(buf, sz, m_IdentHash);
  if (dofree)
    delete[] buf;
}

EmailIdentityPublic::EmailIdentityPublic(const uint8_t *buf, size_t len) {
  FromBuffer(buf, len);
}

EmailIdentityPublic::EmailIdentityPublic(const EmailIdentityPublic &other) {
  *this = other;
}

EmailIdentityPublic::~EmailIdentityPublic() {
  delete m_Verifier;
}

EmailIdentityPublic &EmailIdentityPublic::operator=(const EmailIdentityPublic &other) {
  m_StandardIdentity = other.m_StandardIdentity;
  m_IdentHash = other.m_IdentHash;

  delete m_Verifier;
  m_Verifier = nullptr;

  return *this;
}

size_t EmailIdentityPublic::FromBuffer(const uint8_t *buf, size_t len) {
  if (len < m_StandardIdentity->get_identity_size()) {
    LogPrint(eLogError, "Identity: buffer length ", len, " is too small");
    return 0;
  }
  m_StandardIdentity->from_buffer(buf, len);
  SHA256(buf, GetFullLen(), m_IdentHash);

  delete m_Verifier;
  m_Verifier = nullptr;

  return GetFullLen();
}

size_t EmailIdentityPublic::ToBuffer(uint8_t *buf, size_t len) const {
  const size_t fullLen = GetFullLen();
  if (fullLen > len) return 0; // buffer is too small and may overflow somewhere else
  return m_StandardIdentity->to_buffer(buf, len);
}

size_t EmailIdentityPublic::FromBase64(const std::string &s) {
  //const size_t slen = s.length();
  //std::vector<uint8_t> buf(slen); // binary data can't exceed base64
  uint8_t *buf = new uint8_t[s.length()];
  const size_t l = i2p::data::Base64ToByteStream(s.c_str(), s.length(), buf, s.length());
  //LogPrint(eLogDebug, "EmailIdentityPublic: FromBase64: l: ", l);
  return FromBuffer(buf, l);
}

std::string EmailIdentityPublic::ToBase64() const {
  const size_t bufLen = GetFullLen();
  const size_t strLen = i2p::data::Base64EncodingBufferSize(bufLen);
  std::vector<uint8_t> buf(bufLen);
  std::vector<char> str(strLen);
  size_t l = ToBuffer(buf.data(), bufLen);
  size_t l1 = i2p::data::ByteStreamToBase64(buf.data(), l, str.data(), strLen);
  return std::string(str.data(), l1);
}

size_t EmailIdentityPublic::GetSigningPublicKeyLen() const {
  if (!m_Verifier) CreateVerifier();
  if (m_Verifier)
    return m_Verifier->GetPublicKeyLen();
  return 128;
}

const uint8_t *EmailIdentityPublic::GetSigningPublicKeyBuffer() const {
  return m_StandardIdentity->getSigningPublicKey();
}

size_t EmailIdentityPublic::GetSigningPrivateKeyLen() const {
  if (!m_Verifier) CreateVerifier();
  if (m_Verifier)
    return m_Verifier->GetPrivateKeyLen();
  return GetSignatureLen() / 2;
}

size_t EmailIdentityPublic::GetSignatureLen() const {
  if (!m_Verifier) CreateVerifier();
  if (m_Verifier)
    return m_Verifier->GetSignatureLen();
  return i2p::crypto::DSA_SIGNATURE_LENGTH;
}

bool EmailIdentityPublic::Verify(const uint8_t *buf, size_t len, const uint8_t *signature) const {
  if (!m_Verifier) CreateVerifier();
  if (m_Verifier)
    return m_Verifier->Verify(buf, len, signature);
  return false;
}

SigningKeyType EmailIdentityPublic::GetSigningKeyType() const { return m_StandardIdentity->get_identity_type(); }

CryptoKeyType EmailIdentityPublic::GetCryptoKeyType() const { return m_StandardIdentity->get_identity_type(); }

i2p::crypto::Verifier *EmailIdentityPublic::CreateVerifier(SigningKeyType keyType) {
  switch (keyType) {
    case SIGNING_KEY_TYPE_ECDSA_P256_SHA256:
      return new i2p::crypto::ECDSAP256Verifier();
      break;
    case SIGNING_KEY_TYPE_ECIES_X25519_AES256:
      return nullptr; // ToDo: TBD
    default:
      LogPrint (eLogError, "EmailIdentityPublic: Unknown signing key type ", (int)keyType);
  }
  return nullptr;
}

void EmailIdentityPublic::CreateVerifier() const {
  if (m_Verifier) return; // don't create again
  auto verifier = CreateVerifier(GetSigningKeyType());
  if (verifier) {
    //auto keyLen = verifier->GetPublicKeyLen();
    verifier->SetPublicKey(m_StandardIdentity->getSigningPublicKey());
  }
  UpdateVerifier(verifier);
}

void EmailIdentityPublic::UpdateVerifier(i2p::crypto::Verifier *verifier) const {
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

void EmailIdentityPublic::DropVerifier() const {
  i2p::crypto::Verifier *verifier;
  {
    std::lock_guard<std::mutex> l(m_VerifierMutex);
    verifier = m_Verifier;
    m_Verifier = nullptr;
  }
  delete verifier;
}

size_t EmailIdentityPublic::GetFullLen() const {
  return m_StandardIdentity->get_identity_size();
}

EmailIdentityPrivate &EmailIdentityPrivate::operator=(const EmailIdentityPrivate &other) {
  m_Public = std::make_shared<EmailIdentityPublic>(*other.m_Public);
  memcpy(m_CryptoPrivateKey, other.m_CryptoPrivateKey, 33);
  m_Signer = nullptr;
  CreateSigner();
  return *this;
}

size_t EmailIdentityPrivate::GetFullLen() const {
  size_t ret = m_Public->GetFullLen() + GetPrivateKeyLen() + m_Public->GetSigningPrivateKeyLen();
  return ret;
}

size_t EmailIdentityPrivate::FromBuffer(const uint8_t *buf, size_t len) {
  m_Public = std::make_shared<EmailIdentityPublic>();
  size_t ret = m_Public->FromBuffer(buf, len);

  auto cryptoKeyLen = GetPrivateKeyLen();
  if (!ret || ret + cryptoKeyLen > len) return 0; // overflow
  memcpy(m_CryptoPrivateKey, buf + ret, cryptoKeyLen);
  ret += cryptoKeyLen;
  size_t signingPrivateKeySize = m_Public->GetSigningPrivateKeyLen();
  if (signingPrivateKeySize + ret > len || signingPrivateKeySize > 33) return 0; // overflow
  memcpy(m_SigningPrivateKey, buf + ret, signingPrivateKeySize);
  ret += signingPrivateKeySize;
  m_Signer = nullptr;
  // check if signing private key is all zeros
  bool allzeros = true;
  for (size_t i = 0; i < signingPrivateKeySize; i++)
    if (m_SigningPrivateKey[i]) {
      allzeros = false;
      break;
    }
  if (allzeros) {
    ret += 4; // expires timestamp
    SigningKeyType keyType = bufbe16toh(buf + ret);
    ret += 2; // key type
    std::unique_ptr<i2p::crypto::Verifier> transientVerifier(EmailIdentityPublic::CreateVerifier(keyType));
    if (!transientVerifier) return 0;
    auto keyLen = transientVerifier->GetPublicKeyLen();
    if (keyLen + ret > len) return 0;
    transientVerifier->SetPublicKey(buf + ret);
    ret += keyLen;
    if (m_Public->GetSignatureLen() + ret > len) return 0;
    ret += m_Public->GetSignatureLen();
    CreateSigner(keyType);
  } else
    CreateSigner(m_Public->GetSigningKeyType());
  return ret;
}

size_t EmailIdentityPrivate::ToBuffer(uint8_t *buf, size_t len) const {
  size_t ret = m_Public->ToBuffer(buf, len);
  auto cryptoKeyLen = GetPrivateKeyLen();
  memcpy(buf + ret, m_CryptoPrivateKey, cryptoKeyLen);
  ret += cryptoKeyLen;
  size_t signingPrivateKeySize = m_Public->GetSigningPrivateKeyLen();
  if (ret + signingPrivateKeySize > len) return 0; // overflow
  memcpy(buf + ret, m_SigningPrivateKey, signingPrivateKeySize);
  ret += signingPrivateKeySize;
  return ret;
}

size_t EmailIdentityPrivate::FromBase64(const std::string &s) {
  uint8_t *buf = new uint8_t[s.length()];
  size_t l = i2p::data::Base64ToByteStream(s.c_str(), s.length(), buf, s.length());
  LogPrint(eLogDebug, "EmailIdentityPrivate: FromBase64: l: ", l);
  size_t ret = FromBuffer(buf, l);
  delete[] buf;
  return ret;
}

std::string EmailIdentityPrivate::ToBase64() const {
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

void EmailIdentityPrivate::Sign(const uint8_t *buf, int len, uint8_t *signature) const {
  if (!m_Signer)
    CreateSigner();
  m_Signer->Sign(buf, len, signature);
}

void EmailIdentityPrivate::CreateSigner() const {
  CreateSigner(m_Public->GetSigningKeyType());
}

void EmailIdentityPrivate::CreateSigner(SigningKeyType keyType) const {
  if (m_Signer) return;
  // public key is not required
  auto signer = CreateSigner(keyType, m_SigningPrivateKey);
  if (signer) m_Signer.reset(signer);
}

i2p::crypto::Signer *EmailIdentityPrivate::CreateSigner(SigningKeyType keyType, const uint8_t *priv) {
  switch (keyType) {
    case SIGNING_KEY_TYPE_ECDSA_P256_SHA256:
      return new i2p::crypto::ECDSAP256Signer(priv);
    case SIGNING_KEY_TYPE_ECIES_X25519_AES256:
      return nullptr; // ToDo: TBD
    default:LogPrint(eLogError, "Identity: Signing key type ", (int) keyType, " is not supported");
  }
  return nullptr;
}

size_t EmailIdentityPrivate::GetSignatureLen() const {
  return  m_Public->GetSignatureLen();
}

size_t EmailIdentityPrivate::GetPrivateKeyLen() const {
  return (m_Public->GetCryptoKeyType () == CRYPTO_KEY_TYPE_ECIES_X25519_AES256) ? 32 : 256;
}

std::vector<uint8_t> EmailIdentityPrivate::Decrypt(const uint8_t * encrypted, size_t elen) {
  auto decryptor = CreateDecryptor(nullptr);
  //auto decryptor = CreateDecryptor(m_SigningPrivateKey);
  if (decryptor) {
    auto result = decryptor->Decrypt(encrypted, elen);
    return result;
  }
  return {};
}

std::shared_ptr<pbote::ECDHP256Decryptor> EmailIdentityPrivate::CreateDecryptor(const uint8_t *key) const {
  if (!key) key = m_CryptoPrivateKey; // use privateKey
  return CreateDecryptor(m_Public->GetCryptoKeyType(), key);
}

std::shared_ptr<pbote::ECDHP256Decryptor> EmailIdentityPrivate::CreateDecryptor(CryptoKeyType cryptoType,
                                                                                       const uint8_t *key) {
  if (!key) return nullptr;
  switch (cryptoType) {
    case CRYPTO_KEY_TYPE_ECDH_P256_SHA256_AES256CBC:
      return std::make_shared<pbote::ECDHP256Decryptor>(key);
    default:
      LogPrint(eLogError, "Identity: Unknown crypto key type ", (int) cryptoType);
  };
  return nullptr;
}

std::vector<uint8_t> EmailIdentityPrivate::Encrypt(const uint8_t *data, int len, const uint8_t *pubKey) const {
  auto encryptor = CreateEncryptor(pubKey);
  std::vector<byte> edata;
  if (encryptor)
    edata = encryptor->Encrypt(data, len);
  return edata;
}

std::shared_ptr<pbote::CryptoKeyEncryptor> EmailIdentityPrivate::CreateEncryptor(const uint8_t *key) const {
  if (!key)
    key = m_Public->GetEncryptionPublicKey(); // use publicKey
  return CreateEncryptor(m_Public->GetCryptoKeyType(), key);
}

std::shared_ptr<pbote::ECDHP256Encryptor> EmailIdentityPrivate::CreateEncryptor(const CryptoKeyType keyType,
                                                                               const uint8_t *key) {
  switch (keyType){
    case CRYPTO_KEY_TYPE_ECDH_P256_SHA256_AES256CBC:
      return std::make_shared<pbote::ECDHP256Encryptor>(key);
      break;
    case CRYPTO_KEY_TYPE_ECIES_X25519_AES256:
      return nullptr; // ToDo: TBD
      break;
    default:
      LogPrint (eLogError, "Identity: Unknown crypto key type ", (int)keyType);
  }
  return nullptr;
}

/*EmailIdentityPrivate EmailIdentityPrivate::CreateRandomKeys(SigningKeyType type, CryptoKeyType cryptoType) {
  EmailIdentityPrivate keys;
  // signature
  uint8_t signingPublicKey[33];
  GenerateSigningKeyPair(type, keys.m_SigningPrivateKey, signingPublicKey);
  // encryption
  uint8_t cryptoPublicKey[33];
  GenerateCryptoKeyPair(cryptoType, keys.m_CryptoPrivateKey, cryptoPublicKey);
  // identity
  keys.m_Public = std::make_shared<EmailIdentityPublic>(cryptoPublicKey, signingPublicKey, type, cryptoType);

  keys.CreateSigner();
  return keys;
}*/

void EmailIdentityPrivate::GenerateSigningKeyPair(SigningKeyType type, uint8_t *priv, uint8_t *pub) {
  switch (type) {
    case SIGNING_KEY_TYPE_ECDSA_P256_SHA256:
      i2p::crypto::CreateECDSAP256RandomKeys(priv, pub);
#if (__cplusplus >= 201703L) // C++ 17 or higher
      [[fallthrough]];
#endif
    case SIGNING_KEY_TYPE_ECIES_X25519_AES256:
      // ToDo: TBD
    default:LogPrint(eLogWarning, "Identity: Signing key type ", (int) type, " is not supported.");
  }
}

/*void EmailIdentityPrivate::GenerateCryptoKeyPair(CryptoKeyType type, uint8_t *priv, uint8_t *pub) {
  switch (type) {
    case CRYPTO_KEY_TYPE_ECDH_P256_SHA256_AES256CBC:
      i2p::crypto::CreateECIESP256RandomKeys(priv, pub);
      break;
    default:
      LogPrint(eLogError, "Identity: Crypto key type ", (int) type, " is not supported");
  }
}*/

void identitiesStorage::init() {
  //ToDo: add file encryption/decryption
  LogPrint(eLogInfo, "identitiesStorage: init: Try load identities from file");
  //std::string localDestinationPath = pbote::fs::DataDirPath("identities.dat");
  std::string localDestinationPath = pbote::fs::DataDirPath("identities.txt");

  int identities_count = loadIdentities(localDestinationPath);
  if (identities_count == 0)
    LogPrint(eLogWarning, "identitiesStorage: init: Can't load identities from file: ", localDestinationPath);
  else if (identities_count < 0)
    LogPrint(eLogWarning, "identitiesStorage: init: Identities file does not exist: ", localDestinationPath);
  else
    LogPrint(eLogInfo, "identitiesStorage: init: Load ", identities_count, " identities.");
}

size_t identitiesStorage::loadIdentities(const std::string &path) {
  // ToDo: bad code, need to rethink
  // ToDo: move load to context
  std::string value_delimiter = "=";
  char ident_delimiter = '.';

  LogPrint(eLogDebug, "Email: load identity from file ", path);

  // Check if file exist
  std::ifstream f(path);
  if (!f.good()) return -1;
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

  //for (size_t i = 0; i < lines.size(); i++)
  //LogPrint(eLogDebug, "EmailIdentity: loadIdentities: ", lines[i]);

  // now we can start parse values to identities
  for (std::string ident: identities) {
    EmailIdentityFull temp_ident;
    temp_ident.id = std::atoi(&ident.back());
    //LogPrint(eLogDebug, "EmailIdentity: content for ", temp_ident.id);
    for (std::string line : lines) {
      std::string t_ident = ident;
      t_ident.append(".");
      //LogPrint(eLogDebug, "EmailIdentity: loadIdentities: ident=", ident, ", t_ident=", t_ident);
      if (!line.find(t_ident.append(IDENTITY_PREFIX_KEY))) {
        //LogPrint(eLogDebug, "EmailIdentity: loadIdentities: IDENTITY_PREFIX_KEY=", line);
        temp_ident.full_key = getParam(line, ident, IDENTITY_PREFIX_KEY);
      }
      t_ident = ident;
      t_ident.append(".");
      if (!line.find(t_ident.append(IDENTITY_PREFIX_PUBLIC_NAME))) {
        //LogPrint(eLogDebug, "EmailIdentity: loadIdentities: IDENTITY_PREFIX_PUBLIC_NAME=", line);
        temp_ident.publicName = getParam(line, ident, IDENTITY_PREFIX_PUBLIC_NAME);
      }

      //temp_ident.publicName = getParam(line, ident, IDENTITY_PREFIX_PUBLIC_NAME);
      /*if (!line.find(t_ident.append(IDENTITY_PREFIX_DESCRIPTION)))
        temp_ident.description = getParam(line, ident, IDENTITY_PREFIX_DESCRIPTION);

      if (!line.find(t_ident.append(IDENTITY_PREFIX_PICTURE)))
        temp_ident.picture = getParam(line, ident, IDENTITY_PREFIX_PICTURE);

      if (!line.find(t_ident.append(IDENTITY_PREFIX_TEXT)))
        temp_ident.text = getParam(line, ident, IDENTITY_PREFIX_TEXT);*/
    }
    //LogPrint(eLogDebug, "EmailIdentity: loadIdentities: name=", temp_ident.publicName);
    //LogPrint(eLogDebug, "EmailIdentity: loadIdentities: full_key=", temp_ident.full_key);
    //LogPrint(eLogDebug, "EmailIdentity: loadIdentities: description=", temp_ident.description);
    //LogPrint(eLogDebug, "EmailIdentity: loadIdentities: picture=", temp_ident.picture);
    //LogPrint(eLogDebug, "EmailIdentity: loadIdentities: text=", temp_ident.text);
    //LogPrint(eLogDebug, "EmailIdentity: loadIdentities: size=", temp_ident.full_key.size());
    if (temp_ident.full_key.size() == ECDH256_ECDSA256_COMPLETE_BASE64_LENGTH) {
      temp_ident.isDefault = false;
      temp_ident.isEncrypted = false;
      temp_ident.isPublished = false;

      // Parse keys
      size_t offset = 0;
      std::string cryptoPubKey = "A" + temp_ident.full_key.substr(0, 43);
      offset += 43;
      std::string signingPubKey = "A" + temp_ident.full_key.substr(offset, 43);
      offset += 43;
      std::string cryptoPrivKey = "A" + temp_ident.full_key.substr(offset, 43);
      offset += 43;
      std::string signingPrivKey = "A" + temp_ident.full_key.substr(offset, 43);
      //offset += 43;
      //LogPrint(eLogDebug, "EmailIdentity: loadIdentities: cryptoPubKey=", cryptoPubKey);
      //LogPrint(eLogDebug, "EmailIdentity: loadIdentities: signingPubKey=", signingPubKey);
      //LogPrint(eLogDebug, "EmailIdentity: loadIdentities: cryptoPrivKey=", cryptoPrivKey);
      //LogPrint(eLogDebug, "EmailIdentity: loadIdentities: signingPrivKey=", signingPrivKey);

      const size_t pubKeyPair_slen = cryptoPubKey.length();
      uint8_t* pubKeyPair_buf = new uint8_t[pubKeyPair_slen]; // binary data can't exceed base64
      const size_t cryptoPubKey_buf_len = i2p::data::Base64ToByteStream(cryptoPubKey.c_str(),
                                                                        pubKeyPair_slen,
                                                                        pubKeyPair_buf,
                                                                        pubKeyPair_slen);
      if (cryptoPubKey_buf_len >= 33)
        temp_ident.identity.GetPublicIdentity()->GetStandardIdentity()->setCryptoPublicKey(pubKeyPair_buf, 33);
      //LogPrint(eLogDebug, "EmailIdentity: loadIdentities: cryptoPubKey_buf_len=", cryptoPubKey_buf_len);

      const size_t signingPubKey_slen = signingPubKey.length();
      uint8_t* signingPubKey_buf = new uint8_t[signingPubKey_slen]; // binary data can't exceed base64
      const size_t signingPubKey_buf_len = i2p::data::Base64ToByteStream(signingPubKey.c_str(),
                                                                         signingPubKey_slen,
                                                                         signingPubKey_buf,
                                                                         signingPubKey_slen);
      if (signingPubKey_buf_len >= 33)
        temp_ident.identity.GetPublicIdentity()->GetStandardIdentity()->setSigningPublicKey(signingPubKey_buf, 33);
      //LogPrint(eLogDebug, "EmailIdentity: loadIdentities: signingPubKey_buf_len=", signingPubKey_buf_len);

      const size_t cryptoPrivKey_slen = cryptoPrivKey.length();
      uint8_t* cryptoPrivKey_buf = new uint8_t[cryptoPrivKey_slen]; // binary data can't exceed base64
      const size_t cryptoPrivKey_buf_len = i2p::data::Base64ToByteStream(cryptoPrivKey.c_str(),
                                                                         cryptoPrivKey_slen,
                                                                         cryptoPrivKey_buf,
                                                                         cryptoPrivKey_slen);
      if (cryptoPrivKey_buf_len >= 33)
        temp_ident.identity.GetPublicIdentity()->GetStandardIdentity()->setCryptoPrivateKey(cryptoPrivKey_buf, 33);
      //LogPrint(eLogDebug, "EmailIdentity: loadIdentities: cryptoPrivKey_buf_len=", cryptoPrivKey_buf_len);

      const size_t signingPrivKey_slen = signingPrivKey.length();
      uint8_t* signingPrivKey_buf = new uint8_t[signingPrivKey_slen]; // binary data can't exceed base64
      const size_t signingPrivKey_len = i2p::data::Base64ToByteStream(signingPrivKey.c_str(),
                                                                      signingPrivKey_slen,
                                                                      signingPrivKey_buf,
                                                                      signingPrivKey_slen);
      if (signingPrivKey_len >= 33)
        temp_ident.identity.GetPublicIdentity()->GetStandardIdentity()->setSigningPrivateKey(signingPrivKey_buf, 33);
      //LogPrint(eLogDebug, "EmailIdentity: loadIdentities: signingPrivKey_len=", signingPrivKey_len);

      //temp_ident.identity = temp_ident.keys;
      temp_ident.type = temp_ident.identity.GetPublicIdentity()->GetCryptoKeyType();
      //LogPrint(eLogDebug,"EmailIdentity: loadIdentities: identity.ToBase64()=", temp_ident.identity.ToBase64());
      //LogPrint(eLogDebug,"EmailIdentity: loadIdentities: idenhash.ToBase64()=", temp_ident.identity.GetPublic()->GetIdentHash().ToBase64());
      //LogPrint(eLogDebug,"EmailIdentity: loadIdentities: idenhash.ToBase32()=", temp_ident.identity.GetPublic()->GetIdentHash().ToBase32());
      LogPrint(eLogDebug, "EmailIdentity: loadIdentities: email identity added: ", temp_ident.publicName);
    } else
      LogPrint(eLogDebug, "EmailIdentity: loadIdentities: Can't create email identity from base64");

    addIdentityToStorage(temp_ident);
  }
  return identities.size();
}

/// static
std::string identitiesStorage::getParam(std::string line, const std::string& prefix0, std::string prefix1) {
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

void identitiesStorage::addIdentityToStorage(EmailIdentityFull ident) {
  std::shared_ptr<EmailIdentityFull> s_ident = std::make_shared<EmailIdentityFull>(ident);
  identities_.push_back(s_ident);
}

} // namespace pbote
