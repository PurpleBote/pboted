/**
 * Copyright (c) 2019-2022, polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include "BoteIdentity.h"

namespace pbote
{

/// Public Identity

BoteIdentityPublic::BoteIdentityPublic(KeyType keyType)
{
  LogPrint(eLogDebug, "EmailIdentityPublic: Key type: ", keyTypeToString(keyType));

  switch (keyType)
    {
      case KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC:
        m_Identity.reset(new ECDHP256Identity());
        break;
      case KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC:
        m_Identity.reset(new ECDHP521Identity());
        break;
      case KEY_TYPE_X25519_ED25519_SHA512_AES256CBC:
        m_Identity.reset(new X25519Identity());
        break;
      default:
        LogPrint(eLogError, "EmailIdentityPublic: Unsupported key type: ", keyTypeToString(keyType));
    }

  RecalculateIdentHash();
  /* ToDo
  CreateVerifier();
  */
}

BoteIdentityPublic::BoteIdentityPublic(const uint8_t *cryptoPublicKey, const uint8_t *signingPublicKey, KeyType keyType)
{
  size_t cryptoPublicKeyLen, signingPublicKeyLen;
  LogPrint(eLogDebug, "BoteIdentityPublic: Key type: ", keyTypeToString(keyType));

  if (keyType == KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC)
    {
      cryptoPublicKeyLen = ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH;
      signingPublicKeyLen = ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH;

      m_Identity.reset(new ECDHP256Identity());

      m_Identity->setCryptoPublicKey(cryptoPublicKey, cryptoPublicKeyLen);
      m_Identity->setSigningPublicKey(signingPublicKey, signingPublicKeyLen);
    }
  else if (keyType == KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC)
    {
      cryptoPublicKeyLen = ECDH521_ECDSA521_BYTE_PUBLIC_KEY_LENGTH;
      signingPublicKeyLen = ECDH521_ECDSA521_BYTE_PUBLIC_KEY_LENGTH;

      m_Identity.reset(new ECDHP521Identity());

      m_Identity->setCryptoPublicKey(cryptoPublicKey, cryptoPublicKeyLen);
      m_Identity->setSigningPublicKey(signingPublicKey, signingPublicKeyLen);
    }
  else if (keyType == KEY_TYPE_X25519_ED25519_SHA512_AES256CBC)
    {
      cryptoPublicKeyLen = X25519_ED25519_BYTE_PUBLIC_KEY_LENGTH;
      signingPublicKeyLen = X25519_ED25519_BYTE_PUBLIC_KEY_LENGTH;

      m_Identity.reset(new X25519Identity());

      m_Identity->setCryptoPublicKey(cryptoPublicKey, cryptoPublicKeyLen);
      m_Identity->setSigningPublicKey(signingPublicKey, signingPublicKeyLen);
    }
  else
    {
      LogPrint(eLogError, "BoteIdentityPublic: Unsupported key type: ", keyTypeToString(keyType));
    }

  RecalculateIdentHash();
  /* ToDo
  CreateVerifier();
  */
}

void BoteIdentityPublic::RecalculateIdentHash()
{
  size_t sz = GetFullLen();
  uint8_t *buf = new uint8_t[sz];

  ToBuffer(buf, sz);
  SHA256(buf, sz, m_IdentHash);

  delete[] buf;
}

BoteIdentityPublic &BoteIdentityPublic::operator=(const BoteIdentityPublic &other)
{
  m_Identity = other.m_Identity;
  m_IdentHash = other.m_IdentHash;

  /* ToDo
  delete m_Verifier;
  m_Verifier = nullptr;
  */

  return *this;
}

size_t BoteIdentityPublic::FromBuffer(const uint8_t *buf, size_t len)
{
  if (len < m_Identity->get_identity_size())
    {
      LogPrint(eLogError, "BoteIdentityPublic: FromBuffer: Buffer length ", len, " is too small");
      return 0;
    }

  m_Identity->from_buffer(buf, len);
  RecalculateIdentHash();

  /* ToDo
  delete m_Verifier;
  m_Verifier = nullptr;
   */

  return GetFullLen();
}

size_t BoteIdentityPublic::ToBuffer(uint8_t *buf, size_t len) const
{
  const size_t fullLen = GetFullLen();

  if (fullLen > len)
    return 0; // buffer overflow

  return m_Identity->to_buffer(buf, len);
}

size_t BoteIdentityPublic::FromBase64(const std::string &s)
{
  const size_t slen = s.length();
  std::vector<uint8_t> buf(slen); // binary data can't exceed base64

  const size_t l = i2p::data::Base64ToByteStream(s.c_str(), s.length(), buf.data(), slen);

  return FromBuffer(buf.data(), l);
}

std::string BoteIdentityPublic::ToBase64() const
{
  const size_t bufLen = GetFullLen();
  const size_t strLen = i2p::data::Base64EncodingBufferSize(bufLen);
  std::vector<uint8_t> buf(bufLen);
  std::vector<char> str(strLen);
  size_t l = ToBuffer(buf.data(), bufLen);
  size_t l1 = i2p::data::ByteStreamToBase64(buf.data(), l, str.data(), strLen);

  return std::string(str.data(), l1);
}

std::string BoteIdentityPublic::ToBase64v1() const
{
  const size_t bufLen = GetFullLen();
  const size_t strLen = i2p::data::Base64EncodingBufferSize(bufLen + 5);
  std::vector<uint8_t> data(bufLen);
  std::vector<char> str(strLen);
  size_t l = ToBuffer(data.data(), bufLen);

  std::vector<uint8_t> buf;


  switch(GetKeyType())
    {
      case KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC:
        {
          uint8_t temp_2[5] = {ADDRES_FORMAT_V1,CRYP_TYPE_ECDH256,SIGN_TYPE_ECDSA256,SYMM_TYPE_AES_256,HASH_TYPE_SHA_256};
          buf = std::vector<uint8_t>(std::begin(temp_2), std::end(temp_2));
          break;
        }
      case KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC:
        {
          uint8_t temp_3[5] = {ADDRES_FORMAT_V1,CRYP_TYPE_ECDH521,SIGN_TYPE_ECDSA521,SYMM_TYPE_AES_256,HASH_TYPE_SHA_512};
          buf = std::vector<uint8_t>(std::begin(temp_3), std::end(temp_3));
          break;
        }
      case KEY_TYPE_X25519_ED25519_SHA512_AES256CBC:
        {
          uint8_t temp_4[5] = {ADDRES_FORMAT_V1,CRYP_TYPE_X25519,SIGN_TYPE_ED25519,SYMM_TYPE_AES_256,HASH_TYPE_SHA_512};
          buf = std::vector<uint8_t>(std::begin(temp_4), std::end(temp_4));
          break;
        }
      default:
        return {};
    }

  buf.insert( buf.end(), data.begin(), data.end() );

  size_t l1 = i2p::data::ByteStreamToBase64(buf.data(), l + 5, str.data(), strLen);

  return { str.data(), l1 };
}

size_t BoteIdentityPublic::GetSignatureLen() const
{
  /* ToDo
  if (!m_Verifier)
    CreateVerifier();

  if (m_Verifier)
    return m_Verifier->GetSignatureLen();
  */
  return 0;
}

std::vector<uint8_t> BoteIdentityPublic::Encrypt(const uint8_t *data, int len, const uint8_t *pubKey) const
{
  auto encryptor = CreateEncryptor(pubKey);
  if (encryptor)
    return encryptor->Encrypt(data, len);
  return {};
}

std::shared_ptr<pbote::CryptoKeyEncryptor> BoteIdentityPublic::CreateEncryptor(const uint8_t *key) const
{
  if (!key)
    key = GetCryptoPublicKey();
  return CreateEncryptor(GetKeyType(), key);
}

std::shared_ptr<pbote::CryptoKeyEncryptor> BoteIdentityPublic::CreateEncryptor(const KeyType keyType, const uint8_t *key)
{
  LogPrint (eLogDebug, "BoteIdentityPublic: CreateEncryptor: Crypto key type: ", keyTypeToString(keyType));
  switch (keyType)
    {
      case KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC:
        return std::make_shared<pbote::ECDHP256Encryptor>(key);
      case KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC:
        return std::make_shared<pbote::ECDHP521Encryptor>(key);
      case KEY_TYPE_X25519_ED25519_SHA512_AES256CBC:
        return std::make_shared<pbote::X25519Encryptor>(key);
      default:
        LogPrint (eLogError, "BoteIdentityPublic: CreateEncryptor: Unsupported crypto key type ",
                  keyTypeToString(keyType));
    }
  return nullptr;
}

bool BoteIdentityPublic::Verify(const uint8_t *buf, size_t len, const uint8_t *signature) const
{
  if (!m_Verifier)
    CreateVerifier();

  if (m_Verifier)
    return m_Verifier->Verify(buf, len, signature);
  return false;
}

i2p::crypto::Verifier *BoteIdentityPublic::CreateVerifier(KeyType keyType)
{
  switch (keyType)
    {
      case KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC:
        return nullptr;
        // ToDo: return new i2p::crypto::ECDSAP256Verifier();
      case KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC:
        return nullptr;
        // ToDo: return new i2p::crypto::ECDSAP521Verifier();
      case KEY_TYPE_X25519_ED25519_SHA512_AES256CBC:
        return nullptr;
        // ToDo: return new i2p::crypto::ED25519Verifier();
      default:
        LogPrint (eLogError, "BoteIdentityPublic: CreateVerifier: Unsupported signing key type ", keyTypeToString(keyType));
    }
  return nullptr;
}

void BoteIdentityPublic::DropVerifier() const
{
  i2p::crypto::Verifier *verifier;

  {
    std::lock_guard<std::mutex> l(m_VerifierMutex);
    verifier = m_Verifier;
    m_Verifier = nullptr;
  }

  delete verifier;
}

void BoteIdentityPublic::CreateVerifier() const
{
  if (m_Verifier)
    return; // don't create again

  auto verifier = CreateVerifier(GetKeyType());
  if (verifier)
    verifier->SetPublicKey(m_Identity->getSigningPublicKey());

  UpdateVerifier(verifier);
}

void BoteIdentityPublic::UpdateVerifier(i2p::crypto::Verifier *verifier) const
{
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

BoteIdentityPrivate::BoteIdentityPrivate(KeyType type)
{
  m_Public.reset(new BoteIdentityPublic(type));
}

BoteIdentityPrivate &BoteIdentityPrivate::operator=(const BoteIdentityPrivate &other)
{
  m_Public = std::make_shared<BoteIdentityPublic>(*other.m_Public);

  setCryptoPrivateKey(other.GetCryptoPrivateKey(), other.getCryptoPrivateKeyLen());
  setSigningPrivateKey(other.GetSigningPrivateKey(), other.getSigningPrivateKeyLen());

  /* ToDo
  m_Signer = nullptr;
  CreateSigner();
  */

  return *this;
}

size_t BoteIdentityPrivate::FromBuffer(const uint8_t *buf, size_t len)
{
  m_Public = std::make_shared<BoteIdentityPublic>(GetKeyType());
  size_t ret = m_Public->FromBuffer(buf, len);

  auto cryptoKeyLen = getCryptoPrivateKeyLen();

  if (!ret || ret + cryptoKeyLen > len)
    return 0; // overflow

  setCryptoPrivateKey(buf + ret, cryptoKeyLen);
  ret += cryptoKeyLen;

  size_t signingPrivateKeySize = getSigningPrivateKeyLen();
  if (signingPrivateKeySize + ret > len)
    return 0; // overflow

  setSigningPrivateKey(buf + ret, signingPrivateKeySize);
  ret += signingPrivateKeySize;

  /* ToDo
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
  */

  return ret;
}

size_t BoteIdentityPrivate::ToBuffer(uint8_t *buf, size_t len) const
{
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

size_t BoteIdentityPrivate::FromBase64(const std::string &s)
{
  uint8_t *buf = new uint8_t[s.length()];
  size_t l = i2p::data::Base64ToByteStream(s.c_str(), s.length(), buf, s.length());
  LogPrint(eLogDebug, "BoteIdentityPrivate: FromBase64: l: ", l);
  size_t ret = FromBuffer(buf, l);
  delete[] buf;
  return ret;
}

std::string BoteIdentityPrivate::ToBase64() const
{
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

void BoteIdentityPrivate::Sign(const uint8_t *buf, int len, uint8_t *signature) const
{
  if (!m_Signer)
    CreateSigner();

  m_Signer->Sign(buf, len, signature);
}

i2p::crypto::Signer *BoteIdentityPrivate::CreateSigner(KeyType keyType, const uint8_t *priv)
{
  switch (keyType)
    {
      case KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC:
        return nullptr;
        // ToDo: return new i2p::crypto::ECDSAP256Signer(priv);
      case KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC:
        return nullptr;
        // ToDo: return new i2p::crypto::ECDSAP521Signer(priv);
      case KEY_TYPE_X25519_ED25519_SHA512_AES256CBC:
        return nullptr;
        // ToDo: return new i2p::crypto::ED25519Signer(priv);
      default:
        LogPrint(eLogError, "BoteIdentityPrivate: CreateSigner: Unsupported signing key type ", keyTypeToString(keyType));
    }
  return nullptr;
}

std::vector<uint8_t> BoteIdentityPrivate::Decrypt(const uint8_t * encrypted, size_t len)
{
  auto decryptor = CreateDecryptor();
  if (decryptor)
    return decryptor->Decrypt(encrypted, len);
  return {};
}

std::shared_ptr<pbote::CryptoKeyDecryptor> BoteIdentityPrivate::CreateDecryptor() const
{
  switch (GetKeyType())
    {
      case KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC:
        return std::make_shared<pbote::ECDHP256Decryptor>(GetCryptoPrivateKey());
      case KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC:
        return std::make_shared<pbote::ECDHP521Decryptor>(GetCryptoPrivateKey());
      case KEY_TYPE_X25519_ED25519_SHA512_AES256CBC:
        return std::make_shared<pbote::X25519Decryptor>(GetCryptoPrivateKey());
      default:
        LogPrint(eLogError, "BoteIdentityPrivate: CreateDecryptor: Unsupported crypto key type ",
                 keyTypeToString(GetKeyType()));
    }
  return nullptr;
}

void BoteIdentityPrivate::CreateSigner(KeyType keyType) const
{
  if (m_Signer)
    return;

  auto signer = CreateSigner(keyType, GetSigningPrivateKey());
  if (signer)
    m_Signer.reset(signer);
}

/// Identities Storage

void identitiesStorage::init()
{
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

long identitiesStorage::loadIdentities(const std::string &path)
{
  // ToDo: Move load to context
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

  /// Read lines
  for (std::string line; getline(infile, line);)
    {
      /// If start with "identity" - add to parsing
      if (line.rfind(IDENTITY_PREFIX, 0) == 0)
        {
          lines.push_back(line);

          std::string token = line.substr(0, line.find(value_delimiter));
          std::string ident = token.substr(0, line.find(ident_delimiter));

          /// Add only unique identity prefix like "identity0", "identity1", etc.
          if (std::find(identities.begin(), identities.end(), ident) == identities.end())
            identities.push_back(ident);
        }

      /// If start with "default" - save to default_identity_
      if (!line.find(IDENTITY_PREFIX_DEFAULT))
        default_identity_ = line;
    }
  infile.close();

  /// Now we can start parse values to identities
  for (std::string ident : identities)
    {
      BoteIdentityFull temp_ident;
      temp_ident.id = std::atoi(&ident.back());

      for (const std::string& line : lines)
        {
          std::string t_ident = ident;
          t_ident.append(".");

          if (line.find (t_ident + IDENTITY_PREFIX_KEY) != std::string::npos)
            {
              temp_ident.full_key = getParam(line, ident, IDENTITY_PREFIX_KEY);
              continue;
            }

          if (line.find (t_ident + IDENTITY_PREFIX_PUBLIC_NAME) != std::string::npos)
            {
              temp_ident.publicName = getParam(line, ident, IDENTITY_PREFIX_PUBLIC_NAME);
              continue;
            }

          if (line.find (t_ident + IDENTITY_PREFIX_DESCRIPTION) != std::string::npos)
            {
              temp_ident.description = getParam(line, ident, IDENTITY_PREFIX_DESCRIPTION);
              continue;
            }

          if (line.find (t_ident + IDENTITY_PREFIX_PICTURE) != std::string::npos)
            {
              temp_ident.picture = getParam(line, ident, IDENTITY_PREFIX_PICTURE);
              continue;
            }

          if (line.find (t_ident + IDENTITY_PREFIX_TEXT) != std::string::npos)
            {
              temp_ident.text = getParam(line, ident, IDENTITY_PREFIX_TEXT);
              continue;
            }
        }

      LogPrint(eLogDebug, "identitiesStorage: loadIdentities: name: \"", temp_ident.publicName, "\"");
      LogPrint(eLogDebug, "identitiesStorage: loadIdentities: full_key: ", temp_ident.full_key);
      LogPrint(eLogDebug, "identitiesStorage: loadIdentities: description: \"", temp_ident.description, "\"");
      //LogPrint(eLogDebug, "identitiesStorage: loadIdentities: picture: ", temp_ident.picture);
      //LogPrint(eLogDebug, "identitiesStorage: loadIdentities: text: \"", temp_ident.text, "\"");
      LogPrint(eLogDebug, "identitiesStorage: loadIdentities: size: ", temp_ident.full_key.size());

      bool parse_success = false;
      std::string format_prefix = temp_ident.full_key.substr(0, temp_ident.full_key.find(".") + 1);
      LogPrint(eLogDebug, "identitiesStorage: loadIdentities: format_prefix: \"", format_prefix, "\"");

      if (format_prefix.compare(ADDRESS_B32_PREFIX) == 0)
        parse_success = parse_identity_v1(&temp_ident);
      else if (format_prefix.compare(ADDRESS_B64_PREFIX) == 0)
        parse_success = parse_identity_v1(&temp_ident);
      else
        parse_success = parse_identity_v0(&temp_ident);

      if (!parse_success)
        continue;

      addIdentityToStorage(temp_ident);
    }
  return (long)identities.size();
}

std::string identitiesStorage::getParam(std::string line, const std::string& prefix0, const std::string& prefix1)
{
  std::string prefix = prefix0 + "." + prefix1 + "=";
  std::string line_start = line.substr (0, prefix.length ());

  if (line_start.compare (prefix) != 0)
    return {};

  line.erase (0, prefix.length ());

  //LogPrint(eLogDebug, "identitiesStorage: getParam: prefix: \"", prefix, "\"");
  //LogPrint(eLogDebug, "identitiesStorage: getParam: line_start: \"", line_start, "\"");
  //LogPrint(eLogDebug, "identitiesStorage: getParam: line erased: \"", line, "\"");

  return line;
}

bool identitiesStorage::parse_identity_v0(BoteIdentityFull *identity)
{
  size_t base64_key_len = 0, offset = 0;

  if (identity->full_key.length() == ECDH256_ECDSA256_COMPLETE_BASE64_LENGTH)
    {
      identity->identity = BoteIdentityPrivate(KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC);
      base64_key_len = ECDH256_ECDSA256_PUBLIC_BASE64_LENGTH / 2;
    }
  else if (identity->full_key.length() == ECDH521_ECDSA521_COMPLETE_BASE64_LENGTH)
    {
      identity->identity = BoteIdentityPrivate(KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC);
      base64_key_len = ECDH521_ECDSA521_PUBLIC_BASE64_LENGTH / 2;
    }
  else
    {
      LogPrint(eLogWarning, "identitiesStorage: parse_identity_v0: Unsupported identity type");
      return false;
    }

  identity->type = identity->identity.GetKeyType();
  identity->isDefault = false;
  identity->isEncrypted = false;
  identity->isPublished = false;

  // Restore keys
  std::string cryptoPublicKey = "A" + identity->full_key.substr(offset, (base64_key_len));
  offset += (base64_key_len);
  std::string signingPublicKey = "A" + identity->full_key.substr(offset, (base64_key_len));
  offset += (base64_key_len);
  std::string cryptoPrivateKey = "A" + identity->full_key.substr(offset, (base64_key_len));
  offset += (base64_key_len);
  std::string signingPrivateKey = "A" + identity->full_key.substr(offset, (base64_key_len));

  std::string restored_identity_str;
  restored_identity_str.append(cryptoPublicKey);
  restored_identity_str.append(signingPublicKey);
  restored_identity_str.append(cryptoPrivateKey);
  restored_identity_str.append(signingPrivateKey);

  identity->identity.FromBase64(restored_identity_str);

  LogPrint(eLogDebug, "identitiesStorage: parse_identity_v0: identity.ToBase64: ",
           identity->identity.ToBase64());
  LogPrint(eLogDebug, "identitiesStorage: parse_identity_v0: idenhash.ToBase64: ",
           identity->identity.GetIdentHash().ToBase64());
  LogPrint(eLogDebug, "identitiesStorage: parse_identity_v0: idenhash.ToBase32: ",
           identity->identity.GetIdentHash().ToBase32());
  LogPrint(eLogDebug, "identitiesStorage: parse_identity_v0: email identity added: ",
           identity->publicName);

  return true;
}

bool identitiesStorage::parse_identity_v1 (BoteIdentityFull *identity)
{
  std::string format_prefix = identity->full_key.substr (0, identity->full_key.find (".") + 1);
  std::string base_str = identity->full_key.substr (format_prefix.length ());
  // ToDo: Define length from base32/64
  uint8_t identity_bytes[2048];
  size_t identity_len = 0;

  if (format_prefix.compare (ADDRESS_B32_PREFIX) == 0)
    identity_len = i2p::data::Base32ToByteStream (base_str.c_str (), base_str.length (), identity_bytes, 2048);
  else if (format_prefix.compare (ADDRESS_B64_PREFIX) == 0)
    identity_len = i2p::data::Base64ToByteStream (base_str.c_str (), base_str.length (), identity_bytes, 2048);
  else
    return false;

  if (identity_len < 5)
    {
      LogPrint (eLogError, "identitiesStorage: parse_identity_v1: Malformed address");
      return false;
    }

  if (identity_bytes[0] != ADDRES_FORMAT_V1)
    {
      LogPrint (eLogError, "identitiesStorage: parse_identity_v1: Unsupported address format");
      return false;
    }

  if (identity_bytes[1] == CRYP_TYPE_ECDH256 &&
      identity_bytes[2] == SIGN_TYPE_ECDSA256 &&
      identity_bytes[3] == SYMM_TYPE_AES_256 &&
      identity_bytes[4] == HASH_TYPE_SHA_256)
    {
      identity->identity = BoteIdentityPrivate(KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC);
    }
  else if (identity_bytes[1] == CRYP_TYPE_ECDH521 &&
           identity_bytes[2] == SIGN_TYPE_ECDSA521 &&
           identity_bytes[3] == SYMM_TYPE_AES_256 &&
           identity_bytes[4] == HASH_TYPE_SHA_512)
    {
      identity->identity = BoteIdentityPrivate(KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC);
    }
  else if (identity_bytes[1] == CRYP_TYPE_X25519 &&
           identity_bytes[2] == SIGN_TYPE_ED25519 &&
           identity_bytes[3] == SYMM_TYPE_AES_256 &&
           identity_bytes[4] == HASH_TYPE_SHA_512)
    {
      identity->identity = BoteIdentityPrivate(KEY_TYPE_X25519_ED25519_SHA512_AES256CBC);
    }

  identity->type = identity->identity.GetKeyType();
  identity->isDefault = false;
  identity->isEncrypted = false;
  identity->isPublished = false;

  size_t len = identity->identity.FromBuffer(identity_bytes + 5, identity_len);

  if (len == 0)
    return false;

  LogPrint(eLogDebug, "identitiesStorage: parse_identity_v1: identity.ToBase64: ",
           identity->identity.ToBase64());
  LogPrint(eLogDebug, "identitiesStorage: parse_identity_v1: idenhash.ToBase64: ",
           identity->identity.GetIdentHash().ToBase64());
  LogPrint(eLogDebug, "identitiesStorage: parse_identity_v1: idenhash.ToBase32: ",
           identity->identity.GetIdentHash().ToBase32());
  LogPrint(eLogDebug, "identitiesStorage: parse_identity_v1: email identity added: ",
           identity->publicName);

  return true;
}

} // namespace pbote
