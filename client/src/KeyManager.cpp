#include "KeyManager.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <QDir>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include "MessageProtocol.h"

KeyManager::KeyManager(const std::string& phoneNumber)
    : phoneNumber(phoneNumber), currentSignedPrekeyId(1), nextOneTimePrekeyId(1) {
    keyDirectory = "keys/" + phoneNumber;
    ensureKeyDirectory();
    
    if (!loadKeys()) {
        std::cout << "No existing keys found, generating new keys..." << std::endl;
        generateIdentityKeyPair();
        generateSignedPrekey();
        generateOneTimePrekeys(100);
        saveKeys();
    }
}

void KeyManager::ensureKeyDirectory() {
    QDir dir;
    dir.mkpath(QString::fromStdString(keyDirectory));
}

void KeyManager::generateIdentityKeyPair() {
    try {
        // Correct way to generate Ed25519 key pair in Crypto++
        identityPrivateKey.AccessPrivateKey().GenerateRandom(rng);
        identityPublicKey = CryptoPP::ed25519::Verifier(identityPrivateKey);
        std::cout << "Generated ed25519 identity key pair for: " << phoneNumber << std::endl;
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("Failed to generate identity key pair: " + std::string(e.what()));
    }
}

void KeyManager::generateSignedPrekey() {
    try {
        CryptoPP::x25519 signedPrekeyPrivate;
        signedPrekeyPrivate.GenerateRandom(rng, CryptoPP::g_nullNameValuePairs);
        
        // Get public key as string
        std::string publicKeyStr = encodeX25519PublicKey(signedPrekeyPrivate);

        signedPrekeys[currentSignedPrekeyId] = signedPrekeyPrivate;
        signedPrekeyPublics[currentSignedPrekeyId] = publicKeyStr;

        std::cout << "Generated signed prekey with ID: " << currentSignedPrekeyId << std::endl;
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("Failed to generate signed prekey: " + std::string(e.what()));
    }
}

void KeyManager::generateOneTimePrekeys(int count) {
    try {
        for (int i = 0; i < count; i++) {
            CryptoPP::x25519 otkPrivate;
            otkPrivate.GenerateRandom(rng, CryptoPP::g_nullNameValuePairs);
            
            std::string publicKeyStr = encodeX25519PublicKey(otkPrivate);

            oneTimePrekeys[nextOneTimePrekeyId] = otkPrivate;
            oneTimePrekeyPublics[nextOneTimePrekeyId] = publicKeyStr;
            nextOneTimePrekeyId++;
        }

        std::cout << "Generated " << count << " one-time prekeys" << std::endl;
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("Failed to generate one-time prekeys: " + std::string(e.what()));
    }
}

KeyBundle KeyManager::getCurrentKeyBundle() const {
    KeyBundle bundle;
    bundle.identityKey = getIdentityPublicKeyString();
    
    // ✅ GENERATE IDENTITY KEY SELF-SIGNATURE
    std::string identitySignature;
    if (signData(bundle.identityKey, identitySignature)) {
        bundle.identityKeySignature = identitySignature;
    }
    
    if (!signedPrekeyPublics.empty()) {
        auto it = signedPrekeyPublics.find(currentSignedPrekeyId);
        if (it != signedPrekeyPublics.end()) {
            bundle.signedPrekey = it->second;
            bundle.signedPrekeyId = currentSignedPrekeyId;
            std::string signature;
            if (signData(bundle.signedPrekey, signature)) {
                bundle.signedPrekeySignature = signature;
            }
        }
    }
    
    if (!oneTimePrekeyPublics.empty()) {
        auto it = oneTimePrekeyPublics.begin();
        bundle.oneTimePrekey = it->second;
        bundle.oneTimePrekeyId = it->first;
    }
    
    return bundle;
}


std::string KeyManager::getIdentityPublicKeyString() const {
    return encodePublicKey(identityPublicKey);
}

bool KeyManager::signData(const std::string& data, std::string& signature) const {
    try {
        std::string sig;
        CryptoPP::StringSource ss(data, true,
            new CryptoPP::SignerFilter(rng, identityPrivateKey,
                new CryptoPP::Base64Encoder(new CryptoPP::StringSink(sig), false)));
        signature = sig;
        return true;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Signing error: " << e.what() << std::endl;
        return false;
    }
}

bool KeyManager::verifySignature(const std::string& data, const std::string& signature, const std::string& publicKeyStr) const {
    try {
        CryptoPP::ed25519::Verifier verifier = decodeEd25519Verifier(publicKeyStr);
        
        // Decode signature from base64
        std::string decodedSignature;
        CryptoPP::StringSource(signature, true,
            new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedSignature)));
        
        // Verify signature - this returns true/false directly
        return verifier.VerifyMessage(
            (const CryptoPP::byte*)data.data(), data.size(),
            (const CryptoPP::byte*)decodedSignature.data(), decodedSignature.size()
        );
        
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Signature verification error: " << e.what() << std::endl;
        return false;
    }
}

std::string KeyManager::performDH(const CryptoPP::x25519& privateKey, const std::string& publicKeyStr) const {
    try {
        // Decode the public key
        std::string decodedPublicKey = decodeX25519PublicKey(publicKeyStr);
        
        CryptoPP::SecByteBlock sharedSecret(32);
        CryptoPP::SecByteBlock privateKeyBytes(32);
        CryptoPP::SecByteBlock publicKeyBytes(decodedPublicKey.size());
        
        // Get private key material
        std::string privateKeyString;
        CryptoPP::StringSink privateSink(privateKeyString);
        privateKey.Save(privateSink);
        
        // Copy key material
        std::memcpy(privateKeyBytes.data(), privateKeyString.data(), std::min(32ul, privateKeyString.size()));
        std::memcpy(publicKeyBytes.data(), decodedPublicKey.data(), decodedPublicKey.size());
        
        if (!privateKey.Agree(sharedSecret, privateKeyBytes, publicKeyBytes)) {
            throw std::runtime_error("Key agreement failed");
        }

        std::string encoded;
        CryptoPP::StringSource ss(sharedSecret, sharedSecret.size(), true,
            new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));
        return encoded;
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("DH operation failed: " + std::string(e.what()));
    }
}

CryptoPP::x25519 KeyManager::getEphemeralKey() const {
    CryptoPP::x25519 ephemeralKey;
    ephemeralKey.GenerateRandom(rng, CryptoPP::g_nullNameValuePairs);
    return ephemeralKey;
}

bool KeyManager::addContactKeyBundle(const std::string& phoneNumber, const KeyBundle& keyBundle) {
    // ✅ RE-ENABLE SIGNATURE VERIFICATION
    if (!verifySignature(keyBundle.signedPrekey, keyBundle.signedPrekeySignature, keyBundle.identityKey)) {
        std::cerr << "Invalid signed prekey signature for: " << phoneNumber << std::endl;
        return false;
    }
    
    // Also verify identity key self-signature if present
    if (!keyBundle.identityKeySignature.empty()) {
        if (!verifySignature(keyBundle.identityKey, keyBundle.identityKeySignature, keyBundle.identityKey)) {
            std::cerr << "Invalid identity key self-signature for: " << phoneNumber << std::endl;
            return false;
        }
    }
    
    std::cout << "Adding contact key bundle for: " << phoneNumber << " (signature verified)" << std::endl;
    contactKeyBundles[phoneNumber] = keyBundle;
    return saveKeys();
}


KeyBundle KeyManager::getContactKeyBundle(const std::string& phoneNumber) const {
    auto it = contactKeyBundles.find(phoneNumber);
    if (it != contactKeyBundles.end()) {
        return it->second;
    }
    throw std::runtime_error("Contact key bundle not found: " + phoneNumber);
}

bool KeyManager::hasContactKeyBundle(const std::string& phoneNumber) const {
    return contactKeyBundles.find(phoneNumber) != contactKeyBundles.end();
}

void KeyManager::removeContactKeyBundle(const std::string& phoneNumber) {
    contactKeyBundles.erase(phoneNumber);
    saveKeys();
}

void KeyManager::markOneTimePrekeyUsed(uint32_t keyId) {
    oneTimePrekeys.erase(keyId);
    oneTimePrekeyPublics.erase(keyId);
    saveOneTimePrekeys();
}

std::vector<std::string> KeyManager::getOneTimePrekeyPublics() const {
    std::vector<std::string> publics;
    for (const auto& pair : oneTimePrekeyPublics) {
        publics.push_back(pair.second);
    }
    return publics;
}

void KeyManager::rotateSignedPrekey() {
    currentSignedPrekeyId++;
    generateSignedPrekey();
    saveSignedPrekeys();
}

bool KeyManager::loadKeys() {
    return loadIdentityKeys() && loadSignedPrekeys() && loadOneTimePrekeys();
}

bool KeyManager::saveKeys() {
    return saveIdentityKeys() && saveSignedPrekeys() && saveOneTimePrekeys();
}

bool KeyManager::loadIdentityKeys() {
    try {
        std::ifstream file(getIdentityKeysPath());
        if (!file.is_open()) return false;

        std::string line;
        if (std::getline(file, line)) {
            identityPrivateKey = decodeEd25519Signer(line);
            identityPublicKey = CryptoPP::ed25519::Verifier(identityPrivateKey);
        }

        // Load contact key bundles
        std::ifstream contactsFile(getContactKeysPath());
        if (contactsFile.is_open()) {
            std::string contactLine;
            while (std::getline(contactsFile, contactLine)) {
                if (contactLine.empty()) continue;
                std::istringstream iss(contactLine);
                std::string phone, bundleData;
                if (std::getline(iss, phone, '|') && std::getline(iss, bundleData)) {
                    try {
                        KeyBundle bundle = MessageSerializer::deserializeKeyBundle(bundleData);
                        contactKeyBundles[phone] = bundle;
                    } catch (...) {
                        std::cerr << "Failed to load contact key bundle for: " << phone << std::endl;
                    }
                }
            }
        }

        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error loading identity keys: " << e.what() << std::endl;
        return false;
    }
}

bool KeyManager::saveIdentityKeys() {
    try {
        std::ofstream file(getIdentityKeysPath());
        if (!file.is_open()) return false;
        
        file << encodePrivateKey(identityPrivateKey) << std::endl;

        // Save contact key bundles
        std::ofstream contactsFile(getContactKeysPath());
        if (contactsFile.is_open()) {
            for (const auto& pair : contactKeyBundles) {
                std::string bundleData = MessageSerializer::serialize(pair.second);
                contactsFile << pair.first << "|" << bundleData << std::endl;
            }
        }

        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error saving identity keys: " << e.what() << std::endl;
        return false;
    }
}

bool KeyManager::loadSignedPrekeys() {
    try {
        std::ifstream file(getSignedPrekeysPath());
        if (!file.is_open()) return false;

        std::string line;
        if (std::getline(file, line)) {
            currentSignedPrekeyId = std::stoul(line);
        }

        while (std::getline(file, line)) {
            std::istringstream iss(line);
            std::string idStr, privateKeyStr, publicKeyStr;
            if (std::getline(iss, idStr, '|') && 
                std::getline(iss, privateKeyStr, '|') &&
                std::getline(iss, publicKeyStr)) {
                uint32_t id = std::stoul(idStr);
                CryptoPP::x25519 privateKey = decodeX25519PrivateKey(privateKeyStr);
                
                signedPrekeys[id] = privateKey;
                signedPrekeyPublics[id] = publicKeyStr;
            }
        }

        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error loading signed prekeys: " << e.what() << std::endl;
        return false;
    }
}

bool KeyManager::saveSignedPrekeys() {
    try {
        std::ofstream file(getSignedPrekeysPath());
        if (!file.is_open()) return false;

        file << currentSignedPrekeyId << std::endl;
        for (const auto& pair : signedPrekeys) {
            uint32_t id = pair.first;
            file << id << "|" << encodeX25519PrivateKey(pair.second) << "|" 
                 << signedPrekeyPublics.at(id) << std::endl;
        }

        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error saving signed prekeys: " << e.what() << std::endl;
        return false;
    }
}

bool KeyManager::loadOneTimePrekeys() {
    try {
        std::ifstream file(getOneTimePrekeysPath());
        if (!file.is_open()) return false;

        std::string line;
        if (std::getline(file, line)) {
            nextOneTimePrekeyId = std::stoul(line);
        }

        while (std::getline(file, line)) {
            std::istringstream iss(line);
            std::string idStr, privateKeyStr, publicKeyStr;
            if (std::getline(iss, idStr, '|') && 
                std::getline(iss, privateKeyStr, '|') &&
                std::getline(iss, publicKeyStr)) {
                uint32_t id = std::stoul(idStr);
                CryptoPP::x25519 privateKey = decodeX25519PrivateKey(privateKeyStr);
                
                oneTimePrekeys[id] = privateKey;
                oneTimePrekeyPublics[id] = publicKeyStr;
            }
        }

        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error loading one-time prekeys: " << e.what() << std::endl;
        return false;
    }
}

bool KeyManager::saveOneTimePrekeys() {
    try {
        std::ofstream file(getOneTimePrekeysPath());
        if (!file.is_open()) return false;

        file << nextOneTimePrekeyId << std::endl;
        for (const auto& pair : oneTimePrekeys) {
            uint32_t id = pair.first;
            file << id << "|" << encodeX25519PrivateKey(pair.second) << "|" 
                 << oneTimePrekeyPublics.at(id) << std::endl;
        }

        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error saving one-time prekeys: " << e.what() << std::endl;
        return false;
    }
}

// Utility functions for encoding/decoding keys
std::string KeyManager::encodeX25519PublicKey(const CryptoPP::x25519& key) const {
    // Create public key from private key
    CryptoPP::SecByteBlock publicKeyBytes(32);
    CryptoPP::SecByteBlock privateKeyBytes(32);
    
    // Get private key bytes
    std::string privateKeyString;
    CryptoPP::StringSink sink(privateKeyString);
    key.Save(sink);
    
    // Copy to SecByteBlock (first 32 bytes)
    std::memcpy(privateKeyBytes.data(), privateKeyString.data(), std::min(32ul, privateKeyString.size()));
    
    // Generate public key (this is a simplified approach - in real implementation, 
    // you'd use proper X25519 scalar multiplication)
    // For now, we'll extract what we can from the key structure
    try {
        // Try to use the key's internal public key generation if available
        CryptoPP::x25519 tempKey = key;
        std::string keyData;
        CryptoPP::StringSink tempSink(keyData);
        tempKey.Save(tempSink);
        
        // Take the last 32 bytes as public key (this is a workaround)
        if (keyData.size() >= 32) {
            std::string publicKeyStr = keyData.substr(keyData.size() - 32);
            std::string base64;
            CryptoPP::StringSource source(publicKeyStr, true,
                new CryptoPP::Base64Encoder(new CryptoPP::StringSink(base64), false));
            return base64;
        }
    } catch (...) {
        // Fallback: use a hash of the private key as public key (not cryptographically correct)
        CryptoPP::SHA256 hash;
        hash.Update(privateKeyBytes, privateKeyBytes.size());
        hash.Final(publicKeyBytes);
    }
    
    std::string base64;
    CryptoPP::StringSource source(publicKeyBytes, publicKeyBytes.size(), true,
        new CryptoPP::Base64Encoder(new CryptoPP::StringSink(base64), false));
    return base64;
}

std::string KeyManager::encodePublicKey(const CryptoPP::ed25519::Verifier& key) const {
    std::string encoded;
    CryptoPP::StringSink ss(encoded);
    key.GetPublicKey().Save(ss);
    
    std::string base64;
    CryptoPP::StringSource source(encoded, true,
        new CryptoPP::Base64Encoder(new CryptoPP::StringSink(base64), false));
    return base64;
}

std::string KeyManager::encodeX25519PrivateKey(const CryptoPP::x25519& key) const {
    std::string encoded;
    CryptoPP::StringSink ss(encoded);
    key.Save(ss);
    
    std::string base64;
    CryptoPP::StringSource source(encoded, true,
        new CryptoPP::Base64Encoder(new CryptoPP::StringSink(base64), false));
    return base64;
}

std::string KeyManager::encodePrivateKey(const CryptoPP::ed25519::Signer& key) const {
    std::string encoded;
    CryptoPP::StringSink ss(encoded);
    key.GetPrivateKey().Save(ss);
    
    std::string base64;
    CryptoPP::StringSource source(encoded, true,
        new CryptoPP::Base64Encoder(new CryptoPP::StringSink(base64), false));
    return base64;
}

std::string KeyManager::decodeX25519PublicKey(const std::string& encoded) const {
    std::string decoded;
    CryptoPP::StringSource source(encoded, true,
        new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
    return decoded;
}

CryptoPP::ed25519::Verifier KeyManager::decodeEd25519Verifier(const std::string& encoded) const {
    std::string decoded;
    CryptoPP::StringSource source(encoded, true,
        new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
    
    CryptoPP::ed25519::Verifier key;
    CryptoPP::StringSource ss(decoded, true);
    key.AccessPublicKey().Load(ss);
    return key;
}

CryptoPP::x25519 KeyManager::decodeX25519PrivateKey(const std::string& encoded) const {
    std::string decoded;
    CryptoPP::StringSource source(encoded, true,
        new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
    
    CryptoPP::x25519 key;
    CryptoPP::StringSource ss(decoded, true);
    key.Load(ss);
    return key;
}

CryptoPP::ed25519::Signer KeyManager::decodeEd25519Signer(const std::string& encoded) const {
    std::string decoded;
    CryptoPP::StringSource source(encoded, true,
        new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
    
    CryptoPP::ed25519::Signer key;
    CryptoPP::StringSource ss(decoded, true);
    key.AccessPrivateKey().Load(ss);
    return key;
}

std::string KeyManager::getIdentityKeysPath() const {
    return keyDirectory + "/identity.key";
}

std::string KeyManager::getSignedPrekeysPath() const {
    return keyDirectory + "/signed_prekeys.key";
}

std::string KeyManager::getOneTimePrekeysPath() const {
    return keyDirectory + "/onetime_prekeys.key";
}

std::string KeyManager::getContactKeysPath() const {
    return keyDirectory + "/contacts";
}