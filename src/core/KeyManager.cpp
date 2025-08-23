#include "KeyManager.h"
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/queue.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <QDir>

KeyManager::KeyManager(const std::string& userId) : userId(userId) {
    keyDirectory = "keys/" + userId;
    ensureKeyDirectory();
    
    if (!loadKeys()) {
        std::cout << "No existing keys found, generating new key pair..." << std::endl;
        generateKeyPair();
        if (!saveKeys()) {
            throw std::runtime_error("Failed to save generated keys");
        }
    }
}

void KeyManager::ensureKeyDirectory() {
    QDir dir;
    dir.mkpath(QString::fromStdString(keyDirectory));
}

std::string KeyManager::getPrivateKeyPath() const {
    return keyDirectory + "/private.key";
}

std::string KeyManager::getPublicKeyPath() const {
    return keyDirectory + "/public.key";
}

std::string KeyManager::getContactsKeyPath() const {
    return keyDirectory + "/contacts.txt";
}

void KeyManager::generateKeyPair() {
    try {
        CryptoPP::AutoSeededRandomPool localRng;
        CryptoPP::RSA::PrivateKey newPrivateKey;
        newPrivateKey.GenerateRandomWithKeySize(localRng, 2048);
        
        if (!newPrivateKey.Validate(localRng, 3)) {
            throw std::runtime_error("Generated private key failed validation");
        }
        
        CryptoPP::RSA::PublicKey newPublicKey;
        newPublicKey.AssignFrom(newPrivateKey);
        
        if (!newPublicKey.Validate(localRng, 3)) {
            throw std::runtime_error("Generated public key failed validation");
        }
        
        privateKey = newPrivateKey;
        publicKey = newPublicKey;
        
        std::cout << "Generated and validated new RSA key pair for user: " << userId << std::endl;
        
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("Crypto++ error during key generation: " + std::string(e.what()));
    } catch (const std::exception& e) {
        throw std::runtime_error("Error during key generation: " + std::string(e.what()));
    }
}

bool KeyManager::saveKeys() {
    try {
        return savePrivateKey() && savePublicKey() && saveContactKeys();
    } catch (const std::exception& e) {
        std::cerr << "Error saving keys: " << e.what() << std::endl;
        return false;
    }
}

bool KeyManager::savePrivateKey() {
    try {
        CryptoPP::AutoSeededRandomPool localRng;
        if (!privateKey.Validate(localRng, 3)) {
            std::cerr << "Private key validation failed during save" << std::endl;
            return false;
        }
        
        std::string encoded = encodeDER(privateKey);
        if (encoded.empty()) {
            std::cerr << "Failed to encode private key" << std::endl;
            return false;
        }
        
        std::ofstream file(getPrivateKeyPath());
        if (!file.is_open()) {
            std::cerr << "Failed to open private key file for writing" << std::endl;
            return false;
        }
        
        file << encoded;
        return file.good();
    } catch (const std::exception& e) {
        std::cerr << "Error saving private key: " << e.what() << std::endl;
        return false;
    }
}

bool KeyManager::savePublicKey() {
    try {
        CryptoPP::AutoSeededRandomPool localRng;
        if (!publicKey.Validate(localRng, 3)) {
            std::cerr << "Public key validation failed during save" << std::endl;
            return false;
        }
        
        std::string encoded = encodeDER(publicKey);
        if (encoded.empty()) {
            std::cerr << "Failed to encode public key" << std::endl;
            return false;
        }
        
        std::ofstream file(getPublicKeyPath());
        if (!file.is_open()) {
            std::cerr << "Failed to open public key file for writing" << std::endl;
            return false;
        }
        
        file << encoded;
        return file.good();
    } catch (const std::exception& e) {
        std::cerr << "Error saving public key: " << e.what() << std::endl;
        return false;
    }
}

bool KeyManager::saveContactKeys() {
    try {
        std::ofstream file(getContactsKeyPath());
        if (!file.is_open()) return false;
        
        for (const auto& pair : contactPublicKeys) {
            if (!pair.second.Validate(rng, 3)) {
                std::cerr << "Contact key validation failed for: " << pair.first << std::endl;
                continue;
            }
            
            std::string keyStr = encodeDER(pair.second);
            if (!keyStr.empty()) {
                file << pair.first << "|" << keyStr.length() << "|" << keyStr;
            }
        }
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error saving contact keys: " << e.what() << std::endl;
        return false;
    }
}

bool KeyManager::loadKeys() {
    try {
        CryptoPP::AutoSeededRandomPool localRng;  
        bool privateLoaded = loadPrivateKey();
        bool publicLoaded = loadPublicKey();
        bool contactsLoaded = loadContactKeys();
        
        if (privateLoaded && publicLoaded) {
            if (!privateKey.Validate(localRng, 3)) {
                std::cerr << "Loaded private key failed validation" << std::endl;
                return false;
            }
            if (!publicKey.Validate(localRng, 3)) {
                std::cerr << "Loaded public key failed validation" << std::endl;
                return false;
            }
            std::cout << "Successfully loaded and validated existing keys for user: " << userId << std::endl;
        }
        
        return privateLoaded && publicLoaded && contactsLoaded;
    } catch (const std::exception& e) {
        std::cerr << "Error loading keys: " << e.what() << std::endl;
        return false;
    }
}

bool KeyManager::loadPrivateKey() {
    try {
        std::ifstream file(getPrivateKeyPath());
        if (!file.is_open()) return false;
        
        std::string encoded;
        std::string line;
        while (std::getline(file, line)) {
            encoded += line;
        }
        
        if (encoded.empty()) return false;
        
        CryptoPP::RSA::PrivateKey tempKey;
        decodeDER(encoded, tempKey);
        
        if (!tempKey.Validate(rng, 3)) {
            std::cerr << "Loaded private key failed validation" << std::endl;
            return false;
        }
        
        privateKey = tempKey;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error loading private key: " << e.what() << std::endl;
        return false;
    }
}

bool KeyManager::loadPublicKey() {
    try {
        std::ifstream file(getPublicKeyPath());
        if (!file.is_open()) return false;
        
        std::string encoded;
        std::string line;
        while (std::getline(file, line)) {
            encoded += line;
        }
        
        if (encoded.empty()) return false;
        
        CryptoPP::RSA::PublicKey tempKey;
        decodeDER(encoded, tempKey);
        
        if (!tempKey.Validate(rng, 3)) {
            std::cerr << "Loaded public key failed validation" << std::endl;
            return false;
        }
        
        publicKey = tempKey;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error loading public key: " << e.what() << std::endl;
        return false;
    }
}

bool KeyManager::loadContactKeys() {
    try {
        std::ifstream file(getContactsKeyPath());
        if (!file.is_open()) return true; 
        
        std::string line;
        while (std::getline(file, line)) {
            if (line.empty()) continue;
            
            size_t firstPipe = line.find('|');
            if (firstPipe == std::string::npos) continue;
            
            std::string contactId = line.substr(0, firstPipe);
            
            size_t secondPipe = line.find('|', firstPipe + 1);
            if (secondPipe == std::string::npos) continue;
            
            size_t keyLength = std::stoul(line.substr(firstPipe + 1, secondPipe - firstPipe - 1));
            std::string keyStr = line.substr(secondPipe + 1, keyLength);
            
            try {
                CryptoPP::RSA::PublicKey contactKey;
                decodeDER(keyStr, contactKey);
                
                if (contactKey.Validate(rng, 3)) {
                    contactPublicKeys[contactId] = contactKey;
                } else {
                    std::cerr << "Contact key validation failed for: " << contactId << std::endl;
                }
            } catch (const std::exception& e) {
                std::cerr << "Error loading contact key for " << contactId << ": " << e.what() << std::endl;
            }
        }
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error loading contact keys: " << e.what() << std::endl;
        return false;
    }
}

std::string KeyManager::getPublicKeyString() const {
    try {
        CryptoPP::AutoSeededRandomPool localRng;
        if (!publicKey.Validate(localRng, 3)) {
            std::cerr << "Public key validation failed in getPublicKeyString" << std::endl;
            return "";
        }
        return encodeDER(publicKey);
    } catch (const std::exception& e) {
        std::cerr << "Error getting public key string: " << e.what() << std::endl;
        return "";
    }
}

bool KeyManager::addContactPublicKey(const std::string& contactId, const std::string& publicKeyStr) {
    try {
        CryptoPP::RSA::PublicKey contactKey;
        decodeDER(publicKeyStr, contactKey);
        
        if (!contactKey.Validate(rng, 3)) {
            std::cerr << "Contact public key validation failed for: " << contactId << std::endl;
            return false;
        }
        
        contactPublicKeys[contactId] = contactKey;
        return saveContactKeys();
    } catch (const std::exception& e) {
        std::cerr << "Error adding contact public key: " << e.what() << std::endl;
        return false;
    }
}

CryptoPP::RSA::PublicKey KeyManager::getContactPublicKey(const std::string& contactId) const {
    auto it = contactPublicKeys.find(contactId);
    if (it != contactPublicKeys.end()) {
        return it->second;
    }
    throw std::runtime_error("Contact public key not found: " + contactId);
}

bool KeyManager::hasContactKey(const std::string& contactId) const {
    return contactPublicKeys.find(contactId) != contactPublicKeys.end();
}

std::vector<std::string> KeyManager::getContactIds() const {
    std::vector<std::string> ids;
    for (const auto& pair : contactPublicKeys) {
        ids.push_back(pair.first);
    }
    return ids;
}

bool KeyManager::removeContactKey(const std::string& contactId) {
    auto it = contactPublicKeys.find(contactId);
    if (it != contactPublicKeys.end()) {
        contactPublicKeys.erase(it);
        return saveContactKeys();
    }
    return false;
}

std::string KeyManager::encodeDER(const CryptoPP::RSA::PrivateKey& key) const {
    try {
        std::string der;
        CryptoPP::StringSink ss(der);
        key.DEREncode(ss);
        
        std::string base64;
        CryptoPP::StringSource source(der, true,
            new CryptoPP::Base64Encoder(
                new CryptoPP::StringSink(base64), false
            )
        );
        
        return base64;
    } catch (const std::exception& e) {
        std::cerr << "Error encoding private key to DER: " << e.what() << std::endl;
        return "";
    }
}

std::string KeyManager::encodeDER(const CryptoPP::RSA::PublicKey& key) const {
    try {
        std::string der;
        CryptoPP::StringSink ss(der);
        key.DEREncode(ss);
        
        std::string base64;
        CryptoPP::StringSource source(der, true,
            new CryptoPP::Base64Encoder(
                new CryptoPP::StringSink(base64), false
            )
        );
        
        return base64;
    } catch (const std::exception& e) {
        std::cerr << "Error encoding public key to DER: " << e.what() << std::endl;
        return "";
    }
}

void KeyManager::decodeDER(const std::string& encoded, CryptoPP::RSA::PrivateKey& key) const {
    try {
        std::string der;
        CryptoPP::StringSource source(encoded, true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::StringSink(der)
            )
        );
        
        CryptoPP::StringSource ss(der, true);
        key.BERDecode(ss);
    } catch (const std::exception& e) {
        throw std::runtime_error("Error decoding private key from DER: " + std::string(e.what()));
    }
}

void KeyManager::decodeDER(const std::string& encoded, CryptoPP::RSA::PublicKey& key) const {
    try {
        std::string der;
        CryptoPP::StringSource source(encoded, true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::StringSink(der)
            )
        );
        
        CryptoPP::StringSource ss(der, true);
        key.BERDecode(ss);
    } catch (const std::exception& e) {
        throw std::runtime_error("Error decoding public key from DER: " + std::string(e.what()));
    }
}
