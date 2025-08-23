#pragma once
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <string>
#include <map>
#include <vector>

class KeyManager {
private:
    CryptoPP::RSA::PrivateKey privateKey;
    CryptoPP::RSA::PublicKey publicKey;
    std::map<std::string, CryptoPP::RSA::PublicKey> contactPublicKeys;
    std::string userId;
    std::string keyDirectory;
    mutable CryptoPP::AutoSeededRandomPool rng;

public:
    KeyManager(const std::string& userId);
    
    void generateKeyPair();
    bool loadKeys();
    bool saveKeys();
    
    std::string getPublicKeyString() const;
    bool addContactPublicKey(const std::string& contactId, const std::string& publicKeyStr);
    CryptoPP::RSA::PublicKey getContactPublicKey(const std::string& contactId) const;
    bool hasContactKey(const std::string& contactId) const;
    
    const CryptoPP::RSA::PrivateKey& getPrivateKey() const { return privateKey; }
    const CryptoPP::RSA::PublicKey& getPublicKey() const { return publicKey; }
    const std::string& getUserId() const { return userId; }
    
    std::vector<std::string> getContactIds() const;
    bool removeContactKey(const std::string& contactId);
    
private:
    void ensureKeyDirectory();
    std::string getPrivateKeyPath() const;
    std::string getPublicKeyPath() const;
    std::string getContactsKeyPath() const;
    
    bool savePrivateKey();
    bool savePublicKey();
    bool saveContactKeys();
    bool loadPrivateKey();
    bool loadPublicKey();
    bool loadContactKeys();
    
    std::string encodeDER(const CryptoPP::RSA::PrivateKey& key) const;
    std::string encodeDER(const CryptoPP::RSA::PublicKey& key) const;
    void decodeDER(const std::string& encoded, CryptoPP::RSA::PrivateKey& key) const;
    void decodeDER(const std::string& encoded, CryptoPP::RSA::PublicKey& key) const;
};
