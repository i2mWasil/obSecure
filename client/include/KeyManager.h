#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>
#include <cryptopp/osrng.h>
#include <cryptopp/xed25519.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include "MessageProtocol.h"

class KeyManager {
private:
    // Identity keys (long-term) - use ed25519 for signing
    CryptoPP::ed25519::Signer identityPrivateKey;
    CryptoPP::ed25519::Verifier identityPublicKey;

    // Signed prekeys (medium-term) - use x25519 for key agreement
    std::map<uint32_t, CryptoPP::x25519> signedPrekeys;
    std::map<uint32_t, std::string> signedPrekeyPublics;  // Store as encoded strings
    uint32_t currentSignedPrekeyId;

    // One-time prekeys (short-term) - use x25519 for key agreement
    std::map<uint32_t, CryptoPP::x25519> oneTimePrekeys;
    std::map<uint32_t, std::string> oneTimePrekeyPublics;  // Store as encoded strings
    uint32_t nextOneTimePrekeyId;

    // Contact keys
    std::map<std::string, KeyBundle> contactKeyBundles;

    std::string phoneNumber;
    std::string keyDirectory;
    mutable CryptoPP::AutoSeededRandomPool rng;

public:
    // Friend declarations for X3DHManager access
    friend class X3DHManager;

    KeyManager(const std::string& phoneNumber);

    // Identity key management
    void generateIdentityKeyPair();
    bool loadIdentityKeys();
    bool saveIdentityKeys();
    std::string getIdentityPublicKeyString() const;
    bool signData(const std::string& data, std::string& signature) const;
    bool verifySignature(const std::string& data, const std::string& signature, const std::string& publicKey) const;

    // Signed prekey management
    void generateSignedPrekey();
    bool loadSignedPrekeys();
    bool saveSignedPrekeys();
    KeyBundle getCurrentKeyBundle() const;
    void rotateSignedPrekey();

    // One-time prekey management
    void generateOneTimePrekeys(int count = 100);
    bool loadOneTimePrekeys();
    bool saveOneTimePrekeys();
    std::vector<std::string> getOneTimePrekeyPublics() const;
    void markOneTimePrekeyUsed(uint32_t keyId);

    // Contact management
    bool addContactKeyBundle(const std::string& phoneNumber, const KeyBundle& keyBundle);
    KeyBundle getContactKeyBundle(const std::string& phoneNumber) const;
    bool hasContactKeyBundle(const std::string& phoneNumber) const;
    void removeContactKeyBundle(const std::string& phoneNumber);

    // Key derivation for X3DH
    CryptoPP::x25519 getEphemeralKey() const;
    std::string performDH(const CryptoPP::x25519& privateKey, const std::string& publicKeyStr) const;

    // Utility functions
    bool loadKeys();
    bool saveKeys();
    const std::string& getPhoneNumber() const { return phoneNumber; }

    // Encoding functions
    std::string encodeX25519PublicKey(const CryptoPP::x25519& key) const;
    std::string encodePublicKey(const CryptoPP::ed25519::Verifier& key) const;

private:
    void ensureKeyDirectory();
    std::string getIdentityKeysPath() const;
    std::string getSignedPrekeysPath() const;
    std::string getOneTimePrekeysPath() const;
    std::string getContactKeysPath() const;

    std::string decodeX25519PublicKey(const std::string& encoded) const;
    CryptoPP::ed25519::Verifier decodeEd25519Verifier(const std::string& encoded) const;

    std::string encodeX25519PrivateKey(const CryptoPP::x25519& key) const;
    std::string encodePrivateKey(const CryptoPP::ed25519::Signer& key) const;
    CryptoPP::x25519 decodeX25519PrivateKey(const std::string& encoded) const;
    CryptoPP::ed25519::Signer decodeEd25519Signer(const std::string& encoded) const;
};
