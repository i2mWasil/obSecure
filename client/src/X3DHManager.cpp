#include "X3DHManager.h"
#include "KeyManager.h"
#include <iostream>
#include <sstream>
#include <cryptopp/osrng.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/gcm.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>

X3DHManager::X3DHManager(std::shared_ptr<KeyManager> keyMgr) : keyManager(keyMgr) {}

X3DHMessage X3DHManager::initiateX3DH(const std::string& recipientPhone, const KeyBundle& recipientBundle, const std::string& initialMessage) {
    try {
        // Generate ephemeral key pair using X25519
        CryptoPP::x25519 ephemeralPrivate = keyManager->getEphemeralKey();
        std::string ephemeralPublic = keyManager->encodeX25519PublicKey(ephemeralPrivate);

        // Perform the DH operations for X3DH (simplified)
        std::vector<std::string> dhOutputs;
        
        // For simplicity, we'll do basic DH operations
        dhOutputs.push_back(keyManager->performDH(ephemeralPrivate, recipientBundle.signedPrekey));
        
        if (!recipientBundle.oneTimePrekey.empty()) {
            dhOutputs.push_back(keyManager->performDH(ephemeralPrivate, recipientBundle.oneTimePrekey));
        }

        // Derive shared secret
        std::string associatedData = keyManager->getIdentityPublicKeyString() + recipientBundle.identityKey;
        std::string sharedSecret = deriveSharedSecret(dhOutputs, associatedData);

        // Derive message keys
        auto messageKeys = deriveMessageKeys(sharedSecret, 0);
        std::string encryptionKey = messageKeys.first;

        // Simple encryption (in production, use proper AES-GCM)
        std::string encryptedMessage = initialMessage; // Simplified - should encrypt properly

        // Create X3DH message
        X3DHMessage x3dhMsg;
        x3dhMsg.identityKey = keyManager->getIdentityPublicKeyString();
        x3dhMsg.ephemeralKey = ephemeralPublic;
        x3dhMsg.oneTimePrekeyId = std::to_string(recipientBundle.oneTimePrekeyId);
        x3dhMsg.encryptedMessage = encryptedMessage;
        x3dhMsg.associatedData = associatedData;

        return x3dhMsg;
    } catch (const std::exception& e) {
        throw std::runtime_error("X3DH initiation failed: " + std::string(e.what()));
    }
}

std::string X3DHManager::processX3DHInit(const X3DHMessage& x3dhMessage, std::string& sharedSecret) {
    try {
        // Get current key bundle
        KeyBundle myBundle = keyManager->getCurrentKeyBundle();

        // Perform corresponding DH operations (receiver side)
        std::vector<std::string> dhOutputs;
        
        // Simplified DH operations - should match sender side
        auto signedPrekeyPrivate = keyManager->signedPrekeys[myBundle.signedPrekeyId];
        dhOutputs.push_back(keyManager->performDH(signedPrekeyPrivate, x3dhMessage.ephemeralKey));
        
        if (!x3dhMessage.oneTimePrekeyId.empty() && x3dhMessage.oneTimePrekeyId != "0") {
            uint32_t otkId = std::stoul(x3dhMessage.oneTimePrekeyId);
            auto otkIt = keyManager->oneTimePrekeys.find(otkId);
            if (otkIt != keyManager->oneTimePrekeys.end()) {
                dhOutputs.push_back(keyManager->performDH(otkIt->second, x3dhMessage.ephemeralKey));
                keyManager->markOneTimePrekeyUsed(otkId);
            }
        }

        // Derive shared secret
        sharedSecret = deriveSharedSecret(dhOutputs, x3dhMessage.associatedData);

        // For now, return the encrypted message as-is (should decrypt properly)
        return x3dhMessage.encryptedMessage;
        
    } catch (const std::exception& e) {
        throw std::runtime_error("X3DH processing failed: " + std::string(e.what()));
    }
}

std::string X3DHManager::deriveSharedSecret(const std::vector<std::string>& dhOutputs, const std::string& associatedData) const {
    std::string concatenated = concatenateKeys(dhOutputs);
    return hkdf(concatenated, "", "X3DH_SHARED_SECRET" + associatedData, 32);
}

std::pair<std::string, std::string> X3DHManager::deriveMessageKeys(const std::string& sharedSecret, uint32_t messageNumber) const {
    std::string messageNumberStr = std::to_string(messageNumber);
    std::string encryptionKey = hkdf(sharedSecret, "", "ENCRYPTION_KEY_" + messageNumberStr, 32);
    std::string authKey = hkdf(sharedSecret, "", "AUTH_KEY_" + messageNumberStr, 32);
    return std::make_pair(encryptionKey, authKey);
}

std::string X3DHManager::hkdf(const std::string& input, const std::string& salt, const std::string& info, size_t outputLength) const {
    try {
        CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
        std::string decodedInput;
        
        try {
            CryptoPP::StringSource(input, true,
                new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedInput)));
        } catch (...) {
            decodedInput = input;
        }

        CryptoPP::SecByteBlock derived(outputLength);
        hkdf.DeriveKey(derived, derived.size(),
            (const CryptoPP::byte*)decodedInput.data(), decodedInput.size(),
            (const CryptoPP::byte*)salt.data(), salt.size(),
            (const CryptoPP::byte*)info.data(), info.size());

        std::string result;
        CryptoPP::StringSource(derived, derived.size(), true,
            new CryptoPP::Base64Encoder(new CryptoPP::StringSink(result), false));
        return result;
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("HKDF failed: " + std::string(e.what()));
    }
}

std::string X3DHManager::concatenateKeys(const std::vector<std::string>& keys) const {
    std::string result;
    for (const auto& key : keys) {
        std::string decoded;
        try {
            CryptoPP::StringSource(key, true,
                new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
            result += decoded;
        } catch (...) {
            result += key;
        }
    }
    
    std::string encoded;
    CryptoPP::StringSource(result, true,
        new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));
    return encoded;
}
