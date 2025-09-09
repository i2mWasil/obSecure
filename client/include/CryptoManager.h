#pragma once

#include <string>
#include <cstdint>
#include <cryptopp/osrng.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include "MessageProtocol.h"

class CryptoManager {
private:
    mutable CryptoPP::AutoSeededRandomPool rng;

public:
    CryptoManager();

    EncryptedMessage encryptMessageWithSessionKey(
        const std::string& plaintext,
        const std::string& senderId,
        const std::string& receiverId,
        const std::string& sessionKey,
        uint32_t messageNumber = 0
    );

    std::string decryptMessageWithSessionKey(
        const EncryptedMessage& encMessage,
        const std::string& sessionKey
    );

    EncryptedMessage encryptMessage(
        const std::string& plaintext,
        const std::string& senderId,
        const std::string& receiverId,
        const std::string& sessionKey
    );

    std::string decryptMessage(
        const EncryptedMessage& encMessage,
        const std::string& sessionKey
    );

private:
    std::string generateNonce();
    uint64_t getCurrentTimestamp();

    std::string encryptWithAESGCM(
        const std::string& plaintext,
        const std::string& key,
        const std::string& nonce,
        std::string& authTag
    );

    std::string decryptWithAESGCM(
        const std::string& ciphertext,
        const std::string& key,
        const std::string& nonce,
        const std::string& authTag
    );
};
