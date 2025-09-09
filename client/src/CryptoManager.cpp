#include "CryptoManager.h"
#include <iostream>
#include <chrono>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/gcm.h>
#include <cryptopp/base64.h>

CryptoManager::CryptoManager() {}

EncryptedMessage CryptoManager::encryptMessageWithSessionKey(
    const std::string& plaintext,
    const std::string& senderId,
    const std::string& receiverId,
    const std::string& sessionKey,
    uint32_t messageNumber) {
    
    EncryptedMessage enc;
    enc.senderId = senderId;
    enc.receiverId = receiverId;
    enc.timestamp = getCurrentTimestamp();
    enc.messageNumber = messageNumber;
    enc.nonce = generateNonce();

    try {
        enc.encryptedContent = encryptWithAESGCM(plaintext, sessionKey, enc.nonce, enc.authTag);
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("Encryption failed: " + std::string(e.what()));
    }

    return enc;
}

std::string CryptoManager::decryptMessageWithSessionKey(
    const EncryptedMessage& enc,
    const std::string& sessionKey) {
    try {
        return decryptWithAESGCM(enc.encryptedContent, sessionKey, enc.nonce, enc.authTag);
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("Decryption failed: " + std::string(e.what()));
    }
}

EncryptedMessage CryptoManager::encryptMessage(
    const std::string& plaintext,
    const std::string& senderId,
    const std::string& receiverId,
    const std::string& sessionKey) {
    return encryptMessageWithSessionKey(plaintext, senderId, receiverId, sessionKey, 0);
}

std::string CryptoManager::decryptMessage(
    const EncryptedMessage& enc,
    const std::string& sessionKey) {
    return decryptMessageWithSessionKey(enc, sessionKey);
}

std::string CryptoManager::generateNonce() {
    CryptoPP::SecByteBlock nonce(12);
    rng.GenerateBlock(nonce, nonce.size());

    std::string encoded;
    CryptoPP::StringSource ss(nonce, nonce.size(), true,
        new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));
    return encoded;
}

uint64_t CryptoManager::getCurrentTimestamp() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string CryptoManager::encryptWithAESGCM(
    const std::string& plaintext,
    const std::string& key,
    const std::string& nonce,
    std::string& authTag) {
    try {
        std::string decodedKey, decodedNonce;
        CryptoPP::StringSource(key, true,
            new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedKey)));
        CryptoPP::StringSource(nonce, true,
            new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedNonce)));

        if (decodedKey.size() < 32) decodedKey.resize(32, 0);
        if (decodedNonce.size() < 12) decodedNonce.resize(12, 0);
        else if (decodedNonce.size() > 12) decodedNonce = decodedNonce.substr(0, 12);

        CryptoPP::GCM<CryptoPP::AES>::Encryption encryption;
        encryption.SetKeyWithIV((const CryptoPP::byte*)decodedKey.data(), decodedKey.size(),
                                (const CryptoPP::byte*)decodedNonce.data(), decodedNonce.size());

        std::string cipher;
        CryptoPP::AuthenticatedEncryptionFilter ef(
            encryption,
            new CryptoPP::StringSink(cipher),
            false, 16);

        ef.Put((const CryptoPP::byte*)plaintext.data(), plaintext.size());
        ef.MessageEnd();

        if (cipher.size() < 16) throw std::runtime_error("Encryption output too short");
        
        std::string encryptedText = cipher.substr(0, cipher.size() - 16);
        std::string tag = cipher.substr(cipher.size() - 16);

        std::string encodedCipher;
        CryptoPP::StringSource(encryptedText, true,
            new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encodedCipher), false));

        authTag.clear();
        CryptoPP::StringSource(tag, true,
            new CryptoPP::Base64Encoder(new CryptoPP::StringSink(authTag), false));

        return encodedCipher;
    } catch(const CryptoPP::Exception& e) {
        throw std::runtime_error("Encryption failed: " + std::string(e.what()));
    }
}

std::string CryptoManager::decryptWithAESGCM(
    const std::string& ciphertext,
    const std::string& key,
    const std::string& nonce,
    const std::string& authTag) {
    try {
        std::string decodedKey, decodedNonce, decodedCipher, decodedTag;
        CryptoPP::StringSource(key, true,
            new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedKey)));
        CryptoPP::StringSource(nonce, true,
            new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedNonce)));
        CryptoPP::StringSource(ciphertext, true,
            new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedCipher)));
        CryptoPP::StringSource(authTag, true,
            new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedTag)));

        if (decodedKey.size() < 32) decodedKey.resize(32, 0);
        if (decodedNonce.size() < 12) decodedNonce.resize(12, 0);
        else if (decodedNonce.size() > 12) decodedNonce = decodedNonce.substr(0, 12);

        std::string combined = decodedCipher + decodedTag;

        CryptoPP::GCM<CryptoPP::AES>::Decryption decryption;
        decryption.SetKeyWithIV((const CryptoPP::byte*)decodedKey.data(), decodedKey.size(),
                                (const CryptoPP::byte*)decodedNonce.data(), decodedNonce.size());

        std::string plainText;
        CryptoPP::AuthenticatedDecryptionFilter df(
            decryption,
            new CryptoPP::StringSink(plainText),
            CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION |
            CryptoPP::AuthenticatedDecryptionFilter::MAC_AT_END,
            16);

        CryptoPP::StringSource(combined, true, new CryptoPP::Redirector(df));

        return plainText;
    } catch(const CryptoPP::Exception& e) {
        throw std::runtime_error("Decryption failed: " + std::string(e.what()));
    }
}
