#include "CryptoManager.h"
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <chrono>
#include <iostream>

CryptoManager::CryptoManager() {
}

EncryptedMessage CryptoManager::encryptMessage(
    const std::string& plaintext,
    const std::string& senderId,
    const std::string& receiverId,
    const CryptoPP::RSA::PublicKey& receiverPublicKey) {
    
    EncryptedMessage encMsg;
    encMsg.senderId = senderId;
    encMsg.receiverId = receiverId;
    encMsg.timestamp = getCurrentTimestamp();
    
    std::string sessionKey = generateSessionKey();
    encMsg.iv = generateIV();
    
    encMsg.encryptedContent = encryptWithAES(plaintext, sessionKey, encMsg.iv);
    encMsg.encryptedSessionKey = encryptWithRSA(sessionKey, receiverPublicKey);
    
    return encMsg;
}

std::string CryptoManager::decryptMessage(
    const EncryptedMessage& encMsg,
    const CryptoPP::RSA::PrivateKey& privateKey) {
    
    try {
        std::string sessionKey = decryptWithRSA(encMsg.encryptedSessionKey, privateKey);
        std::string plaintext = decryptWithAES(encMsg.encryptedContent, sessionKey, encMsg.iv);
        return plaintext;

    } catch (const std::exception& e) {
        std::cerr << "Decryption error: " << e.what() << std::endl;
        throw;
    }
}

std::string CryptoManager::generateSessionKey() {
    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, key.size());
    
    std::string keyStr;
    CryptoPP::StringSource ss(key, key.size(), true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(keyStr), false
        )
    );
    return keyStr;
}

std::string CryptoManager::generateIV() {
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
    rng.GenerateBlock(iv, iv.size());
    
    std::string ivStr;
    CryptoPP::StringSource ss(iv, iv.size(), true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(ivStr), false
        )
    );
    return ivStr;
}

uint64_t CryptoManager::getCurrentTimestamp() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

std::string CryptoManager::encryptWithAES(const std::string& plaintext, 
                                        const std::string& key, 
                                        const std::string& iv) {
    try {
        std::string decodedKey, decodedIV;
        CryptoPP::StringSource ss1(key, true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::StringSink(decodedKey)
            )
        );
        CryptoPP::StringSource ss2(iv, true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::StringSink(decodedIV)
            )
        );
        
        std::string ciphertext;
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption;
        encryption.SetKeyWithIV((const CryptoPP::byte*)decodedKey.data(), decodedKey.size(),
                               (const CryptoPP::byte*)decodedIV.data());
        
        CryptoPP::StringSource ss(plaintext, true,
            new CryptoPP::StreamTransformationFilter(encryption,
                new CryptoPP::Base64Encoder(
                    new CryptoPP::StringSink(ciphertext), false
                )
            )
        );
        
        return ciphertext;
    } catch (const std::exception& e) {
        std::cerr << "AES encryption error: " << e.what() << std::endl;
        throw;
    }
}

std::string CryptoManager::decryptWithAES(const std::string& ciphertext, 
                                        const std::string& key, 
                                        const std::string& iv) {
    try {
        std::string decodedKey, decodedIV;
        CryptoPP::StringSource ss1(key, true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::StringSink(decodedKey)
            )
        );
        CryptoPP::StringSource ss2(iv, true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::StringSink(decodedIV)
            )
        );
        
        std::string plaintext;
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption;
        decryption.SetKeyWithIV((const CryptoPP::byte*)decodedKey.data(), decodedKey.size(),
                               (const CryptoPP::byte*)decodedIV.data());
        
        CryptoPP::StringSource ss(ciphertext, true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::StreamTransformationFilter(decryption,
                    new CryptoPP::StringSink(plaintext)
                )
            )
        );
        
        return plaintext;
    } catch (const std::exception& e) {
        std::cerr << "AES decryption error: " << e.what() << std::endl;
        throw;
    }
}

std::string CryptoManager::encryptWithRSA(const std::string& plaintext, 
                                        const CryptoPP::RSA::PublicKey& publicKey) {
    try {
        std::string ciphertext;
        CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
        
        CryptoPP::StringSource ss(plaintext, true,
            new CryptoPP::PK_EncryptorFilter(rng, encryptor,
                new CryptoPP::Base64Encoder(
                    new CryptoPP::StringSink(ciphertext), false
                )
            )
        );
        
        return ciphertext;
    } catch (const std::exception& e) {
        std::cerr << "RSA encryption error: " << e.what() << std::endl;
        throw;
    }
}

std::string CryptoManager::decryptWithRSA(const std::string& ciphertext, 
                                        const CryptoPP::RSA::PrivateKey& privateKey) {
    try {
        std::string plaintext;
        CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
        
        CryptoPP::StringSource ss(ciphertext, true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::PK_DecryptorFilter(rng, decryptor,
                    new CryptoPP::StringSink(plaintext)
                )
            )
        );
        
        return plaintext;
    } catch (const std::exception& e) {
        std::cerr << "RSA decryption error: " << e.what() << std::endl;
        throw;
    }
}
