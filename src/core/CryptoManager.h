#pragma once
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oaep.h>
#include <string>
#include "MessageProtocol.h"

class CryptoManager {
private:
    CryptoPP::AutoSeededRandomPool rng;
    
public:
    CryptoManager();
    
    EncryptedMessage encryptMessage(
        const std::string& plaintext,
        const std::string& senderId,
        const std::string& receiverId,
        const CryptoPP::RSA::PublicKey& receiverPublicKey
    );
    
    std::string decryptMessage(
        const EncryptedMessage& encMsg,
        const CryptoPP::RSA::PrivateKey& privateKey
    );
    
private:
    std::string generateSessionKey();
    std::string generateIV();
    uint64_t getCurrentTimestamp();
    
    std::string encryptWithAES(const std::string& plaintext, 
                              const std::string& key, 
                              const std::string& iv);
    std::string decryptWithAES(const std::string& ciphertext, 
                              const std::string& key, 
                              const std::string& iv);
    std::string encryptWithRSA(const std::string& plaintext, 
                              const CryptoPP::RSA::PublicKey& publicKey);
    std::string decryptWithRSA(const std::string& ciphertext, 
                              const CryptoPP::RSA::PrivateKey& privateKey);
};
