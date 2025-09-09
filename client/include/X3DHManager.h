#pragma once

#include <string>
#include <memory>
#include "KeyManager.h"
#include "MessageProtocol.h"

class X3DHManager {
private:
    std::shared_ptr<KeyManager> keyManager;
    mutable CryptoPP::AutoSeededRandomPool rng;

public:
    X3DHManager(std::shared_ptr<KeyManager> keyMgr);
    
    // X3DH protocol implementation
    X3DHMessage initiateX3DH(const std::string& recipientPhone, const KeyBundle& recipientBundle, const std::string& initialMessage);
    std::string processX3DHInit(const X3DHMessage& x3dhMessage, std::string& sharedSecret);
    
    // Shared secret derivation
    std::string deriveSharedSecret(const std::vector<std::string>& dhOutputs, const std::string& associatedData) const;
    
    // Key derivation functions
    std::pair<std::string, std::string> deriveMessageKeys(const std::string& sharedSecret, uint32_t messageNumber) const;
    
private:
    std::string hkdf(const std::string& input, const std::string& salt, const std::string& info, size_t outputLength) const;
    std::string concatenateKeys(const std::vector<std::string>& keys) const;
};
