#pragma once

#include <string>
#include <vector>
#include <cstdint>

enum class MessageType : uint8_t {
    TEXT_MESSAGE = 1,
    X3DH_INIT = 2,
    X3DH_RESPONSE = 3,
    CONNECTION_REQUEST = 4,
    ACKNOWLEDGMENT = 5,
    USER_STATUS = 6,
    KEY_BUNDLE_REQUEST = 7,
    KEY_BUNDLE_RESPONSE = 8
};

struct KeyBundle {
    std::string identityKey;
    std::string signedPrekey;
    std::string signedPrekeySignature;
    std::string identityKeySignature;
    std::string oneTimePrekey;  // Optional
    uint32_t signedPrekeyId;
    uint32_t oneTimePrekeyId;
    
    KeyBundle() : signedPrekeyId(0), oneTimePrekeyId(0) {}
};

struct X3DHMessage {
    std::string identityKey;
    std::string ephemeralKey;
    std::string oneTimePrekeyId;  // If used
    std::string encryptedMessage;
    std::string associatedData;
    
    X3DHMessage() {}
};

struct EncryptedMessage {
    std::string encryptedContent;
    std::string authTag;
    std::string nonce;
    std::string senderId;
    std::string receiverId;
    uint64_t timestamp;
    uint32_t messageNumber;
    
    EncryptedMessage() : timestamp(0), messageNumber(0) {}
};

struct MessageProtocol {
    MessageType type;
    std::string senderId;
    std::string receiverId;
    std::string payload;
    uint64_t timestamp;
    
    MessageProtocol() : type(MessageType::TEXT_MESSAGE), timestamp(0) {}
};

class MessageSerializer {
public:
    static std::string serialize(const MessageProtocol& message);
    static MessageProtocol deserialize(const std::string& data);
    static std::string serialize(const EncryptedMessage& message);
    static EncryptedMessage deserializeEncrypted(const std::string& data);
    static std::string serialize(const KeyBundle& keyBundle);
    static KeyBundle deserializeKeyBundle(const std::string& data);
    static std::string serialize(const X3DHMessage& x3dhMsg);
    static X3DHMessage deserializeX3DH(const std::string& data);
};
