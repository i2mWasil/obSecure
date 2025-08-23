#pragma once
#include <string>
#include <cstdint>

enum class MessageType : uint8_t {
    TEXT_MESSAGE = 1,
    KEY_EXCHANGE = 2,
    CONNECTION_REQUEST = 3,
    ACKNOWLEDGMENT = 4,
    USER_STATUS = 5
};

struct EncryptedMessage {
    std::string encryptedContent;
    std::string encryptedSessionKey;
    std::string iv;
    std::string senderId;
    std::string receiverId;
    uint64_t timestamp;
    
    EncryptedMessage() : timestamp(0) {}
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
};
