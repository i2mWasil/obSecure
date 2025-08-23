#include "MessageProtocol.h"
#include <sstream>
#include <chrono>

std::string MessageSerializer::serialize(const MessageProtocol& message) {
    std::ostringstream oss;
    oss << static_cast<int>(message.type) << "|"
        << message.senderId << "|"
        << message.receiverId << "|"
        << message.timestamp << "|"
        << message.payload.length() << "|"
        << message.payload;
    return oss.str();
}

MessageProtocol MessageSerializer::deserialize(const std::string& data) {
    MessageProtocol message;
    std::istringstream iss(data);
    std::string token;
    
    if (std::getline(iss, token, '|')) {
        message.type = static_cast<MessageType>(std::stoi(token));
    }
    
    if (std::getline(iss, token, '|')) {
        message.senderId = token;
    }
    
    if (std::getline(iss, token, '|')) {
        message.receiverId = token;
    }
    
    if (std::getline(iss, token, '|')) {
        message.timestamp = std::stoull(token);
    }
    
    size_t payloadLength = 0;
    if (std::getline(iss, token, '|')) {
        payloadLength = std::stoul(token);
    }
    
    if (payloadLength > 0) {
        message.payload.resize(payloadLength);
        iss.read(&message.payload[0], payloadLength);
    }
    
    return message;
}

std::string MessageSerializer::serialize(const EncryptedMessage& message) {
    std::ostringstream oss;
    oss << message.senderId << "|"
        << message.receiverId << "|"
        << message.timestamp << "|"
        << message.iv.length() << "|" << message.iv
        << message.encryptedSessionKey.length() << "|" << message.encryptedSessionKey
        << message.encryptedContent.length() << "|" << message.encryptedContent;
    return oss.str();
}

EncryptedMessage MessageSerializer::deserializeEncrypted(const std::string& data) {
    EncryptedMessage message;
    std::istringstream iss(data);
    std::string token;
    
    if (std::getline(iss, token, '|')) {
        message.senderId = token;
    }
    
    if (std::getline(iss, token, '|')) {
        message.receiverId = token;
    }
    
    if (std::getline(iss, token, '|')) {
        message.timestamp = std::stoull(token);
    }
    
    size_t ivLength = 0;
    if (std::getline(iss, token, '|')) {
        ivLength = std::stoul(token);
    }
    if (ivLength > 0) {
        message.iv.resize(ivLength);
        iss.read(&message.iv[0], ivLength);
    }
    
    size_t keyLength = 0;
    if (std::getline(iss, token, '|')) {
        keyLength = std::stoul(token);
    }
    if (keyLength > 0) {
        message.encryptedSessionKey.resize(keyLength);
        iss.read(&message.encryptedSessionKey[0], keyLength);
    }
    
    size_t contentLength = 0;
    if (std::getline(iss, token, '|')) {
        contentLength = std::stoul(token);
    }
    if (contentLength > 0) {
        message.encryptedContent.resize(contentLength);
        iss.read(&message.encryptedContent[0], contentLength);
    }
    
    return message;
}
