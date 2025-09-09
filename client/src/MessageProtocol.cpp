#include "MessageProtocol.h"
#include <sstream>
#include <iostream>

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
        << message.messageNumber << "|"
        << message.nonce.length() << "|" << message.nonce
        << message.authTag.length() << "|" << message.authTag
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
    
    if (std::getline(iss, token, '|')) {
        message.messageNumber = std::stoul(token);
    }
    
    // Read nonce
    size_t nonceLength = 0;
    if (std::getline(iss, token, '|')) {
        nonceLength = std::stoul(token);
    }
    
    if (nonceLength > 0) {
        message.nonce.resize(nonceLength);
        iss.read(&message.nonce[0], nonceLength);
    }
    
    // Read auth tag
    size_t tagLength = 0;
    if (std::getline(iss, token, '|')) {
        tagLength = std::stoul(token);
    }
    
    if (tagLength > 0) {
        message.authTag.resize(tagLength);
        iss.read(&message.authTag[0], tagLength);
    }
    
    // Read encrypted content
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

std::string MessageSerializer::serialize(const KeyBundle& keyBundle) {
    std::ostringstream oss;
    oss << keyBundle.identityKey << "|"
        << keyBundle.identityKeySignature << "|"  // ✅ ADD THIS LINE
        << keyBundle.signedPrekey << "|"
        << keyBundle.signedPrekeySignature << "|"
        << keyBundle.oneTimePrekey << "|"
        << keyBundle.signedPrekeyId << "|"
        << keyBundle.oneTimePrekeyId;
    return oss.str();
}

KeyBundle MessageSerializer::deserializeKeyBundle(const std::string& data) {
    KeyBundle bundle;
    std::istringstream iss(data);
    std::string token;
    
    if (std::getline(iss, token, '|')) {
        bundle.identityKey = token;
    }
    
    // ✅ ADD THIS BLOCK
    if (std::getline(iss, token, '|')) {
        bundle.identityKeySignature = token;
    }
    
    if (std::getline(iss, token, '|')) {
        bundle.signedPrekey = token;
    }
    
    if (std::getline(iss, token, '|')) {
        bundle.signedPrekeySignature = token;
    }
    
    if (std::getline(iss, token, '|')) {
        bundle.oneTimePrekey = token;
    }
    
    if (std::getline(iss, token, '|')) {
        bundle.signedPrekeyId = std::stoul(token);
    }
    
    if (std::getline(iss, token, '|')) {
        bundle.oneTimePrekeyId = std::stoul(token);
    }
    
    return bundle;
}

std::string MessageSerializer::serialize(const X3DHMessage& x3dhMsg) {
    std::ostringstream oss;
    oss << x3dhMsg.identityKey << "|"
        << x3dhMsg.ephemeralKey << "|"
        << x3dhMsg.oneTimePrekeyId << "|"
        << x3dhMsg.associatedData.length() << "|" << x3dhMsg.associatedData
        << x3dhMsg.encryptedMessage.length() << "|" << x3dhMsg.encryptedMessage;
    return oss.str();
}

X3DHMessage MessageSerializer::deserializeX3DH(const std::string& data) {
    X3DHMessage message;
    std::istringstream iss(data);
    std::string token;
    
    if (std::getline(iss, token, '|')) {
        message.identityKey = token;
    }
    
    if (std::getline(iss, token, '|')) {
        message.ephemeralKey = token;
    }
    
    if (std::getline(iss, token, '|')) {
        message.oneTimePrekeyId = token;
    }
    
    // Read associated data
    size_t adLength = 0;
    if (std::getline(iss, token, '|')) {
        adLength = std::stoul(token);
    }
    
    if (adLength > 0) {
        message.associatedData.resize(adLength);
        iss.read(&message.associatedData[0], adLength);
    }
    
    // Read encrypted message
    size_t msgLength = 0;
    if (std::getline(iss, token, '|')) {
        msgLength = std::stoul(token);
    }
    
    if (msgLength > 0) {
        message.encryptedMessage.resize(msgLength);
        iss.read(&message.encryptedMessage[0], msgLength);
    }
    
    return message;
}
