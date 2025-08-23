#include "NetworkManager.h"
#include <QHostAddress>
#include <QDataStream>
#include <QDebug>
#include <iostream>
#include <chrono>

NetworkManager::NetworkManager(const QString& userId, int port, QObject* parent)
    : QObject(parent), server(nullptr), serverPort(port), currentUserId(userId) {
}

NetworkManager::~NetworkManager() {
    stopServer();
}

bool NetworkManager::startServer() {
    if (server) {
        return true; 
    }
    
    server = new QTcpServer(this);
    connect(server, &QTcpServer::newConnection, this, &NetworkManager::onNewConnection);
    
    if (!server->listen(QHostAddress::Any, serverPort)) {
        qDebug() << "Failed to start server on port" << serverPort << ":" << server->errorString();
        qDebug() << "Port may already be in use. Try a different port.";
        delete server;
        server = nullptr;
        return false;
    }
    
    qDebug() << "Server started on port" << serverPort;
    return true;
}

void NetworkManager::stopServer() {
    if (server) {
        server->close();
        delete server;
        server = nullptr;
    }
    
    for (auto& pair : activeConnections) {
        pair.second->close();
        pair.second->deleteLater();
    }
    activeConnections.clear();
    socketToUserId.clear();
}

bool NetworkManager::connectToUser(const QString& userId, const QString& address, int port) {
    if (activeConnections.find(userId) != activeConnections.end()) {
        return true; 
    }
    
    QTcpSocket* socket = new QTcpSocket(this);
    connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onDataReceived);
    connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onClientDisconnected);
    connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QAbstractSocket::errorOccurred),
            this, &NetworkManager::onConnectionError);
    
    socket->connectToHost(address, port);
    
    if (socket->waitForConnected(5000)) {
        activeConnections[userId] = socket;
        socketToUserId[socket] = userId;
        sendHandshake(socket);
        emit userConnected(userId);
        qDebug() << "Connected to user:" << userId;
        return true;
    } else {
        qDebug() << "Failed to connect to user" << userId << ":" << socket->errorString();
        socket->deleteLater();
        return false;
    }
}

void NetworkManager::disconnectFromUser(const QString& userId) {
    auto it = activeConnections.find(userId);
    if (it != activeConnections.end()) {
        QTcpSocket* socket = it->second;
        cleanupConnection(socket);
        socket->close();
        socket->deleteLater();
    }
}

bool NetworkManager::sendMessage(const QString& receiverId, const EncryptedMessage& message) {
    auto it = activeConnections.find(receiverId);
    if (it == activeConnections.end()) {
        qDebug() << "No connection to user:" << receiverId;
        return false;
    }
    
    QTcpSocket* socket = it->second;
    if (socket->state() != QAbstractSocket::ConnectedState) {
        qDebug() << "Socket not connected to user:" << receiverId;
        return false;
    }
    
    MessageProtocol protocol;
    protocol.type = MessageType::TEXT_MESSAGE;
    protocol.senderId = message.senderId;
    protocol.receiverId = message.receiverId;
    protocol.timestamp = message.timestamp;
    protocol.payload = MessageSerializer::serialize(message);
    
    std::string serialized = MessageSerializer::serialize(protocol);
    QByteArray data = QByteArray::fromStdString(serialized);
    
    uint32_t dataLength = data.size();
    socket->write(reinterpret_cast<const char*>(&dataLength), sizeof(dataLength));
    socket->write(data);
    socket->flush();
    
    qDebug() << "Sent message to" << receiverId;
    return true;
}

bool NetworkManager::isConnectedToUser(const QString& userId) const {
    auto it = activeConnections.find(userId);
    return it != activeConnections.end() && it->second->state() == QAbstractSocket::ConnectedState;
}

std::vector<QString> NetworkManager::getConnectedUsers() const {
    std::vector<QString> users;
    for (const auto& pair : activeConnections) {
        if (pair.second->state() == QAbstractSocket::ConnectedState) {
            users.push_back(pair.first);
        }
    }
    return users;
}

void NetworkManager::onNewConnection() {
    while (server->hasPendingConnections()) {
        QTcpSocket* socket = server->nextPendingConnection();
        connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onDataReceived);
        connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onClientDisconnected);
        connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QAbstractSocket::errorOccurred),
                this, &NetworkManager::onConnectionError);
        
        qDebug() << "New incoming connection from:" << socket->peerAddress().toString();
    }
}

void NetworkManager::onDataReceived() {
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if (!socket) return;
    
    while (socket->bytesAvailable() >= sizeof(uint32_t)) {
        uint32_t dataLength;
        if (socket->peek(reinterpret_cast<char*>(&dataLength), sizeof(dataLength)) != sizeof(dataLength)) {
            break;
        }
        
        if (socket->bytesAvailable() < sizeof(dataLength) + dataLength) {
            break;
        }
        
        socket->read(sizeof(dataLength));
        
        QByteArray data = socket->read(dataLength);
        processIncomingData(socket, data);
    }
}

void NetworkManager::onClientDisconnected() {
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if (!socket) return;
    
    auto it = socketToUserId.find(socket);
    if (it != socketToUserId.end()) {
        QString userId = it->second;
        qDebug() << "User disconnected:" << userId;
        emit userDisconnected(userId);
        cleanupConnection(socket);
    }
    
    socket->deleteLater();
}

void NetworkManager::onConnectionError(QAbstractSocket::SocketError error) {
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if (!socket) return;
    
    QString errorMsg = QString("Network error: %1").arg(socket->errorString());
    qDebug() << errorMsg;
    emit connectionError(errorMsg);
    
    auto it = socketToUserId.find(socket);
    if (it != socketToUserId.end()) {
        emit userDisconnected(it->second);
        cleanupConnection(socket);
    }
}

void NetworkManager::processIncomingData(QTcpSocket* socket, const QByteArray& data) {
    try {
        std::string dataStr = data.toStdString();
        MessageProtocol protocol = MessageSerializer::deserialize(dataStr);
        
        switch (protocol.type) {
            case MessageType::CONNECTION_REQUEST:
                handleHandshake(socket, protocol);
                break;
                
            case MessageType::TEXT_MESSAGE: {
                EncryptedMessage encMsg = MessageSerializer::deserializeEncrypted(protocol.payload);
                emit messageReceived(encMsg);
                break;
            }
            
            default:
                qDebug() << "Unknown message type received";
                break;
        }
    } catch (const std::exception& e) {
        qDebug() << "Error processing incoming data:" << e.what();
    }
}

void NetworkManager::handleHandshake(QTcpSocket* socket, const MessageProtocol& message) {
    QString userId = QString::fromStdString(message.senderId);
    
    auto existingIt = activeConnections.find(userId);
    if (existingIt != activeConnections.end()) {
        QTcpSocket* existingSocket = existingIt->second;
        if (existingSocket != socket) {
            cleanupConnection(existingSocket);
            existingSocket->close();
            existingSocket->deleteLater();
        }
    }
    
    activeConnections[userId] = socket;
    socketToUserId[socket] = userId;
    
    qDebug() << "Handshake completed with user:" << userId;
    emit userConnected(userId);
}

void NetworkManager::sendHandshake(QTcpSocket* socket) {
    MessageProtocol handshake;
    handshake.type = MessageType::CONNECTION_REQUEST;
    handshake.senderId = currentUserId.toStdString();
    handshake.receiverId = "";
    handshake.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    handshake.payload = "HANDSHAKE";
    
    std::string serialized = MessageSerializer::serialize(handshake);
    QByteArray data = QByteArray::fromStdString(serialized);
    
    uint32_t dataLength = data.size();
    socket->write(reinterpret_cast<const char*>(&dataLength), sizeof(dataLength));
    socket->write(data);
    socket->flush();
}

void NetworkManager::cleanupConnection(QTcpSocket* socket) {
    auto socketIt = socketToUserId.find(socket);
    if (socketIt != socketToUserId.end()) {
        QString userId = socketIt->second;
        socketToUserId.erase(socketIt);
        
        auto connIt = activeConnections.find(userId);
        if (connIt != activeConnections.end()) {
            activeConnections.erase(connIt);
        }
    }
}
