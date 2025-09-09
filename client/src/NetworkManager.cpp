
#include "NetworkManager.h"
#include <QTcpServer>
#include <QTcpSocket>
#include <QHostAddress>
#include <QDebug>
#include <QTimer>

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
    qDebug() << "Attempting to connect to:" << userId << "at" << address << ":" << port;
    
    if (activeConnections.find(userId) != activeConnections.end()) {
        qDebug() << "Already connected to" << userId;
        return true;
    }

    QTcpSocket* socket = new QTcpSocket(this);
    connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onDataReceived);
    connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onClientDisconnected);
    connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QAbstractSocket::errorOccurred),
        this, &NetworkManager::onConnectionError);
    
    qDebug() << "Connecting to host:" << address << "port:" << port;
    socket->connectToHost(address, port);
    
    qDebug() << "Waiting for connection...";
    if (socket->waitForConnected(100000)) { // Increased timeout to 5 seconds
        activeConnections[userId] = socket;
        socketToUserId[socket] = userId;
        sendHandshake(socket);
        emit userConnected(userId);
        qDebug() << "Successfully connected to user:" << userId;
        return true;
    } else {
        qDebug() << "Connection failed. Error:" << socket->errorString();
        qDebug() << "Socket state:" << socket->state();
        qDebug() << "Socket error:" << socket->error();
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
    MessageProtocol protocol;
    protocol.type = MessageType::TEXT_MESSAGE;
    protocol.senderId = message.senderId;
    protocol.receiverId = message.receiverId;
    protocol.timestamp = message.timestamp;
    protocol.payload = MessageSerializer::serialize(message);

    return sendProtocolMessage(receiverId, protocol);
}

bool NetworkManager::sendProtocolMessage(const QString& receiverId, const MessageProtocol& protocol) {
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

    std::string serialized = MessageSerializer::serialize(protocol);
    return sendData(socket, serialized);
}

bool NetworkManager::sendData(QTcpSocket* socket, const std::string& data) {
    QByteArray byteArray = QByteArray::fromStdString(data);
    uint32_t dataLength = byteArray.size();

    // Send length header first
    if (socket->write(reinterpret_cast<const char*>(&dataLength), sizeof(dataLength)) == -1) {
        return false;
    }

    // Send actual data
    if (socket->write(byteArray) == -1) {
        return false;
    }

    return socket->flush();
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

            case MessageType::X3DH_INIT: {
                X3DHMessage x3dhMsg = MessageSerializer::deserializeX3DH(protocol.payload);
                emit x3dhMessageReceived(x3dhMsg);
                break;
            }

            case MessageType::ACKNOWLEDGMENT:
                qDebug() << "Received acknowledgment from" << QString::fromStdString(protocol.senderId);
                break;

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
    sendData(socket, serialized);
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
