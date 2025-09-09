#include "MainWindow.h"
#include "ConfigManager.h"
#include <QApplication>
#include <QMessageBox>
#include <QInputDialog>
#include <QFileDialog>
#include <QClipboard>
#include <QScrollBar>
#include <QDateTime>
#include <QFormLayout>
#include <QSpinBox>
#include <QDialogButtonBox>
#include <QFont>
#include <QBrush>
#include <QColor>
#include <iostream>
#include <chrono>
#include <QJsonDocument> 
#include <QJsonObject>

MainWindow::MainWindow(const QString& phoneNumber, int port, QWidget* parent)
    : QMainWindow(parent), currentPhoneNumber(phoneNumber), serverPort(port) { 
    
    setWindowTitle(QString("obSecure - %1 (Port: %2)").arg(phoneNumber).arg(port));
    setMinimumSize(900, 700);
    
    try {
        setupUI();
        initializeManagers();
        updateContactsList();
        updateStatusLabel();
        updateButtonStates();
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "Initialization Error", 
                            QString("Failed to initialize application: %1").arg(e.what()));
        QApplication::quit();
    }
}

MainWindow::~MainWindow() {}

void MainWindow::setupUI() {
    centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    
    mainLayout = new QHBoxLayout(centralWidget);
    leftLayout = new QVBoxLayout();
    rightLayout = new QVBoxLayout();
    
    // Left panel - Contacts
    contactsLabel = new QLabel("Contacts", this);
    contactsLabel->setStyleSheet("font-weight: bold; font-size: 14px; color: white;");
    
    contactsList = new QListWidget(this);
    contactsList->setMaximumWidth(280);
    contactsList->setStyleSheet("background-color: #2b2b2b; color: white; border: 1px solid #444;");
    connect(contactsList, &QListWidget::itemSelectionChanged, 
            this, &MainWindow::onContactSelected);
    
    addContactButton = new QPushButton("Add Contact", this);
    addContactButton->setStyleSheet("background-color: #28a745; color: white; padding: 8px; border: none; border-radius: 4px;");
    connect(addContactButton, &QPushButton::clicked, this, &MainWindow::onAddContact);
    
    connectButton = new QPushButton("Connect", this);
    connectButton->setStyleSheet("background-color: #007acc; color: white; padding: 8px; border: none; border-radius: 4px;");
    connect(connectButton, &QPushButton::clicked, this, &MainWindow::onConnectToUser);
    
    disconnectButton = new QPushButton("Disconnect", this);
    disconnectButton->setStyleSheet("background-color: #6c757d; color: white; padding: 8px; border: none; border-radius: 4px;");
    connect(disconnectButton, &QPushButton::clicked, this, &MainWindow::onDisconnectFromUser);
    
    deleteContactButton = new QPushButton("Delete Contact", this);
    deleteContactButton->setStyleSheet("background-color: #dc3545; color: white; padding: 8px; border: none; border-radius: 4px;");
    connect(deleteContactButton, &QPushButton::clicked, this, &MainWindow::onDeleteContact);
    
    sharePublicKeyButton = new QPushButton("Share Identity Key", this);
    sharePublicKeyButton->setStyleSheet("background-color: #17a2b8; color: white; padding: 8px; border: none; border-radius: 4px;");
    connect(sharePublicKeyButton, &QPushButton::clicked, this, &MainWindow::onSharePublicKey);
    
    refreshKeysButton = new QPushButton("Refresh Keys", this);
    refreshKeysButton->setStyleSheet("background-color: #ffc107; color: black; padding: 8px; border: none; border-radius: 4px;");
    connect(refreshKeysButton, &QPushButton::clicked, this, &MainWindow::onRefreshKeys);
    
    statusLabel = new QLabel("Server: Initializing...", this);
    statusLabel->setStyleSheet("font-size: 10px; color: #ccc; padding: 4px;");
    
    leftLayout->addWidget(contactsLabel);
    leftLayout->addWidget(contactsList);
    leftLayout->addWidget(addContactButton);
    leftLayout->addWidget(connectButton);
    leftLayout->addWidget(disconnectButton);
    leftLayout->addWidget(deleteContactButton);
    leftLayout->addWidget(sharePublicKeyButton);
    leftLayout->addWidget(refreshKeysButton);
    leftLayout->addStretch();
    leftLayout->addWidget(statusLabel);
    
    // Right panel - Chat
    chatLabel = new QLabel("Select a contact to start chatting", this);
    chatLabel->setStyleSheet("font-weight: bold; font-size: 14px; color: white; padding: 8px;");
    
    messageDisplay = new QTextEdit(this);
    messageDisplay->setReadOnly(true);
    messageDisplay->setStyleSheet("background-color: #1e1e1e; color: white; border: 1px solid #444; padding: 8px;");
    
    inputLayout = new QHBoxLayout();
    messageInput = new QLineEdit(this);
    messageInput->setPlaceholderText("Type your message here...");
    messageInput->setStyleSheet("padding: 8px; font-size: 12px; background-color: #2b2b2b; color: white; border: 1px solid #444; border-radius: 4px;");
    connect(messageInput, &QLineEdit::returnPressed, this, &MainWindow::onSendMessage);
    
    sendButton = new QPushButton("Send", this);
    sendButton->setStyleSheet("background-color: #007acc; color: white; padding: 8px 16px; border: none; border-radius: 4px;");
    connect(sendButton, &QPushButton::clicked, this, &MainWindow::onSendMessage);
    
    inputLayout->addWidget(messageInput);
    inputLayout->addWidget(sendButton);
    
    rightLayout->addWidget(chatLabel);
    rightLayout->addWidget(messageDisplay);
    rightLayout->addLayout(inputLayout);
    
    mainLayout->addLayout(leftLayout);
    mainLayout->addLayout(rightLayout);
    mainLayout->setStretch(0, 0);
    mainLayout->setStretch(1, 1);
    
    // Set overall dark theme
    setStyleSheet("QMainWindow { background-color: #1a1a1a; }");
}

void MainWindow::initializeManagers() {
    try {
        std::cout << "Initializing managers for: " << currentPhoneNumber.toStdString() << std::endl;
        
        // Initialize key manager
        keyManager = std::make_shared<KeyManager>(currentPhoneNumber.toStdString());
        
        // Initialize server API with configurable URL
        ConfigManager* config = ConfigManager::getInstance();
        QString serverUrl = config->getFullServerUrl();
        std::cout << "Using server URL: " << serverUrl.toStdString() << std::endl;
        
        serverAPI = std::make_shared<ServerAPI>(serverUrl.toStdString(), this);

        // Initialize phone auth manager
        phoneAuthManager = std::make_unique<PhoneAuthManager>(serverAPI, keyManager, this);
        
        // Initialize X3DH manager
        x3dhManager = std::make_unique<X3DHManager>(keyManager);
        
        // Initialize crypto manager
        cryptoManager = std::make_unique<CryptoManager>();
        
        // Initialize user manager
        userManager = std::make_unique<UserManager>(currentPhoneNumber.toStdString());
        
        // Initialize network manager
        networkManager = std::make_unique<NetworkManager>(currentPhoneNumber, serverPort, this);
        
        // Connect signals
        connect(networkManager.get(), &NetworkManager::messageReceived,
                this, &MainWindow::onMessageReceived);
        connect(networkManager.get(), &NetworkManager::x3dhMessageReceived,
                this, &MainWindow::onX3DHMessageReceived);
        connect(networkManager.get(), &NetworkManager::userConnected,
                this, &MainWindow::onUserConnected);
        connect(networkManager.get(), &NetworkManager::userDisconnected,
                this, &MainWindow::onUserDisconnected);
        connect(networkManager.get(), &NetworkManager::connectionError,
                this, &MainWindow::onConnectionError);
        
        // Start server
        if (networkManager->startServer()) {
            statusLabel->setText(QString("Server: Running on port %1").arg(serverPort));
        } else {
            statusLabel->setText(QString("Server: Failed to start on port %1").arg(serverPort));
        }
        
        // Check if user is registered with server
        serverAPI->verifyPhone(currentPhoneNumber.toStdString(),
    [this](bool success, const std::string& response) {
        if (success) {
            // Parse the JSON response
            QJsonDocument doc = QJsonDocument::fromJson(QByteArray::fromStdString(response));
            QJsonObject obj = doc.object();
            
            bool userExists = obj["exists"].toBool();
            bool userActive = obj["active"].toBool();
            
            if (!userExists) {  // ✅ CORRECT CONDITION
                // User not registered, register now
                phoneAuthManager->registerWithServer([this](bool regSuccess, const std::string& regResponse) {
                if (regSuccess) {
                        statusLabel->setText(statusLabel->text() + " | Registered");
                } else {
                        statusLabel->setText(statusLabel->text() + " | Registration Failed");
                    }
                });
            } else if (userExists && userActive) {
                statusLabel->setText(statusLabel->text() + " | Verified");
            } else {
                statusLabel->setText(statusLabel->text() + " | User Inactive");
            }
            } 
        else {
            statusLabel->setText(statusLabel->text() + " | Verification Failed");
        }
    });

        
    std::cout << "All managers initialized successfully" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error in initializeManagers: " << e.what() << std::endl;
        throw;
    }
}

void MainWindow::onSendMessage() {
    if (currentChatUser.isEmpty()) {
        QMessageBox::warning(this, "No Contact Selected", 
                           "Please select a contact to send a message to.");
        return;
    }
    
    QString messageText = messageInput->text().trimmed();
    if (messageText.isEmpty()) {
        return;
    }
    
    try {
        if (!keyManager->hasContactKeyBundle(currentChatUser.toStdString())) {
            QMessageBox::warning(this, "No Key Bundle", 
                               QString("No key bundle found for %1. Please refresh contact keys.")
                               .arg(currentChatUser));
            return;
        }
        
        if (!networkManager->isConnectedToUser(currentChatUser)) {
            QMessageBox::warning(this, "Not Connected", 
                               QString("Not connected to %1. Please connect first.")
                               .arg(currentChatUser));
            return;
        }
        
        // Get contact key bundle
        KeyBundle contactBundle = keyManager->getContactKeyBundle(currentChatUser.toStdString());
        
        // Check if we have an active session, if not, initiate X3DH
        if (!hasActiveSession(currentChatUser)) {
            // Initiate X3DH handshake
            X3DHMessage x3dhMsg = x3dhManager->initiateX3DH(
                currentChatUser.toStdString(), 
                contactBundle, 
                messageText.toStdString()
            );
            
            // Send X3DH message
            MessageProtocol protocol;
            protocol.type = MessageType::X3DH_INIT;
            protocol.senderId = currentPhoneNumber.toStdString();
            protocol.receiverId = currentChatUser.toStdString();
            protocol.timestamp = getCurrentTimestamp();
            protocol.payload = MessageSerializer::serialize(x3dhMsg);
            
            if (networkManager->sendProtocolMessage(currentChatUser, protocol)) {
                displayMessage("You", messageText, true);
                messageInput->clear();
                
                // Mark session as active (session key will be set by X3DH)
                setActiveSession(currentChatUser, true);
            } else {
                QMessageBox::warning(this, "Send Failed", "Failed to send X3DH message.");
            }
        } else {
            // Use existing session to send regular encrypted message
            EncryptedMessage encMsg = cryptoManager->encryptMessageWithSessionKey(
                messageText.toStdString(),
                currentPhoneNumber.toStdString(),
                currentChatUser.toStdString(),
                getSessionKey(currentChatUser),
                getMessageCounter(currentChatUser)
            );
            
            if (networkManager->sendMessage(currentChatUser, encMsg)) {
                displayMessage("You", messageText, true);
                messageInput->clear();
                incrementMessageCounter(currentChatUser);
            } else {
                QMessageBox::warning(this, "Send Failed", "Failed to send message.");
            }
        }
        
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "Send Error", 
                            QString("Failed to send message: %1").arg(e.what()));
    }
}

void MainWindow::onMessageReceived(const EncryptedMessage& message) {
    try {
        std::string plaintext;
        QString sender = QString::fromStdString(message.senderId);
        
        if (hasActiveSession(sender)) {
            plaintext = cryptoManager->decryptMessageWithSessionKey(message, getSessionKey(sender));
        } else {
            // This shouldn't happen with regular messages
            displayMessage("System", QString("Received message without active session from %1")
                          .arg(sender), false);
            return;
        }
        
        QString messageText = QString::fromStdString(plaintext);
        displayMessage(sender, messageText, false);
        
        // Auto-scroll if this is the current chat
        if (sender == currentChatUser) {
            QScrollBar* scrollBar = messageDisplay->verticalScrollBar();
            scrollBar->setValue(scrollBar->maximum());
        }
        
    } catch (const std::exception& e) {
        displayMessage("System", QString("Failed to decrypt message: %1").arg(e.what()), false);
    }
}

void MainWindow::onX3DHMessageReceived(const X3DHMessage& x3dhMessage) {
    try {
        std::string sharedSecret;
        std::string plaintext = x3dhManager->processX3DHInit(x3dhMessage, sharedSecret);
        
        // Extract sender from the message (simplified - in reality you'd verify this)
        QString sender = QString::fromStdString(x3dhMessage.identityKey).left(10);
        QString messageText = QString::fromStdString(plaintext);
        
        // Store the shared secret for future messages
        setSessionKey(sender, sharedSecret);
        setActiveSession(sender, true);
        
        displayMessage(sender, messageText, false);
        
        // Send acknowledgment
        MessageProtocol ackProtocol;
        ackProtocol.type = MessageType::ACKNOWLEDGMENT;
        ackProtocol.senderId = currentPhoneNumber.toStdString();
        ackProtocol.receiverId = sender.toStdString();
        ackProtocol.timestamp = getCurrentTimestamp();
        ackProtocol.payload = "X3DH_ACK";
        
        networkManager->sendProtocolMessage(sender, ackProtocol);
        
    } catch (const std::exception& e) {
        displayMessage("System", QString("Failed to process X3DH message: %1").arg(e.what()), false);
    }
}

void MainWindow::onContactSelected() {
    QListWidgetItem* item = contactsList->currentItem();
    if (!item) {
        currentChatUser.clear();
        chatLabel->setText("Select a contact to start chatting");
        updateButtonStates();
        return;
    }
    
    QString itemText = item->text();
    currentChatUser = itemText.split(" (").first();
    chatLabel->setText(QString("Chatting with %1").arg(currentChatUser));
    updateButtonStates(); 
    
    messageDisplay->clear();
}

void MainWindow::onAddContact() {
    QDialog dialog(this);
    dialog.setWindowTitle("Add Contact");
    dialog.setModal(true);
    dialog.setStyleSheet("QDialog { background-color: #2b2b2b; color: white; }");
    
    QVBoxLayout* layout = new QVBoxLayout(&dialog);
    
    QFormLayout* formLayout = new QFormLayout;
    QLineEdit* phoneEdit = new QLineEdit;
    phoneEdit->setPlaceholderText("+1234567890");
    phoneEdit->setStyleSheet("padding: 8px; background-color: #1e1e1e; color: white; border: 1px solid #444;");
    
    QLineEdit* displayNameEdit = new QLineEdit;
    displayNameEdit->setStyleSheet("padding: 8px; background-color: #1e1e1e; color: white; border: 1px solid #444;");
    
    QLineEdit* ipAddressEdit = new QLineEdit;
    ipAddressEdit->setText("127.0.0.1"); // Default
    ipAddressEdit->setStyleSheet("padding: 8px; background-color: #1e1e1e; color: white; border: 1px solid #444;");
    
    QSpinBox* portSpin = new QSpinBox;
    portSpin->setRange(1024, 65535);
    portSpin->setValue(8888);
    portSpin->setStyleSheet("padding: 8px; background-color: #1e1e1e; color: white; border: 1px solid #444;");
    
    formLayout->addRow("Phone Number:", phoneEdit);
    formLayout->addRow("Display Name:", displayNameEdit);
    formLayout->addRow("IP Address:", ipAddressEdit);
    formLayout->addRow("Port:", portSpin);
    
    QDialogButtonBox* buttonBox = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    buttonBox->setStyleSheet("QPushButton { background-color: #007acc; color: white; padding: 8px; border: none; border-radius: 4px; }");
    
    connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    
    layout->addLayout(formLayout);
    layout->addWidget(buttonBox);
    
    if (dialog.exec() == QDialog::Accepted) {
        QString phoneNumber = phoneEdit->text().trimmed();
        QString displayName = displayNameEdit->text().trimmed();
        QString ipAddress = ipAddressEdit->text().trimmed();
        int port = portSpin->value();
        
        if (phoneNumber.isEmpty() || ipAddress.isEmpty()) {
            QMessageBox::warning(this, "Invalid Input", "Phone number and IP address are required.");
            return;
        }
        
        if (!PhoneAuthManager::validatePhoneNumber(phoneNumber.toStdString())) {
            QMessageBox::warning(this, "Invalid Phone Number", 
                               "Please enter a valid phone number with country code.");
            return;
        }
        
        phoneNumber = QString::fromStdString(PhoneAuthManager::normalizePhoneNumber(phoneNumber.toStdString()));
        
        if (displayName.isEmpty()) {
            displayName = phoneNumber;
        }
        
        // Fetch key bundle from server
        phoneAuthManager->fetchContactKeyBundle(phoneNumber.toStdString(), 
            [this, phoneNumber, displayName, ipAddress, port](bool success, const KeyBundle& bundle) {
                if (success) {
                    // Add key bundle to key manager
                    if (keyManager->addContactKeyBundle(phoneNumber.toStdString(), bundle)) {
                        // Add contact to user manager
                        Contact contact(phoneNumber.toStdString(), displayName.toStdString(), 
                                      ipAddress.toStdString(), port);
                        
                        if (userManager->addContact(contact)) {
                            updateContactsList();
                            QMessageBox::information(this, "Contact Added", 
                                QString("Successfully added %1 to contacts").arg(phoneNumber));
                        } else {
                            QMessageBox::warning(this, "Add Contact Failed", 
                                               "Failed to add contact to user manager.");
                        }
                    } else {
                        QMessageBox::warning(this, "Key Bundle Error", 
                                           "Failed to add contact key bundle.");
                    }
                } else {
                    QMessageBox::warning(this, "Fetch Failed", 
                                       QString("Failed to fetch key bundle for %1. Contact may not be registered.")
                                       .arg(phoneNumber));
                }
            });
    }
}

void MainWindow::onDeleteContact() {
    QListWidgetItem* selectedItem = contactsList->currentItem();
    if (!selectedItem) {
        QMessageBox::warning(this, "No Contact Selected", 
                           "Please select a contact to delete.");
        return;
    }
    
    QString itemText = selectedItem->text();
    QString contactUserId = itemText.split(" (").first();
    
    int result = QMessageBox::question(this, "Delete Contact", 
                                     QString("Are you sure you want to delete contact '%1'?\n\n"
                                            "This will remove the contact and their keys permanently.")
                                     .arg(contactUserId),
                                     QMessageBox::Yes | QMessageBox::No,
                                     QMessageBox::No);
    
    if (result != QMessageBox::Yes) {
        return;
    }
    
    try {
        if (networkManager->isConnectedToUser(contactUserId)) {
            networkManager->disconnectFromUser(contactUserId);
            displayMessage("System", QString("Disconnected from %1 (contact deleted)")
                          .arg(contactUserId), false);
        }
        
        if (currentChatUser == contactUserId) {
            currentChatUser.clear();
            chatLabel->setText("Select a contact to start chatting");
            messageDisplay->clear();
        }
        
        if (!userManager->removeContact(contactUserId.toStdString())) {
            QMessageBox::warning(this, "Delete Failed", 
                               "Failed to remove contact from user manager.");
            return;
        }
        
        // Remove key bundle from KeyManager
        keyManager->removeContactKeyBundle(contactUserId.toStdString());
        
        // Remove session data
        setActiveSession(contactUserId, false);
        sessionKeys.erase(contactUserId);
        messageCounters.erase(contactUserId);
        
        // Remove from UI list
        int row = contactsList->row(selectedItem);
        QListWidgetItem* item = contactsList->takeItem(row);
        delete item;
        
        // Update UI
        updateButtonStates();
        updateStatusLabel();
        
        QMessageBox::information(this, "Contact Deleted", 
                               QString("Contact '%1' has been deleted successfully.")
                               .arg(contactUserId));
        
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "Delete Error", 
                            QString("Failed to delete contact: %1").arg(e.what()));
    }
}

void MainWindow::onConnectToUser() {
    if (currentChatUser.isEmpty()) {
        QMessageBox::warning(this, "No Contact Selected", "Please select a contact to connect to.");
        return;
    }
    
    try {
        Contact contact = userManager->getContact(currentChatUser.toStdString());
        if (networkManager->connectToUser(currentChatUser, 
                                        QString::fromStdString(contact.ipAddress), 
                                        contact.port)) {
            displayMessage("System", QString("Connecting to %1...").arg(currentChatUser), false);
        } else {
            QMessageBox::warning(this, "Connection Failed", 
                               QString("Failed to connect to %1").arg(currentChatUser));
        }
    } catch (const std::exception& e) {
        QMessageBox::warning(this, "Connection Error", e.what());
    }
}

void MainWindow::onDisconnectFromUser() {
    if (currentChatUser.isEmpty()) {
        QMessageBox::warning(this, "No Contact Selected", "Please select a contact to disconnect from.");
        return;
    }
    
    networkManager->disconnectFromUser(currentChatUser);
    displayMessage("System", QString("Disconnected from %1").arg(currentChatUser), false);
}

void MainWindow::onUserConnected(const QString& userId) {
    displayMessage("System", QString("%1 connected").arg(userId), false);
    userManager->updateContactStatus(userId.toStdString(), true);
    updateContactsList();
    updateStatusLabel();
}

void MainWindow::onUserDisconnected(const QString& userId) {
    displayMessage("System", QString("%1 disconnected").arg(userId), false);
    userManager->updateContactStatus(userId.toStdString(), false);
    updateContactsList();
    updateStatusLabel();
}

void MainWindow::onConnectionError(const QString& error) {
    displayMessage("System", QString("Connection error: %1").arg(error), false);
}

void MainWindow::onRefreshKeys() {
    // Upload new one-time prekeys
    phoneAuthManager->uploadNewOneTimePrekeys([this](bool success, const std::string& message) {
        if (success) {
            QMessageBox::information(this, "Keys Refreshed", 
                QString::fromStdString(message));
        } else {
            QMessageBox::warning(this, "Refresh Failed", 
                QString::fromStdString(message));
        }
    });
}

void MainWindow::onSharePublicKey() {
    QString identityKey = QString::fromStdString(keyManager->getIdentityPublicKeyString());
    
    QDialog dialog(this);
    dialog.setWindowTitle("Share Identity Key");
    dialog.setModal(true);
    dialog.resize(600, 450);
    dialog.setStyleSheet("QDialog { background-color: #2b2b2b; color: white; }");
    
    QVBoxLayout* layout = new QVBoxLayout(&dialog);
    
    QLabel* label = new QLabel("Share this identity key with your contacts:");
    label->setStyleSheet("color: white; font-weight: bold; margin-bottom: 10px;");
    
    QTextEdit* textEdit = new QTextEdit;
    textEdit->setPlainText(identityKey);
    textEdit->setReadOnly(true);
    textEdit->setFont(QFont("Courier", 10));
    textEdit->setStyleSheet("background-color: #1e1e1e; color: white; border: 1px solid #444;");
    
    QPushButton* copyButton = new QPushButton("Copy to Clipboard");
    copyButton->setStyleSheet("background-color: #28a745; color: white; padding: 8px; border: none; border-radius: 4px;");
    connect(copyButton, &QPushButton::clicked, [identityKey]() {
        QApplication::clipboard()->setText(identityKey);
    });
    
    QPushButton* closeButton = new QPushButton("Close");
    closeButton->setStyleSheet("background-color: #6c757d; color: white; padding: 8px; border: none; border-radius: 4px;");
    connect(closeButton, &QPushButton::clicked, &dialog, &QDialog::accept);
    
    QHBoxLayout* buttonLayout = new QHBoxLayout;
    buttonLayout->addWidget(copyButton);
    buttonLayout->addStretch();
    buttonLayout->addWidget(closeButton);
    
    layout->addWidget(label);
    layout->addWidget(textEdit);
    layout->addLayout(buttonLayout);
    
    dialog.exec();
}

void MainWindow::updateContactsList() {
    if (!contactsList) return;
    
    contactsList->clear();
    
    auto contacts = userManager->getAllContacts();
    for (const auto& contact : contacts) {
        QString userId = QString::fromStdString(contact.userId);
        QString status = contact.isOnline ? " (Online)" : " (Offline)";
        QListWidgetItem* item = new QListWidgetItem(userId + status);
        
        if (contact.isOnline) {
            item->setForeground(QBrush(QColor("#28a745"))); 
        } else {
            item->setForeground(QBrush(QColor("#6c757d")));  
        }
        
        contactsList->addItem(item);
    }
}

void MainWindow::updateStatusLabel() {
    if (!statusLabel || !networkManager) return; 
    
    auto connectedUsers = networkManager->getConnectedUsers();
    statusLabel->setText(QString("Server: Running | Connected: %1")
                        .arg(connectedUsers.size()));
}

void MainWindow::updateButtonStates() {
    bool hasSelection = !currentChatUser.isEmpty();
    bool hasListSelection = (contactsList->currentItem() != nullptr);
    bool isConnected = hasSelection && networkManager && networkManager->isConnectedToUser(currentChatUser);
    
    if (connectButton) connectButton->setEnabled(hasSelection && !isConnected);
    if (disconnectButton) disconnectButton->setEnabled(hasSelection && isConnected);
    if (sendButton) sendButton->setEnabled(hasSelection && isConnected);
    if (messageInput) messageInput->setEnabled(hasSelection && isConnected);
    if (deleteContactButton) deleteContactButton->setEnabled(hasListSelection);  
}

void MainWindow::displayMessage(const QString& sender, const QString& message, bool isOutgoing) {
    QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
    QString color = isOutgoing ? "#007acc" : "#28a745";
    QString alignment = isOutgoing ? "right" : "left";
    
    QString html = QString(
        "<div style='margin: 8px 0; text-align: %1;'>"
        "<div style='color: #888; font-size: 10px;'>%2</div>"
        "<div style='color: %3; font-weight: bold; font-size: 12px;'>%4:</div>"
        "<div style='color: white; margin-top: 2px; background-color: %5; padding: 8px; border-radius: 8px; display: inline-block; max-width: 70%%;'>%6</div>"
        "</div>"
    ).arg(alignment, timestamp, color, sender, 
          isOutgoing ? "#007acc40" : "#28a74540", 
          message.toHtmlEscaped());
    
    messageDisplay->append(html);
    
    // Auto-scroll to bottom
    QScrollBar* scrollBar = messageDisplay->verticalScrollBar();
    scrollBar->setValue(scrollBar->maximum());
}

QString MainWindow::getCurrentTime() {
    return QDateTime::currentDateTime().toString("hh:mm:ss");
}

// Session management helper functions
bool MainWindow::hasActiveSession(const QString& phoneNumber) {
    return activeSessions.find(phoneNumber) != activeSessions.end();
}

void MainWindow::setActiveSession(const QString& phoneNumber, bool active) {
    if (active) {
        activeSessions.insert(phoneNumber);
    } else {
        activeSessions.erase(phoneNumber);
    }
}

std::string MainWindow::getSessionKey(const QString& phoneNumber) {
    auto it = sessionKeys.find(phoneNumber);
    if (it != sessionKeys.end()) {
        return it->second;
    }
    return "";
}

void MainWindow::setSessionKey(const QString& phoneNumber, const std::string& key) {
    sessionKeys[phoneNumber] = key;
}

uint32_t MainWindow::getMessageCounter(const QString& phoneNumber) {
    auto it = messageCounters.find(phoneNumber);
    if (it != messageCounters.end()) {
        return it->second;
    }
    return 0;
}

void MainWindow::incrementMessageCounter(const QString& phoneNumber) {
    messageCounters[phoneNumber]++;
}

uint64_t MainWindow::getCurrentTimestamp() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}
