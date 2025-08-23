#include "MainWindow.h"
#include <QApplication>
#include <QMessageBox>
#include <QInputDialog>
#include <QFileDialog>
#include <QClipboard>
#include <QScrollBar>
#include <QDateTime>

MainWindow::MainWindow(const QString& userId, int port, QWidget* parent)
    : QMainWindow(parent), currentUserId(userId), serverPort(port) { 
    
    setWindowTitle(QString("obSecure - %1 (Port: %2)").arg(userId).arg(port));
    setMinimumSize(800, 600);
    
    centralWidget = nullptr;
    mainLayout = nullptr;
    leftLayout = nullptr;
    rightLayout = nullptr;
    contactsLabel = nullptr;
    contactsList = nullptr;
    addContactButton = nullptr;
    deleteContactButton = nullptr;
    connectButton = nullptr;
    disconnectButton = nullptr;
    sharePublicKeyButton = nullptr;
    statusLabel = nullptr;
    chatLabel = nullptr;
    messageDisplay = nullptr;
    inputLayout = nullptr;
    messageInput = nullptr;
    sendButton = nullptr;
    
    
    try {
        setupUI();
        initializeManagers();
        updateContactsList();
        updateStatusLabel();
        updateButtonStates();
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "Initialization Error", 
                            QString("Failed to initialize obSecure: %1").arg(e.what()));
        QApplication::quit();
    }
}

MainWindow::~MainWindow() {
}

void MainWindow::setupUI() {
    centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    
    mainLayout = new QHBoxLayout(centralWidget);
    leftLayout = new QVBoxLayout();
    rightLayout = new QVBoxLayout();
    
    contactsLabel = new QLabel("Contacts", this);
    contactsLabel->setStyleSheet("font-weight: bold; font-size: 14px;");
    
    contactsList = new QListWidget(this);
    contactsList->setMaximumWidth(250);
    connect(contactsList, &QListWidget::itemSelectionChanged, 
            this, &MainWindow::onContactSelected);
    
    addContactButton = new QPushButton("Add Contact", this);
    connect(addContactButton, &QPushButton::clicked, this, &MainWindow::onAddContact);
    
    connectButton = new QPushButton("Connect", this);
    connect(connectButton, &QPushButton::clicked, this, &MainWindow::onConnectToUser);
    
    disconnectButton = new QPushButton("Disconnect", this);
    connect(disconnectButton, &QPushButton::clicked, this, &MainWindow::onDisconnectFromUser);
    
    deleteContactButton = new QPushButton("Delete Contact", this);
    deleteContactButton->setStyleSheet("background-color: #d32f2f; color: white;");
    connect(deleteContactButton, &QPushButton::clicked, this, &MainWindow::onDeleteContact);
    
    sharePublicKeyButton = new QPushButton("Share Public Key", this);
    connect(sharePublicKeyButton, &QPushButton::clicked, this, &MainWindow::onSharePublicKey);
    
    statusLabel = new QLabel("Server: Initializing...", this);
    statusLabel->setStyleSheet("font-size: 10px; color: white;");
    
    leftLayout->addWidget(contactsLabel);
    leftLayout->addWidget(contactsList);
    leftLayout->addWidget(addContactButton);
    leftLayout->addWidget(connectButton);
    leftLayout->addWidget(disconnectButton);
    leftLayout->addWidget(deleteContactButton);
    leftLayout->addWidget(sharePublicKeyButton); 
    leftLayout->addStretch();
    leftLayout->addWidget(statusLabel);
    
    chatLabel = new QLabel("Select a contact to start chatting", this);
    chatLabel->setStyleSheet("font-weight: bold; font-size: 14px;");
    
    messageDisplay = new QTextEdit(this);
    messageDisplay->setReadOnly(true);
    messageDisplay->setStyleSheet("background-color: #0e0c0cff; border: 1px solid #ccc;");
    
    inputLayout = new QHBoxLayout();
    messageInput = new QLineEdit(this);
    messageInput->setPlaceholderText("Type your message here...");
    connect(messageInput, &QLineEdit::returnPressed, this, &MainWindow::onSendMessage);
    
    sendButton = new QPushButton("Send", this);
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
    
    if (!statusLabel || !chatLabel || !contactsLabel || !sharePublicKeyButton) {
        throw std::runtime_error("Critical UI elements failed to initialize");
    }
}

void MainWindow::initializeManagers() {
    try {
        std::cout << "Creating KeyManager for user: " << currentUserId.toStdString() << std::endl;
        keyManager = std::make_unique<KeyManager>(currentUserId.toStdString());
        
        std::cout << "Keys directory should be at: keys/" << currentUserId.toStdString() << std::endl;
        
        std::string publicKey = keyManager->getPublicKeyString();
        std::cout << "=== YOUR PUBLIC KEY ===" << std::endl;
        std::cout << publicKey << std::endl;
        std::cout << "======================" << std::endl;
        
        cryptoManager = std::make_unique<CryptoManager>();
        userManager = std::make_unique<UserManager>(currentUserId.toStdString());
        networkManager = std::make_unique<NetworkManager>(currentUserId, serverPort, this);
        
        connect(networkManager.get(), &NetworkManager::messageReceived,
                this, &MainWindow::onMessageReceived);
        connect(networkManager.get(), &NetworkManager::userConnected,
                this, &MainWindow::onUserConnected);
        connect(networkManager.get(), &NetworkManager::userDisconnected,
                this, &MainWindow::onUserDisconnected);
        connect(networkManager.get(), &NetworkManager::connectionError,
                this, &MainWindow::onConnectionError);
        
        if (networkManager->startServer()) {
            statusLabel->setText(QString("Server: Running on port %1").arg(serverPort));
        } else {
            statusLabel->setText(QString("Server: Failed to start on port %1").arg(serverPort));
        }
        
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
        if (!keyManager->hasContactKey(currentChatUser.toStdString())) {
            QMessageBox::warning(this, "No Public Key", 
                               QString("No public key found for %1. Please exchange public keys first.")
                               .arg(currentChatUser));
            return;
        }
        
        if (!networkManager->isConnectedToUser(currentChatUser)) {
            QMessageBox::warning(this, "Not Connected", 
                               QString("Not connected to %1. Please connect first.")
                               .arg(currentChatUser));
            return;
        }
        
        auto contactKey = keyManager->getContactPublicKey(currentChatUser.toStdString());
        EncryptedMessage encMsg = cryptoManager->encryptMessage(
            messageText.toStdString(),
            currentUserId.toStdString(),
            currentChatUser.toStdString(),
            contactKey
        );
        
        if (networkManager->sendMessage(currentChatUser, encMsg)) {
            displayMessage("You", messageText, true);
            messageInput->clear();
        } else {
            QMessageBox::warning(this, "Send Failed", "Failed to send message.");
        }
        
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "Encryption Error", 
                            QString("Failed to encrypt message: %1").arg(e.what()));
    }
}

void MainWindow::onMessageReceived(const EncryptedMessage& message) {
    try {
        std::string plaintext = cryptoManager->decryptMessage(message, keyManager->getPrivateKey());
        QString sender = QString::fromStdString(message.senderId);
        QString messageText = QString::fromStdString(plaintext);
        
        displayMessage(sender, messageText, false);
        
        // If this message is from current chat user, scroll to bottom
        if (sender == currentChatUser) {
            QScrollBar* scrollBar = messageDisplay->verticalScrollBar();
            scrollBar->setValue(scrollBar->maximum());
        }
        
    } catch (const std::exception& e) {
        displayMessage("System", QString("Failed to decrypt message from %1: %2")
                      .arg(QString::fromStdString(message.senderId))
                      .arg(e.what()), false);
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
    
    QVBoxLayout* layout = new QVBoxLayout(&dialog);
    
    QFormLayout* formLayout = new QFormLayout;
    QLineEdit* userIdEdit = new QLineEdit;
    QLineEdit* displayNameEdit = new QLineEdit;
    QLineEdit* ipAddressEdit = new QLineEdit;
    QSpinBox* portSpin = new QSpinBox;
    portSpin->setRange(1024, 65535);
    portSpin->setValue(8888);
    
    formLayout->addRow("User ID:", userIdEdit);
    formLayout->addRow("Display Name:", displayNameEdit);
    formLayout->addRow("IP Address:", ipAddressEdit);
    formLayout->addRow("Port:", portSpin);
    
    QDialogButtonBox* buttonBox = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    
    connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    
    layout->addLayout(formLayout);
    layout->addWidget(buttonBox);
    
    if (dialog.exec() == QDialog::Accepted) {
        QString userId = userIdEdit->text().trimmed();
        QString displayName = displayNameEdit->text().trimmed();
        QString ipAddress = ipAddressEdit->text().trimmed();
        int port = portSpin->value();
        
        if (userId.isEmpty() || ipAddress.isEmpty()) {
            QMessageBox::warning(this, "Invalid Input", "User ID and IP Address are required.");
            return;
        }
        
        if (displayName.isEmpty()) {
            displayName = userId;
        }
        
        Contact contact(userId.toStdString(), displayName.toStdString(), 
                       ipAddress.toStdString(), port);
        
        if (userManager->addContact(contact)) {
            updateContactsList();
            
            // Prompt for public key
            QString publicKey = QInputDialog::getMultiLineText(this, 
                "Public Key", 
                QString("Enter the public key for %1:").arg(userId));
            
            if (!publicKey.isEmpty()) {
                if (keyManager->addContactPublicKey(userId.toStdString(), publicKey.toStdString())) {
                    QMessageBox::information(this, "Contact Added", 
                                           QString("Contact %1 added successfully.").arg(userId));
                } else {
                    QMessageBox::warning(this, "Invalid Public Key", 
                                       "Failed to add public key. Please check the format.");
                }
            }
        } else {
            QMessageBox::warning(this, "Add Contact Failed", "Failed to add contact.");
        }
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
                                            "This will remove the contact and their public key permanently.")
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
        
        // Remove public key from KeyManager
        if (!keyManager->removeContactKey(contactUserId.toStdString())) {
            QMessageBox::warning(this, "Key Removal Failed", 
                               "Contact removed but failed to remove public key.");
        }
        
        // Remove from UI list
        int row = contactsList->row(selectedItem);
        QListWidgetItem* item = contactsList->takeItem(row);
        delete item;  // Important: delete the item to prevent memory leak
        
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

void MainWindow::onSharePublicKey() {
    QString publicKey = QString::fromStdString(keyManager->getPublicKeyString());
    
    QDialog dialog(this);
    dialog.setWindowTitle("Share Public Key");
    dialog.setModal(true);
    dialog.resize(500, 400);
    
    QVBoxLayout* layout = new QVBoxLayout(&dialog);
    
    QLabel* label = new QLabel("Share this public key with your contacts:");
    QTextEdit* textEdit = new QTextEdit;
    textEdit->setPlainText(publicKey);
    textEdit->setReadOnly(true);
    
    QPushButton* copyButton = new QPushButton("Copy to Clipboard");
    connect(copyButton, &QPushButton::clicked, [publicKey]() {
        QApplication::clipboard()->setText(publicKey);
    });
    
    QPushButton* closeButton = new QPushButton("Close");
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

void MainWindow::displayMessage(const QString& sender, const QString& message, bool isOutgoing) {
    QString timestamp = getCurrentTime();
    QString color = isOutgoing ? "#0084ff" : "#09801fff";
    QString alignment = isOutgoing ? "right" : "left";
    
    QString html = QString(
        "<div style='margin: 5px 0; text-align: %1;'>"
        "<span style='color: white; font-size: 10px;'>%2</span><br>"
        "<span style='color: %3; font-weight: bold;'>%4:</span> %5"
        "</div>"
    ).arg(alignment, timestamp, color, sender, message.toHtmlEscaped());
    
    messageDisplay->append(html);
    
    // Auto-scroll to bottom
    QScrollBar* scrollBar = messageDisplay->verticalScrollBar();
    scrollBar->setValue(scrollBar->maximum());
}

void MainWindow::updateContactsList() {
    if (!contactsList) return; // Safety check
    
    contactsList->clear();
    
    auto contacts = userManager->getAllContacts();
    for (const auto& contact : contacts) {
        QString userId = QString::fromStdString(contact.userId);
        QString status = contact.isOnline ? " (Online)" : " (Offline)";
        QListWidgetItem* item = new QListWidgetItem(userId + status);
        
        if (contact.isOnline) {
            item->setForeground(QBrush(QColor("#00aa00"))); 
        } else {
            item->setForeground(QBrush(QColor("#9e0000ff")));  
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


QString MainWindow::getCurrentTime() {
    return QDateTime::currentDateTime().toString("hh:mm:ss");
}
