#include "ConfigManager.h"
#include <QCoreApplication>

ConfigManager* ConfigManager::instance = nullptr;

ConfigManager::ConfigManager() {
    // Set default values
    serverUrl = "http://localhost";
    serverPort = 5000;
}

ConfigManager* ConfigManager::getInstance() {
    if (!instance) {
        instance = new ConfigManager();
        instance->loadConfiguration();
    }
    return instance;
}

void ConfigManager::loadConfiguration() {
    // Load in priority order: defaults -> .env file -> environment variables
    loadFromEnvFile();
    loadFromEnvironment();
    
    qDebug() << "Configuration loaded:";
    qDebug() << "Server URL:" << getFullServerUrl();
}

void ConfigManager::loadFromEnvFile() {
    // Look for .env file in application directory
    QString envFilePath = QCoreApplication::applicationDirPath() + "/../.env";
    
    QFile envFile(envFilePath);
    if (!envFile.exists()) {
        qDebug() << ".env file not found at:" << envFilePath;
        return;
    }
    
    if (!envFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qDebug() << "Failed to open .env file:" << envFilePath;
        return;
    }
    
    QTextStream stream(&envFile);
    qDebug() << "Loading configuration from .env file:" << envFilePath;
    
    while (!stream.atEnd()) {
        QString line = stream.readLine().trimmed();
        
        // Skip empty lines and comments
        if (line.isEmpty() || line.startsWith("#")) {
            continue;
        }
        
        // Parse KEY=VALUE pairs
        int equalPos = line.indexOf('=');
        if (equalPos == -1) {
            continue;
        }
        
        QString key = line.left(equalPos).trimmed();
        QString value = line.mid(equalPos + 1).trimmed();
        
        // Remove quotes if present
        if ((value.startsWith('"') && value.endsWith('"')) || 
            (value.startsWith('\'') && value.endsWith('\''))) {
            value = value.mid(1, value.length() - 2);
        }
        
        // Set configuration values
        if (key == "SERVER_URL") {
            serverUrl = value;
            qDebug() << "Set SERVER_URL from .env:" << value;
        } else if (key == "SERVER_PORT") {
            bool ok;
            int port = value.toInt(&ok);
            if (ok && port > 0 && port <= 65535) {
                serverPort = port;
                qDebug() << "Set SERVER_PORT from .env:" << port;
            }
        }
    }
}

void ConfigManager::loadFromEnvironment() {
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    
    // Override with environment variables if they exist
    if (env.contains("SERVER_URL")) {
        serverUrl = env.value("SERVER_URL");
        qDebug() << "Set SERVER_URL from environment:" << serverUrl;
    }
    
    if (env.contains("SERVER_PORT")) {
        bool ok;
        int port = env.value("SERVER_PORT").toInt(&ok);
        if (ok && port > 0 && port <= 65535) {
            serverPort = port;
            qDebug() << "Set SERVER_PORT from environment:" << port;
        }
    }
}

QString ConfigManager::getFullServerUrl() const {
    return QString("%1:%2").arg(serverUrl).arg(serverPort);
}
