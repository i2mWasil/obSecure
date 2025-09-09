#pragma once

#include <QString>
#include <QSettings>
#include <QProcessEnvironment>
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QDebug>

class ConfigManager {
private:
    static ConfigManager* instance;
    QString serverUrl;
    int serverPort;
    
    ConfigManager();
    void loadFromEnvFile();
    void loadFromEnvironment();
    
public:
    static ConfigManager* getInstance();
    
    // Server configuration
    QString getServerUrl() const { return serverUrl; }
    int getServerPort() const { return serverPort; }
    QString getFullServerUrl() const;
    
    // Load configuration in priority order: .env file -> environment variables -> defaults
    void loadConfiguration();
};
