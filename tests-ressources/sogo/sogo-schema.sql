-- Schéma de base de données pour SOGo
CREATE TABLE IF NOT EXISTS sogo_users (
                                          c_uid VARCHAR(255) PRIMARY KEY,
    c_name VARCHAR(255),
    c_password VARCHAR(255),
    c_cn VARCHAR(255),
    c_givenname VARCHAR(255),
    c_sn VARCHAR(255),
    c_email VARCHAR(255),
    c_email2 VARCHAR(255),
    c_email3 VARCHAR(255),
    c_domain VARCHAR(255),
    c_imaphost VARCHAR(255) DEFAULT 'dovecot',
    c_imapuid VARCHAR(255),
    c_sievehost VARCHAR(255) DEFAULT 'dovecot'
    );

-- Index pour améliorer les performances
CREATE INDEX IF NOT EXISTS idx_sogo_users_email ON sogo_users(c_email);
CREATE INDEX IF NOT EXISTS idx_sogo_users_domain ON sogo_users(c_domain);
CREATE INDEX IF NOT EXISTS idx_sogo_users_uid ON sogo_users(c_uid);

-- Utilisateur exemple
INSERT INTO sogo_users (c_uid, c_name, c_password, c_cn, c_givenname, c_sn, c_email, c_domain, c_imapuid)
VALUES ('admin', 'Administrator', '{MD5}21232f297a57a5a743894a0e4a801fc3', 'Administrator', 'Admin', 'User', 'admin@example.com', 'example.com', 'admin@example.com')
    ON CONFLICT (c_uid) DO NOTHING;

-- Table pour les profils utilisateur SOGo
CREATE TABLE IF NOT EXISTS sogo_user_profile (
                                                 c_uid VARCHAR(255) NOT NULL,
    c_defaults TEXT,
    c_settings TEXT,
    CONSTRAINT sogo_user_profile_pkey PRIMARY KEY (c_uid)
    );

-- Table pour les informations de dossiers SOGo
CREATE TABLE IF NOT EXISTS sogo_folder_info (
                                                c_folder_id VARCHAR(255) NOT NULL,
    c_path VARCHAR(255) NOT NULL,
    c_path1 VARCHAR(255) NOT NULL,
    c_path2 VARCHAR(255),
    c_path3 VARCHAR(255),
    c_path4 VARCHAR(255),
    c_foldername VARCHAR(255) NOT NULL,
    c_location VARCHAR(2048) NOT NULL,
    c_quick_location VARCHAR(2048),
    c_acl_location VARCHAR(2048),
    c_folder_type VARCHAR(255) NOT NULL,
    CONSTRAINT sogo_folder_info_pkey PRIMARY KEY (c_folder_id)
    );

-- Table pour les sessions SOGo
CREATE TABLE IF NOT EXISTS sogo_sessions_folder (
                                                    c_id VARCHAR(255) NOT NULL,
    c_value VARCHAR(255) NOT NULL,
    c_creationdate INTEGER NOT NULL,
    c_lastseen INTEGER NOT NULL,
    CONSTRAINT sogo_sessions_folder_pkey PRIMARY KEY (c_id)
    );

-- Index pour les performances des sessions
CREATE INDEX IF NOT EXISTS idx_sogo_sessions_lastseen ON sogo_sessions_folder(c_lastseen);