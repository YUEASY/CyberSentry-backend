-- 创建数据库
CREATE DATABASE IF NOT EXISTS app_monitor DEFAULT CHARSET utf8mb4 COLLATE utf8mb4_general_ci;

USE app_monitor;

CREATE TABLE app_info (
    id INT UNSIGNED PRIMARY KEY,
    app_name VARCHAR(255) NOT NULL,
    executable_path VARCHAR(512) NOT NULL,
    icon_path VARCHAR(512),
    create_time DATETIME NOT NULL,
    update_time DATETIME NOT NULL
);

CREATE TABLE monitoring_rule (
    id BIGINT UNSIGNED PRIMARY KEY,
    app_id INT UNSIGNED NOT NULL,
    is_camouflaged BOOLEAN DEFAULT FALSE,
    camouflage_pid INT UNSIGNED DEFAULT 0,
    is_recording_prevention_enabled BOOLEAN DEFAULT FALSE,
    current_wnd BIGINT UNSIGNED DEFAULT 0,
    hwnd_val INT UNSIGNED DEFAULT 0,
    is_protected BOOLEAN DEFAULT FALSE
);

CREATE TABLE system_monitor (
    id BIGINT UNSIGNED PRIMARY KEY,
    cpu_usage FLOAT NOT NULL,
    memory_usage FLOAT NOT NULL,
    disk_usage FLOAT NOT NULL,
    network_upload FLOAT NOT NULL,
    network_download FLOAT NOT NULL,
    temperature FLOAT NOT NULL,
    sample_time DATETIME NOT NULL,
    ac_line_status_raw INT NOT NULL,
    battery_flag_raw INT NOT NULL
);

CREATE TABLE app_resource_monitor (
    id BIGINT UNSIGNED PRIMARY KEY,
    app_id BIGINT UNSIGNED NOT NULL,
    app_name VARCHAR(255) NOT NULL,
    icon_path VARCHAR(512),
    cpu_usage FLOAT NOT NULL,
    memory_usage_mb FLOAT NOT NULL,
    disk_io_read FLOAT NOT NULL,
    disk_io_write FLOAT NOT NULL,
    sample_time DATETIME NOT NULL,
    use_duration BIGINT UNSIGNED NOT NULL,
    power_use_level VARCHAR(50) NOT NULL  
);

CREATE TABLE malicious_thread_log (
    id BIGINT UNSIGNED PRIMARY KEY,
    app_id BIGINT UNSIGNED NOT NULL,
    thread_name VARCHAR(255) NOT NULL,
    thread_hash VARCHAR(255) NOT NULL,
    risk_level INT NOT NULL,
    detection_time DATETIME NOT NULL
);

CREATE TABLE file_modification_log (
    id BIGINT UNSIGNED PRIMARY KEY,
    app_id BIGINT UNSIGNED NOT NULL,
    file_path VARCHAR(512) NOT NULL,
    operation_type VARCHAR(255) NOT NULL,
    file_hash VARCHAR(255) NOT NULL,
    alert_time DATETIME NOT NULL
);

CREATE TABLE ai_analysis_result (
    id BIGINT UNSIGNED PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    analysis_type VARCHAR(255) NOT NULL,
    content_hash VARCHAR(255) NOT NULL,
    result TEXT NOT NULL,
    confidence FLOAT NOT NULL,
    analysis_time DATETIME NOT NULL
);

CREATE TABLE system_config (
    config_key VARCHAR(255) PRIMARY KEY,
    config_value TEXT NOT NULL,
    description TEXT,
    last_modified DATETIME NOT NULL
);

CREATE TABLE user_info (
    user_id BIGINT UNSIGNED PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    email VARCHAR(255) UNIQUE,
    phone VARCHAR(20) UNIQUE,
    last_login_ip VARCHAR(45),
    last_login_time DATETIME,
    is_locked BOOLEAN DEFAULT FALSE,
    create_time DATETIME NOT NULL
);

CREATE TABLE user_operation_log (
    log_id BIGINT UNSIGNED PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    operation_type VARCHAR(255) NOT NULL,
    target_id BIGINT UNSIGNED NOT NULL,
    operation_detail TEXT NOT NULL,
    client_info VARCHAR(255),
    operation_time DATETIME NOT NULL,
    result_status BOOLEAN DEFAULT FALSE
);

CREATE TABLE file_info (
    file_id BIGINT UNSIGNED PRIMARY KEY,
    path VARCHAR(512) NOT NULL,
    force_delete BOOLEAN NOT NULL DEFAULT FALSE,
    is_encrypted BOOLEAN NOT NULL DEFAULT FALSE,
    secret_key VARCHAR(255) NULL
);