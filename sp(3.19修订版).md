## 数据库

### AppInfo
| 字段名          | 数据类型        | 约束        | 说明           |
| --------------- | --------------- | ----------- | -------------- |
| id              | BIGINT UNSIGNED | PRIMARY KEY | 应用 ID        |
| app_name        | VARCHAR(255)    | NOT NULL    | 应用名称       |
| executable_path | VARCHAR(512)    | NOT NULL    | 可执行文件路径 |
| icon_path       | VARCHAR(512)    | NULLABLE    | 图标路径       |
| create_time     | DATETIME        | NOT NULL    | 创建时间       |
| update_time     | DATETIME        | NOT NULL    | 更新时间       |

### MonitoringRule
| 字段名                          | 数据类型        | 约束        | 说明              |
| ------------------------------- | --------------- | ----------- | ----------------- |
| id                              | BIGINT UNSIGNED | PRIMARY KEY | 规则 ID           |
| app_id                          | BIGINT UNSIGNED | NOT NULL    | 关联的 AppInfo ID |
| is_camouflaged                  | BOOLEAN         | NOT NULL    | 是否启用伪装      |
| camouflage_pid                  | INT UNSIGNED    | NOT NULL    | 伪装进程 ID       |
| is_recording_prevention_enabled | BOOLEAN         | NOT NULL    | 是否启用反录屏    |
| current_wnd                     | BIGINT UNSIGNED | NOT NULL    | 当前窗口句柄      |
| hwnd_val                        | INT UNSIGNED    | NOT NULL    | 窗口属性          |
| is_protected                    | BOOLEAN         | NOT NULL    | 是否受保护        |

### SystemMonitor
| 字段名             | 数据类型        | 约束        | 说明               |
| ------------------ | --------------- | ----------- | ------------------ |
| id                 | BIGINT UNSIGNED | PRIMARY KEY | 记录 ID            |
| cpu_usage          | FLOAT           | NOT NULL    | CPU 使用率         |
| memory_usage       | FLOAT           | NOT NULL    | 内存使用率         |
| disk_usage         | FLOAT           | NOT NULL    | 磁盘使用率         |
| network_upload     | FLOAT           | NOT NULL    | 网络上传流量       |
| network_download   | FLOAT           | NOT NULL    | 网络下载流量       |
| temperature        | FLOAT           | NOT NULL    | 温度               |
| sample_time        | DATETIME        | NOT NULL    | 采样时间           |
| ac_line_status_raw | INT             | NOT NULL    | 原始交流电源状态值 |
| battery_flag_raw   | INT             | NOT NULL    | 原始电池标志值     |

### AppResourceMonitor
| 字段名          | 数据类型        | 约束        | 说明               |
| --------------- | --------------- | ----------- | ------------------ |
| id              | BIGINT UNSIGNED | PRIMARY KEY | 记录 ID            |
| app_id          | BIGINT UNSIGNED | NOT NULL    | 关联的 AppInfo ID  |
| app_name        | VARCHAR(255)    | NOT NULL    | 应用名称           |
| icon_path       | VARCHAR(512)    | NULLABLE    | 图标路径           |
| cpu_usage       | FLOAT           | NOT NULL    | CPU 使用率         |
| memory_usage_mb | FLOAT           | NOT NULL    | 内存使用量（MB）   |
| disk_io_read    | FLOAT           | NOT NULL    | 磁盘读取量         |
| disk_io_write   | FLOAT           | NOT NULL    | 磁盘写入量         |
| sample_time     | DATETIME        | NOT NULL    | 采样时间           |
| use_duration    | BIGINT          | NOT NULL    | 使用时长（时间戳） |
| power_use_level | VARCHAR(50)     | NOT NULL    | 电源消耗评级       |

### MaliciousThreadLog
| 字段名         | 数据类型        | 约束        | 说明              |
| -------------- | --------------- | ----------- | ----------------- |
| id             | BIGINT UNSIGNED | PRIMARY KEY | 记录 ID           |
| app_id         | BIGINT UNSIGNED | NOT NULL    | 关联的 AppInfo ID |
| thread_name    | VARCHAR(255)    | NOT NULL    | 线程名称          |
| thread_hash    | VARCHAR(255)    | NOT NULL    | 线程哈希          |
| risk_level     | INT             | NOT NULL    | 风险级别          |
| detection_time | DATETIME        | NOT NULL    | 发现时间          |

### FileModificationLog
| 字段名         | 数据类型        | 约束        | 说明              |
| -------------- | --------------- | ----------- | ----------------- |
| id             | BIGINT UNSIGNED | PRIMARY KEY | 记录 ID           |
| app_id         | BIGINT UNSIGNED | NOT NULL    | 关联的 AppInfo ID |
| file_path      | VARCHAR(512)    | NOT NULL    | 文件路径          |
| operation_type | VARCHAR(255)    | NOT NULL    | 操作类型          |
| file_hash      | VARCHAR(255)    | NOT NULL    | 文件哈希          |
| alert_time     | DATETIME        | NOT NULL    | 警报时间          |

### AIAnalysisResult
| 字段名        | 数据类型        | 约束        | 说明          |
| ------------- | --------------- | ----------- | ------------- |
| id            | BIGINT UNSIGNED | PRIMARY KEY | 记录 ID       |
| user_id       | BIGINT UNSIGNED | NOT NULL    | 关联的用户 ID |
| analysis_type | VARCHAR(255)    | NOT NULL    | 分析类型      |
| content_hash  | VARCHAR(255)    | NOT NULL    | 内容哈希      |
| result        | VARCHAR(255)    | NOT NULL    | 分析结果      |
| confidence    | FLOAT           | NOT NULL    | 置信度        |
| analysis_time | DATETIME        | NOT NULL    | 分析时间      |
| score         | INT UNSIGNED    | NOT NULL    | 得分          |

### SystemConfig
| 字段名        | 数据类型     | 约束        | 说明         |
| ------------- | ------------ | ----------- | ------------ |
| config_key    | VARCHAR(255) | PRIMARY KEY | 配置键       |
| config_value  | TEXT         | NOT NULL    | 配置值       |
| description   | TEXT         | NULLABLE    | 配置描述     |
| last_modified | DATETIME     | NOT NULL    | 最后修改时间 |

### UserInfo
| 字段名          | 数据类型        | 约束            | 说明         |
| --------------- | --------------- | --------------- | ------------ |
| user_id         | BIGINT UNSIGNED | PRIMARY KEY     | 用户 ID      |
| username        | VARCHAR(255)    | UNIQUE NOT NULL | 用户名       |
| password        | VARCHAR(255)    | NOT NULL        | 密码哈希     |
| role            | VARCHAR(255)    | NOT NULL        | 用户角色     |
| email           | VARCHAR(255)    | UNIQUE NOT NULL | 邮箱         |
| phone           | VARCHAR(20)     | UNIQUE NOT NULL | 手机号       |
| last_login_ip   | VARCHAR(45)     | NULLABLE        | 最后登录 IP  |
| last_login_time | DATETIME        | NULLABLE        | 最后登录时间 |
| is_locked       | BOOLEAN         | NOT NULL        | 是否锁定     |
| create_time     | DATETIME        | NOT NULL        | 创建时间     |

### UserOperationLog
| 字段名           | 数据类型        | 约束        | 说明          |
| ---------------- | --------------- | ----------- | ------------- |
| log_id           | BIGINT UNSIGNED | PRIMARY KEY | 日志 ID       |
| user_id          | BIGINT UNSIGNED | NOT NULL    | 关联的用户 ID |
| operation_type   | VARCHAR(255)    | NOT NULL    | 操作类型      |
| target_id        | BIGINT UNSIGNED | NULLABLE    | 目标 ID       |
| operation_detail | TEXT            | NOT NULL    | 操作详情      |
| client_info      | VARCHAR(255)    | NOT NULL    | 客户端信息    |
| operation_time   | DATETIME        | NOT NULL    | 操作时间      |
| result_status    | BOOLEAN         | NOT NULL    | 操作结果      |

### FileInfo

| 字段名       | 数据类型        | 约束                   | 说明                 |
| ------------ | --------------- | ---------------------- | -------------------- |
| file_id      | BIGINT UNSIGNED | PRIMARY KEY            | 文件唯一 ID          |
| path         | VARCHAR(512)    | NOT NULL               | 文件路径             |
| force_delete | BOOLEAN         | NOT NULL DEFAULT FALSE | 是否强制删除         |
| is_encrypted | BOOLEAN         | NOT NULL DEFAULT FALSE | 是否加密             |
| secret_key   | VARCHAR(255)    | NULL                   | 加密密钥（如果加密） |

## 网络api

### **应用信息（App Info）**

##### `GET /api/app_info/{id}` 获取指定 `id` 的应用信息。

成功：

```json
{
  "result": {
    "status": "success",
    "data": {
      "id": 1,
      "app_name": "ExampleApp",
      "executable_path": "C:\\Program Files\\ExampleApp\\example.exe",
      "icon_path": "C:\\Program Files\\ExampleApp\\icon.png",
      "create_time": "2025-03-15 12:00:00",
      "update_time": "2025-03-15 12:30:00"
    },
    "message": "Application info retrieved successfully."
  }
}

```

失败

```json
{
  "result": {
    "status": "error",
    "data": null,
    "message": "AppInfo not found."
  }
}
```

##### `GET /api/app_infos` 获取所有应用信息。

```json
{
  "result": {
    "status": "success",
    "data": [
      {
        "id": 1,
        "app_name": "ExampleApp",
        "executable_path": "C:\\Program Files\\ExampleApp\\example.exe",
        "icon_path": "C:\\Program Files\\ExampleApp\\icon.png",
        "create_time": "2025-03-15 12:00:00",
        "update_time": "2025-03-15 12:30:00"
      },
      {
        "id": 2,
        "app_name": "AnotherApp",
        "executable_path": "D:\\Software\\AnotherApp\\run.exe",
        "icon_path": "D:\\Software\\AnotherApp\\icon.ico",
        "create_time": "2025-03-14 14:20:00",
        "update_time": "2025-03-15 08:10:00"
      }
    ],
    "message": "All application info retrieved successfully."
  }
}
```

##### `GET /api/image/{path}`

### **监控规则（Monitoring Rule）**

##### `GET /api/monitoring_rule/{id}` 获取指定 `id` 的监控规则。

```json
{
  "result": {
    "status": "success",
    "data": {
      "id": 1,
      "app_id": 101,
      "is_camouflaged": true,
      "camouflage_pid": 1234,
      "is_recording_prevention_enabled": true,
      "current_wnd": 56789,
      "hwnd_val": 4321,
      "is_protected": true
    },
    "message": "Monitoring rule retrieved successfully."
  }
}
```

##### `GET /api/monitoring_rules` 获取所有监控规则。

```json
{
  "result": {
    "status": "success",
    "data": [
      {
        "id": 1,
        "app_id": 101,
        "is_camouflaged": true,
        "camouflage_pid": 1234,
        "is_recording_prevention_enabled": true,
        "current_wnd": 56789,
        "hwnd_val": 4321,
        "is_protected": true
      },
      {
        "id": 2,
        "app_id": 102,
        "is_camouflaged": false,
        "camouflage_pid": 0,
        "is_recording_prevention_enabled": false,
        "current_wnd": 67890,
        "hwnd_val": 5678,
        "is_protected": false
      }
    ],
    "message": "All monitoring rules retrieved successfully."
  }
}
```

##### `POST /api/monitoring_rules` 修改

```json

{
  "app_id": 101,
  "is_camouflaged": true,
  "camouflage_pid": 1234,
  "is_recording_prevention_enabled": true,
  "is_protected": true
}

```

成功

```json
{
  "result": {
    "status": "success",
    "data": {
      "id": 3
    },
    "message": "Monitoring rule created successfully."
  }
}

```



### **系统监控（System Monitor）**

##### `GET /api/system_monitor/long` 获取系统监控数据。(间隔1分钟）

```json
{
  "result": {
    "status": "success",
    "data": {
      "id": 1234567890123456,
      "cpu_usage": 23.5,
      "memory_usage": 58.7,
      "disk_usage": 75.2,
      "network_upload": 1024.5,
      "network_download": 512.3,
      "temperature": 45.6,
      "sample_time": "2025-03-15T10:30:00Z",
      "ac_line_status_raw":"电源断开",
      "battery_flag_raw":"无电池"
    },
    "message": "System monitor data retrieved successfully."
  }
}
```

##### `GET /api/system_monitor/short` 获取系统监控数据。（间隔5秒，最多1000条）

```json
{
  "result": {
    "status": "success",
    "data": {
      "id": 1234567890123456,
      "cpu_usage": 23.5,
      "memory_usage": 58.7,
      "disk_usage": 75.2,
      "network_upload": 1024.5,
      "network_download": 512.3,
      "temperature": 45.6,
      "sample_time": "2025-03-15T10:30:00Z",
      "ac_line_status_raw":"电源断开",
      "battery_flag_raw":"电池充电中"
    },
    "message": "System monitor data retrieved successfully."
  }
}
```



### **应用资源监控（App Resource Monitor）**

##### `GET /api/app_resource_monitors` 获取所有应用资源监控数据。

```json
{
  "result": {
    "status": "success",
    "data": [
      {
        "id": 1234567890123456,
        "app_id": 101,
        "app_name": "App1",
        "icon_path": "/path/to/icon1.png",
        "cpu_usage": 23.5,
        "memory_usage_mb": 256.4,
        "disk_io_read": 123.5,
        "disk_io_write": 78.2,
        "sample_time": "2025-03-15T10:30:00Z",
        "use_duration":"1111",
        "power_use_level":"较高"
      },
      {
        "id": 2345678901234567,
        "app_id": 102,
        "app_name": "App2",
        "icon_path": "/path/to/icon2.png",
        "cpu_usage": 56.7,
        "memory_usage_mb": 512.3,
        "disk_io_read": 233.6,
        "disk_io_write": 112.5,
        "sample_time": "2025-03-15T10:35:00Z",
         "use_duration":"222",
        "power_use_level":"较低"
      }
    ],
    "message": "All application resource monitor data retrieved successfully."
  }
}
```

##### `GET /api/app_resource_monitor/{id}` 获取指定 `id` 的应用资源监控数据。

```json
{
  "result": {
    "status": "success",
    "data": {
      "id": 1234567890123456,
      "app_id": 101,
      "app_name": "App1",
      "icon_path": "/path/to/icon1.png",
      "cpu_usage": 23.5,
      "memory_usage_mb": 256.4,
      "disk_io_read": 123.5,
      "disk_io_write": 78.2,
      "sample_time": "2025-03-15T10:30:00Z",
      "use_duration":"",
      "power_use_level":""
    },
    "message": "Application resource monitor data retrieved successfully."
  }
}
```

##### `GET /api/app_resource_monitors/app/{id}` 获取指定 `app_id` 的应用资源监控数据。

```json
{
  "result": {
    "status": "success",
    "data": [
      {
        "id": 1234567890123456,
        "app_id": 101,
        "app_name": "App1",
        "icon_path": "/path/to/icon1.png",
        "cpu_usage": 23.5,
        "memory_usage_mb": 256.4,
        "disk_io_read": 123.5,
        "disk_io_write": 78.2,
        "sample_time": "2025-03-15T10:30:00Z",
        "use_duration":"",
        "power_use_level":""
      },
      {
        "id": 2345678901234567,
        "app_id": 101,
        "app_name": "App1",
        "icon_path": "/path/to/icon3.png",
        "cpu_usage": 45.6,
        "memory_usage_mb": 420.7,
        "disk_io_read": 145.6,
        "disk_io_write": 95.4,
        "sample_time": "2025-03-15T10:40:00Z",
        "use_duration":"",
        "power_use_level":""
      }
    ],
    "message": "Application resource monitor data for app_id 101 retrieved successfully."
  }
}
```

### **用户操作日志（User Operation Log）**

##### `POST /api/user_operation_log` 创建用户操作日志。

```json
{
  "user_id": 12345,
  "operation_type": "login",
  "target_id": 0,
  "operation_detail": "User logged in successfully",
  "client_info": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  "operation_time": "2025-03-15T10:30:00Z",
  "result_status": true
}

```

成功

```json
{
  "result": {
    "status": "success",
    "data": {
      "log_id": 9876543210,
      "user_id": 12345,
      "operation_type": "login",
      "target_id": 0,
      "operation_detail": "User logged in successfully",
      "client_info": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "operation_time": "2025-03-15T10:30:00Z",
      "result_status": true
    },
    "message": "User operation log created successfully."
  }
}

```



##### `GET /api/user_operation_logs` 获取所有用户操作日志。

```json
{
  "result": {
    "status": "success",
    "data": [
      {
        "log_id": 9876543210,
        "user_id": 12345,
        "operation_type": "login",
        "target_id": 0,
        "operation_detail": "User logged in successfully",
        "client_info": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "operation_time": "2025-03-15T10:30:00Z",
        "result_status": true
      },
      {
        "log_id": 9876543211,
        "user_id": 12346,
        "operation_type": "logout",
        "target_id": 0,
        "operation_detail": "User logged out",
        "client_info": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "operation_time": "2025-03-15T11:00:00Z",
        "result_status": true
      }
    ],
    "message": "All user operation logs retrieved successfully."
  }
}

```



##### `GET /api/user_operation_logs/{id}` 获取指定 `id` 的用户操作日志。

```json
{
  "result": {
    "status": "success",
    "data": {
      "log_id": 9876543210,
      "user_id": 12345,
      "operation_type": "login",
      "target_id": 0,
      "operation_detail": "User logged in successfully",
      "client_info": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "operation_time": "2025-03-15T10:30:00Z",
      "result_status": true
    },
    "message": "User operation log retrieved successfully."
  }
}

```



### **系统配置（System Config）**

##### `GET /api/system_config` 获取系统配置。

##### `POST /api/system_config` 创建系统配置。

##### `POST /api/system_config/delete` 删除系统配置。



### **恶意线程日志（Malicious Thread Logs）**

##### `GET /api/malicious_thread_logs/{id}` 获取指定 `id` 的恶意线程日志。

```json
{
  "result": {
    "status": "success",
    "data": {
      "id": 1001,
      "app_id": 50001,
      "thread_name": "SuspiciousThreadX",
      "thread_hash": "abc123def456",
      "risk_level": 3,
      "detection_time": "2025-03-15T12:45:00Z"
    },
    "message": "Malicious thread log retrieved successfully."
  }
}
```

##### `GET /api/malicious_thread_logs` 获取所有恶意线程日志。

```json
{
  "result": {
    "status": "success",
    "data": [
      {
        "id": 1001,
        "app_id": 50001,
        "thread_name": "SuspiciousThreadX",
        "thread_hash": "abc123def456",
        "risk_level": 3,
        "detection_time": "2025-03-15T12:45:00Z"
      },
      {
        "id": 1002,
        "app_id": 50002,
        "thread_name": "MalwareProcessY",
        "thread_hash": "xyz789ghi012",
        "risk_level": 5,
        "detection_time": "2025-03-15T14:10:00Z"
      }
    ],
    "message": "All malicious thread logs retrieved successfully."
  }
}
```

### **文件修改日志（File Modification Logs）**

##### `GET /api/file_modification_logs/{id}` 获取指定 `id` 的文件修改日志。

```json
{
  "result": {
    "status": "success",
    "data": {
      "id": 1001,
      "app_id": 5001,
      "file_path": "/var/www/html/index.php",
      "operation_type": "modified",
      "file_hash": "a1b2c3d4e5f67890",
      "alert_time": "2025-03-15T14:20:00Z"
    },
    "message": "File modification log retrieved successfully."
  }
}

```



##### `GET /api/file_modification_logs` 获取所有文件修改日志。

```json
{
  "result": {
    "status": "success",
    "data": [
      {
        "id": 1001,
        "app_id": 5001,
        "file_path": "/var/www/html/index.php",
        "operation_type": "modified",
        "file_hash": "a1b2c3d4e5f67890",
        "alert_time": "2025-03-15T14:20:00Z"
      },
      {
        "id": 1002,
        "app_id": 5002,
        "file_path": "/etc/nginx/nginx.conf",
        "operation_type": "deleted",
        "file_hash": "f9e8d7c6b5a43210",
        "alert_time": "2025-03-15T15:10:00Z"
      }
    ],
    "message": "All file modification logs retrieved successfully."
  }
}

```



### **AI分析结果（AI Analysis Results）**

##### `GET /api/ai_analysis_results/{id}` 获取指定 `id` 的AI分析结果。

```json

{
  "result": {
    "status": "success",
    "data": {
      "id": 1,
      "user_id": 101,
      "analysis_type": "1",
      "result":"hello",
      "content_hash": "def456",
      "confidence":"1",
      "analysis_time": "2025-03-13T12:00:00",
       "score":77
    },
    "message": "File modification log retrieved successfully."
  }
}

```



##### `GET /api/ai_analysis_results/user/{user_id}` 获取特定用户的AI分析结果。

```json
{
  "result": {
    "status": "success",
    "data": [
      {
        "id": 3001,
        "user_id": 2001,
        "analysis_type": "sentiment_analysis",
        "content_hash": "a1b2c3d4e5f67890",
        "result": "hello",
        "confidence": 0.92,
        "analysis_time": "2025-03-15T14:30:00Z",
          "score":77
      },
      {
        "id": 3002,
        "user_id": 2001,
        "analysis_type": "face_recognition",
        "content_hash": "z9y8x7w6v5u43210",
        "result": "hello2",
        "confidence": 0.87,
        "analysis_time": "2025-03-15T15:05:00Z",
          "score":77
      }
    ],
    "message": "AI analysis results retrieved successfully."
  }
}


```



##### `POST /api/ai_analysis` 创建AI分析任务。

```json
{
    "user_id":"123",
    "prompt":"你是一只猫娘。叫两声"
}
```

成功

```json

{
  "result": {
    "status": "success",
    "data": {
      "id": 1,
      "user_id": 101,
      "analysis_type": "1",
      "result":"hello",
      "content_hash": "def456",
      "confidence":"1",
      "analysis_time": "2025-03-13T12:00:00",
        "score":77
    },
    "message": "File modification log retrieved successfully."
  }
}

```



### **用户信息（User Info）**

##### `GET /api/user/{id}` 获取指定 `id` 的用户信息。

```json
{
  "result": {
    "status": "success",
    "data": {
      "user_id": 1001,
      "username": "john_doe",
      "role": "admin",
      "email": "john.doe@example.com",
      "phone": "+1234567890",
      "last_login_ip": "192.168.1.10",
      "last_login_time": "2025-03-15T14:30:00Z",
      "is_locked": false,
      "create_time": "2023-06-10T08:15:00Z"
    },
    "message": "User information retrieved successfully."
  }
}

```



##### `POST /api/user/{id}/update`

```json
{
  "email": "new_email@example.com",
  "phone": "+9876543210",
  "role": "user",
  "is_locked": true
}
```

成功

```json
{
  "result": {
    "status": "success",
    "message": "User information updated successfully."
  }
}
```



##### `POST /api/user/{id}/delete`

```json
{
  "result": {
    "status": "success",
    "message": "User deleted successfully."
  }
}
```



##### `POST /api/login` 用户登录。

```json
header: "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

{
  "result": {
    "status": "success",
    "data": {
      "user_id": 101,
      "username": "john_doe",
      "role": "admin",
      "email": "john.doe@example.com",
      "phone": "123-456-7890",
      "last_login_ip": "192.168.1.1",
      "last_login_time": "2025-03-13T12:00:00",
      "is_locked": false,
      "create_time": "2025-03-13T11:00:00"
    },
    "message": "User information retrieved successfully."
  }
}

```



##### `POST /api/verification_code`发送验证码

```json
{
    "email":"123@qq.com"
}
```

成功

```json
{
  "result": {
    "status": "success",
    "message": "Verification code sent successfully."
  }
}
```

### 文件信息（FileInfo）

##### `GET /api/files`查询所有文件

```json
{
  "result": {
    "status": "success",
    "data": [
      {
        "file_id": 1,
        "path": "/data/file1.txt",
        "force_delete": false,
        "is_encrypted": false,
        "secret_key": null,
        "create_time": "2025-03-15T14:30:00Z"
      },
      {
        "file_id": 2,
        "path": "/data/file2.txt",
        "force_delete": true,
        "is_encrypted": true,
        "secret_key": "*****",
        "create_time": "2025-03-16T10:00:00Z"
      }
    ],
    "message": "Files retrieved successfully."
  }
}

```

##### `GET /api/files/1`根据 ID 查询文件信息

```json
{
  "result": {
    "status": "success",
    "data": {
      "file_id": 1,
      "path": "/data/file1.txt",
      "force_delete": false,
      "is_encrypted": false,
      "secret_key": null,
      "create_time": "2025-03-15T14:30:00Z"
    },
    "message": "File information retrieved successfully."
  }
}
```

##### `POST /api/files/encrypt 加密文件

```json
{
    "file_id":123,
    "secret_key": "my_secret"
}
```

成功

```json
{
  "result": {
    "status": "success",
    "message": "File encrypted successfully."
  }
}
```

#####  `POST /api/files/decrypt` 解密文件

```json
{
    "file_id":123,
    "secret_key": "my_secret"
}
```

成功

```json
{
  "result": {
    "status": "success",
    "message": "File decrypted successfully."
  }
}
```

