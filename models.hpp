#pragma once
#include <iostream>

namespace sp {
    
	struct AppInfo {
		uint64_t id = 0;
		std::string app_name;
		std::string executable_path;
		std::string icon_path;
		std::string create_time;
		std::string update_time;

		// 默认构造函数
		AppInfo() = default;

		// 全参构造函数
		AppInfo(uint64_t _id, const std::string& _app_name, const std::string& _executable_path,
			const std::string& _icon_path, const std::string& _create_time, const std::string& _update_time)
			: id(_id), app_name(_app_name), executable_path(_executable_path),
			icon_path(_icon_path), create_time(_create_time), update_time(_update_time) {
		}
	};

    
	struct MonitoringRule {
		bool is_camouflaged = false;
		bool is_protected = false;
		bool is_recording_prevention_enabled = false;
		uint32_t current_wnd = 0;
		uint64_t id = 0;
		uint64_t app_id = 0;
		uint64_t camouflage_pid = 0;
		uint64_t hwnd_val = 0;

		// 默认构造函数
		MonitoringRule() = default;

		// 全参构造函数
		MonitoringRule(uint64_t _id, uint64_t _app_id, bool _is_recording_prevention_enabled,
			bool _is_protected, bool _is_camouflaged, uint64_t _camouflage_pid,
			uint32_t _current_wnd = 0, uint64_t _hwnd_val = 0)
			: id(_id), app_id(_app_id), is_recording_prevention_enabled(_is_recording_prevention_enabled),
			is_protected(_is_protected), is_camouflaged(_is_camouflaged),
			camouflage_pid(_camouflage_pid), current_wnd(_current_wnd), hwnd_val(_hwnd_val) {
		}
	};
    
	
	struct SystemMonitor {
		bool is_charging = false;         // 是否正在充电
		bool is_ac_power = false;         // 是否连接交流电源
		BYTE ac_line_status_raw = 0;      // 原始交流电源状态值
		BYTE battery_flag_raw = 0;        // 原始电池标志值
		uint32_t battery_percentage = 0;  // 电池电量百分比 (0-100)
		uint64_t battery_life_time = 0;   // 电池剩余使用时间 (秒)
		uint64_t id = 0;                  // 唯一标识符
		float cpu_usage = 0.0f;           // CPU 使用率
		float memory_usage = 0.0f;        // 内存使用率
		float disk_usage = 0.0f;          // 磁盘使用率
		float network_upload = 0.0f;      // 网络上行速度
		float network_download = 0.0f;    // 网络下行速度
		float temperature = 0.0f;         // 设备温度
		std::string sample_time;          // 采样时间

		// 默认构造函数
		SystemMonitor() = default;

		// 完整构造函数
		SystemMonitor(bool _is_charging, bool _is_ac_power, BYTE _ac_line_status_raw, BYTE _battery_flag_raw,
			uint32_t _battery_percentage, uint64_t _battery_life_time, uint64_t _id,
			float _cpu_usage, float _memory_usage, float _disk_usage,
			float _network_upload, float _network_download, float _temperature,
			const std::string& _sample_time)
			: is_charging(_is_charging), is_ac_power(_is_ac_power),
			ac_line_status_raw(_ac_line_status_raw), battery_flag_raw(_battery_flag_raw),
			battery_percentage(_battery_percentage), battery_life_time(_battery_life_time),
			id(_id), cpu_usage(_cpu_usage), memory_usage(_memory_usage), disk_usage(_disk_usage),
			network_upload(_network_upload), network_download(_network_download),
			temperature(_temperature), sample_time(_sample_time) {
		}

		// 部分成员构造函数（适用于仅初始化性能相关参数）
		SystemMonitor(float _cpu_usage, float _memory_usage, float _disk_usage,
			float _network_upload, float _network_download, float _temperature, const std::string& _sample_time)
			: cpu_usage(_cpu_usage), memory_usage(_memory_usage), disk_usage(_disk_usage),
			network_upload(_network_upload), network_download(_network_download),
			temperature(_temperature), sample_time(_sample_time) {
		}
	};
    
	
	struct AppResourceMonitor {
		uint64_t id = 0;
		uint64_t app_id = 0;      // 等于 pid
		uint64_t use_duration = 0;
		float cpu_usage = 0.0f;
		float memory_usage_mb = 0.0f;
		float disk_io_read = 0.0f;
		float disk_io_write = 0.0f;
		std::string sample_time;
		std::string app_name;
		std::string icon_path;
		std::string power_use_level; // 电源消耗评级

		// 无参构造函数
		AppResourceMonitor() = default;

		// 全参构造函数 (包含 use_duration 和 power_use_level)
		AppResourceMonitor(uint64_t _app_id, const std::string& _app_name,
			const std::string& _icon_path, float _cpu_usage, float _memory_usage_mb,
			float _disk_io_read, float _disk_io_write, const std::string& _sample_time,
			uint64_t _use_duration, const std::string& _power_use_level)
			: id(0), app_id(_app_id), use_duration(_use_duration), cpu_usage(_cpu_usage),
			memory_usage_mb(_memory_usage_mb), disk_io_read(_disk_io_read), disk_io_write(_disk_io_write),
			sample_time(_sample_time), app_name(_app_name), icon_path(_icon_path),
			power_use_level(_power_use_level) {
		}
	};


    
	struct MaliciousThreadLog {
		uint32_t risk_level = 0;
		uint64_t id = 0;
		uint64_t app_id = 0;
		std::string thread_name;
		std::string thread_hash;
		std::string detection_time;

		// 默认构造函数
		MaliciousThreadLog() = default;

		// 全参构造函数
		MaliciousThreadLog(uint64_t _id, uint64_t _app_id, const std::string& _thread_name,
			const std::string& _thread_hash, uint32_t _risk_level, const std::string& _detection_time)
			: id(_id), app_id(_app_id), risk_level(_risk_level),
			thread_name(_thread_name), thread_hash(_thread_hash), detection_time(_detection_time) {
		}
	};

    
	struct FileModificationLog {
		uint64_t id = 0;
		uint64_t app_id = 0;
		std::string file_path;
		std::string operation_type;
		std::string file_hash;
		std::string alert_time;

		// 默认构造函数
		FileModificationLog() = default;

		// 全参构造函数
		FileModificationLog(uint64_t _id, uint64_t _app_id, const std::string& _file_path,
			const std::string& _operation_type, const std::string& _file_hash, const std::string& _alert_time)
			: id(_id), app_id(_app_id), file_path(_file_path), operation_type(_operation_type),
			file_hash(_file_hash), alert_time(_alert_time) {
		}
	};

	struct AIAnalysisResult {
		uint64_t id = 0;
		uint64_t user_id = 0;
		uint16_t score = 0;
		float confidence = 0.0f;
		std::string analysis_type;
		std::string content_hash;
		std::string result;
		std::string analysis_time;

		// 默认构造函数
		AIAnalysisResult() = default;

		// 全参构造函数
		AIAnalysisResult(uint64_t _id, uint64_t _user_id, const std::string& _analysis_type,
			const std::string& _content_hash, const std::string& _result, float _confidence,
			const std::string& _analysis_time, uint16_t _score)
			: id(_id), user_id(_user_id), analysis_type(_analysis_type),
			content_hash(_content_hash), result(_result), confidence(_confidence),
			analysis_time(_analysis_time), score(_score) {
		}
	};

	struct SystemConfig {
		std::string config_key;
		std::string config_value;
		std::string description;
		std::string last_modified;

		// 默认构造函数
		SystemConfig() = default;

		// 全参构造函数
		SystemConfig(const std::string& _config_key, const std::string& _config_value,
			const std::string& _description, const std::string& _last_modified)
			: config_key(_config_key), config_value(_config_value),
			description(_description), last_modified(_last_modified) {
		}
	};

	struct UserInfo {
		uint64_t user_id = 0;
		bool is_locked = false;
		std::string username;
		std::string password;
		std::string role;
		std::string email;
		std::string phone;
		std::string last_login_ip;
		std::string last_login_time;
		std::string create_time;

		// 默认构造函数
		UserInfo() = default;

		// 全参构造函数
		UserInfo(uint64_t _user_id, const std::string& _username, const std::string& _password,
			const std::string& _role, const std::string& _email, const std::string& _phone,
			const std::string& _last_login_ip, const std::string& _last_login_time,
			bool _is_locked, const std::string& _create_time)
			: user_id(_user_id), is_locked(_is_locked), username(_username),
			password(_password), role(_role), email(_email), phone(_phone),
			last_login_ip(_last_login_ip), last_login_time(_last_login_time),
			create_time(_create_time) {
		}
	};

	struct UserOperationLog {
		uint64_t log_id = 0;
		uint64_t user_id = 0;
		uint64_t target_id = 0;
		bool result_status = false;
		std::string operation_type;
		std::string operation_detail;
		std::string client_info;
		std::string operation_time;

		// 默认构造函数
		UserOperationLog() = default;

		// 全参构造函数
		UserOperationLog(uint64_t _log_id, uint64_t _user_id, const std::string& _operation_type,
			uint64_t _target_id, const std::string& _operation_detail,
			const std::string& _client_info, const std::string& _operation_time,
			bool _result_status)
			: log_id(_log_id), user_id(_user_id), target_id(_target_id),
			result_status(_result_status), operation_type(_operation_type),
			operation_detail(_operation_detail), client_info(_client_info),
			operation_time(_operation_time) {
		}
	};

	struct FileInfo {
		uint64_t file_id = 0;
		bool force_delete = false;
		bool is_encrypted = false;
		std::string path;
		std::string secret_key;

		// 默认构造函数
		FileInfo() = default;

		// 全参构造函数
		FileInfo(uint64_t _id, const std::string& _path, bool _forceDel, bool _encrypted, const std::string& _key)
			: file_id(_id), force_delete(_forceDel), is_encrypted(_encrypted), path(_path), secret_key(_key) {
		}
	};


}