#pragma once
#include <iostream>

/*
	三月27日：越
	修改内容：
	删除 MonitoringRule 中的 强制删除 字段；
	MonitoringRule 中的 currentWnd hwndVal 改为蛇形命名法；
	所有 long long 改为 uint64_t ；
	FileModificationLog 新增app_id；
	所有char* 改为 string；
*/




namespace sp {
    
	struct AppInfo {
		uint64_t id;
		std::string app_name;
		std::string executable_path;
		std::string icon_path;
		std::string  create_time; // 改成 std::string
		std::string  update_time; // 改成 std::string

		// 默认构造函数，初始化所有成员
		AppInfo() : id(0), app_name(""), executable_path(""), icon_path(""), create_time(""), update_time("") {} // create_time 和 update_time 初始化为空字符串

		AppInfo(uint64_t _id, const std::string& _app_name, const std::string& _executable_path,
			const std::string& _icon_path, const std::string& _create_time, const std::string& _update_time) // 参数类型改成 std::string
			: id(_id), app_name(_app_name), executable_path(_executable_path),
			icon_path(_icon_path), create_time(_create_time), update_time(_update_time) {}

		// 重载 == 运算符，用于比较两个 AppInfo 是否相同（基于 ID）
		bool operator==(const AppInfo& other) const {
			return id == other.id;
		}
	};

    
	struct MonitoringRule {
		bool is_camouflaged;                 // 应用伪装开关
		bool is_protected;                   // 保护开关
		bool is_recording_prevention_enabled; // 反录屏/反截图功能开关
		uint32_t current_wnd; //当前窗口句柄
		uint64_t id;
		uint64_t app_id;                 // 应用ID
		uint64_t camouflage_pid;          // 伪装显示的进程ID
		uint64_t hwnd_val; // 窗口属性




		// 无参构造函数
		MonitoringRule()
			: id(0),
			app_id(0),
			is_recording_prevention_enabled(false),
			is_protected(false),
			is_camouflaged(false),
			camouflage_pid(0),
			current_wnd(0),
			hwnd_val(0)
		{
		}

		// 全参构造函数
		MonitoringRule(uint64_t _id,uint64_t _app_id, bool _is_recording_prevention_enabled, bool _prevent_termination,
			bool _is_protected, bool _is_camouflaged, uint64_t _camouflage_pid,
			uint32_t _current_wnd = 0, uint64_t _hwnd_val = 0) 
			: id(_id),
			app_id(_app_id),
			is_recording_prevention_enabled(_is_recording_prevention_enabled),
			is_protected(_is_protected),
			is_camouflaged(_is_camouflaged),
			camouflage_pid(_camouflage_pid),
			current_wnd(_current_wnd),
			hwnd_val(_hwnd_val)
		{
		}

	};

    
	
	struct SystemMonitor {
		bool is_charging;       // 是否正在充电
		bool is_ac_power;       // 是否连接交流电源
		BYTE ac_line_status_raw; // 原始交流电源状态值
		BYTE battery_flag_raw; // 原始电池标志值
		uint32_t battery_percentage; // 电池电量百分比 (0-100)
		uint64_t battery_life_time; // 电池剩余使用时间 (秒)
		uint64_t id;
		float cpu_usage;
		float memory_usage;
		float disk_usage;
		float network_upload;
		float network_download;
		float temperature;
		std::string sample_time; 
		SystemMonitor() {} 

		// Full parameter constructor declaration - sample_time parameter type changed
		SystemMonitor(float _cpu_usage, float _memory_usage, float _disk_usage,
			float _network_upload, float _network_download, float _temperature, std::string _sample_time)
			: cpu_usage(_cpu_usage), memory_usage(_memory_usage), disk_usage(_disk_usage),
			network_upload(_network_upload), network_download(_network_download), temperature(_temperature), sample_time(_sample_time)
		{}
	};
    
	
	struct AppResourceMonitor {
		uint64_t id;
		uint64_t app_id;	// 等于pid
		uint64_t use_duration;
		float cpu_usage;
		float memory_usage_mb;
		float disk_io_read;
		float disk_io_write;
		std::string sample_time;
		std::string app_name;
		std::string icon_path; 
		std::string power_use_level;       //电源消耗评级

		// 无参构造函数
		AppResourceMonitor()
			: app_id(0), app_name(""), icon_path(""), cpu_usage(0.0), memory_usage_mb(0.0), disk_io_read(0.0), disk_io_write(0.0), sample_time(""),
			use_duration(0), power_use_level("") { // 初始化新增的 use_duration 和 power_use_level
		}

		// 全参构造函数 (包含 use_duration 和 power_use_level)
		AppResourceMonitor(uint64_t _app_id, const std::string& _app_name,
			const std::string& _icon_path, float _cpu_usage, float _memory_usage_mb, float _disk_io_read,
			float _disk_io_write, const std::string& _sample_time, uint64_t _use_duration, const std::string& _power_use_level)
			: app_id(_app_id), app_name(_app_name), icon_path(_icon_path), cpu_usage(_cpu_usage),
			memory_usage_mb(_memory_usage_mb), disk_io_read(_disk_io_read), disk_io_write(_disk_io_write),
			sample_time(_sample_time), use_duration(_use_duration), power_use_level(_power_use_level) { // 初始化新增的 use_duration 和 power_use_level
		}
	};

    
	struct MaliciousThreadLog {
		uint32_t risk_level;
		uint64_t id;
		uint64_t app_id;
		std::string thread_name; // 线程名 (现在是TID)
		std::string thread_hash; // 模块名的哈希值
		std::string detection_time;

		// 无参构造函数
		MaliciousThreadLog()
			: id(0), app_id(0), risk_level(0) {
		}

		// 全参构造函数
		MaliciousThreadLog(uint64_t _id, uint64_t _app_id, const std::string& _thread_name,
			const std::string& _thread_hash, uint32_t _risk_level, const std::string& _detection_time)
			: id(_id), app_id(_app_id), thread_name(_thread_name), thread_hash(_thread_hash),
			risk_level(_risk_level), detection_time(_detection_time) {
		}
	};

    
	struct FileModificationLog {
		uint64_t id;
		uint64_t app_id;
		std::string file_path;
		std::string operation_type;
		std::string file_hash;
		std::string alert_time;
	   

		FileModificationLog() : id(0),app_id(0) {}
		FileModificationLog(uint64_t _id, uint64_t _app_id, const std::string& _file_path,
			const std::string& _operation_type, const std::string& _file_hash, const std::string& _alert_time)
			: id(_id), app_id(_app_id), file_path(_file_path), operation_type(_operation_type),
			file_hash(_file_hash), alert_time(_alert_time) {}
	};

    struct AIAnalysisResult {
        uint64_t id;
        uint64_t user_id;
		uint16_t score;
		float confidence;
        std::string analysis_type;
        std::string content_hash;
        std::string result;
        std::string analysis_time;
        // 无参构造函数
        AIAnalysisResult()
            : id(0), user_id(0), confidence(0.0), score(0){
        }

        // 全参构造函数
        AIAnalysisResult(uint64_t _id, uint64_t _user_id, const std::string& _analysis_type,
            const std::string& _content_hash, const std::string& _result, float _confidence,
            const std::string& _analysis_time, uint16_t _score)
            : id(_id), user_id(_user_id), analysis_type(_analysis_type), content_hash(_content_hash),
            result(_result), confidence(_confidence), analysis_time(_analysis_time), score(_score){
        }
    };

    struct SystemConfig {
        std::string config_key;
        std::string config_value;
        std::string description;
        std::string last_modified;

        // 无参构造函数
        SystemConfig() {}

        // 全参构造函数
        SystemConfig(const std::string& _config_key, const std::string& _config_value, const std::string& _description,
            const std::string& _last_modified)
            : config_key(_config_key), config_value(_config_value), description(_description), last_modified(_last_modified) {
        }
    };

    struct UserInfo {
		bool is_locked;
        uint64_t user_id;
        std::string username;
        std::string password;
        std::string role;
        std::string email;
        std::string phone;
        std::string last_login_ip;
        std::string last_login_time;
        std::string create_time;

        // 无参构造函数
        UserInfo()
            : user_id(0), is_locked(0) {
        }

        // 全参构造函数
        UserInfo(uint64_t _user_id, const std::string& _username, const std::string& _password, const std::string& _role,
            const std::string& _email, const std::string& _phone, const std::string& _last_login_ip,
            const std::string& _last_login_time, bool _is_locked, const std::string& _create_time)
            : user_id(_user_id), username(_username), password(_password), role(_role), email(_email), phone(_phone),
            last_login_ip(_last_login_ip), last_login_time(_last_login_time), is_locked(_is_locked), create_time(_create_time) {
        }
    };

    struct UserOperationLog {
        uint64_t log_id;
        uint64_t user_id;
		uint64_t target_id;
        std::string operation_type;
        std::string operation_detail;
        std::string client_info;
        std::string operation_time;
        bool result_status;

        // 无参构造函数
        UserOperationLog()
            : log_id(0), user_id(0), target_id(0), result_status(0) {
        }

        // 全参构造函数
        UserOperationLog(uint64_t _log_id, uint64_t _user_id, const std::string& _operation_type,
            uint64_t _target_id, const std::string& _operation_detail, const std::string& _client_info,
            const std::string& _operation_time, bool _result_status)
            : log_id(_log_id), user_id(_user_id), operation_type(_operation_type), target_id(_target_id),
            operation_detail(_operation_detail), client_info(_client_info), operation_time(_operation_time),
            result_status(_result_status) {
        }
    };


    
	
	struct FileInfo
	{
		bool force_delete;
		bool is_encrypted;
		uint64_t file_id;
		std::string path;
		std::string secret_key;     

		// 默认构造函数 (Default Constructor)
		FileInfo() : file_id(0), force_delete(false), is_encrypted(false) {}


		// 参数构造函数 (Parameterized Constructor)
		FileInfo(uint64_t _id, std::string _path, bool _forceDel, bool _encrypted, std::string _key)
			: file_id(_id), path(_path), force_delete(_forceDel), is_encrypted(_encrypted), secret_key(_key) {
		}

	};


}