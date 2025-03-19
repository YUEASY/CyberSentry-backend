#pragma once

#include "httpServer.hpp"
#include "smtpServer.hpp"
#include "models.hpp"
#include "md5.h"
#include "utils.hpp"
#include "mysqlOperations.hpp"
#include "deepSeek.hpp"
#include "protectServer.hpp"

#include <mutex>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <vector>
#include <string>
#include <chrono>
#include <json/json.h>

namespace sp {

    // ----------------------- 数据库相关服务 ----------------------------

    // 负责AppInfo相关的数据库操作
    class AppInfoService {
    public:
        bool getAppInfoById(uint64_t id, AppInfo& info) {
            std::lock_guard<std::mutex> lock(mutex_);

            // 先检查缓存中是否有数据
            auto it = app_info_list.find(id);
            if (it != app_info_list.end()) {
                info = it->second; // 从缓存中获取
                return true;
            }

            // 如果缓存中没有，去数据库查询
            if (!appInfoTable_) {
                appInfoTable_ = std::make_shared<AppInfoTable>();
            }

            bool result = appInfoTable_->getAppInfoById(id, info);
            if (result) {
                app_info_list[id] = info; // 查询到数据后缓存起来
            }
            return result;
        }

        bool getAllAppInfo(std::vector<AppInfo>& app_info_list_out) {
            std::lock_guard<std::mutex> lock(mutex_);

            // 先检查缓存中是否有数据
            if (!app_info_list.empty()) {
                // 将缓存数据转换为向量输出
                for (const auto& [id, info] : app_info_list) {
                    app_info_list_out.push_back(info);
                }
                return true;
            }

            // 如果缓存中没有，去数据库查询
            if (!appInfoTable_) {
                appInfoTable_ = std::make_shared<AppInfoTable>();
            }

            bool result = appInfoTable_->getAllAppInfo(app_info_list_out);
            if (result) {
                // 缓存查询到的所有数据
                for (const auto& info : app_info_list_out) {
                    app_info_list[info.id] = info;
                }
            }
            return result;
        }

        // 刷新缓存：从数据库中获取最新数据，更新内存中的缓存
        void refreshCache() {
            std::lock_guard<std::mutex> lock(mutex_);
            std::vector<AppInfo> dbData;
            if (!appInfoTable_) {
                appInfoTable_ = std::make_shared<AppInfoTable>();
            }
            if (appInfoTable_->getAllAppInfo(dbData)) {
                // 清空原有缓存并更新为最新数据
                app_info_list.clear();
                for (const auto& info : dbData) {
                    app_info_list[info.id] = info;
                }
            }
        }

        explicit AppInfoService(int interval_seconds = 300)
        {
            startPeriodicRefresh(interval_seconds);
        }

        ~AppInfoService() {
            stop_flag = true; // 请求线程停止
            if (refresh_thread.joinable()) {
                refresh_thread.join(); // 等待线程结束
            }
        }

    private:
        // 启动后台线程，定时刷新缓存
        void startPeriodicRefresh(int interval_seconds) 
        {
            refresh_thread = std::thread([this, interval_seconds]() 
                {
                while (!stop_flag) 
                {
                    std::this_thread::sleep_for(std::chrono::seconds(interval_seconds));
                    if (!stop_flag.load()) 
                    {
                        refreshCache();
                    }
                }
                });
        }



    private:
        std::shared_ptr<AppInfoTable> appInfoTable_;
        std::unordered_map<uint64_t, AppInfo> app_info_list; // 缓存的App信息
        std::mutex mutex_;
        std::atomic<bool> stop_flag{ false };
        std::thread refresh_thread;
    };


    // 负责监控规则相关操作
    class MonitoringRuleService {
    public:
        bool getMonitoringRuleById(uint64_t rule_id, MonitoringRule& rule) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!monitoringRuleTable_) {
                monitoringRuleTable_ = std::make_shared<MonitoringRuleTable>();
            }
            return monitoringRuleTable_->getMonitoringRuleByAppId(rule_id, rule);
        }

        bool getMonitoringRuleByAppId(uint64_t app_id, MonitoringRule& rule) {
            std::lock_guard<std::mutex> lock(mutex_);

            // 先检查缓存中是否有数据
            auto it = monitoring_rule_list.find(app_id);
            if (it != monitoring_rule_list.end()) {
                rule = it->second; // 从缓存中获取
                return true;
            }

            // 如果缓存中没有，去数据库查询
            if (!monitoringRuleTable_) {
                monitoringRuleTable_ = std::make_shared<MonitoringRuleTable>();
            }

            bool result = monitoringRuleTable_->getMonitoringRuleByAppId(app_id, rule);
            if (result) {
                monitoring_rule_list[app_id] = rule; // 查询到数据后缓存起来
            }
            return result;
        }

        bool updateMonitoringRule(MonitoringRule& rule) {
            std::lock_guard<std::mutex> lock(mutex_);

            if (!monitoringRuleTable_) {
                monitoringRuleTable_ = std::make_shared<MonitoringRuleTable>();
            }

            bool result = monitoringRuleTable_->updateMonitoringRule(rule);
            if (result) {
                monitoring_rule_list[rule.id] = rule; // 更新缓存中的数据
            }
            return result;
        }

        bool getAllMonitoringRules(std::vector<MonitoringRule>& rules) {
            std::lock_guard<std::mutex> lock(mutex_);

            // 先检查缓存中是否有数据
            if (!monitoring_rule_list.empty()) {
                // 将缓存数据转换为向量输出
                for (const auto& [id, rule] : monitoring_rule_list) {
                    rules.push_back(rule);
                }
                return true;
            }

            // 如果缓存中没有，去数据库查询
            if (!monitoringRuleTable_) {
                monitoringRuleTable_ = std::make_shared<MonitoringRuleTable>();
            }

            bool result = monitoringRuleTable_->getAllMonitoringRules(rules);
            if (result) {
                // 缓存查询到的所有数据
                for (const auto& rule : rules) {
                    monitoring_rule_list[rule.id] = rule;
                }
            }
            return result;
        }

        // 从数据库中获取最新数据，并更新内存中的缓存
        void refreshCache() {
            std::lock_guard<std::mutex> lock(mutex_);
            std::vector<MonitoringRule> dbRules;
            if (!monitoringRuleTable_) {
                monitoringRuleTable_ = std::make_shared<MonitoringRuleTable>();
            }
            if (monitoringRuleTable_->getAllMonitoringRules(dbRules)) {
                monitoring_rule_list.clear();
                for (const auto& rule : dbRules) {
                    monitoring_rule_list[rule.id] = rule;
                }
            }
        }



        explicit MonitoringRuleService(int interval_seconds = 300) {
            startPeriodicRefresh(interval_seconds);
        }

        // 析构函数确保线程安全退出
        ~MonitoringRuleService() {
            stop_flag_.store(true);  // 设置停止标志
            if (refresh_thread_.joinable()) {
                refresh_thread_.join();  // 等待线程结束
            }
        }
    private:
        void startPeriodicRefresh(int interval_seconds)    
        {
            refresh_thread_ = std::thread([this, interval_seconds]() 
                {
                while (!stop_flag_.load()) 
                {
                    std::this_thread::sleep_for(std::chrono::seconds(interval_seconds));
                    if (!stop_flag_.load()) 
                    {  
                        refreshCache();
                    }
                }
                });
        }

    private:
        std::shared_ptr<MonitoringRuleTable> monitoringRuleTable_;
        std::unordered_map<uint64_t, MonitoringRule> monitoring_rule_list; //key :app_id
        std::mutex mutex_;
        std::atomic<bool> stop_flag_{ false };
        std::thread refresh_thread_;
 
    };

    // 负责用户操作日志相关操作
    class UserOperationLogService {
    public:
        bool saveUserOperationLog(const UserOperationLog& log) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!userOperationLogTable_) {
                userOperationLogTable_ = std::make_shared<UserOperationLogTable>();
            }
            return userOperationLogTable_->insertUserOperationLog(log);
        }

        bool getUserOperationLogs(uint64_t user_id, std::vector<UserOperationLog>& logs) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!userOperationLogTable_) {
                userOperationLogTable_ = std::make_shared<UserOperationLogTable>();
            }
            return userOperationLogTable_->getUserOperationLogsByUserId(user_id, logs);
        }

        bool getAllUserOperationLogs(std::vector<UserOperationLog>& logs) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!userOperationLogTable_) {
                userOperationLogTable_ = std::make_shared<UserOperationLogTable>();
            }
            return userOperationLogTable_->getAllUserOperationLogs(logs);
        }
    private:
        std::shared_ptr<UserOperationLogTable> userOperationLogTable_;
        std::mutex mutex_;
    };

    // 负责系统监控数据相关操作
    class SystemMonitorService {
    public:
        bool getAllSystemMonitors(std::vector<SystemMonitor>& records) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!systemMonitorTable_) {
                systemMonitorTable_ = std::make_shared<SystemMonitorTable>();
            }
            return systemMonitorTable_->getAllSystemMonitors(records);
        }
        bool getAllSystemMonitorsFromCache(std::vector<SystemMonitor>& records) {
            std::lock_guard<std::mutex> lock(mutex_);

            // 如果缓存中有数据，直接返回缓存
            if (!system_monitor_buffer.empty()) {
                records.assign(system_monitor_buffer.begin(), system_monitor_buffer.end());
                return true;
            }
            return false;  
        }
        void updateCache(const std::vector<SystemMonitor>& newData) {
            std::lock_guard<std::mutex> lock(mutex_);

            // 清空缓存并插入新的数据
            system_monitor_buffer.clear();
            system_monitor_buffer.insert(system_monitor_buffer.end(), newData.begin(), newData.end());

            // 如果缓存中记录大于 1000 条，保留后 1000 条记录
            if (system_monitor_buffer.size() > 1000) {
                system_monitor_buffer.erase(system_monitor_buffer.begin(), system_monitor_buffer.begin() + (system_monitor_buffer.size() - 1000));
            }
        }
        // 检查缓存中的数据并将符合条件的写入数据库
        void writeToDatabaseIfNeeded() {
            std::lock_guard<std::mutex> lock(mutex_);

            // 检查缓存是否为空
            if (system_monitor_buffer.empty()) {
                return;
            }

            // 遍历缓存中的数据，检查 sample_time 是否能被 20 除尽
            for (const auto& monitor : system_monitor_buffer) {
                if (std::stoull(monitor.sample_time) % 20 == 0) {
                    // 如果 sample_time 能被 20 除尽，写入数据库
                    if (!systemMonitorTable_) {
                        systemMonitorTable_ = std::make_shared<SystemMonitorTable>();
                    }
                    systemMonitorTable_->insertSystemMonitor(monitor);
                }
            }
        }

        // 构造函数启动定时任务
        explicit SystemMonitorService(int cache_update_interval = 1, int db_write_interval = 300) {
            startPeriodicCacheUpdate(cache_update_interval);
            startPeriodicWriteToDatabase(db_write_interval);
        }

        // 析构函数确保线程安全退出
        ~SystemMonitorService() {
            stop_flag_.store(true);  // 设置停止标志
            if (cache_thread_.joinable()) cache_thread_.join();
            if (db_thread_.joinable()) db_thread_.join();
        }
    private:
        void startPeriodicCacheUpdate(int interval_seconds) {
            cache_thread_ = std::thread([this, interval_seconds]() {
                while (!stop_flag_.load()) {
                    std::this_thread::sleep_for(std::chrono::seconds(interval_seconds));
                    if (stop_flag_.load()) break;

                    std::vector<SystemMonitor> newData /*= fetchNewData()*/;  // 假设已实现
                    updateCache(newData);
                }
                });
        }

        // 启动数据库写入线程
        void startPeriodicWriteToDatabase(int interval_seconds) {
            db_thread_ = std::thread([this, interval_seconds]() {
                while (!stop_flag_.load()) {
                    std::this_thread::sleep_for(std::chrono::seconds(interval_seconds));
                    if (stop_flag_.load()) break;
                    writeToDatabaseIfNeeded();
                }
                });
        }


    private:
        std::shared_ptr<SystemMonitorTable> systemMonitorTable_;
        std::deque<SystemMonitor> system_monitor_buffer; // 1000条
        std::mutex mutex_;
        std::atomic<bool> stop_flag_{ false };
        std::thread cache_thread_;
        std::thread db_thread_;
    };

    // 负责用户信息相关操作
    class UserInfoService {
    public:
        bool getUserInfoByEmail(const std::string& email, UserInfo& user) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!userInfoTable_) {
                userInfoTable_ = std::make_shared<UserInfoTable>();
            }
            return userInfoTable_->getUserInfoByEmail(email, user);
        }

        bool insertUserInfo(const UserInfo& user) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!userInfoTable_) {
                userInfoTable_ = std::make_shared<UserInfoTable>();
            }
            return userInfoTable_->insertUserInfo(user);
        }

        bool updateUserInfo(const UserInfo& user) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!userInfoTable_) {
                userInfoTable_ = std::make_shared<UserInfoTable>();
            }
            return userInfoTable_->updateUserInfo(user);
        }
    private:
        std::shared_ptr<UserInfoTable> userInfoTable_;
        std::mutex mutex_;
    };

    // 负责应用资源监控数据操作
    class AppResourceMonitorService {
    public:
        bool getAllAppResourceMonitors(std::vector<AppResourceMonitor>& records) {
            std::lock_guard<std::mutex> lock(mutex_);

            // 如果缓存中没有数据，则从数据库获取
            if (app_resource_monitor_lists.empty()) {
                if (!appResourceMonitorTable_) {
                    appResourceMonitorTable_ = std::make_shared<AppResourceMonitorTable>();
                }
                return appResourceMonitorTable_->getAllAppResourceMonitors(records);
            }

            // 从缓存中获取数据
            for (const auto& entry : app_resource_monitor_lists) {
                for (const auto& record : entry.second) {
                    records.push_back(record);
                }
            }
            return true;
        }

        // 获取指定应用的资源监控记录
        bool getAppResourceMonitorsByAppId(uint32_t app_id, std::vector<AppResourceMonitor>& records) {
            std::lock_guard<std::mutex> lock(mutex_);

            // 如果缓存中没有数据，则从数据库获取
            if (app_resource_monitor_lists.find(app_id) == app_resource_monitor_lists.end()) {
                if (!appResourceMonitorTable_) {
                    appResourceMonitorTable_ = std::make_shared<AppResourceMonitorTable>();
                }
                return appResourceMonitorTable_->getAppResourceMonitorsByAppId(app_id, records);
            }

            // 从缓存中获取数据
            const auto& appData = app_resource_monitor_lists[app_id];
            records.insert(records.end(), appData.begin(), appData.end());
            return true;
        }

        // 更新缓存中的数据
        void updateCache(uint32_t app_id, const std::vector<AppResourceMonitor>& newData) {
            std::lock_guard<std::mutex> lock(mutex_);

            // 如果没有缓存该应用的数据，则初始化缓存
            if (app_resource_monitor_lists.find(app_id) == app_resource_monitor_lists.end()) {
                app_resource_monitor_lists[app_id] = std::deque<AppResourceMonitor>();
            }

            auto& appData = app_resource_monitor_lists[app_id];

            // 将新数据插入缓存
            appData.insert(appData.end(), newData.begin(), newData.end());

            // 如果缓存中的数据超过了 600 条，保留后 600 条记录
            if (appData.size() > 600) {
                appData.erase(appData.begin(), appData.begin() + (appData.size() - 600));
            }
        }

        void refreshCache() {
            std::lock_guard<std::mutex> lock(mutex_);
            std::vector<AppResourceMonitor> records;
            if (!appResourceMonitorTable_) {
                appResourceMonitorTable_ = std::make_shared<AppResourceMonitorTable>();
            }
            if (appResourceMonitorTable_->getAllAppResourceMonitors(records)) {
                // 清空当前缓存
                app_resource_monitor_lists.clear();
                // 按照 app_id 分组插入记录
                for (const auto& record : records) {
                    app_resource_monitor_lists[record.app_id].push_back(record);
                    // 保证每个应用的记录不超过 600 条
                    if (app_resource_monitor_lists[record.app_id].size() > 600) {
                        app_resource_monitor_lists[record.app_id].erase(
                            app_resource_monitor_lists[record.app_id].begin(),
                            app_resource_monitor_lists[record.app_id].begin() +
                            (app_resource_monitor_lists[record.app_id].size() - 600));
                    }
                }
            }
        }

        // 构造函数启动定时刷新
        explicit AppResourceMonitorService(int interval_seconds = 300) {
            startPeriodicRefresh(interval_seconds);
        }

        // 析构函数确保线程安全终止
        ~AppResourceMonitorService() {
            stop_flag_.store(true);  // 设置停止标志
            if (refresh_thread_.joinable()) {
                refresh_thread_.join();  // 等待线程结束
            }
        }
    private:
        void startPeriodicRefresh(int interval_seconds) {
            refresh_thread_ = std::thread([this, interval_seconds]() {
                while (!stop_flag_.load()) {
                    std::this_thread::sleep_for(std::chrono::seconds(interval_seconds));
                    if (!stop_flag_.load()) refreshCache();
                }
                });
        }
    private:
        std::shared_ptr<AppResourceMonitorTable> appResourceMonitorTable_;
        std::unordered_map<uint64_t, std::deque<AppResourceMonitor>> app_resource_monitor_lists;   // 600条
        std::mutex mutex_;
        std::atomic<bool> stop_flag_{ false };
        std::thread refresh_thread_;
    };

    // 负责AI分析结果相关操作
    class AIAnalysisResultService {
    public:
        bool getAIAnalysisResultsByUserId(uint64_t user_id, std::vector<AIAnalysisResult>& results) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!aiAnalysisResultTable_) {
                aiAnalysisResultTable_ = std::make_shared<AIAnalysisResultTable>();
            }
            return aiAnalysisResultTable_->getAIAnalysisResultsByUserId(user_id, results);
        }

        bool insertAIAnalysisResult(const AIAnalysisResult& result) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!aiAnalysisResultTable_) {
                aiAnalysisResultTable_ = std::make_shared<AIAnalysisResultTable>();
            }
            return aiAnalysisResultTable_->insertAIAnalysisResult(result);
        }
    private:
        std::shared_ptr<AIAnalysisResultTable> aiAnalysisResultTable_;
        std::mutex mutex_;
    };

    // 负责恶意线程日志相关操作
    class MaliciousThreadLogService {
    public:
        bool getAllMaliciousThreadLogs(std::vector<MaliciousThreadLog>& logs) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!maliciousThreadLogTable_) {
                maliciousThreadLogTable_ = std::make_shared<MaliciousThreadLogTable>();
            }
            return maliciousThreadLogTable_->getAllMaliciousThreadLogs(logs);
        }

        bool getMaliciousThreadLogsByAppId(uint32_t app_id, std::vector<MaliciousThreadLog>& logs) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!maliciousThreadLogTable_) {
                maliciousThreadLogTable_ = std::make_shared<MaliciousThreadLogTable>();
            }
            return maliciousThreadLogTable_->getMaliciousThreadLogsByAppId(app_id, logs);
        }
    private:
        std::shared_ptr<MaliciousThreadLogTable> maliciousThreadLogTable_;
        std::mutex mutex_;
    };

    // 负责文件修改日志相关操作
    class FileModificationLogService {
    public:

        // 获取文件修改日志
        bool getFileModificationLogsByAppId(uint64_t app_id, std::vector<FileModificationLog>& logs) {
            std::lock_guard<std::mutex> lock(mutex_);

            for (const auto& log : file_modification_log_buffer) {
                if (log.app_id == app_id) {
                    logs.push_back(log);
                }
            }
            return !logs.empty();
        }

        bool getAllFileModificationLogs(std::vector<FileModificationLog>& logs) {
            std::lock_guard<std::mutex> lock(mutex_);
            logs.insert(logs.end(), file_modification_log_buffer.begin(), file_modification_log_buffer.end());
            return !logs.empty();
        }

        // 更新缓存
        void updateCache(const std::vector<FileModificationLog>& newData) {
            std::lock_guard<std::mutex> lock(mutex_);

            // 清空缓存并插入新的数据
            file_modification_log_buffer.clear();
            file_modification_log_buffer.insert(file_modification_log_buffer.end(), newData.begin(), newData.end());

            // 如果缓存中记录大于 1000 条，保留后 1000 条记录
            if (file_modification_log_buffer.size() > 1000) {
                file_modification_log_buffer.erase(file_modification_log_buffer.begin(), file_modification_log_buffer.begin() + (file_modification_log_buffer.size() - 1000));
            }
        }

        // 构造函数启动定时任务
        explicit FileModificationLogService(int interval_seconds = 10) {
            startPeriodicCacheUpdate(interval_seconds);
        }

        // 析构函数确保线程安全退出
        ~FileModificationLogService() {
            stop_flag_.store(true);
            if (refresh_thread_.joinable()) refresh_thread_.join();
        }
    private:
        // 启动后台刷新线程
        void startPeriodicCacheUpdate(int interval_seconds) {
            refresh_thread_ = std::thread([this, interval_seconds]() {
                while (!stop_flag_.load()) {
                    std::this_thread::sleep_for(std::chrono::seconds(interval_seconds));
                    if (stop_flag_.load()) break;

                    std::vector<FileModificationLog> newData /*= fetchNewData()*/;
                    updateCache(newData);
                }
                });
        }
    private:
        std::shared_ptr<FileModificationLogTable> fileModificationLogTable_;
        std::deque<FileModificationLog> file_modification_log_buffer;   // 1000条
        std::mutex mutex_;
        std::atomic<bool> stop_flag_{ false };
        std::thread refresh_thread_;
    };

    // ----------------------- 认证和验证服务 ----------------------------

    class AuthService {
    public:
        std::string getToken() {
            std::lock_guard<std::mutex> lock(mutex_);
            std::string token = Utils::token();
            token_list_.insert(token);
            return token;
        }

        bool verifyToken(const std::string& token) {
            std::lock_guard<std::mutex> lock(mutex_);
            return token_list_.find(token) != token_list_.end();
        }

        bool verificationCaptcha(std::string& email, std::string& code) {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = verification_code_list_.find(email);
            uint64_t now_time = getCurrentTimestamp();
            if (it != verification_code_list_.end()) {
                if (now_time - it->second.second > 300) {
                    verification_code_list_.erase(email);
                    return false;
                }
                if (it->second.first == code) {
                    verification_code_list_.erase(email);
                    return true;
                }
            }
            return false;
        }

        std::string generateVerificationCode(std::string& email) {
            std::lock_guard<std::mutex> lock(mutex_);
            std::string code = Utils::verificationCode();
            verification_code_list_[email] = std::make_pair(code, getCurrentTimestamp());
            return code;
        }
    private:
        uint64_t getCurrentTimestamp() {
            return std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count();
        }
        std::unordered_set<std::string> token_list_;
        std::unordered_map<std::string, std::pair<std::string, uint64_t>> verification_code_list_;
        std::mutex mutex_;
    };

    // ----------------------- 系统信息与Deepseek服务 ----------------------------

    class SystemInfoService {
    public:
        Json::Value askDeepseek(const std::string& prompt) {
            std::lock_guard<std::mutex> lock(mutex_);
            std::string sys_info;
            for (const auto& e : sys_info_list_) {
                sys_info += e.first + ":" + e.second + ";";
            }
            return DeepseekApi::getInstance().sendRequest(prompt, sys_info);
        }

        void writeSysInfo(const SystemMonitor& sm,
            const std::vector<AppResourceMonitor>& var,
            const std::vector<MaliciousThreadLog>& vm,
            const std::vector<FileModificationLog>& vf,
            const std::vector<AppInfo>& va) {
            std::lock_guard<std::mutex> lock(mutex_);
            sys_info_list_["SystemMonitor"] =
                "cpu_usage:" + std::to_string(sm.cpu_usage) +
                ";memory_usage:" + std::to_string(sm.memory_usage) +
                ";disk_usage:" + std::to_string(sm.disk_usage) +
                ";network_upload/download:" + std::to_string(sm.network_upload) + "/" + std::to_string(sm.network_download) +
                ";temperature:" + std::to_string(sm.temperature) +
                ";sample_time:" + sm.sample_time;

            for (const auto& app : va) {
                sys_info_list_["AppInfo_" + std::to_string(app.id)] =
                    "app_name:" + app.app_name +
                    ";executable_path:" + app.executable_path +
                    ";icon_path:" + app.icon_path +
                    ";create_time:" + app.create_time +
                    ";update_time:" + app.update_time;
            }

            for (const auto& resource : var) {
                sys_info_list_["AppResourceMonitor_" + std::to_string(resource.id)] =
                    "app_id:" + std::to_string(resource.app_id) +
                    ";app_name:" + resource.app_name +
                    ";icon_path:" + resource.icon_path +
                    ";cpu_usage:" + std::to_string(resource.cpu_usage) +
                    ";memory_usage_mb:" + std::to_string(resource.memory_usage_mb) +
                    ";disk_io_read:" + std::to_string(resource.disk_io_read) +
                    ";disk_io_write:" + std::to_string(resource.disk_io_write) +
                    ";sample_time:" + resource.sample_time;
            }

            for (const auto& log : vm) {
                sys_info_list_["MaliciousThreadLog_" + std::to_string(log.id)] =
                    "app_id:" + std::to_string(log.app_id) +
                    ";thread_name:" + log.thread_name +
                    ";thread_hash:" + log.thread_hash +
                    ";risk_level:" + std::to_string(log.risk_level) +
                    ";detection_time:" + log.detection_time;
            }

            for (const auto& fileLog : vf) {
                sys_info_list_["FileModificationLog_" + std::to_string(fileLog.id)] =
                    "app_id:" + std::to_string(fileLog.app_id) +
                    ";file_path:" + fileLog.file_path +
                    ";operation_type:" + fileLog.operation_type +
                    ";file_hash:" + fileLog.file_hash +
                    ";alert_time:" + fileLog.alert_time;
            }
        }
    private:
        std::unordered_map<std::string, std::string> sys_info_list_;
        std::mutex mutex_;
    };

    // ----------------------- 保护功能服务 ----------------------------

    class ProtectionService {
    public:
        //bool protectFakeProcess(uint64_t TargetPid, uint64_t FakePid) {
        //    return ProtectServer::GetInstance().protectFakeProcess(TargetPid, FakePid);
        //}
        //bool protectAntiScreenShot(uint64_t TargetPid) {
        //    return ProtectServer::GetInstance().protectAntiScreenShot(TargetPid);
        //}
        //bool protectAntiModify(uint64_t TargetPid) {
        //    return ProtectServer::GetInstance().protectAntiModify(TargetPid);
        //}
        //bool protectForceDelete(uint64_t TargetPid) {
        //    return ProtectServer::GetInstance().protectForceDelete("");
        //}
    };

    // ----------------------- 邮件发送服务 ----------------------------

    class EmailService {
    public:
        bool sendMail(std::string_view address, std::string_view subject, std::string_view body) {
            return SmtpServer::getInstance().sendMail(address, subject, body);
        }
    };

    // ----------------------- 文件信息加密服务 ----------------------------

    class FileInfoService
    {
    public:
        bool getAllFileInfo(std::vector<FileInfo>& files)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!FileInfoTable_)
            {
                FileInfoTable_ = std::make_shared<FileInfoTable>();
            }
            return FileInfoTable_->getAllFileInfo(files);
        }

        bool getFileInfoById(uint64_t file_id, FileInfo& file)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!FileInfoTable_)
            {
                FileInfoTable_ = std::make_shared<FileInfoTable>();
            }
            return FileInfoTable_->getFileInfoById(file_id,file);
        }

        // 加密文件
        bool encryptFile(uint64_t file_id, const std::string& key)
        {
            //加密函数
            //...
            std::lock_guard<std::mutex> lock(mutex_);
            if (!FileInfoTable_)
            {
                FileInfoTable_ = std::make_shared<FileInfoTable>();
            }
            return FileInfoTable_->encryptFile(file_id, key);
        }

        // 解密文件
        bool decryptFile(uint64_t file_id)
        {
            //解密函数
            //.....
            std::lock_guard<std::mutex> lock(mutex_);
            if (!FileInfoTable_)
            {
                FileInfoTable_ = std::make_shared<FileInfoTable>();
            }
            return FileInfoTable_->decryptFile(file_id);
        }
        bool forceDeleteFile(uint64_t file_id)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!FileInfoTable_)
            {
                FileInfoTable_ = std::make_shared<FileInfoTable>();
            }
            return FileInfoTable_->forceDeleteFile(file_id);
        }
    private:
        std::shared_ptr<FileInfoTable> FileInfoTable_;
        std::mutex mutex_;
    };

    // ----------------------- 聚合各个服务的门面 ----------------------------

    class ServerManager {
    public:
        static ServerManager& getInstance() {
            return instance;
        }

        // 禁止拷贝构造和赋值操作
        ServerManager(const ServerManager&) = delete;
        ServerManager& operator=(const ServerManager&) = delete;

        // 提供对各个服务的访问接口
        AppInfoService& getAppInfoService() { return appInfoService_; }
        MonitoringRuleService& getMonitoringRuleService() { return monitoringRuleService_; }
        UserOperationLogService& getUserOperationLogService() { return userOperationLogService_; }
        SystemMonitorService& getSystemMonitorService() { return systemMonitorService_; }
        UserInfoService& getUserInfoService() { return userInfoService_; }
        AppResourceMonitorService& getAppResourceMonitorService() { return appResourceMonitorService_; }
        AIAnalysisResultService& getAIAnalysisResultService() { return aiAnalysisResultService_; }
        MaliciousThreadLogService& getMaliciousThreadLogService() { return maliciousThreadLogService_; }
        FileModificationLogService& getFileModificationLogService() { return fileModificationLogService_; }
        AuthService& getAuthService() { return authService_; }
        SystemInfoService& getSystemInfoService() { return systemInfoService_; }
        ProtectionService& getProtectionService() { return protectionService_; }
        EmailService& getEmailService() { return emailService_; }
        FileInfoService& getFileInfoService() { return FileInfoService_; }

    private:
        ServerManager() = default;
        ~ServerManager() = default; // 析构函数需要公有以允许静态成员析构

        static ServerManager instance; // 静态成员声明

        // 各个服务的实例
        AppInfoService appInfoService_;
        MonitoringRuleService monitoringRuleService_;
        UserOperationLogService userOperationLogService_;
        SystemMonitorService systemMonitorService_;
        UserInfoService userInfoService_;
        AppResourceMonitorService appResourceMonitorService_;
        AIAnalysisResultService aiAnalysisResultService_;
        MaliciousThreadLogService maliciousThreadLogService_;
        FileModificationLogService fileModificationLogService_;
        AuthService authService_;
        SystemInfoService systemInfoService_;
        ProtectionService protectionService_;
        EmailService emailService_;
        FileInfoService FileInfoService_;
    };
    ServerManager ServerManager::instance;
} // namespace sp
