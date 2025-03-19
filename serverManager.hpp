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

    // ----------------------- ���ݿ���ط��� ----------------------------

    // ����AppInfo��ص����ݿ����
    class AppInfoService {
    public:
        bool getAppInfoById(uint64_t id, AppInfo& info) {
            std::lock_guard<std::mutex> lock(mutex_);

            // �ȼ�黺�����Ƿ�������
            auto it = app_info_list.find(id);
            if (it != app_info_list.end()) {
                info = it->second; // �ӻ����л�ȡ
                return true;
            }

            // ���������û�У�ȥ���ݿ��ѯ
            if (!appInfoTable_) {
                appInfoTable_ = std::make_shared<AppInfoTable>();
            }

            bool result = appInfoTable_->getAppInfoById(id, info);
            if (result) {
                app_info_list[id] = info; // ��ѯ�����ݺ󻺴�����
            }
            return result;
        }

        bool getAllAppInfo(std::vector<AppInfo>& app_info_list_out) {
            std::lock_guard<std::mutex> lock(mutex_);

            // �ȼ�黺�����Ƿ�������
            if (!app_info_list.empty()) {
                // ����������ת��Ϊ�������
                for (const auto& [id, info] : app_info_list) {
                    app_info_list_out.push_back(info);
                }
                return true;
            }

            // ���������û�У�ȥ���ݿ��ѯ
            if (!appInfoTable_) {
                appInfoTable_ = std::make_shared<AppInfoTable>();
            }

            bool result = appInfoTable_->getAllAppInfo(app_info_list_out);
            if (result) {
                // �����ѯ������������
                for (const auto& info : app_info_list_out) {
                    app_info_list[info.id] = info;
                }
            }
            return result;
        }

        // ˢ�»��棺�����ݿ��л�ȡ�������ݣ������ڴ��еĻ���
        void refreshCache() {
            std::lock_guard<std::mutex> lock(mutex_);
            std::vector<AppInfo> dbData;
            if (!appInfoTable_) {
                appInfoTable_ = std::make_shared<AppInfoTable>();
            }
            if (appInfoTable_->getAllAppInfo(dbData)) {
                // ���ԭ�л��沢����Ϊ��������
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
            stop_flag = true; // �����߳�ֹͣ
            if (refresh_thread.joinable()) {
                refresh_thread.join(); // �ȴ��߳̽���
            }
        }

    private:
        // ������̨�̣߳���ʱˢ�»���
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
        std::unordered_map<uint64_t, AppInfo> app_info_list; // �����App��Ϣ
        std::mutex mutex_;
        std::atomic<bool> stop_flag{ false };
        std::thread refresh_thread;
    };


    // �����ع�����ز���
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

            // �ȼ�黺�����Ƿ�������
            auto it = monitoring_rule_list.find(app_id);
            if (it != monitoring_rule_list.end()) {
                rule = it->second; // �ӻ����л�ȡ
                return true;
            }

            // ���������û�У�ȥ���ݿ��ѯ
            if (!monitoringRuleTable_) {
                monitoringRuleTable_ = std::make_shared<MonitoringRuleTable>();
            }

            bool result = monitoringRuleTable_->getMonitoringRuleByAppId(app_id, rule);
            if (result) {
                monitoring_rule_list[app_id] = rule; // ��ѯ�����ݺ󻺴�����
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
                monitoring_rule_list[rule.id] = rule; // ���»����е�����
            }
            return result;
        }

        bool getAllMonitoringRules(std::vector<MonitoringRule>& rules) {
            std::lock_guard<std::mutex> lock(mutex_);

            // �ȼ�黺�����Ƿ�������
            if (!monitoring_rule_list.empty()) {
                // ����������ת��Ϊ�������
                for (const auto& [id, rule] : monitoring_rule_list) {
                    rules.push_back(rule);
                }
                return true;
            }

            // ���������û�У�ȥ���ݿ��ѯ
            if (!monitoringRuleTable_) {
                monitoringRuleTable_ = std::make_shared<MonitoringRuleTable>();
            }

            bool result = monitoringRuleTable_->getAllMonitoringRules(rules);
            if (result) {
                // �����ѯ������������
                for (const auto& rule : rules) {
                    monitoring_rule_list[rule.id] = rule;
                }
            }
            return result;
        }

        // �����ݿ��л�ȡ�������ݣ��������ڴ��еĻ���
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

        // ��������ȷ���̰߳�ȫ�˳�
        ~MonitoringRuleService() {
            stop_flag_.store(true);  // ����ֹͣ��־
            if (refresh_thread_.joinable()) {
                refresh_thread_.join();  // �ȴ��߳̽���
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

    // �����û�������־��ز���
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

    // ����ϵͳ���������ز���
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

            // ��������������ݣ�ֱ�ӷ��ػ���
            if (!system_monitor_buffer.empty()) {
                records.assign(system_monitor_buffer.begin(), system_monitor_buffer.end());
                return true;
            }
            return false;  
        }
        void updateCache(const std::vector<SystemMonitor>& newData) {
            std::lock_guard<std::mutex> lock(mutex_);

            // ��ջ��沢�����µ�����
            system_monitor_buffer.clear();
            system_monitor_buffer.insert(system_monitor_buffer.end(), newData.begin(), newData.end());

            // ��������м�¼���� 1000 ���������� 1000 ����¼
            if (system_monitor_buffer.size() > 1000) {
                system_monitor_buffer.erase(system_monitor_buffer.begin(), system_monitor_buffer.begin() + (system_monitor_buffer.size() - 1000));
            }
        }
        // ��黺���е����ݲ�������������д�����ݿ�
        void writeToDatabaseIfNeeded() {
            std::lock_guard<std::mutex> lock(mutex_);

            // ��黺���Ƿ�Ϊ��
            if (system_monitor_buffer.empty()) {
                return;
            }

            // ���������е����ݣ���� sample_time �Ƿ��ܱ� 20 ����
            for (const auto& monitor : system_monitor_buffer) {
                if (std::stoull(monitor.sample_time) % 20 == 0) {
                    // ��� sample_time �ܱ� 20 ������д�����ݿ�
                    if (!systemMonitorTable_) {
                        systemMonitorTable_ = std::make_shared<SystemMonitorTable>();
                    }
                    systemMonitorTable_->insertSystemMonitor(monitor);
                }
            }
        }

        // ���캯��������ʱ����
        explicit SystemMonitorService(int cache_update_interval = 1, int db_write_interval = 300) {
            startPeriodicCacheUpdate(cache_update_interval);
            startPeriodicWriteToDatabase(db_write_interval);
        }

        // ��������ȷ���̰߳�ȫ�˳�
        ~SystemMonitorService() {
            stop_flag_.store(true);  // ����ֹͣ��־
            if (cache_thread_.joinable()) cache_thread_.join();
            if (db_thread_.joinable()) db_thread_.join();
        }
    private:
        void startPeriodicCacheUpdate(int interval_seconds) {
            cache_thread_ = std::thread([this, interval_seconds]() {
                while (!stop_flag_.load()) {
                    std::this_thread::sleep_for(std::chrono::seconds(interval_seconds));
                    if (stop_flag_.load()) break;

                    std::vector<SystemMonitor> newData /*= fetchNewData()*/;  // ������ʵ��
                    updateCache(newData);
                }
                });
        }

        // �������ݿ�д���߳�
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
        std::deque<SystemMonitor> system_monitor_buffer; // 1000��
        std::mutex mutex_;
        std::atomic<bool> stop_flag_{ false };
        std::thread cache_thread_;
        std::thread db_thread_;
    };

    // �����û���Ϣ��ز���
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

    // ����Ӧ����Դ������ݲ���
    class AppResourceMonitorService {
    public:
        bool getAllAppResourceMonitors(std::vector<AppResourceMonitor>& records) {
            std::lock_guard<std::mutex> lock(mutex_);

            // ���������û�����ݣ�������ݿ��ȡ
            if (app_resource_monitor_lists.empty()) {
                if (!appResourceMonitorTable_) {
                    appResourceMonitorTable_ = std::make_shared<AppResourceMonitorTable>();
                }
                return appResourceMonitorTable_->getAllAppResourceMonitors(records);
            }

            // �ӻ����л�ȡ����
            for (const auto& entry : app_resource_monitor_lists) {
                for (const auto& record : entry.second) {
                    records.push_back(record);
                }
            }
            return true;
        }

        // ��ȡָ��Ӧ�õ���Դ��ؼ�¼
        bool getAppResourceMonitorsByAppId(uint32_t app_id, std::vector<AppResourceMonitor>& records) {
            std::lock_guard<std::mutex> lock(mutex_);

            // ���������û�����ݣ�������ݿ��ȡ
            if (app_resource_monitor_lists.find(app_id) == app_resource_monitor_lists.end()) {
                if (!appResourceMonitorTable_) {
                    appResourceMonitorTable_ = std::make_shared<AppResourceMonitorTable>();
                }
                return appResourceMonitorTable_->getAppResourceMonitorsByAppId(app_id, records);
            }

            // �ӻ����л�ȡ����
            const auto& appData = app_resource_monitor_lists[app_id];
            records.insert(records.end(), appData.begin(), appData.end());
            return true;
        }

        // ���»����е�����
        void updateCache(uint32_t app_id, const std::vector<AppResourceMonitor>& newData) {
            std::lock_guard<std::mutex> lock(mutex_);

            // ���û�л����Ӧ�õ����ݣ����ʼ������
            if (app_resource_monitor_lists.find(app_id) == app_resource_monitor_lists.end()) {
                app_resource_monitor_lists[app_id] = std::deque<AppResourceMonitor>();
            }

            auto& appData = app_resource_monitor_lists[app_id];

            // �������ݲ��뻺��
            appData.insert(appData.end(), newData.begin(), newData.end());

            // ��������е����ݳ����� 600 ���������� 600 ����¼
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
                // ��յ�ǰ����
                app_resource_monitor_lists.clear();
                // ���� app_id ��������¼
                for (const auto& record : records) {
                    app_resource_monitor_lists[record.app_id].push_back(record);
                    // ��֤ÿ��Ӧ�õļ�¼������ 600 ��
                    if (app_resource_monitor_lists[record.app_id].size() > 600) {
                        app_resource_monitor_lists[record.app_id].erase(
                            app_resource_monitor_lists[record.app_id].begin(),
                            app_resource_monitor_lists[record.app_id].begin() +
                            (app_resource_monitor_lists[record.app_id].size() - 600));
                    }
                }
            }
        }

        // ���캯��������ʱˢ��
        explicit AppResourceMonitorService(int interval_seconds = 300) {
            startPeriodicRefresh(interval_seconds);
        }

        // ��������ȷ���̰߳�ȫ��ֹ
        ~AppResourceMonitorService() {
            stop_flag_.store(true);  // ����ֹͣ��־
            if (refresh_thread_.joinable()) {
                refresh_thread_.join();  // �ȴ��߳̽���
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
        std::unordered_map<uint64_t, std::deque<AppResourceMonitor>> app_resource_monitor_lists;   // 600��
        std::mutex mutex_;
        std::atomic<bool> stop_flag_{ false };
        std::thread refresh_thread_;
    };

    // ����AI���������ز���
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

    // ��������߳���־��ز���
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

    // �����ļ��޸���־��ز���
    class FileModificationLogService {
    public:

        // ��ȡ�ļ��޸���־
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

        // ���»���
        void updateCache(const std::vector<FileModificationLog>& newData) {
            std::lock_guard<std::mutex> lock(mutex_);

            // ��ջ��沢�����µ�����
            file_modification_log_buffer.clear();
            file_modification_log_buffer.insert(file_modification_log_buffer.end(), newData.begin(), newData.end());

            // ��������м�¼���� 1000 ���������� 1000 ����¼
            if (file_modification_log_buffer.size() > 1000) {
                file_modification_log_buffer.erase(file_modification_log_buffer.begin(), file_modification_log_buffer.begin() + (file_modification_log_buffer.size() - 1000));
            }
        }

        // ���캯��������ʱ����
        explicit FileModificationLogService(int interval_seconds = 10) {
            startPeriodicCacheUpdate(interval_seconds);
        }

        // ��������ȷ���̰߳�ȫ�˳�
        ~FileModificationLogService() {
            stop_flag_.store(true);
            if (refresh_thread_.joinable()) refresh_thread_.join();
        }
    private:
        // ������̨ˢ���߳�
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
        std::deque<FileModificationLog> file_modification_log_buffer;   // 1000��
        std::mutex mutex_;
        std::atomic<bool> stop_flag_{ false };
        std::thread refresh_thread_;
    };

    // ----------------------- ��֤����֤���� ----------------------------

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

    // ----------------------- ϵͳ��Ϣ��Deepseek���� ----------------------------

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

    // ----------------------- �������ܷ��� ----------------------------

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

    // ----------------------- �ʼ����ͷ��� ----------------------------

    class EmailService {
    public:
        bool sendMail(std::string_view address, std::string_view subject, std::string_view body) {
            return SmtpServer::getInstance().sendMail(address, subject, body);
        }
    };

    // ----------------------- �ļ���Ϣ���ܷ��� ----------------------------

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

        // �����ļ�
        bool encryptFile(uint64_t file_id, const std::string& key)
        {
            //���ܺ���
            //...
            std::lock_guard<std::mutex> lock(mutex_);
            if (!FileInfoTable_)
            {
                FileInfoTable_ = std::make_shared<FileInfoTable>();
            }
            return FileInfoTable_->encryptFile(file_id, key);
        }

        // �����ļ�
        bool decryptFile(uint64_t file_id)
        {
            //���ܺ���
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

    // ----------------------- �ۺϸ������������ ----------------------------

    class ServerManager {
    public:
        static ServerManager& getInstance() {
            return instance;
        }

        // ��ֹ��������͸�ֵ����
        ServerManager(const ServerManager&) = delete;
        ServerManager& operator=(const ServerManager&) = delete;

        // �ṩ�Ը�������ķ��ʽӿ�
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
        ~ServerManager() = default; // ����������Ҫ����������̬��Ա����

        static ServerManager instance; // ��̬��Ա����

        // ���������ʵ��
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
