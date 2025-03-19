#pragma once
#include "utils.hpp"
#include "models.hpp"

namespace sp
{
    class BaseTable
    {
    public:
        using ptr = std::shared_ptr<BaseTable>;
        BaseTable()
        {
            mysql = Utils::mysqlInit(DB_NAME, HOST, PORT, USER, PASSWD);
            if (mysql == nullptr)
            {
                exit(-1);
            }
        }
        ~BaseTable()
        {
            Utils::mysqlDestroy(mysql);
        }

    protected:
        MYSQL* mysql;
        std::mutex mtx;

        const char* HOST = "127.0.0.1";
        const char* PORT = "3306";
        const char* USER = "root";
        const char* PASSWD = "";
        const char* DB_NAME = "app_monitor";
    };

    class AppInfoTable : public BaseTable
    {
    public:
        using ptr = std::shared_ptr<AppInfoTable>;

        // 通过应用名称获取应用信息
        bool getAppInfoByName(std::string_view app_name, AppInfo& app_info)
        {
            std::string sql = "SELECT * FROM app_info WHERE app_name = '";
            sql.append(app_name);
            sql.append("';");

            mtx.lock();
            if (!Utils::mysqlQuery(mysql, sql))
            {
                mtx.unlock();
                return false;
            }

            MYSQL_RES* res = mysql_store_result(mysql);
            if (res == nullptr)
            {
                LOG_ERROR("mysql store result error: {}", std::string(mysql_error(mysql)));
                mtx.unlock();
                return false;
            }
            mtx.unlock();

            MYSQL_ROW row = mysql_fetch_row(res);
            if (row != nullptr)
            {
                app_info.id = std::stoull(row[0]);
                app_info.app_name = row[1];
                app_info.executable_path = row[2];
                app_info.icon_path = row[3] ? row[3] : "";
                app_info.create_time = row[4];
                app_info.update_time = row[5];
                mysql_free_result(res);
                return true;
            }

            mysql_free_result(res);
            return false;
        }

        // 根据ID获取应用信息
        bool getAppInfoById(uint64_t id, AppInfo& app_info)
        {
            std::string sql = "SELECT * FROM app_info WHERE id = ";
            sql.append(std::to_string(id));
            sql.append(";");

            mtx.lock();
            if (!Utils::mysqlQuery(mysql, sql))
            {
                mtx.unlock();
                return false;
            }

            MYSQL_RES* res = mysql_store_result(mysql);
            if (res == nullptr)
            {
                LOG_ERROR("mysql store result error: {}", std::string(mysql_error(mysql)));
                mtx.unlock();
                return false;
            }
            mtx.unlock();

            MYSQL_ROW row = mysql_fetch_row(res);
            if (row != nullptr)
            {
                app_info.id = std::stoull(row[0]);
                app_info.app_name = row[1];
                app_info.executable_path = row[2];
                app_info.icon_path = row[3] ? row[3] : "";
                app_info.create_time = row[4];
                app_info.update_time = row[5];
                mysql_free_result(res);
                return true;
            }

            mysql_free_result(res);
            return false;
        }


        // 创建新应用信息
        bool createAppInfo(const AppInfo& app_info)
        {
            std::string sql;
            sql.append("INSERT INTO AppInfo (id, app_name, executable_path, icon_path, create_time, update_time) VALUES (");
            sql.append(std::to_string(app_info.id));
            sql.append(", '");
            sql.append(app_info.app_name);
            sql.append("', '");
            sql.append(app_info.executable_path);
            sql.append("', '");
            sql.append(app_info.icon_path);
            sql.append("', '");
            sql.append(app_info.create_time);
            sql.append("', '");
            sql.append(app_info.create_time);
            sql.append("');");

            mtx.lock();
            bool result = Utils::mysqlQuery(mysql, sql);
            mtx.unlock();

            return result;
        }

        // 更新应用信息
        bool updateAppInfo(const AppInfo& app_info)
        {
            std::string sql;
            sql.append("UPDATE AppInfo SET app_name = '");
            sql.append(app_info.app_name);
            sql.append("', executable_path = '");
            sql.append(app_info.executable_path);
            sql.append("', icon_path = '");
            sql.append(app_info.icon_path);
            sql.append("', update_time = '");
            sql.append(app_info.update_time);
            sql.append("' WHERE id = ");
            sql.append(std::to_string(app_info.id));
            sql.append(";");

            mtx.lock();
            bool result = Utils::mysqlQuery(mysql, sql);
            mtx.unlock();

            return result;
        }
        // 获取所有应用信息
        bool getAllAppInfo(std::vector<AppInfo>& app_info_list)
        {
            std::string sql = "SELECT * FROM app_info;";

            mtx.lock();
            if (!Utils::mysqlQuery(mysql, sql))
            {
                mtx.unlock();
                return false;
            }

            MYSQL_RES* res = mysql_store_result(mysql);
            if (res == nullptr)
            {
                LOG_ERROR("mysql store result error: {}", std::string(mysql_error(mysql)));
                mtx.unlock();
                return false;
            }
            mtx.unlock();

            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr)
            {
                AppInfo app_info;
                app_info.id = std::stoull(row[0]);
                app_info.app_name = row[1];
                app_info.executable_path = row[2];
                app_info.icon_path = row[3] ? row[3] : "";
                app_info.create_time = row[4];
                app_info.update_time = row[5];

                app_info_list.push_back(app_info);
            }

            mysql_free_result(res);
            return true;
        }
    };

    class MonitoringRuleTable : public BaseTable
    {
    public:
        using ptr = std::shared_ptr<MonitoringRuleTable>;

        // 通过应用ID获取监控规则
        bool getMonitoringRuleByAppId(uint64_t app_id, MonitoringRule& rule)
        {
            std::string sql = "SELECT * FROM monitoring_rule WHERE app_id = ";
            sql.append(std::to_string(app_id));
            sql.append(";");

            mtx.lock();
            if (!Utils::mysqlQuery(mysql, sql))
            {
                mtx.unlock();
                return false;
            }

            MYSQL_RES* res = mysql_store_result(mysql);
            if (res == nullptr)
            {
                LOG_ERROR("mysql store result error: {}", std::string(mysql_error(mysql)));
                mtx.unlock();
                return false;
            }
            mtx.unlock();

            MYSQL_ROW row = mysql_fetch_row(res);
            if (row != nullptr)
            {
                rule.id = std::stoull(row[0]);
                rule.app_id = std::stoull(row[1]);
                rule.is_camouflaged = std::stoi(row[2]);
                rule.camouflage_pid = std::stoul(row[3]);
                rule.is_recording_prevention_enabled = std::stoi(row[4]);
                rule.current_wnd = std::stoul(row[5]);
                rule.hwnd_val = std::stoul(row[6]);
                rule.is_protected = std::stoi(row[7]);
                rule.force_delete = std::stoi(row[8]);
                rule.file_name = row[9] ? row[9] : "";

                mysql_free_result(res);
                return true;
            }

            mysql_free_result(res);
            return false;
        }


        // 获取所有监控规则
        bool getAllMonitoringRules(std::vector<MonitoringRule>& rules)
        {
            std::string sql = "SELECT * FROM monitoring_rule;";

            mtx.lock();
            if (!Utils::mysqlQuery(mysql, sql))
            {
                mtx.unlock();
                return false;
            }

            MYSQL_RES* res = mysql_store_result(mysql);
            if (res == nullptr)
            {
                LOG_ERROR("mysql store result error: {}", std::string(mysql_error(mysql)));
                mtx.unlock();
                return false;
            }
            mtx.unlock();

            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr)
            {
                MonitoringRule rule;
                rule.id = std::stoull(row[0]);
                rule.app_id = std::stoull(row[1]);
                rule.is_camouflaged = std::stoi(row[2]);
                rule.camouflage_pid = std::stoul(row[3]);
                rule.is_recording_prevention_enabled = std::stoi(row[4]);
                rule.current_wnd = std::stoul(row[5]);
                rule.hwnd_val = std::stoul(row[6]);
                rule.is_protected = std::stoi(row[7]);
                rule.force_delete = std::stoi(row[8]);
                rule.file_name = row[9] ? row[9] : "";

                rules.push_back(rule);
            }

            mysql_free_result(res);
            return true;
        }

        // 创建新的监控规则
        bool createMonitoringRule(const MonitoringRule& rule)
        {
            std::string sql = "INSERT INTO monitoring_rule (app_id, is_camouflaged, camouflage_pid, "
                "is_recording_prevention_enabled, current_wnd, hwnd_val, is_protected, force_delete, file_name) VALUES (";
            sql.append(std::to_string(rule.app_id) + ", ");
            sql.append(std::to_string(rule.is_camouflaged) + ", ");
            sql.append(std::to_string(rule.camouflage_pid) + ", ");
            sql.append(std::to_string(rule.is_recording_prevention_enabled) + ", ");
            sql.append(std::to_string(rule.current_wnd) + ", ");
            sql.append(std::to_string(rule.hwnd_val) + ", ");
            sql.append(std::to_string(rule.is_protected) + ", ");
            sql.append(std::to_string(rule.force_delete) + ", ");
            sql.append("'" + rule.file_name + "');");

            mtx.lock();
            bool result = Utils::mysqlQuery(mysql, sql);
            mtx.unlock();

            return result;
        }

        // 更新监控规则
        bool updateMonitoringRule(const MonitoringRule& rule)
        {
            std::string sql = "UPDATE monitoring_rule SET "
                "app_id = " + std::to_string(rule.app_id) + ", "
                "is_camouflaged = " + std::to_string(rule.is_camouflaged) + ", "
                "camouflage_pid = " + std::to_string(rule.camouflage_pid) + ", "
                "is_recording_prevention_enabled = " + std::to_string(rule.is_recording_prevention_enabled) + ", "
                "current_wnd = " + std::to_string(rule.current_wnd) + ", "
                "hwnd_val = " + std::to_string(rule.hwnd_val) + ", "
                "is_protected = " + std::to_string(rule.is_protected) + ", "
                "force_delete = " + std::to_string(rule.force_delete) + ", "
                "file_name = '" + rule.file_name + "' "
                "WHERE id = " + std::to_string(rule.id) + ";";

            mtx.lock();
            bool result = Utils::mysqlQuery(mysql, sql);
            mtx.unlock();

            return result;
        }


        // 删除监控规则
        bool deleteMonitoringRule(uint64_t app_id)
        {
            std::string sql = "DELETE FROM monitoring_rules WHERE app_id = ";
            sql.append(std::to_string(app_id));
            sql.append(";");

            mtx.lock();
            bool result = Utils::mysqlQuery(mysql, sql);
            mtx.unlock();

            return result;
        }
    };

    class SystemMonitorTable : public BaseTable
    {
    public:
        using ptr = std::shared_ptr<SystemMonitorTable>;

        // 插入系统监控记录
        bool insertSystemMonitor(const SystemMonitor& record)
        {
            std::string sql;
            sql.append("INSERT INTO system_monitor (cpu_usage, memory_usage, disk_usage, network_upload, network_download, temperature, sample_time) ");
            sql.append("VALUES (");
            sql.append(std::to_string(record.cpu_usage));
            sql.append(", ");
            sql.append(std::to_string(record.memory_usage));
            sql.append(", ");
            sql.append(std::to_string(record.disk_usage));
            sql.append(", ");
            sql.append(std::to_string(record.network_upload));
            sql.append(", ");
            sql.append(std::to_string(record.network_download));
            sql.append(", ");
            sql.append(record.temperature >= 0 ? std::to_string(record.temperature) : "NULL");  // 允许温度为NULL
            sql.append(", '");
            sql.append(record.sample_time);  // 使用字符串格式的时间
            sql.append("');");

            mtx.lock();
            bool result = Utils::mysqlQuery(mysql, sql);
            mtx.unlock();

            return result;
        }

        // 获取所有系统监控记录
        bool getAllSystemMonitors(std::vector<SystemMonitor>& records)
        {
            std::string sql = "SELECT * FROM system_monitor;";

            mtx.lock();
            if (!Utils::mysqlQuery(mysql, sql))
            {
                mtx.unlock();
                return false;
            }

            MYSQL_RES* res = mysql_store_result(mysql);
            if (res == nullptr)
            {
                LOG_ERROR("mysql store result error: {}", std::string(mysql_error(mysql)));
                mtx.unlock();
                return false;
            }
            mtx.unlock();

            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr)
            {
                SystemMonitor record;
                record.id = std::stoull(row[0]);                    // 主键ID
                record.cpu_usage = std::stod(row[1]);               // CPU使用率
                record.memory_usage = std::stod(row[2]);            // 内存使用率
                record.disk_usage = std::stod(row[3]);              // 磁盘使用率
                record.network_upload = std::stod(row[4]);          // 上传速度
                record.network_download = std::stod(row[5]);        // 下载速度
                record.temperature = row[6] ? std::stod(row[6]) : -1; // 温度（如果是NULL则赋值为-1）
                record.sample_time = row[7] ? row[7] : "";          // 采样时间

                records.push_back(record);
            }

            mysql_free_result(res);
            return true;
        }

        // 获取特定时间范围内的系统监控记录
        bool getSystemMonitorsByTime(const std::string& start_time, const std::string& end_time, std::vector<SystemMonitor>& records)
        {
            std::string sql = "SELECT * FROM system_monitor WHERE sample_time BETWEEN '";
            sql.append(start_time);
            sql.append("' AND '");
            sql.append(end_time);
            sql.append("';");

            mtx.lock();
            if (!Utils::mysqlQuery(mysql, sql))
            {
                mtx.unlock();
                return false;
            }

            MYSQL_RES* res = mysql_store_result(mysql);
            if (res == nullptr)
            {
                LOG_ERROR("mysql store result error: {}", std::string(mysql_error(mysql)));
                mtx.unlock();
                return false;
            }
            mtx.unlock();

            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr)
            {
                SystemMonitor record;
                record.id = std::stoull(row[0]);                    // 主键ID
                record.cpu_usage = std::stod(row[1]);               // CPU使用率
                record.memory_usage = std::stod(row[2]);            // 内存使用率
                record.disk_usage = std::stod(row[3]);              // 磁盘使用率
                record.network_upload = std::stod(row[4]);          // 上传速度
                record.network_download = std::stod(row[5]);        // 下载速度
                record.temperature = row[6] ? std::stod(row[6]) : -1; // 温度
                record.sample_time = row[7] ? row[7] : "";          // 采样时间

                records.push_back(record);
            }

            mysql_free_result(res);
            return true;
        }
    };

    class AppResourceMonitorTable : public BaseTable
    {
    public:
        using ptr = std::shared_ptr<AppResourceMonitorTable>;

        // 插入应用资源监控记录
        bool insertAppResourceMonitor(const AppResourceMonitor& record)
        {
            std::string sql;
            sql.append("INSERT INTO app_resource_monitor (app_id, app_name, icon_path, cpu_usage, memory_usage_mb, ");
            sql.append("disk_io_read, disk_io_write, gpu_usage, sample_time) ");
            sql.append("VALUES (");
            sql.append(std::to_string(record.app_id));
            sql.append(", '");
            sql.append(record.app_name);
            sql.append("', '");
            sql.append(record.icon_path.empty() ? "NULL" : record.icon_path);
            sql.append("', ");
            sql.append(std::to_string(record.cpu_usage));
            sql.append(", ");
            sql.append(std::to_string(record.memory_usage_mb));
            sql.append(", ");
            sql.append(std::to_string(record.disk_io_read));
            sql.append(", ");
            sql.append(std::to_string(record.disk_io_write));
            sql.append(", ");
            sql.append(record.sample_time);  // 使用字符串格式的时间
            sql.append("');");

            mtx.lock();
            bool result = Utils::mysqlQuery(mysql, sql);
            mtx.unlock();

            return result;
        }

        // 获取所有应用资源监控记录
        bool getAllAppResourceMonitors(std::vector<AppResourceMonitor>& records)
        {
            std::string sql = "SELECT * FROM app_resource_monitor;";

            mtx.lock();
            if (!Utils::mysqlQuery(mysql, sql))
            {
                mtx.unlock();
                return false;
            }

            MYSQL_RES* res = mysql_store_result(mysql);
            if (res == nullptr)
            {
                LOG_ERROR("mysql store result error: {}", std::string(mysql_error(mysql)));
                mtx.unlock();
                return false;
            }
            mtx.unlock();

            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr)
            {
                AppResourceMonitor record;
                record.id = std::stoull(row[0]);                       // 主键ID
                record.app_id = std::stoi(row[1]);                     // 关联应用ID
                record.app_name = row[2];                               // 应用名称
                record.icon_path = row[3] ? row[3] : "";               // 图标文件路径
                record.cpu_usage = std::stod(row[4]);                  // 进程CPU使用率
                record.memory_usage_mb = std::stod(row[5]);            // 内存占用量 (MB)
                record.disk_io_read = std::stod(row[6]);               // 磁盘读取速度 (MB/s)
                record.disk_io_write = std::stod(row[7]);              // 磁盘写入速度 (MB/s)
                record.sample_time = row[8] ? row[8] : "";             // 采样时间

                records.push_back(record);
            }

            mysql_free_result(res);
            return true;
        }

        // 获取特定应用的监控记录
        bool getAppResourceMonitorsByAppId(uint32_t app_id, std::vector<AppResourceMonitor>& records)
        {
            std::string sql = "SELECT * FROM app_resource_monitor WHERE app_id = ";
            sql.append(std::to_string(app_id));
            sql.append(";");

            mtx.lock();
            if (!Utils::mysqlQuery(mysql, sql))
            {
                mtx.unlock();
                return false;
            }

            MYSQL_RES* res = mysql_store_result(mysql);
            if (res == nullptr)
            {
                LOG_ERROR("mysql store result error: {}", std::string(mysql_error(mysql)));
                mtx.unlock();
                return false;
            }
            mtx.unlock();

            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr)
            {
                AppResourceMonitor record;
                record.id = std::stoull(row[0]);                       // 主键ID
                record.app_id = std::stoi(row[1]);                     // 关联应用ID
                record.app_name = row[2];                               // 应用名称
                record.icon_path = row[3] ? row[3] : "";               // 图标文件路径
                record.cpu_usage = std::stod(row[4]);                  // 进程CPU使用率
                record.memory_usage_mb = std::stod(row[5]);            // 内存占用量 (MB)
                record.disk_io_read = std::stod(row[6]);               // 磁盘读取速度 (MB/s)
                record.disk_io_write = std::stod(row[7]);              // 磁盘写入速度 (MB/s)
                record.sample_time = row[8] ? row[8] : "";             // 采样时间

                records.push_back(record);
            }

            mysql_free_result(res);
            return true;
        }
    };

    class MaliciousThreadLogTable : public BaseTable
    {
    public:
        using ptr = std::shared_ptr<MaliciousThreadLogTable>;

        // 插入恶意线程日志记录
        bool insertMaliciousThreadLogs(const MaliciousThreadLog& record)
        {
            std::string sql;
            sql.append("INSERT INTO malicious_thread_logs (app_id, thread_name, thread_hash, risk_level, detection_time) ");
            sql.append("VALUES (");
            sql.append(std::to_string(record.app_id));
            sql.append(", '");
            sql.append(record.thread_name);
            sql.append("', '");
            sql.append(record.thread_hash);
            sql.append("', ");
            sql.append(std::to_string(record.risk_level));
            sql.append(", '");
            sql.append(record.detection_time);  // 使用字符串格式的时间
            sql.append("');");

            mtx.lock();
            bool result = Utils::mysqlQuery(mysql, sql);
            mtx.unlock();

            return result;
        }

        // 获取所有恶意线程日志记录
        bool getAllMaliciousThreadLogs(std::vector<MaliciousThreadLog>& logs)
        {
            std::string sql = "SELECT * FROM malicious_thread_logs;";

            mtx.lock();
            if (!Utils::mysqlQuery(mysql, sql))
            {
                mtx.unlock();
                return false;
            }

            MYSQL_RES* res = mysql_store_result(mysql);
            if (res == nullptr)
            {
                LOG_ERROR("mysql store result error: {}", std::string(mysql_error(mysql)));
                mtx.unlock();
                return false;
            }
            mtx.unlock();

            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr)
            {
                MaliciousThreadLog record;
                record.id = std::stoull(row[0]);                    // 主键ID
                record.app_id = std::stoi(row[1]);                  // 关联应用ID
                record.thread_name = row[2];                         // 可疑线程名称
                record.thread_hash = row[3];                         // 线程特征哈希值
                record.risk_level = static_cast<uint8_t>(std::stoi(row[4]));  // 风险等级
                record.detection_time = row[5] ? row[5] : "";       // 检测到的时间

                logs.push_back(record);
            }

            mysql_free_result(res);
            return true;
        }

        // 获取指定应用的恶意线程日志
        bool getMaliciousThreadLogsByAppId(uint32_t app_id, std::vector<MaliciousThreadLog>& logs)
        {
            std::string sql = "SELECT * FROM malicious_thread_logs WHERE app_id = ";
            sql.append(std::to_string(app_id));
            sql.append(";");

            mtx.lock();
            if (!Utils::mysqlQuery(mysql, sql))
            {
                mtx.unlock();
                return false;
            }

            MYSQL_RES* res = mysql_store_result(mysql);
            if (res == nullptr)
            {
                LOG_ERROR("mysql store result error: {}", std::string(mysql_error(mysql)));
                mtx.unlock();
                return false;
            }
            mtx.unlock();

            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr)
            {
                MaliciousThreadLog record;
                record.id = std::stoull(row[0]);                    // 主键ID
                record.app_id = std::stoi(row[1]);                  // 关联应用ID
                record.thread_name = row[2];                         // 可疑线程名称
                record.thread_hash = row[3];                         // 线程特征哈希值
                record.risk_level = static_cast<uint8_t>(std::stoi(row[4]));  // 风险等级
                record.detection_time = row[5] ? row[5] : "";       // 检测到的时间

                logs.push_back(record);
            }

            mysql_free_result(res);
            return true;
        }

        // 获取指定线程哈希的恶意线程日志
        bool getMaliciousThreadLogsByThreadHash(const std::string& thread_hash, std::vector<MaliciousThreadLog>& logs)
        {
            std::string sql = "SELECT * FROM malicious_thread_logs WHERE thread_hash = '";
            sql.append(thread_hash);
            sql.append("';");

            mtx.lock();
            if (!Utils::mysqlQuery(mysql, sql))
            {
                mtx.unlock();
                return false;
            }

            MYSQL_RES* res = mysql_store_result(mysql);
            if (res == nullptr)
            {
                LOG_ERROR("mysql store result error: {}", std::string(mysql_error(mysql)));
                mtx.unlock();
                return false;
            }
            mtx.unlock();

            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr)
            {
                MaliciousThreadLog record;
                record.id = std::stoull(row[0]);                    // 主键ID
                record.app_id = std::stoi(row[1]);                  // 关联应用ID
                record.thread_name = row[2];                         // 可疑线程名称
                record.thread_hash = row[3];                         // 线程特征哈希值
                record.risk_level = static_cast<uint8_t>(std::stoi(row[4]));  // 风险等级
                record.detection_time = row[5] ? row[5] : "";       // 检测到的时间

                logs.push_back(record);
            }

            mysql_free_result(res);
            return true;
        }
    };

    class FileModificationLogTable : public BaseTable
    {
    public:
        using ptr = std::shared_ptr<FileModificationLogTable>;

        // 插入文件修改日志记录
        bool insertFileModificationLogs(const FileModificationLog& record)
        {
            std::string sql;
            sql.append("INSERT INTO file_modification_logs (app_id, file_path, operation_type, file_hash, alert_time) ");
            sql.append("VALUES (");
            sql.append(std::to_string(record.app_id));
            sql.append(", '");
            sql.append(record.file_path);
            sql.append("', '");
            sql.append(record.operation_type);
            sql.append("', '");
            sql.append(record.file_hash);
            sql.append("', '");
            sql.append(record.alert_time);  // 使用字符串格式的时间
            sql.append("');");

            mtx.lock();
            bool result = Utils::mysqlQuery(mysql, sql);
            mtx.unlock();

            return result;
        }

        // 获取所有文件修改日志记录
        bool getAllFileModificationLogs(std::vector<FileModificationLog>& logs)
        {
            std::string sql = "SELECT * FROM file_modification_logs;";

            mtx.lock();
            if (!Utils::mysqlQuery(mysql, sql))
            {
                mtx.unlock();
                return false;
            }

            MYSQL_RES* res = mysql_store_result(mysql);
            if (res == nullptr)
            {
                LOG_ERROR("mysql store result error: {}", std::string(mysql_error(mysql)));
                mtx.unlock();
                return false;
            }
            mtx.unlock();

            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr)
            {
                FileModificationLog record;
                record.id = std::stoull(row[0]);                  // 主键ID
                record.app_id = std::stoull(row[1]);              // 关联应用ID
                record.file_path = row[2];                        // 被修改的文件路径
                record.operation_type = row[3];                   // 操作类型（CREATE/MODIFY/DELETE）
                record.file_hash = row[4] ? row[4] : "";         // 文件哈希值（修改后）
                record.alert_time = row[5] ? row[5] : "";         // 告警触发时间

                logs.push_back(record);
            }

            mysql_free_result(res);
            return true;
        }

        // 获取指定应用的文件修改日志记录
        bool getFileModificationLogsByAppId(uint64_t app_id, std::vector<FileModificationLog>& logs)
        {
            std::string sql = "SELECT * FROM file_modification_logs WHERE app_id = ";
            sql.append(std::to_string(app_id));
            sql.append(";");

            mtx.lock();
            if (!Utils::mysqlQuery(mysql, sql))
            {
                mtx.unlock();
                return false;
            }

            MYSQL_RES* res = mysql_store_result(mysql);
            if (res == nullptr)
            {
                LOG_ERROR("mysql store result error: {}", std::string(mysql_error(mysql)));
                mtx.unlock();
                return false;
            }
            mtx.unlock();

            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr)
            {
                FileModificationLog record;
                record.id = std::stoull(row[0]);                  // 主键ID
                record.app_id = std::stoull(row[1]);              // 关联应用ID
                record.file_path = row[2];                        // 被修改的文件路径
                record.operation_type = row[3];                   // 操作类型（CREATE/MODIFY/DELETE）
                record.file_hash = row[4] ? row[4] : "";         // 文件哈希值（修改后）
                record.alert_time = row[5] ? row[5] : "";         // 告警触发时间

                logs.push_back(record);
            }

            mysql_free_result(res);
            return true;
        }

        // 获取指定文件路径的文件修改日志记录
        bool getFileModificationLogsByFilePath(const std::string& file_path, std::vector<FileModificationLog>& logs)
        {
            std::string sql = "SELECT * FROM file_modification_logs WHERE file_path = '";
            sql.append(file_path);
            sql.append("';");

            mtx.lock();
            if (!Utils::mysqlQuery(mysql, sql))
            {
                mtx.unlock();
                return false;
            }

            MYSQL_RES* res = mysql_store_result(mysql);
            if (res == nullptr)
            {
                LOG_ERROR("mysql store result error: {}", std::string(mysql_error(mysql)));
                mtx.unlock();
                return false;
            }
            mtx.unlock();

            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr)
            {
                FileModificationLog record;
                record.id = std::stoull(row[0]);                  // 主键ID
                record.app_id = std::stoull(row[1]);              // 关联应用ID
                record.file_path = row[2];                        // 被修改的文件路径
                record.operation_type = row[3];                   // 操作类型（CREATE/MODIFY/DELETE）
                record.file_hash = row[4] ? row[4] : "";         // 文件哈希值（修改后）
                record.alert_time = row[5] ? row[5] : "";         // 告警触发时间

                logs.push_back(record);
            }

            mysql_free_result(res);
            return true;
        }
    };

    class AIAnalysisResultTable : public BaseTable
    {
    public:
        using ptr = std::shared_ptr<AIAnalysisResultTable>;

        // 插入AI分析结果记录
        bool insertAIAnalysisResult(const AIAnalysisResult& result)
        {
            std::string sql;
            sql.append("INSERT INTO ai_analysis_result (id, user_id, analysis_type, content_hash, result, confidence, analysis_time, score) ");
            sql.append("VALUES (");
            sql.append(std::to_string(result.id));
            sql.append(", '");
            sql.append(std::to_string(result.user_id));
            sql.append("', '");
            sql.append(result.analysis_type);
            sql.append("', '");
            sql.append(result.content_hash);
            sql.append("', '");
            sql.append(result.result);
            sql.append("', ");
            sql.append(std::to_string(result.confidence));
            sql.append(", '");
            sql.append(result.analysis_time);
            sql.append("', ");  
            sql.append(std::to_string(result.score)); 
            sql.append(");");   

            mtx.lock();
            bool result_status = Utils::mysqlQuery(mysql, sql);
            mtx.unlock();

            return result_status;
        }

        // 获取所有AI分析结果记录
        bool getAllAIAnalysisResults(std::vector<AIAnalysisResult>& results)
        {
            std::string sql = "SELECT * FROM ai_analysis_result;";

            mtx.lock();
            if (!Utils::mysqlQuery(mysql, sql))
            {
                mtx.unlock();
                return false;
            }

            MYSQL_RES* res = mysql_store_result(mysql);
            if (res == nullptr)
            {
                LOG_ERROR("mysql store result error: {}", std::string(mysql_error(mysql)));
                mtx.unlock();
                return false;
            }
            mtx.unlock();

            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr)
            {
                AIAnalysisResult result;
                result.id = std::stoull(row[0]);
                result.user_id = std::stoull(row[1]);
                result.analysis_type = row[2];
                result.content_hash = row[3];
                result.result = row[4];
                result.confidence = std::stof(row[5]);
                result.analysis_time = row[6];
                result.score = static_cast<uint16_t>(std::stoi(row[7]));  

                results.push_back(result);
            }

            mysql_free_result(res);
            return true;
        }

        // 获取指定用户的AI分析结果记录
        bool getAIAnalysisResultsByUserId(uint64_t user_id, std::vector<AIAnalysisResult>& results)
        {
            std::string sql = "SELECT * FROM ai_analysis_result WHERE user_id = ";
            sql.append(std::to_string(user_id));
            sql.append(";");

            mtx.lock();
            if (!Utils::mysqlQuery(mysql, sql))
            {
                mtx.unlock();
                return false;
            }

            MYSQL_RES* res = mysql_store_result(mysql);
            if (res == nullptr)
            {
                LOG_ERROR("mysql store result error: {}", std::string(mysql_error(mysql)));
                mtx.unlock();
                return false;
            }
            mtx.unlock();

            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr)
            {
                AIAnalysisResult result;
                result.id = std::stoull(row[0]);
                result.user_id = std::stoull(row[1]);
                result.analysis_type = row[2];
                result.content_hash = row[3];
                result.result = row[4];
                result.confidence = std::stof(row[5]);
                result.analysis_time = row[6];
                result.score = static_cast<uint16_t>(std::stoi(row[7]));  

                results.push_back(result);
            }

            mysql_free_result(res);
            return true;
        }
    };

    class SystemConfigTable : public BaseTable
    {
    public:
        using ptr = std::shared_ptr<SystemConfigTable>;

        // 插入系统配置
        bool insertSystemConfig(const SystemConfig& config)
        {
            std::string sql;
            sql.append("INSERT INTO system_config (config_key, config_value, description, last_modified) ");
            sql.append("VALUES ('");
            sql.append(config.config_key);
            sql.append("', '");
            sql.append(config.config_value);
            sql.append("', '");
            sql.append(config.description);
            sql.append("', '");
            sql.append(config.last_modified);
            sql.append("');");

            mtx.lock();
            bool result_status = Utils::mysqlQuery(mysql, sql);
            mtx.unlock();

            return result_status;
        }

        // 获取所有系统配置
        bool getAllSystemConfig(std::vector<SystemConfig>& configs)
        {
            std::string sql = "SELECT * FROM system_config;";

            mtx.lock();
            if (!Utils::mysqlQuery(mysql, sql))
            {
                mtx.unlock();
                return false;
            }

            MYSQL_RES* res = mysql_store_result(mysql);
            if (res == nullptr)
            {
                LOG_ERROR("mysql store result error: {}", std::string(mysql_error(mysql)));
                mtx.unlock();
                return false;
            }
            mtx.unlock();

            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr)
            {
                SystemConfig config;
                config.config_key = row[0];
                config.config_value = row[1];
                config.description = row[2] ? row[2] : "";
                config.last_modified = row[3];

                configs.push_back(config);
            }

            mysql_free_result(res);
            return true;
        }
    };

    class UserInfoTable : public BaseTable
    {
    public:
        using ptr = std::shared_ptr<UserInfoTable>;

        // 用户登录验证
        bool verifyUserLogin(std::string_view username, std::string_view password)
        {
            // 构造SQL查询语句
            std::string sql = "SELECT password, is_locked FROM user_info WHERE username = '";
            sql.append(username);
            sql.append("';");

            mtx.lock();
            if (!Utils::mysqlQuery(mysql, sql))
            {
                mtx.unlock();
                return false;
            }

            MYSQL_RES* res = mysql_store_result(mysql);
            if (res == nullptr)
            {
                LOG_ERROR("mysql store result error: {}", std::string(mysql_error(mysql)));
                mtx.unlock();
                return false;
            }

            MYSQL_ROW row = mysql_fetch_row(res);
            mtx.unlock();

            if (row == nullptr)
            {
                // 用户名不存在
                mysql_free_result(res);
                return false;
            }

            std::string stored_password = row[0];
            bool is_locked = row[1][0] == '1';  // 假设 1 表示锁定，0 表示未锁定

            // 检查用户是否被锁定
            if (is_locked)
            {
                mysql_free_result(res);
                return false;  // 用户被锁定，不能登录
            }

            // 验证密码是否正确
            if (password == stored_password)
            {
                mysql_free_result(res);
                return true;  // 登录成功
            }

            mysql_free_result(res);
            return false;  // 密码错误
        }

        // 插入用户信息
        bool insertUserInfo(const UserInfo& user)
        {
            std::string sql;
            sql.append("INSERT INTO user_info (user_id, username, password, role, email, phone, last_login_ip, last_login_time, is_locked, create_time) ");
            sql.append("VALUES ('");
            sql.append(std::to_string(user.user_id));
            sql.append("', '");
            sql.append(user.username);
            sql.append("', '");
            sql.append(user.password);
            sql.append("', '");
            sql.append(user.role);
            sql.append("', '");
            sql.append(user.email);
            sql.append("', '");
            sql.append(user.phone);
            sql.append("', '");
            sql.append(user.last_login_ip);
            sql.append("', '");
            sql.append(user.last_login_time);
            sql.append("', ");
            sql.append(std::to_string(user.is_locked));
            sql.append(", '");
            sql.append(user.create_time);
            sql.append("');");

            mtx.lock();
            bool result_status = Utils::mysqlQuery(mysql, sql);
            mtx.unlock();

            return result_status;
        }

        // 获取所有用户信息
        bool getAllUserInfo(std::vector<UserInfo>& users)
        {
            std::string sql = "SELECT * FROM user_info;";

            mtx.lock();
            if (!Utils::mysqlQuery(mysql, sql))
            {
                mtx.unlock();
                return false;
            }

            MYSQL_RES* res = mysql_store_result(mysql);
            if (res == nullptr)
            {
                LOG_ERROR("mysql store result error: {}", std::string(mysql_error(mysql)));
                mtx.unlock();
                return false;
            }
            mtx.unlock();

            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr)
            {
                UserInfo user;
                user.user_id = std::stoull(row[0]);
                user.username = row[1];
                user.password = row[2];
                user.role = row[3];
                user.email = row[4];
                user.phone = row[5];
                user.last_login_ip = row[6] ? row[6] : "";
                user.last_login_time = row[7] ? row[7] : "";
                user.is_locked = row[8][0] == '1';
                user.create_time = row[9];

                users.push_back(user);
            }

            mysql_free_result(res);
            return true;
        }

        // 获取指定用户ID的信息
        bool getUserInfoById(uint64_t user_id, UserInfo& user)
        {
            std::string sql = "SELECT * FROM user_info WHERE user_id = ";
            sql.append(std::to_string(user_id));
            sql.append(";");

            mtx.lock();
            if (!Utils::mysqlQuery(mysql, sql))
            {
                mtx.unlock();
                return false;
            }

            MYSQL_RES* res = mysql_store_result(mysql);
            if (res == nullptr)
            {
                LOG_ERROR("mysql store result error: {}", std::string(mysql_error(mysql)));
                mtx.unlock();
                return false;
            }
            mtx.unlock();

            MYSQL_ROW row = mysql_fetch_row(res);
            if (row != nullptr)
            {
                user.user_id = std::stoull(row[0]);
                user.username = row[1];
                user.password = row[2];
                user.role = row[3];
                user.email = row[4];
                user.phone = row[5];
                user.last_login_ip = row[6] ? row[6] : "";
                user.last_login_time = row[7] ? row[7] : "";
                user.is_locked = row[8][0] == '1';
                user.create_time = row[9];
            }

            mysql_free_result(res);
            return row != nullptr;
        }
    
        // 获取指定电子邮件地址的用户信息
        bool getUserInfoByEmail(const std::string& email, UserInfo& user)
        {
            std::string sql = "SELECT * FROM user_info WHERE email = '";
            sql.append(email);
            sql.append("';");

            mtx.lock();
            if (!Utils::mysqlQuery(mysql, sql))
            {
                mtx.unlock();
                return false;
            }

            MYSQL_RES* res = mysql_store_result(mysql);
            if (res == nullptr)
            {
                LOG_ERROR("mysql store result error: {}", std::string(mysql_error(mysql)));
                mtx.unlock();
                return false;
            }
            mtx.unlock();

            MYSQL_ROW row = mysql_fetch_row(res);
            if (row != nullptr)
            {
                user.user_id = std::stoull(row[0]);
                user.username = row[1];
                user.password = row[2];
                user.role = row[3];
                user.email = row[4];
                user.phone = row[5];
                user.last_login_ip = row[6] ? row[6] : "";
                user.last_login_time = row[7] ? row[7] : "";
                user.is_locked = row[8][0] == '1';
                user.create_time = row[9];
            }

            mysql_free_result(res);
            return row != nullptr;
        }

        // 更新用户信息
        bool updateUserInfo(const UserInfo& user)
        {
            std::string sql;
            sql.append("UPDATE user_info SET ");
            sql.append("username = '").append(user.username).append("', ");
            sql.append("password = '").append(user.password).append("', ");
            sql.append("role = '").append(user.role).append("', ");
            sql.append("email = '").append(user.email).append("', ");
            sql.append("phone = '").append(user.phone).append("', ");
            sql.append("last_login_ip = '").append(user.last_login_ip).append("', ");
            sql.append("last_login_time = '").append(user.last_login_time).append("', ");
            sql.append("is_locked = ").append(std::to_string(user.is_locked)).append(", ");
            sql.append("create_time = '").append(user.create_time).append("' ");
            sql.append("WHERE user_id = ").append(std::to_string(user.user_id)).append(";");

            mtx.lock();
            bool result_status = Utils::mysqlQuery(mysql, sql);
            mtx.unlock();

            return result_status;
        }

};

    class UserOperationLogTable : public BaseTable
    {
    public:
        using ptr = std::shared_ptr<UserOperationLogTable>;

        // 插入用户操作日志
        bool insertUserOperationLog(const UserOperationLog& log)
        {
            std::string sql;
            sql.append("INSERT INTO user_operation_logs (user_id, operation_type, target_id, operation_detail, client_info, operation_time, result_status) ");
            sql.append("VALUES (");
            sql.append(std::to_string(log.user_id));
            sql.append(", '");
            sql.append(log.operation_type);
            sql.append("', ");
            sql.append(std::to_string(log.target_id));
            sql.append(", '");
            sql.append(log.operation_detail);
            sql.append("', '");
            sql.append(log.client_info);
            sql.append("', '");
            sql.append(log.operation_time);
            sql.append("', ");
            sql.append(std::to_string(log.result_status));
            sql.append(");");

            mtx.lock();
            bool result_status = Utils::mysqlQuery(mysql, sql);
            mtx.unlock();

            return result_status;
        }

        // 获取所有用户操作日志
        bool getAllUserOperationLogs(std::vector<UserOperationLog>& logs)
        {
            std::string sql = "SELECT * FROM user_operation_logs;";

            mtx.lock();
            if (!Utils::mysqlQuery(mysql, sql))
            {
                mtx.unlock();
                return false;
            }

            MYSQL_RES* res = mysql_store_result(mysql);
            if (res == nullptr)
            {
                LOG_ERROR("mysql store result error: {}", std::string(mysql_error(mysql)));
                mtx.unlock();
                return false;
            }
            mtx.unlock();

            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr)
            {
                UserOperationLog log;
                log.log_id = std::stoull(row[0]);
                log.user_id = std::stoull(row[1]);
                log.operation_type = row[2];
                log.target_id = std::stoull(row[3]);
                log.operation_detail = row[4] ? row[4] : "";
                log.client_info = row[5];
                log.operation_time = row[6];
                log.result_status = row[7][0] == '1';

                logs.push_back(log);
            }

            mysql_free_result(res);
            return true;
        }

        bool getUserOperationLogsByUserId(uint64_t user_id, std::vector<UserOperationLog>& logs)
        {
            std::string sql = "SELECT * FROM user_operation_logs WHERE user_id = " + std::to_string(user_id) + ";";

            mtx.lock();
            if (!Utils::mysqlQuery(mysql, sql))
            {
                mtx.unlock();
                return false;
            }

            MYSQL_RES* res = mysql_store_result(mysql);
            if (res == nullptr)
            {
                LOG_ERROR("mysql store result error: {}", mysql_error(mysql));
                mtx.unlock();
                return false;
            }
            mtx.unlock();

            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr)
            {
                UserOperationLog log;
                log.log_id = std::stoull(row[0]);
                log.user_id = std::stoull(row[1]);
                log.operation_type = row[2];
                log.target_id = std::stoull(row[3]);
                log.operation_detail = row[4] ? row[4] : "";
                log.client_info = row[5];
                log.operation_time = row[6];
                log.result_status = row[7][0] == '1'; // 假设 result_status 存储为 0/1

                logs.push_back(log);
            }

            mysql_free_result(res);
            return true;
        }
    };

}