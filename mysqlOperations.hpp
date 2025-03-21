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

        // ͨ��Ӧ�����ƻ�ȡӦ����Ϣ
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

        // ����ID��ȡӦ����Ϣ
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


        // ������Ӧ����Ϣ
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
        bool createOrUpdateAppInfoBatch(const std::vector<AppInfo>& app_info_list)
        {
            if (app_info_list.empty())
            {
                return false;
            }

            std::string sql;
            sql.append("INSERT INTO AppInfo (id, app_name, executable_path, icon_path, create_time, update_time) VALUES ");

            for (size_t i = 0; i < app_info_list.size(); ++i)
            {
                const AppInfo& app_info = app_info_list[i];

                sql.append("(");
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
                sql.append("')");

                if (i != app_info_list.size() - 1)
                {
                    sql.append(", ");
                }
            }

            // ��� ON DUPLICATE KEY UPDATE �Ӿ�
            sql.append(" ON DUPLICATE KEY UPDATE ");
            sql.append("app_name = VALUES(app_name), ");
            sql.append("executable_path = VALUES(executable_path), ");
            sql.append("icon_path = VALUES(icon_path), ");
            sql.append("create_time = VALUES(create_time), ");
            sql.append("update_time = VALUES(update_time);");

            mtx.lock();
            bool result = Utils::mysqlQuery(mysql, sql);
            mtx.unlock();

            return result;
        }

        // ����Ӧ����Ϣ
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
        // ��ȡ����Ӧ����Ϣ
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

        // ͨ��Ӧ��ID��ȡ��ع���
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

                mysql_free_result(res);
                return true;
            }

            mysql_free_result(res);
            return false;
        }


        // ��ȡ���м�ع���
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

                rules.push_back(rule);
            }

            mysql_free_result(res);
            return true;
        }

        // �����µļ�ع���
        bool createMonitoringRule(const MonitoringRule& rule)
        {
            std::string sql = "INSERT INTO monitoring_rule (app_id, is_camouflaged, camouflage_pid, "
                "is_recording_prevention_enabled, current_wnd, hwnd_val, is_protected) VALUES (";
            sql.append(std::to_string(rule.app_id) + ", ");
            sql.append(std::to_string(rule.is_camouflaged) + ", ");
            sql.append(std::to_string(rule.camouflage_pid) + ", ");
            sql.append(std::to_string(rule.is_recording_prevention_enabled) + ", ");
            sql.append(std::to_string(rule.current_wnd) + ", ");
            sql.append(std::to_string(rule.hwnd_val) + ", ");
            sql.append(std::to_string(rule.is_protected) + "); ");

            mtx.lock();
            bool result = Utils::mysqlQuery(mysql, sql);
            mtx.unlock();

            return result;
        }

        // ���¼�ع���
        bool updateMonitoringRule(const MonitoringRule& rule)
        {
            std::string sql = "UPDATE monitoring_rule SET "
                "app_id = " + std::to_string(rule.app_id) + ", "
                "is_camouflaged = " + std::to_string(rule.is_camouflaged) + ", "
                "camouflage_pid = " + std::to_string(rule.camouflage_pid) + ", "
                "is_recording_prevention_enabled = " + std::to_string(rule.is_recording_prevention_enabled) + ", "
                "current_wnd = " + std::to_string(rule.current_wnd) + ", "
                "hwnd_val = " + std::to_string(rule.hwnd_val) + ", "
                "is_protected = " + std::to_string(rule.is_protected) + 
                "WHERE id = " + std::to_string(rule.id) + ";";

            mtx.lock();
            bool result = Utils::mysqlQuery(mysql, sql);
            mtx.unlock();

            return result;
        }


        // ɾ����ع���
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

        // ����ϵͳ��ؼ�¼
        bool insertSystemMonitor(const SystemMonitor& record)
        {
            std::string sql;
            sql.append("INSERT INTO system_monitor (cpu_usage, memory_usage, disk_usage, network_upload, network_download, temperature, sample_time, ");
            sql.append("battery_percentage, is_charging, is_ac_power, battery_life_time, ac_line_status_raw, battery_flag_raw) VALUES (");
            sql.append(std::to_string(record.cpu_usage) + ", ");
            sql.append(std::to_string(record.memory_usage) + ", ");
            sql.append(std::to_string(record.disk_usage) + ", ");
            sql.append(std::to_string(record.network_upload) + ", ");
            sql.append(std::to_string(record.network_download) + ", ");
            sql.append(record.temperature >= 0 ? std::to_string(record.temperature) : "NULL");  // �����¶�ΪNULL
            sql.append(", '");
            sql.append(record.sample_time);
            sql.append("', ");
            sql.append(std::to_string(record.battery_percentage) + ", ");
            sql.append(record.is_charging ? "1" : "0");
            sql.append(", ");
            sql.append(record.is_ac_power ? "1" : "0");
            sql.append(", ");
            sql.append(std::to_string(record.battery_life_time) + ", ");
            sql.append(std::to_string(record.ac_line_status_raw) + ", ");
            sql.append(std::to_string(record.battery_flag_raw));
            sql.append(");");

            mtx.lock();
            bool result = Utils::mysqlQuery(mysql, sql);
            mtx.unlock();
            return result;
        }

        // ��ȡ����ϵͳ��ؼ�¼
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
                record.id = std::stoull(row[0]);
                record.cpu_usage = std::stof(row[1]);
                record.memory_usage = std::stof(row[2]);
                record.disk_usage = std::stof(row[3]);
                record.network_upload = std::stof(row[4]);
                record.network_download = std::stof(row[5]);
                record.temperature = row[6] ? std::stof(row[6]) : -1;
                record.sample_time = row[7] ? row[7] : "";

                record.battery_percentage = static_cast<uint32_t>(std::stoul(row[8]));
                record.is_charging = std::stoi(row[9]) != 0;
                record.is_ac_power = std::stoi(row[10]) != 0;
                record.battery_life_time = std::stoull(row[11]);
                record.ac_line_status_raw = static_cast<BYTE>(std::stoul(row[12]));
                record.battery_flag_raw = static_cast<BYTE>(std::stoul(row[13]));

                records.push_back(record);
            }

            mysql_free_result(res);
            return true;
        }

        // ��ȡ�ض�ʱ�䷶Χ�ڵ�ϵͳ��ؼ�¼
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
                record.id = std::stoull(row[0]);
                record.cpu_usage = std::stof(row[1]);
                record.memory_usage = std::stof(row[2]);
                record.disk_usage = std::stof(row[3]);
                record.network_upload = std::stof(row[4]);
                record.network_download = std::stof(row[5]);
                record.temperature = row[6] ? std::stof(row[6]) : -1;
                record.sample_time = row[7] ? row[7] : "";

                record.battery_percentage = static_cast<uint32_t>(std::stoul(row[8]));
                record.is_charging = std::stoi(row[9]) != 0;
                record.is_ac_power = std::stoi(row[10]) != 0;
                record.battery_life_time = std::stoull(row[11]);
                record.ac_line_status_raw = static_cast<BYTE>(std::stoul(row[12]));
                record.battery_flag_raw = static_cast<BYTE>(std::stoul(row[13]));

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

        // ����Ӧ����Դ��ؼ�¼
        bool insertAppResourceMonitor(const AppResourceMonitor& record)
        {
            std::string sql;
            sql.append("INSERT INTO app_resource_monitor (app_id, app_name, icon_path, cpu_usage, memory_usage_mb, ");
            sql.append("disk_io_read, disk_io_write, sample_time, use_duration, power_use_level) VALUES (");
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
            sql.append(", '");
            sql.append(record.sample_time);
            sql.append("', ");
            sql.append(std::to_string(record.use_duration));
            sql.append(", '");
            sql.append(record.power_use_level);
            sql.append("');");

            mtx.lock();
            bool result = Utils::mysqlQuery(mysql, sql);
            mtx.unlock();

            return result;
        }

        // ��ȡ����Ӧ����Դ��ؼ�¼
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

            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr)
            {
                AppResourceMonitor record;
                record.id = std::stoull(row[0]);                       // ����ID
                record.app_id = std::stoull(row[1]);                   // ���� ID (pid)
                record.app_name = row[2];                               // Ӧ������
                record.icon_path = row[3] ? row[3] : "";               // ͼ���ļ�·��
                record.cpu_usage = std::stof(row[4]);                  // ����CPUʹ����
                record.memory_usage_mb = std::stof(row[5]);            // �ڴ�ռ���� (MB)
                record.disk_io_read = std::stof(row[6]);               // ���̶�ȡ�ٶ� (MB/s)
                record.disk_io_write = std::stof(row[7]);              // ����д���ٶ� (MB/s)
                record.sample_time = row[8] ? row[8] : "";             // ����ʱ��
                record.use_duration = std::stoull(row[9]);             // ʹ��ʱ����ʱ�����
                record.power_use_level = row[10] ? row[10] : "";       // ��Դ��������

                records.push_back(record);
            }

            mysql_free_result(res);
            mtx.unlock();
            return true;
        }

        // ��ȡ�ض�Ӧ�õļ�ؼ�¼
        bool getAppResourceMonitorsByAppId(uint64_t app_id, std::vector<AppResourceMonitor>& records)
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

            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr)
            {
                AppResourceMonitor record;
                record.id = std::stoull(row[0]);                       // ����ID
                record.app_id = std::stoull(row[1]);                   // ���� ID (pid)
                record.app_name = row[2];                               // Ӧ������
                record.icon_path = row[3] ? row[3] : "";               // ͼ���ļ�·��
                record.cpu_usage = std::stof(row[4]);                  // ����CPUʹ����
                record.memory_usage_mb = std::stof(row[5]);            // �ڴ�ռ���� (MB)
                record.disk_io_read = std::stof(row[6]);               // ���̶�ȡ�ٶ� (MB/s)
                record.disk_io_write = std::stof(row[7]);              // ����д���ٶ� (MB/s)
                record.sample_time = row[8] ? row[8] : "";             // ����ʱ��
                record.use_duration = std::stoull(row[9]);             // ʹ��ʱ����ʱ�����
                record.power_use_level = row[10] ? row[10] : "";       // ��Դ��������

                records.push_back(record);
            }

            mysql_free_result(res);
            mtx.unlock();
            return true;
        }
    };


    class MaliciousThreadLogTable : public BaseTable
    {
    public:
        using ptr = std::shared_ptr<MaliciousThreadLogTable>;

        // ��������߳���־��¼
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
            sql.append(record.detection_time);  // ʹ���ַ�����ʽ��ʱ��
            sql.append("');");

            mtx.lock();
            bool result = Utils::mysqlQuery(mysql, sql);
            mtx.unlock();

            return result;
        }

        // ��ȡ���ж����߳���־��¼
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
                record.id = std::stoull(row[0]);                    // ����ID
                record.app_id = std::stoi(row[1]);                  // ����Ӧ��ID
                record.thread_name = row[2];                         // �����߳�����
                record.thread_hash = row[3];                         // �߳�������ϣֵ
                record.risk_level = static_cast<uint8_t>(std::stoi(row[4]));  // ���յȼ�
                record.detection_time = row[5] ? row[5] : "";       // ��⵽��ʱ��

                logs.push_back(record);
            }

            mysql_free_result(res);
            return true;
        }

        // ��ȡָ��Ӧ�õĶ����߳���־
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
                record.id = std::stoull(row[0]);                    // ����ID
                record.app_id = std::stoi(row[1]);                  // ����Ӧ��ID
                record.thread_name = row[2];                         // �����߳�����
                record.thread_hash = row[3];                         // �߳�������ϣֵ
                record.risk_level = static_cast<uint8_t>(std::stoi(row[4]));  // ���յȼ�
                record.detection_time = row[5] ? row[5] : "";       // ��⵽��ʱ��

                logs.push_back(record);
            }

            mysql_free_result(res);
            return true;
        }

        // ��ȡָ���̹߳�ϣ�Ķ����߳���־
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
                record.id = std::stoull(row[0]);                    // ����ID
                record.app_id = std::stoi(row[1]);                  // ����Ӧ��ID
                record.thread_name = row[2];                         // �����߳�����
                record.thread_hash = row[3];                         // �߳�������ϣֵ
                record.risk_level = static_cast<uint8_t>(std::stoi(row[4]));  // ���յȼ�
                record.detection_time = row[5] ? row[5] : "";       // ��⵽��ʱ��

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

        // �����ļ��޸���־��¼
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
            sql.append(record.alert_time);  // ʹ���ַ�����ʽ��ʱ��
            sql.append("');");

            mtx.lock();
            bool result = Utils::mysqlQuery(mysql, sql);
            mtx.unlock();

            return result;
        }

        // ��ȡ�����ļ��޸���־��¼
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
                record.id = std::stoull(row[0]);                  // ����ID
                record.app_id = std::stoull(row[1]);              // ����Ӧ��ID
                record.file_path = row[2];                        // ���޸ĵ��ļ�·��
                record.operation_type = row[3];                   // �������ͣ�CREATE/MODIFY/DELETE��
                record.file_hash = row[4] ? row[4] : "";         // �ļ���ϣֵ���޸ĺ�
                record.alert_time = row[5] ? row[5] : "";         // �澯����ʱ��

                logs.push_back(record);
            }

            mysql_free_result(res);
            return true;
        }

        // ��ȡָ��Ӧ�õ��ļ��޸���־��¼
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
                record.id = std::stoull(row[0]);                  // ����ID
                record.app_id = std::stoull(row[1]);              // ����Ӧ��ID
                record.file_path = row[2];                        // ���޸ĵ��ļ�·��
                record.operation_type = row[3];                   // �������ͣ�CREATE/MODIFY/DELETE��
                record.file_hash = row[4] ? row[4] : "";         // �ļ���ϣֵ���޸ĺ�
                record.alert_time = row[5] ? row[5] : "";         // �澯����ʱ��

                logs.push_back(record);
            }

            mysql_free_result(res);
            return true;
        }

        // ��ȡָ���ļ�·�����ļ��޸���־��¼
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
                record.id = std::stoull(row[0]);                  // ����ID
                record.app_id = std::stoull(row[1]);              // ����Ӧ��ID
                record.file_path = row[2];                        // ���޸ĵ��ļ�·��
                record.operation_type = row[3];                   // �������ͣ�CREATE/MODIFY/DELETE��
                record.file_hash = row[4] ? row[4] : "";         // �ļ���ϣֵ���޸ĺ�
                record.alert_time = row[5] ? row[5] : "";         // �澯����ʱ��

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

        // ����AI���������¼
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

        // ��ȡ����AI���������¼
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

        // ��ȡָ���û���AI���������¼
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

        // ����ϵͳ����
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

        // ��ȡ����ϵͳ����
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

        // �û���¼��֤
        bool verifyUserLogin(std::string_view username, std::string_view password)
        {
            // ����SQL��ѯ���
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
                // �û���������
                mysql_free_result(res);
                return false;
            }

            std::string stored_password = row[0];
            bool is_locked = row[1][0] == '1';  // ���� 1 ��ʾ������0 ��ʾδ����

            // ����û��Ƿ�����
            if (is_locked)
            {
                mysql_free_result(res);
                return false;  // �û������������ܵ�¼
            }

            // ��֤�����Ƿ���ȷ
            if (password == stored_password)
            {
                mysql_free_result(res);
                return true;  // ��¼�ɹ�
            }

            mysql_free_result(res);
            return false;  // �������
        }

        // �����û���Ϣ
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

        // ��ȡ�����û���Ϣ
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

        // ��ȡָ���û�ID����Ϣ
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
    
        // ��ȡָ�������ʼ���ַ���û���Ϣ
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

        // �����û���Ϣ
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

        // �����û�������־
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

        // ��ȡ�����û�������־
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
                log.result_status = row[7][0] == '1'; // ���� result_status �洢Ϊ 0/1

                logs.push_back(log);
            }

            mysql_free_result(res);
            return true;
        }
    };


    class FileInfoTable : public BaseTable
    {
    public:
        using ptr = std::shared_ptr<FileInfoTable>;

        bool getAllFileInfo(std::vector<FileInfo>& files)
        {
            std::string sql = "SELECT file_id, path, force_delete, is_encrypted, secret_key FROM file_info WHERE force_delete = 0;"; // ֻ��ѯδ��ǿɾ���ļ�

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

            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr)
            {
                FileInfo file;
                file.file_id = std::stoull(row[0]);
                file.path = row[1] ? row[1] : "";
                file.force_delete = std::stoi(row[2]);
                file.is_encrypted = std::stoi(row[3]);
                file.secret_key = row[4] ? row[4] : "";

                files.push_back(file);
            }

            mysql_free_result(res);
            mtx.unlock();
            return true;
        }


        bool getFileInfoById(uint64_t file_id, FileInfo& file)
        {
            std::string sql = "SELECT file_id, path, force_delete, is_encrypted, secret_key FROM file_info WHERE file_id = " + std::to_string(file_id) + " AND force_delete = 0;"; // ���������ж��Ƿ�ǿɾ

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
            if (row)
            {
                file.file_id = std::stoull(row[0]);
                file.path = row[1] ? row[1] : "";
                file.force_delete = std::stoi(row[2]);
                file.is_encrypted = std::stoi(row[3]);
                file.secret_key = row[4] ? row[4] : "";
            }
            else
            {
                mysql_free_result(res);
                mtx.unlock();
                return false;
            }

            mysql_free_result(res);
            mtx.unlock();
            return true;
        }


        // �����ļ�
        bool encryptFile(uint64_t file_id, const std::string& key)
        {
            std::string sql = "UPDATE file_info SET is_encrypted = 1, secret_key = '" + key + "' WHERE file_id = " + std::to_string(file_id) + "AND force_delete = 0;";

            mtx.lock();
            bool result = Utils::mysqlQuery(mysql, sql);
            mtx.unlock();
            return result;
        }

        // �����ļ�
        bool decryptFile(uint64_t file_id)
        {
            std::string sql = "UPDATE file_info SET is_encrypted = 0, secret_key = '' WHERE file_id = " + std::to_string(file_id) + "AND force_delete = 0;";

            mtx.lock();
            bool result = Utils::mysqlQuery(mysql, sql);
            mtx.unlock();
            return result;
        }

        bool forceDeleteFile(uint64_t file_id)
        {
            std::string sql = "UPDATE file_info SET force_delete = 1 WHERE file_id = " + std::to_string(file_id) + "AND force_delete = 0;";
            mtx.lock();
            bool result = Utils::mysqlQuery(mysql, sql);
            mtx.unlock();
            return result;
        }

    };


}