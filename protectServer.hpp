#pragma once
#include <AllHeader.h>
#include "models.hpp"

namespace sp {

    class ProtectServer
    {
    public:
        ProtectServer(const ProtectServer&) = delete;
        ProtectServer& operator=(const ProtectServer&) = delete;
        ProtectServer(ProtectServer&&) = delete;
        ProtectServer& operator=(ProtectServer&&) = delete;

        static ProtectServer& GetInstance(const char* driverPath = "default.sys")
        {
            static ProtectServer instance(driverPath);
            return instance;
        }

        enum class FunctionNumber {
            FakeProcess = 0,       // ������ƭ
            AntiScreenShot = 1,    // ����ͼ
            AntiModify = 2,        // ���̱��� (���޸�)
            ForceDelete = 3        // ǿ��ɾ���ļ�(������)
        };

        bool protectFunctionWrapper(FunctionNumber func, uint64_t TargetPid, uint64_t FakePid = 0, const char* FilePath = nullptr) {
            sp::MonitoringRule rule;  // ���� MonitoringRules �ṹ��ʵ��
            bool result = All_Protect_Function(rule, TargetPid, FakePid,static_cast<Function_number>(func));

            if (result) {
                LOG_INFO("All_Protect_Function ���óɹ�: Function = {}, TargetPid = {}, FakePid = {}, FilePath = {}",
                    static_cast<int>(func), TargetPid, FakePid, FilePath ? FilePath : "nullptr");
            }
            else {
                LOG_ERROR("All_Protect_Function ����ʧ��: Function = {}, TargetPid = {}, FakePid = {}, FilePath = {}",
                    static_cast<int>(func), TargetPid, FakePid, FilePath ? FilePath : "nullptr");
            }

            return result;
        }

        // ������ƭ
        bool protectFakeProcess(uint64_t TargetPid, uint64_t FakePid) {
            LOG_DEBUG("���� ProtectFakeProcess, TargetPid = {}, FakePid = {}", TargetPid, FakePid);
            return protectFunctionWrapper(FunctionNumber::FakeProcess, TargetPid, FakePid);
        }

        // ����ͼ
        bool protectAntiScreenShot(uint64_t TargetPid) {
            LOG_DEBUG("���� ProtectAntiScreenShot, TargetPid = {}", TargetPid);
            return protectFunctionWrapper(FunctionNumber::AntiScreenShot, TargetPid);
        }

        // ���̱��� 
        bool protectAntiModify(uint64_t TargetPid) {
            LOG_DEBUG("���� ProtectAntiModify, TargetPid = {}", TargetPid);
            return protectFunctionWrapper(FunctionNumber::AntiModify, TargetPid);
        }

        // ǿ��ɾ���ļ�
        bool protectForceDelete(const char* FilePath) {
            LOG_DEBUG("���� ProtectForceDelete, FilePath = {}", FilePath ? FilePath : "nullptr");
            return protectFunctionWrapper(FunctionNumber::ForceDelete, 0, 0, FilePath);
        }

        // ��ȡ������Ϣ
        bool getProcessInfoWindows(std::vector<AppResourceMonitor>& resourceMonitors) {
            for (auto& resourceMonitor : resourceMonitors) {
                bool result = GetProcessInfoWindows(resourceMonitor.app_id, resourceMonitor);
                if (result) {
                    LOG_INFO("getProcessInfoWindows �ɹ�: PID = {}, AppName = {}, CPU = {:.2f}%, �ڴ� = {:.2f}MB, ���� IO (��: {:.2f}MB, д: {:.2f}MB), ����ʱ�� = {}",
                        resourceMonitor.app_id, resourceMonitor.app_name, resourceMonitor.cpu_usage,
                        resourceMonitor.memory_usage_mb, resourceMonitor.disk_io_read,
                        resourceMonitor.disk_io_write, resourceMonitor.sample_time);
                }
                else {
                    LOG_ERROR("getProcessInfoWindows ʧ��: ���� PID = {}", resourceMonitor.app_id);
                }
            }

            return true;
        }

        bool getProcessInfoWindows(sp::AppResourceMonitor& resourceMonitor)
        {
            return GetProcessInfoWindows(resourceMonitor.app_id, resourceMonitor);
        }

        //����
        bool encryptFile(const std::string& file_path, const std::string& key, const std::string& extension =".lock")
        {
            return encrypt_file(file_path, extension, key);
        }

        //����
        bool decodeFile(const std::string& file_path, const std::string& key ,const std::string& extension =".lock")
        {
            std::string _file_path = Utils::changeFileExtension(file_path, extension);
            std::string _extension = Utils::getFileExtension(file_path);
            return encrypt_file(_file_path, _extension, key);
        }

        //�ļ�������־
        bool getFileMonitorInfo(std::vector<sp::FileModificationLog>& logData,uint64_t& last_id)
        {
            return GetFileMonitorInfo(logData, last_id);
        }

        bool getAllProcessInfo(std::vector<sp::AppInfo>& knownProcesses) {
            knownProcesses = get_all_processes();
            return  true;
        }

        bool getNewProcessInfo(std::vector<sp::AppInfo>& known_processes, sp::AppInfo& out_new_process)
        {
            return get_new_process_info(known_processes, out_new_process);
        }

        bool getSystemStatus(sp::SystemMonitor& monitor)
        {
            return GetSystemStatus(monitor);
        }

        bool checkForMaliciousActivitys(const std::vector<sp::AppInfo>& targetPIDs, std::vector<sp::MaliciousThreadLog>& maliciousLogs)
        {
            std::vector<sp::MaliciousThreadLog> tmp;
            bool ret = false;
            for (const auto& e : targetPIDs)
            {
                ret = CheckForMaliciousActivity(e.id, tmp);
                maliciousLogs.insert(maliciousLogs.end(), tmp.begin(), tmp.end());
                tmp.clear();
                if (!ret)
                    return ret;
            }
            return ret;
        }

        ~ProtectServer()
        {
            if (initialized)
            {
                LOG_INFO("Unloading driver...");
                UnloadDriver();
                stopFileMonitor();
                LOG_DEBUG("Driver unloaded successfully.");
            }
        }

    private:
        bool initialized = false;

        ProtectServer(const char* driverPath)
        {
            LOG_INFO("ProtectServer initializing with driver: {}", driverPath);

            if (!LoadDriver(driverPath))
            {
                LOG_ERROR("LoadDriver failed!");
                return;
            }

            if (!initcom())
            {
                LOG_ERROR("initcom failed! Unloading driver...");
                UnloadDriver();  // ������Դ
                return;
            }
            initFileMonitor();
            initialized = true;
            LOG_INFO("ProtectServer initialized successfully.");
        }


    };





}