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
            ForceDelete = 3        // ǿ��ɾ���ļ�
        };

        bool protectFunctionWrapper(FunctionNumber func, uint64_t TargetPid, uint64_t FakePid = 0, const char* FilePath = nullptr) {
            ::MonitoringRule rule;  // ���� MonitoringRules �ṹ��ʵ��
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

        // ���̱��� (���޸�)
        bool protectAntiModify(uint64_t TargetPid) {
            LOG_DEBUG("���� ProtectAntiModify, TargetPid = {}", TargetPid);
            return protectFunctionWrapper(FunctionNumber::AntiModify, TargetPid);
        }

        // ǿ��ɾ���ļ�
        bool protectForceDelete(const char* FilePath) {
            LOG_DEBUG("���� ProtectForceDelete, FilePath = {}", FilePath ? FilePath : "nullptr");
            return protectFunctionWrapper(FunctionNumber::ForceDelete, 0, 0, FilePath);
        }

        /*bool getProcessInfoWindows(AppResourceMonitor& resourceMonitor) {
            if (resourceMonitor.app_id == 0) {
                LOG_ERROR("getProcessInfoWindows: ��Ч�Ľ��� PID");
                return false;
            }

            LOG_DEBUG("���� getProcessInfoWindows, ���� PID = {}", resourceMonitor.app_id);

            bool result = GetProcessInfoWindows(static_cast<DWORD>(resourceMonitor.app_id), resourceMonitor);

            if (result) {
                LOG_INFO("getProcessInfoWindows �ɹ�: PID = {}, AppName = {}, CPU = {:.2f}%, �ڴ� = {:.2f}MB, ���� IO (��: {:.2f}MB, д: {:.2f}MB), ����ʱ�� = {}",
                    resourceMonitor.app_id, resourceMonitor.app_name, resourceMonitor.cpu_usage,
                    resourceMonitor.memory_usage_mb, resourceMonitor.disk_io_read,
                    resourceMonitor.disk_io_write, resourceMonitor.sample_time);
            }
            else {
                LOG_ERROR("getProcessInfoWindows ʧ��: ���� PID = {}", resourceMonitor.app_id);
            }

            return result;
        }*/




        ~ProtectServer()
        {
            if (initialized)
            {
                LOG_INFO("Unloading driver...");
                UnloadDriver();
                LOG_INFO("Driver unloaded successfully.");
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

            initialized = true;
            LOG_INFO("ProtectServer initialized successfully.");
        }
    };





}