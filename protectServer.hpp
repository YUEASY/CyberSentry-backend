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
            FakeProcess = 0,       // 进程欺骗
            AntiScreenShot = 1,    // 反截图
            AntiModify = 2,        // 进程保护 (反修改)
            ForceDelete = 3        // 强制删除文件
        };

        bool protectFunctionWrapper(FunctionNumber func, uint64_t TargetPid, uint64_t FakePid = 0, const char* FilePath = nullptr) {
            ::MonitoringRule rule;  // 创建 MonitoringRules 结构体实例
            bool result = All_Protect_Function(rule, TargetPid, FakePid,static_cast<Function_number>(func));

            if (result) {
                LOG_INFO("All_Protect_Function 调用成功: Function = {}, TargetPid = {}, FakePid = {}, FilePath = {}",
                    static_cast<int>(func), TargetPid, FakePid, FilePath ? FilePath : "nullptr");
            }
            else {
                LOG_ERROR("All_Protect_Function 调用失败: Function = {}, TargetPid = {}, FakePid = {}, FilePath = {}",
                    static_cast<int>(func), TargetPid, FakePid, FilePath ? FilePath : "nullptr");
            }

            return result;
        }

        // 进程欺骗
        bool protectFakeProcess(uint64_t TargetPid, uint64_t FakePid) {
            LOG_DEBUG("调用 ProtectFakeProcess, TargetPid = {}, FakePid = {}", TargetPid, FakePid);
            return protectFunctionWrapper(FunctionNumber::FakeProcess, TargetPid, FakePid);
        }

        // 反截图
        bool protectAntiScreenShot(uint64_t TargetPid) {
            LOG_DEBUG("调用 ProtectAntiScreenShot, TargetPid = {}", TargetPid);
            return protectFunctionWrapper(FunctionNumber::AntiScreenShot, TargetPid);
        }

        // 进程保护 (反修改)
        bool protectAntiModify(uint64_t TargetPid) {
            LOG_DEBUG("调用 ProtectAntiModify, TargetPid = {}", TargetPid);
            return protectFunctionWrapper(FunctionNumber::AntiModify, TargetPid);
        }

        // 强制删除文件
        bool protectForceDelete(const char* FilePath) {
            LOG_DEBUG("调用 ProtectForceDelete, FilePath = {}", FilePath ? FilePath : "nullptr");
            return protectFunctionWrapper(FunctionNumber::ForceDelete, 0, 0, FilePath);
        }

        /*bool getProcessInfoWindows(AppResourceMonitor& resourceMonitor) {
            if (resourceMonitor.app_id == 0) {
                LOG_ERROR("getProcessInfoWindows: 无效的进程 PID");
                return false;
            }

            LOG_DEBUG("调用 getProcessInfoWindows, 进程 PID = {}", resourceMonitor.app_id);

            bool result = GetProcessInfoWindows(static_cast<DWORD>(resourceMonitor.app_id), resourceMonitor);

            if (result) {
                LOG_INFO("getProcessInfoWindows 成功: PID = {}, AppName = {}, CPU = {:.2f}%, 内存 = {:.2f}MB, 磁盘 IO (读: {:.2f}MB, 写: {:.2f}MB), 采样时间 = {}",
                    resourceMonitor.app_id, resourceMonitor.app_name, resourceMonitor.cpu_usage,
                    resourceMonitor.memory_usage_mb, resourceMonitor.disk_io_read,
                    resourceMonitor.disk_io_write, resourceMonitor.sample_time);
            }
            else {
                LOG_ERROR("getProcessInfoWindows 失败: 进程 PID = {}", resourceMonitor.app_id);
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
                UnloadDriver();  // 清理资源
                return;
            }

            initialized = true;
            LOG_INFO("ProtectServer initialized successfully.");
        }
    };





}