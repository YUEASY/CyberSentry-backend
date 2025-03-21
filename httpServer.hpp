#pragma once
#include <iostream>
#include "httplib.h"
#include "models.hpp"
#include "json/json.h"
#include "serverManager.hpp"
#include "md5.h"
#include <filesystem>
#include <curl/curl.h>
namespace sp
{
    std::atomic<bool> running(true);
    class HttpServer {
    public:
        using Handler = std::function<void(const httplib::Request&, httplib::Response&)>;
        using ErrorHandler = std::function<void(const httplib::Response&)>;

        explicit HttpServer(int _port = 8080, ErrorHandler _error_handler = NULL)
            : port(_port) , error_handler(_error_handler){
            if (error_handler != NULL)
            {
                server.set_error_handler([this](const httplib::Request& req, httplib::Response& res) {
                    if (error_handler) error_handler(res);
                    });
            }
        }
        // 设置GET请求路由
        void Get(const std::string& path, Handler handler) {
            server.Get(path, [handler](const httplib::Request& req, httplib::Response& res) {
                handler(req, res);
                });
        }
        // 设置POST请求路由
        void Post(const std::string& path, Handler handler) {
            server.Post(path, [handler](const httplib::Request& req, httplib::Response& res) {
                handler(req, res);
                });
        }

        // 设置静态文件目录
        bool SetStaticDir(const std::string& mount_point, const std::string& dir) {
            return server.set_mount_point(mount_point, dir);
        }
        bool Run() {
            if (!server.is_valid()) {
                return false;
            }
            close_thread = std::thread([this]() {
                while (running.load()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                server.stop();
                });
            bool ret = server.listen("0.0.0.0", port);

            if (close_thread.joinable()) {
                close_thread.join();
            }
            return ret;
        }
    private:
        httplib::Server server;
        int port;
        ErrorHandler error_handler;
        std::thread close_thread;
    };

    bool verifyToken(const httplib::Request& req, httplib::Response& res)
    {
        //for (auto e:req.headers)
        //{
        //    std::cout << e.first << " :" << e.second << std::endl;
        //}
        auto it = req.headers.find("token");
        if (it != req.headers.end()) {
            if (ServerManager::getInstance().getAuthService().verifyToken(it->second))
            {
                return true;
            }
        }
        res.status = 401;
        res.set_content("{\"result\": {\"status\": \"error\", \"message\": \"Invalid token.\"}}", "application/json");
        return false;
    }

    std::string getRemoteAddr(const httplib::Request& req)
    {
        auto it = req.headers.find("REMOTE_ADDR");
        if (it != req.headers.end()) {
            return it->second;
        }
        return "";
    }

    void handle_get_app_info(const httplib::Request& req, httplib::Response& res)
    {
        if (!verifyToken(req, res)) return;
        try {
            int id = std::stoi(req.matches[1]);  // req.matches[1] 是路径中捕获的 ID 部分
            sp::AppInfo app_info;
            bool flag = ServerManager::getInstance().getAppInfoService().getAppInfoById(id, app_info);
            Json::Value root;
            if (flag)
            {
                root["result"]["status"] = "success";
                root["result"]["message"] = "Application information retrieved successfully.";

                root["result"]["data"]["id"] = app_info.id;
                root["result"]["data"]["app_name"] = app_info.app_name;
                root["result"]["data"]["executable_path"] = app_info.executable_path;
                root["result"]["data"]["icon_path"] = app_info.icon_path;
                root["result"]["data"]["create_time"] = app_info.create_time;
                root["result"]["data"]["update_time"] = app_info.update_time;
            }
            else
            {
                root["result"]["status"] = "fail";
                root["result"]["message"] = "Get app_info fails";
            }
            res.set_content(root.toStyledString(), "application/json");
        }
        catch (const std::exception& e) {
            // 处理异常情况，例如 id 转换失败
            res.status = 500;  // 设置为错误的 HTTP 状态码
            res.set_content("{\"result\": {\"status\": \"error\", \"message\": \"Invalid app ID.\"}}", "application/json");
        }
    }

    void handle_get_all_app_info(const httplib::Request& req, httplib::Response& res) {
        if (!verifyToken(req, res)) return;
        try {
            std::vector<sp::AppInfo> app_info_list;  // 存储所有应用信息的列表
            bool flag = ServerManager::getInstance().getAppInfoService().getAllAppInfo(app_info_list);  // 获取所有应用信息
            Json::Value root;  // JSON 根对象
            if (flag) {
                root["result"]["status"] = "success";  // 状态为成功
                root["result"]["message"] = "All application information has been successfully obtained.";

                // 遍历所有应用信息，并将其添加到 JSON 响应中
                for (const auto& app_info : app_info_list) {
                    Json::Value app_data;  // 存储单个应用信息的 JSON 对象
                    app_data["id"] = app_info.id;
                    app_data["app_name"] = app_info.app_name;
                    app_data["executable_path"] = app_info.executable_path;
                    app_data["icon_path"] = app_info.icon_path;
                    app_data["create_time"] = app_info.create_time;
                    app_data["update_time"] = app_info.update_time;

                    // 将单个应用信息添加到结果数组中
                    root["result"]["data"].append(app_data);
                }
            }
            else {
                root["result"]["status"] = "fail";  // 如果获取失败，设置失败状态
                root["result"]["message"] = "Failed to obtain all application information.";
            }

            // 设置响应内容为 JSON 格式
            res.set_content(root.toStyledString(), "application/json");
        }
        catch (const std::exception& e) {
            // 处理异常情况，例如数据库或服务器错误
            res.status = 500;  // 设置 HTTP 状态码为服务器错误
            res.set_content("{\"result\": {\"status\": \"error\", \"message\": \"An error occurred while retrieving all application information.\"}}", "application/json");
        }
    }

    void handle_get_monitoring_rule(const httplib::Request& req, httplib::Response& res) {
        if (!verifyToken(req, res)) return;

        try {
            if (!req.has_param("app_id")) {
                res.status = 400;
                res.set_content("{\"result\": {\"status\": \"fail\", \"message\": \"The app_id parameter is missing.\"}}", "application/json");
                return;
            }

            uint64_t app_id = std::stoull(req.get_param_value("app_id"));
            MonitoringRule rule{};
            bool flag = ServerManager::getInstance().getMonitoringRuleService().getMonitoringRuleByAppId(app_id, rule);

            Json::Value root;
            if (flag) {
                root["result"]["status"] = "success";
                root["result"]["message"] = "The monitoring rules have been successfully obtained.";
                root["result"]["data"]["id"] = rule.id;
                root["result"]["data"]["app_id"] = rule.app_id;
                root["result"]["data"]["is_camouflaged"] = rule.is_camouflaged;
                root["result"]["data"]["camouflage_pid"] = rule.camouflage_pid;
                root["result"]["data"]["is_recording_prevention_enabled"] = rule.is_recording_prevention_enabled;
                root["result"]["data"]["current_wnd"] = rule.current_wnd;  // 统一转换类型
                root["result"]["data"]["hwnd_val"] = rule.hwnd_val;  // 变量名对齐
                root["result"]["data"]["is_protected"] = rule.is_protected;

            }
            else {
                root["result"]["status"] = "fail";
                root["result"]["message"] = "The monitoring rules for this application have not been found.";
            }

            res.set_content(root.toStyledString(), "application/json");
        }
        catch (const std::exception& e) {
            res.status = 500;
            res.set_content("{\"result\": {\"status\": \"error\", \"message\": \"An error occurred while obtaining the monitoring rules.\"}}", "application/json");
        }
    }

    void handle_get_all_monitoring_rules(const httplib::Request& req, httplib::Response& res) {
        if (!verifyToken(req, res)) return;

        try {
            std::vector<MonitoringRule> rules;
            bool flag = ServerManager::getInstance().getMonitoringRuleService().getAllMonitoringRules(rules);

            Json::Value root;
            if (flag) {
                root["result"]["status"] = "success";
                root["result"]["message"] = "The monitoring rules have been successfully obtained.";

                for (const auto& rule : rules) {
                    Json::Value rule_data;
                    rule_data["id"] = rule.id;
                    rule_data["app_id"] = rule.app_id;
                    rule_data["is_camouflaged"] = rule.is_camouflaged;
                    rule_data["camouflage_pid"] = rule.camouflage_pid;
                    rule_data["is_recording_prevention_enabled"] = rule.is_recording_prevention_enabled;
                    rule_data["current_wnd"] = rule.current_wnd;  // uint32_t 类型，直接赋值
                    rule_data["hwnd_val"] = rule.hwnd_val;
                    rule_data["is_protected"] = rule.is_protected;

                    root["result"]["data"].append(rule_data);
                }
            }
            else {
                root["result"]["status"] = "fail";
                root["result"]["message"] = "Failed to obtain all monitoring rules.";
            }

            res.set_content(root.toStyledString(), "application/json");
        }
        catch (const std::exception& e) {
            res.status = 500;
            res.set_content("{\"result\": {\"status\": \"error\", \"message\": \"An error occurred while obtaining all the monitoring rules.\"}}", "application/json");
        }
    }

    void handle_user_login(const httplib::Request& req, httplib::Response& res) {
        try {
            // 解析请求中的 JSON 数据
            Json::Reader reader;
            Json::Value json_data;
            if (!reader.parse(req.body, json_data)) {
                // 如果 JSON 格式不正确，返回错误响应
                res.status = 400;  // 错误的请求
                Json::Value error_response;
                error_response["result"]["status"] = "error";
                error_response["result"]["message"] = "Invalid JSON format";
                res.set_content(error_response.toStyledString(), "application/json");
                return;
            }

            std::string email = json_data["email"].asString();
            std::string code = json_data["code"].asString();
            bool found = ServerManager::getInstance().getAuthService().verificationCaptcha(email, code);
            Json::Value root;
            if (!found)
            {
                res.status = 400;
                root["result"]["status"] = "fail";
                root["result"]["message"] = "Incorrect verification code";
                res.set_content(root.toStyledString(), "application/json");
                return;
            }
            UserInfo user;
            user.email = email;
            found = ServerManager::getInstance().getUserInfoService().getUserInfoByEmail(email, user);
            if (!found)
            {
                user.user_id = Utils::generateUUID(1);
                user.username = Utils::token();
                user.password = MD5("123456").toStr();
                user.role = "OPERATOR";
                user.phone = "";
                user.last_login_ip = getRemoteAddr(req);
                user.is_locked = 0;
                user.last_login_time = user.create_time = Utils::timestampToMySQLFormat(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
                bool flag = ServerManager::getInstance().getUserInfoService().insertUserInfo(user);
                if (!flag)
                {
                    res.status = 500;
                    root["result"]["status"] = "fail";
                    root["result"]["message"] = "Failed to add user";
                    res.set_content(root.toStyledString(), "application/json");
                    return;
                }
            }
            user.last_login_ip = getRemoteAddr(req);
            user.last_login_time = Utils::timestampToMySQLFormat(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
            root["result"]["data"]["user_id"] = user.user_id;
            root["result"]["data"]["username"] = user.username;
            root["result"]["data"]["password"] = user.password;
            root["result"]["data"]["role"] = user.role;
            root["result"]["data"]["email"] = user.email;
            root["result"]["data"]["phone"] = user.phone;
            root["result"]["data"]["last_login_ip"] = user.last_login_ip;
            root["result"]["data"]["last_login_time"] = user.last_login_time;
            root["result"]["data"]["is_locked"] = user.is_locked;
            root["result"]["data"]["create_time"] = user.create_time;
            res.status = 200;
            res.set_content(root.toStyledString(), "application/json");
        }
        catch (const std::exception& e) {
            // 捕获异常，返回错误信息
            res.status = 500;  // 服务器错误
            Json::Value error_response;
            error_response["result"]["status"] = "error";
            error_response["result"]["message"] = "An error occurred during login: " + std::string(e.what());
            res.set_content(error_response.toStyledString(), "application/json");
        }
    }

    void handle_get_user_operation_logs(const httplib::Request& req, httplib::Response& res) {
        if (!verifyToken(req, res)) return;  

        try {
            // 假设 user_id 是通过请求路径参数获取的
            uint64_t user_id = std::stoull(req.matches[1]);  // req.matches[1] 是路径中捕获的 user_id 部分

            // 获取该用户的所有操作日志
            std::vector<sp::UserOperationLog> logs;
            bool found = sp::ServerManager::getInstance().getUserOperationLogService().getUserOperationLogs(user_id, logs);

            Json::Value root;
            if (found) {
                // 如果找到了操作日志，将它们加入到响应中
                root["result"]["status"] = "success";
                root["result"]["message"] = "User operation logs retrieved successfully.";

                // 将所有操作日志加入到响应的 JSON 数据中
                Json::Value logs_array(Json::arrayValue);  // Create an array to store logs
                for (const auto& log : logs) {
                    Json::Value log_data;
                    log_data["log_id"] = log.log_id;
                    log_data["user_id"] = log.user_id;
                    log_data["operation_type"] = log.operation_type;
                    log_data["target_id"] = log.target_id;
                    log_data["operation_detail"] = log.operation_detail;
                    log_data["client_info"] = log.client_info;
                    log_data["operation_time"] = log.operation_time;
                    log_data["result_status"] = log.result_status;
                    logs_array.append(log_data);
                }
                root["result"]["data"] = logs_array;
            }
            else {
                res.status = 404;
                // 如果没有找到该用户的操作日志，返回失败状态
                root["result"]["status"] = "fail";
                root["result"]["message"] = "No operation logs found for the user.";
            }

            // 设置响应内容为 JSON 格式
            res.set_content(root.toStyledString(), "application/json");

        }
        catch (const std::exception& e) {
            // 捕获异常，返回错误信息
            res.status = 500;  // 服务器错误
            Json::Value error_response;
            error_response["result"]["status"] = "error";
            error_response["result"]["message"] = "An error occurred while retrieving user operation logs: " + std::string(e.what());
            res.set_content(error_response.toStyledString(), "application/json");
        }
    }

    void handle_create_user_operation_log(const httplib::Request& req, httplib::Response& res) {}

    void handle_get_all_user_operation_logs(const httplib::Request& req, httplib::Response& res) {
        if (!verifyToken(req, res)) return;

        try {
            // 获取所有用户的操作日志
            std::vector<sp::UserOperationLog> logs;
            bool found = sp::ServerManager::getInstance().getUserOperationLogService().getAllUserOperationLogs(logs);

            Json::Value root;
            if (found) {
                root["result"]["status"] = "success";
                root["result"]["message"] = "All user operation logs retrieved successfully.";

                Json::Value logs_array(Json::arrayValue);
                for (const auto& log : logs) {
                    Json::Value log_data;
                    log_data["log_id"] = log.log_id;
                    log_data["user_id"] = log.user_id;
                    log_data["operation_type"] = log.operation_type;
                    log_data["target_id"] = log.target_id;
                    log_data["operation_detail"] = log.operation_detail;
                    log_data["client_info"] = log.client_info;
                    log_data["operation_time"] = log.operation_time;
                    log_data["result_status"] = log.result_status;
                    logs_array.append(log_data);
                }
                root["result"]["data"] = logs_array;
            }
            else {
                res.status = 404;
                root["result"]["status"] = "fail";
                root["result"]["message"] = "No operation logs found.";
            }

            res.set_content(root.toStyledString(), "application/json");
        }
        catch (const std::exception& e) {
            res.status = 500;
            Json::Value error_response;
            error_response["result"]["status"] = "error";
            error_response["result"]["message"] = "An error occurred while retrieving all user operation logs: " + std::string(e.what());
            res.set_content(error_response.toStyledString(), "application/json");
        }
    }

    void handle_get_system_monitors(const httplib::Request& req, httplib::Response& res) {
        try {
            // 获取系统监控数据
            std::vector<sp::SystemMonitor> monitors;
            bool found = sp::ServerManager::getInstance().getSystemMonitorService().getAllSystemMonitors(monitors);

            Json::Value root;
            if (found) {
                root["result"]["status"] = "success";
                root["result"]["message"] = "System monitor data retrieved successfully.";

                Json::Value monitors_array(Json::arrayValue);
                for (const auto& monitor : monitors) {
                    Json::Value monitor_data;
                    monitor_data["id"] = monitor.id;
                    monitor_data["cpu_usage"] = monitor.cpu_usage;
                    monitor_data["memory_usage"] = monitor.memory_usage;
                    monitor_data["disk_usage"] = monitor.disk_usage;
                    monitor_data["network_upload"] = monitor.network_upload;
                    monitor_data["network_download"] = monitor.network_download;
                    monitor_data["temperature"] = monitor.temperature;
                    monitor_data["sample_time"] = monitor.sample_time;
                    monitor_data["battery_percentage"] = monitor.battery_percentage;
                    monitor_data["is_charging"] = monitor.is_charging;
                    monitor_data["is_ac_power"] = monitor.is_ac_power;
                    monitor_data["battery_life_time"] = monitor.battery_life_time;
                    monitor_data["ac_line_status_raw"] = Utils::StatusToString("ACLineStatus",monitor.ac_line_status_raw);
                    monitor_data["battery_flag_raw"] = Utils::StatusToString("BatteryFlag", monitor.battery_flag_raw);
                    monitors_array.append(monitor_data);
                }
                root["result"]["data"] = monitors_array;
            }
            else {
                res.status = 404;
                root["result"]["status"] = "fail";
                root["result"]["message"] = "No system monitor data found.";
            }

            res.set_content(root.toStyledString(), "application/json");
        }
        catch (const std::exception& e) {
            res.status = 500;
            Json::Value error_response;
            error_response["result"]["status"] = "error";
            error_response["result"]["message"] = "An error occurred while retrieving system monitor data: " + std::string(e.what());
            res.set_content(error_response.toStyledString(), "application/json");
        }
    }

    void handle_get_system_monitors_short(const httplib::Request& req, httplib::Response& res) {
        try {
            // 获取系统监控数据
            std::vector<sp::SystemMonitor> monitors;
            bool found = sp::ServerManager::getInstance().getSystemMonitorService().getAllSystemMonitorsFromCache(monitors);

            Json::Value root;
            if (found) {
                root["result"]["status"] = "success";
                root["result"]["message"] = "System monitor data retrieved successfully.";

                Json::Value monitors_array(Json::arrayValue);
                for (const auto& monitor : monitors) {
                    Json::Value monitor_data;
                    monitor_data["id"] = monitor.id;
                    monitor_data["cpu_usage"] = monitor.cpu_usage;
                    monitor_data["memory_usage"] = monitor.memory_usage;
                    monitor_data["disk_usage"] = monitor.disk_usage;
                    monitor_data["network_upload"] = monitor.network_upload;
                    monitor_data["network_download"] = monitor.network_download;
                    monitor_data["temperature"] = monitor.temperature;
                    monitor_data["sample_time"] = monitor.sample_time;
                    monitor_data["battery_percentage"] = monitor.battery_percentage;
                    monitor_data["is_charging"] = monitor.is_charging;
                    monitor_data["is_ac_power"] = monitor.is_ac_power;
                    monitor_data["battery_life_time"] = monitor.battery_life_time;
                    monitor_data["ac_line_status_raw"] = Utils::StatusToString("ACLineStatus", monitor.ac_line_status_raw);
                    monitor_data["battery_flag_raw"] = Utils::StatusToString("BatteryFlag", monitor.battery_flag_raw);
                    monitors_array.append(monitor_data);
                }
                root["result"]["data"] = monitors_array;
            }
            else {
                res.status = 404;
                root["result"]["status"] = "fail";
                root["result"]["message"] = "No system monitor data found.";
            }

            res.set_content(root.toStyledString(), "application/json");
        }
        catch (const std::exception& e) {
            res.status = 500;
            Json::Value error_response;
            error_response["result"]["status"] = "error";
            error_response["result"]["message"] = "An error occurred while retrieving system monitor data: " + std::string(e.what());
            res.set_content(error_response.toStyledString(), "application/json");
        }
    }



    void handle_get_all_app_resource_monitors(const httplib::Request& req, httplib::Response& res) {
        if (!verifyToken(req, res)) return;

        try {
            // 获取所有应用资源监控数据
            std::vector<sp::AppResourceMonitor> app_monitors;
            bool found = sp::ServerManager::getInstance().getAppResourceMonitorService().getAllAppResourceMonitors(app_monitors);

            Json::Value root;
            if (found) {
                root["result"]["status"] = "success";
                root["result"]["message"] = "Application resource monitor data retrieved successfully.";

                Json::Value app_monitors_array(Json::arrayValue);
                for (const auto& app_monitor : app_monitors) {
                    Json::Value app_monitor_data;
                    app_monitor_data["id"] = app_monitor.id;
                    app_monitor_data["app_id"] = app_monitor.app_id;
                    app_monitor_data["app_name"] = app_monitor.app_name;
                    app_monitor_data["icon_path"] = app_monitor.icon_path;
                    app_monitor_data["cpu_usage"] = app_monitor.cpu_usage;
                    app_monitor_data["memory_usage_mb"] = app_monitor.memory_usage_mb;
                    app_monitor_data["disk_io_read"] = app_monitor.disk_io_read;
                    app_monitor_data["disk_io_write"] = app_monitor.disk_io_write;
                    app_monitor_data["sample_time"] = app_monitor.sample_time;
                    app_monitor_data["use_duration"] = app_monitor.use_duration;
                    app_monitor_data["power_use_level"] = app_monitor.power_use_level;

                    app_monitors_array.append(app_monitor_data);
                }
                root["result"]["data"] = app_monitors_array;
            }
            else {
                res.status = 404;
                root["result"]["status"] = "fail";
                root["result"]["message"] = "No application resource monitor data found.";
            }

            res.set_content(root.toStyledString(), "application/json");
        }
        catch (const std::exception& e) {
            res.status = 500;
            Json::Value error_response;
            error_response["result"]["status"] = "error";
            error_response["result"]["message"] = "An error occurred while retrieving application resource monitor data: " + std::string(e.what());
            res.set_content(error_response.toStyledString(), "application/json");
        }
    }

    void handle_get_app_resource_monitor_by_id(const httplib::Request& req, httplib::Response& res) {}

    void handle_get_app_resource_monitor_by_app_id(const httplib::Request& req, httplib::Response& res) {
        if (!verifyToken(req, res)) return;

        try {
            // 从请求路径参数获取 app_id
            uint64_t app_id = std::stoull(req.matches[1]);  // 假设 app_id 作为路径参数被捕获

            // 获取指定 app_id 的所有资源监控数据
            std::vector<sp::AppResourceMonitor> app_monitors;
            bool found = sp::ServerManager::getInstance().getAppResourceMonitorService().getAppResourceMonitorsByAppId(app_id, app_monitors);

            Json::Value root;
            if (found && !app_monitors.empty()) {
                root["result"]["status"] = "success";
                root["result"]["message"] = "Application resource monitor data retrieved successfully.";

                Json::Value app_monitors_array(Json::arrayValue);
                for (const auto& app_monitor : app_monitors) {
                    Json::Value app_monitor_data;
                    app_monitor_data["id"] = app_monitor.id;
                    app_monitor_data["app_id"] = app_monitor.app_id;
                    app_monitor_data["app_name"] = app_monitor.app_name;
                    app_monitor_data["icon_path"] = app_monitor.icon_path;
                    app_monitor_data["cpu_usage"] = app_monitor.cpu_usage;
                    app_monitor_data["memory_usage_mb"] = app_monitor.memory_usage_mb;
                    app_monitor_data["disk_io_read"] = app_monitor.disk_io_read;
                    app_monitor_data["disk_io_write"] = app_monitor.disk_io_write;
                    app_monitor_data["sample_time"] = app_monitor.sample_time;
                    app_monitor_data["use_duration"] = app_monitor.use_duration;
                    app_monitor_data["power_use_level"] = app_monitor.power_use_level;



                    app_monitors_array.append(app_monitor_data);
                }
                root["result"]["data"] = app_monitors_array;
            }
            else {
                res.status = 404;
                root["result"]["status"] = "fail";
                root["result"]["message"] = "No application resource monitor data found for the specified app_id.";
            }

            res.set_content(root.toStyledString(), "application/json");
        }
        catch (const std::exception& e) {
            res.status = 500;
            Json::Value error_response;
            error_response["result"]["status"] = "error";
            error_response["result"]["message"] = "An error occurred while retrieving application resource monitor data: " + std::string(e.what());
            res.set_content(error_response.toStyledString(), "application/json");
        }
    }
    
    void handle_modify_app_resource_monitor(const httplib::Request& req, httplib::Response& res) {
    
    }



    void handle_get_system_config(const httplib::Request& req, httplib::Response& res) {}

    void handle_update_system_config(const httplib::Request& req, httplib::Response& res) {}

    void handle_delete_system_config(const httplib::Request& req, httplib::Response& res) {}

    void handle_create_system_config(const httplib::Request& req, httplib::Response& res) {}

    void handle_get_malicious_thread_log_by_app_id(const httplib::Request& req, httplib::Response& res) {
        if (!verifyToken(req, res)) return;

        try {
            auto app_id_str = req.get_param_value("app_id");
            if (app_id_str.empty()) {
                res.status = 400;
                res.set_content("{\"result\": {\"status\": \"fail\", \"message\": \"The parameter app_id is missing.\"}}", "application/json");
                return;
            }

            uint64_t app_id;
            try {
                app_id = std::stoull(app_id_str);
            }
            catch (const std::exception&) {
                res.status = 400;
                res.set_content("{\"result\": {\"status\": \"fail\", \"message\": \"The app_id parameter is invalid.\"}}", "application/json");
                return;
            }

            std::vector<MaliciousThreadLog> logs;
            bool success = ServerManager::getInstance().getMaliciousThreadLogService().getMaliciousThreadLogsByAppId(app_id, logs);

            Json::Value response;
            if (success) {
                response["result"]["status"] = "success";
                response["result"]["message"] = "Successfully obtained the malicious thread logs of the specified application.";

                for (const auto& log : logs) {
                    Json::Value log_data;
                    log_data["id"] = log.id;
                    log_data["app_id"] = log.app_id;
                    log_data["thread_name"] = log.thread_name;
                    log_data["thread_hash"] = log.thread_hash;
                    log_data["risk_level"] = log.risk_level;
                    log_data["detection_time"] = log.detection_time;

                    response["result"]["data"].append(log_data);
                }
            }
            else {
                response["result"]["status"] = "fail";
                response["result"]["message"] = "Failed to obtain the malicious thread logs.";
            }

            res.set_content(response.toStyledString(), "application/json");
        }
        catch (const std::exception&) {
            res.status = 500;
            res.set_content("{\"result\": {\"status\": \"error\", \"message\": \"An error occurred while obtaining the malicious thread logs.\"}}", "application/json");
        }
    }

    void handle_get_all_malicious_thread_logs(const httplib::Request& req, httplib::Response& res) {
        if (!verifyToken(req, res)) return;

        try {
            std::vector<MaliciousThreadLog> logs;
            bool success = ServerManager::getInstance().getMaliciousThreadLogService().getAllMaliciousThreadLogs(logs);

            Json::Value response;
            if (success) {
                response["result"]["status"] = "success";
                response["result"]["message"] = "Successfully obtained all malicious thread logs.";

                for (const auto& log : logs) {
                    Json::Value log_data;
                    log_data["id"] = log.id;
                    log_data["app_id"] = log.app_id;
                    log_data["thread_name"] = log.thread_name;
                    log_data["thread_hash"] = log.thread_hash;
                    log_data["risk_level"] = log.risk_level;
                    log_data["detection_time"] = log.detection_time;

                    response["result"]["data"].append(log_data);
                }
            }
            else {
                response["result"]["status"] = "fail";
                response["result"]["message"] = "Failed to obtain all malicious thread logs.";
            }

            res.set_content(response.toStyledString(), "application/json");
        }
        catch (const std::exception&) {
            res.status = 500;
            res.set_content("{\"result\": {\"status\": \"error\", \"message\": \"An error occurred while obtaining all the malicious thread logs.\"}}", "application/json");
        }
    }


    void handle_get_file_modification_log_by_app_id(const httplib::Request& req, httplib::Response& res) {
        if (!verifyToken(req, res)) return;

        try {
            auto app_id_str = req.get_param_value("app_id");
            if (app_id_str.empty()) {
                res.status = 400;
                res.set_content("{\"result\": {\"status\": \"fail\", \"message\": \"The parameter app_id is missing.\"}}", "application/json");
                return;
            }

            uint64_t app_id;
            try {
                app_id = std::stoull(app_id_str);
            }
            catch (const std::exception&) {
                res.status = 400;
                res.set_content("{\"result\": {\"status\": \"fail\", \"message\": \"The app_id parameter is invalid.\"}}", "application/json");
                return;
            }

            std::vector<FileModificationLog> logs;
            bool success = ServerManager::getInstance().getFileModificationLogService().getFileModificationLogsByAppId(app_id, logs);

            Json::Value response;
            if (success) {
                response["result"]["status"] = "success";
                response["result"]["message"] = "Successfully obtained the file modification logs of the specified application.";

                for (const auto& log : logs) {
                    Json::Value log_data;
                    log_data["id"] = log.id;
                    log_data["app_id"] = log.app_id;
                    log_data["file_path"] = log.file_path;
                    log_data["operation_type"] = log.operation_type;
                    log_data["file_hash"] = log.file_hash;
                    log_data["alert_time"] = log.alert_time;

                    response["result"]["data"].append(log_data);
                }
            }
            else {
                response["result"]["status"] = "fail";
                response["result"]["message"] = "Failed to obtain the file modification logs.";
            }

            res.set_content(response.toStyledString(), "application/json");
        }
        catch (const std::exception&) {
            res.status = 500;
            res.set_content("{\"result\": {\"status\": \"error\", \"message\": \"An error occurred while obtaining the file modification logs.\"}}", "application/json");
        }
    }

    void handle_get_all_file_modification_logs(const httplib::Request& req, httplib::Response& res) {
        if (!verifyToken(req, res)) return;

        try {
            std::vector<FileModificationLog> logs;
            bool success = ServerManager::getInstance().getFileModificationLogService().getAllFileModificationLogs(logs);

            Json::Value response;
            if (success) {
                response["result"]["status"] = "success";
                response["result"]["message"] = "Successfully obtained all file modification logs.";

                for (const auto& log : logs) {
                    Json::Value log_data;
                    log_data["id"] = log.id;
                    log_data["app_id"] = log.app_id;
                    log_data["file_path"] = log.file_path;
                    log_data["operation_type"] = log.operation_type;
                    log_data["file_hash"] = log.file_hash;
                    log_data["alert_time"] = log.alert_time;

                    response["result"]["data"].append(log_data);
                }
            }
            else {
                response["result"]["status"] = "fail";
                response["result"]["message"] = "Failed to obtain all file modification logs.";
            }

            res.set_content(response.toStyledString(), "application/json");
        }
        catch (const std::exception&) {
            res.status = 500;
            res.set_content("{\"result\": {\"status\": \"error\", \"message\": \"An error occurred while obtaining all the file modification logs.\"}}", "application/json");
        }
    }


    void handle_get_ai_analysis_result(const httplib::Request& req, httplib::Response& res) {}

    void handle_get_ai_analysis_results_by_user(const httplib::Request& req, httplib::Response& res) {
        if (!verifyToken(req, res)) return;

        try {
            uint64_t user_id = std::stoull(req.matches[1]);

            // 获取指定 user_id 的所有 AI 分析结果数据
            std::vector<AIAnalysisResult> analysis_results;
            bool found = sp::ServerManager::getInstance().getAIAnalysisResultService().getAIAnalysisResultsByUserId(user_id, analysis_results);

            Json::Value root;
            if (found && !analysis_results.empty()) {
                root["result"]["status"] = "success";
                root["result"]["message"] = "The AI analysis results have been successfully obtained.";

                Json::Value results_array(Json::arrayValue);
                for (const auto& ai_result : analysis_results) {
                    Json::Value ai_result_data;
                    ai_result_data["id"] = ai_result.id;
                    ai_result_data["user_id"] = ai_result.user_id;
                    ai_result_data["analysis_type"] = ai_result.analysis_type;
                    ai_result_data["content_hash"] = ai_result.content_hash;
                    ai_result_data["result"] = ai_result.result;
                    ai_result_data["confidence"] = ai_result.confidence;
                    ai_result_data["analysis_time"] = ai_result.analysis_time;
                    ai_result_data["score"] = ai_result.score;

                    results_array.append(ai_result_data);
                }
                root["result"]["data"] = results_array;
            }
            else {
                res.status = 404;
                root["result"]["status"] = "fail";
                root["result"]["message"] = "The AI analysis results for the specified user have not been found.";
            }

            res.set_content(root.toStyledString(), "application/json");
        }
        catch (const std::exception& e) {
            res.status = 500;
            Json::Value error_response;
            error_response["result"]["status"] = "error";
            error_response["result"]["message"] = "An error occurred while obtaining the AI analysis results:" + std::string(e.what());
            res.set_content(error_response.toStyledString(), "application/json");
        }
    }

    void handle_ai_analysis(const httplib::Request& req, httplib::Response& res)
    {
        //if (!verifyToken(req, res)) return;

        try {
            
            Json::Reader reader;
            Json::Value json_data;
            if (!reader.parse(req.body, json_data)) {
                res.status = 400; 
                Json::Value error_response;
                error_response["result"]["status"] = "error";
                error_response["result"]["message"] = "Invalid JSON format";
                res.set_content(error_response.toStyledString(), "application/json");
                return;
            }
            std::string prompt = json_data["prompt"].asString();
            std::string user_id = json_data["user_id"].asString();

            AIAnalysisResult analysis_result;
            Json::Value root = sp::ServerManager::getInstance().getSystemInfoService().askDeepseek(prompt);
            
            analysis_result.id = Utils::generateUUID(1);
            analysis_result.result = Utils::withEscape(root["choices"][0]["message"]["content"].asString());
            analysis_result.user_id = std::stoull(user_id);
            analysis_result.analysis_type = "1";
            analysis_result.analysis_time = Utils::timestampToMySQLFormat(std::stoll(root["created"].asString()));
            analysis_result.confidence = 1;
            analysis_result.content_hash = MD5(analysis_result.result).toStr();
            analysis_result.score = Utils::getScore(analysis_result.result);
            bool flag = sp::ServerManager::getInstance().getAIAnalysisResultService().insertAIAnalysisResult(analysis_result);

            Json::Value val;
            val["result"]["status"] = "success";
            val["result"]["data"]["id"] = analysis_result.id;
            val["result"]["data"]["result"] = root["choices"][0]["message"]["content"].asString();
            val["result"]["data"]["user_id"] = analysis_result.user_id;
            val["result"]["data"]["analysis_type"] = analysis_result.analysis_type;
            val["result"]["data"]["analysis_time"] = analysis_result.analysis_time;
            val["result"]["data"]["confidence"] = analysis_result.confidence;
            val["result"]["data"]["content_hash"] = analysis_result.content_hash;
            val["result"]["data"]["score"] = analysis_result.score;
            val["result"]["message"] = "The AI analysis results have been successfully obtained.";
            res.status = 200;
            res.set_content(val.toStyledString(), "application/json");
        }
        catch (const std::exception& e) {
            res.status = 500;
            Json::Value error_response;
            error_response["result"]["status"] = "error";
            error_response["result"]["message"] = "An error occurred while obtaining the AI analysis results: " + std::string(e.what());
            res.set_content(error_response.toStyledString(), "application/json");
        }
    }

    void handle_get_user_info(const httplib::Request& req, httplib::Response& res) {}

    void handle_update_user_info(const httplib::Request& req, httplib::Response& res) {
        if (!verifyToken(req, res)) return;

        try {
            Json::CharReaderBuilder reader;
            Json::Value root;
            std::string errs;

            std::unique_ptr<Json::CharReader> jsonReader(reader.newCharReader());
            if (!jsonReader->parse(req.body.c_str(), req.body.c_str() + req.body.size(), &root, &errs)) {
                res.status = 400;
                res.set_content("{\"result\": {\"status\": \"fail\", \"message\": \"The JSON data is invalid.\"}}", "application/json");
                return;
            }

            if (!root.isMember("user_id") || !root["user_id"].isUInt64()) {
                res.status = 400;
                res.set_content("{\"result\": {\"status\": \"fail\", \"message\": \"The necessary parameter user_id is missing.\"}}", "application/json");
                return;
            }

            UserInfo userInfo;
            userInfo.user_id = root["user_id"].asUInt64();
            if (root.isMember("username")) userInfo.username = root["username"].asString();
            if (root.isMember("password")) userInfo.password = root["password"].asString();
            if (root.isMember("role")) userInfo.role = root["role"].asString();
            if (root.isMember("email")) userInfo.email = root["email"].asString();
            if (root.isMember("phone")) userInfo.phone = root["phone"].asString();
            if (root.isMember("last_login_ip")) userInfo.last_login_ip = root["last_login_ip"].asString();
            if (root.isMember("last_login_time")) userInfo.last_login_time = root["last_login_time"].asString();
            if (root.isMember("is_locked")) userInfo.is_locked = root["is_locked"].asBool();
            if (root.isMember("create_time")) userInfo.create_time = root["create_time"].asString();

            bool success = ServerManager::getInstance().getUserInfoService().updateUserInfo(userInfo);

            Json::Value response;
            if (success) {
                response["result"]["status"] = "success";
                response["result"]["message"] = "用户信息更新成功。";
            }
            else {
                response["result"]["status"] = "fail";
                response["result"]["message"] = "用户信息更新失败。";
            }

            res.set_content(response.toStyledString(), "application/json");
        }
        catch (const std::exception& e) {
            res.status = 500;
            res.set_content("{\"result\": {\"status\": \"error\", \"message\": \"An error occurred while updating the user information.\"}}", "application/json");
        }
    }

    void handle_delete_user_info(const httplib::Request& req, httplib::Response& res) {}

    void handle_send_verification_code(const httplib::Request& req, httplib::Response& res)
    {
        try {
            Json::Reader reader;
            Json::Value json_data;
            if (!reader.parse(req.body, json_data)) {
                // 如果 JSON 格式不正确，返回错误响应
                res.status = 400;  // 错误的请求
                Json::Value error_response;
                error_response["result"]["status"] = "error";
                error_response["result"]["message"] = "Invalid JSON format";
                res.set_content(error_response.toStyledString(), "application/json");
                return;
            }

            std::string email = json_data["email"].asString();
            std::string code = sp::ServerManager::getInstance().getAuthService().generateVerificationCode(email);
            std::string body = "验证码：" + code;
            std::string subject = "CyberSentry验证码";
            sp::ServerManager::getInstance().getEmailService().sendMail(email, subject, body);

            res.status = 200;

            Json::Value root;
            root["result"]["status"] = "success";
            root["result"]["message"] = "Verification code sent successfully.";
            res.set_content(root.toStyledString(), "application/json");
        }
        catch (const std::exception& e) {
            // 捕获异常，返回错误信息
            res.status = 500;  // 服务器错误
            Json::Value error_response;
            error_response["result"]["status"] = "error";
            error_response["result"]["message"] = "An error occurred while retrieving user operation logs: " + std::string(e.what());
            res.set_content(error_response.toStyledString(), "application/json");
        }
    }

    void handle_get_image(const httplib::Request& req, httplib::Response& res) {
        static const std::unordered_map<std::string, std::string> MIME_TYPES = {
            {".jpg",  "image/jpeg"},
            {".jpeg", "image/jpeg"},
            {".png",  "image/png"},
            {".gif",  "image/gif"},
            {".bmp",  "image/bmp"},
            {".webp", "image/webp"}
        };

        namespace fs = std::filesystem;

        try {
            // 验证路径参数存在
            if (req.matches.size() < 2) {
                res.status = 400;
                res.set_content("Bad Request: Missing file path", "text/plain");
                return;
            }

            // 获取 URL 解码后的路径
            std::string encoded_url = Utils::utf8ToGbk(req.matches[1]);
            std::cout << encoded_url;

            // 设置安全根目录
            const fs::path root_dir = "";  // 修改为你希望的目录
            fs::path requested_path = encoded_url;

            // 构造完整路径并规范化
            fs::path full_path = root_dir / requested_path;
            full_path = fs::weakly_canonical(full_path);

            // 防止路径遍历攻击
            if (full_path.string().find(root_dir.string()) != 0) {
                res.status = 403;
                res.set_content("Forbidden: Path traversal attempt detected", "text/plain");
                return;
            }

            // 获取并处理扩展名
            std::string ext = full_path.extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), [](char c) {
                return std::tolower(static_cast<unsigned char>(c));
                });

            // 验证MIME类型支持
            if (MIME_TYPES.find(ext) == MIME_TYPES.end()) {
                res.status = 415;
                res.set_content("Unsupported Media Type", "text/plain");
                return;
            }

            // 验证文件状态
            if (!fs::exists(full_path)) {
                res.status = 404;
                res.set_content("Not Found", "text/plain");
                return;
            }

            if (!fs::is_regular_file(full_path)) {
                res.status = 403;
                res.set_content("Forbidden: Not a regular file", "text/plain");
                return;
            }

            // 打开文件并验证
            auto file = std::make_shared<std::ifstream>(
                full_path,
                std::ios::binary | std::ios::ate
            );

            if (!file->is_open()) {
                res.status = 500;
                res.set_content("Internal Server Error", "text/plain");
                return;
            }

            // 获取文件大小
            const auto file_size = static_cast<size_t>(file->tellg());
            file->seekg(0);

            // 设置内容提供器
            res.set_content_provider(
                file_size,
                MIME_TYPES.at(ext),
                [file, file_size](size_t offset, size_t length, httplib::DataSink& sink) {
                    // 处理超出文件范围的请求
                    if (offset >= file_size) {
                        sink.write(nullptr, 0);
                        return true;
                    }

                    // 计算实际可读取的长度
                    const size_t adjusted_length = min(length, file_size - offset);
                    file->seekg(offset);

                    // 使用智能指针管理缓冲区
                    auto buffer = std::make_unique<char[]>(adjusted_length);
                    file->read(buffer.get(), adjusted_length);

                    if (file->gcount() > 0) {
                        sink.write(buffer.get(), static_cast<size_t>(file->gcount()));
                    }
                    return true;
                }
            );
        }
        catch (const std::exception& e) {
            res.status = 500;
            LOG_ERROR("Internal Server Error: " + std::string(e.what()));
            res.set_content("Internal Server Error: " + std::string(e.what()), "text/plain");
        }
    }
    
    void handle_get_file_list(const httplib::Request& req, httplib::Response& res) {
        if (!verifyToken(req, res)) return;  // 验证令牌
        try {
            std::vector<FileInfo> file_list;  // 存储所有文件信息的列表
            bool flag = ServerManager::getInstance().getFileInfoService().getAllFileInfo(file_list);  // 获取所有文件信息
            Json::Value root;  // JSON 根对象
            if (flag) {
                root["result"]["status"] = "success";  // 状态为成功
                root["result"]["message"] = "All file information has been successfully obtained.";

                // 遍历所有文件信息，并将其添加到 JSON 响应中
                for (const auto& file_info : file_list) {
                    Json::Value file_data;  // 存储单个文件信息的 JSON 对象
                    file_data["file_id"] = file_info.file_id;
                    file_data["path"] = file_info.path;
                    file_data["force_delete"] = file_info.force_delete;
                    file_data["is_encrypted"] = file_info.is_encrypted;
                    file_data["secret_key"] = file_info.secret_key;

                    // 将单个文件信息添加到结果数组中
                    root["result"]["data"].append(file_data);
                }
            }
            else {
                root["result"]["status"] = "fail";  // 获取失败
                root["result"]["message"] = "Failed to obtain all file information.";
            }

            // 设置响应内容为 JSON 格式
            res.set_content(root.toStyledString(), "application/json");
        }
        catch (const std::exception& e) {
            // 处理异常
            res.status = 500;  // 设置为服务器错误
            res.set_content("{\"result\": {\"status\": \"error\", \"message\": \"An error occurred while retrieving file information.\"}}", "application/json");
        }
    }

    void handle_get_file_info(const httplib::Request& req, httplib::Response& res) {
        if (!verifyToken(req, res)) return;  // 验证令牌
        try {
            int file_id = std::stoi(req.matches[1]);  // 获取路径中捕获的文件 ID
            FileInfo file_info;
            bool flag = ServerManager::getInstance().getFileInfoService().getFileInfoById(file_id, file_info);  // 获取文件信息
            Json::Value root;  // JSON 根对象
            if (flag) {
                root["result"]["status"] = "success";  // 状态为成功
                root["result"]["message"] = "File information retrieved successfully.";

                // 将文件信息添加到 JSON 响应中
                root["result"]["data"]["file_id"] = file_info.file_id;
                root["result"]["data"]["path"] = file_info.path;
                root["result"]["data"]["force_delete"] = file_info.force_delete;
                root["result"]["data"]["is_encrypted"] = file_info.is_encrypted;
                root["result"]["data"]["secret_key"] = file_info.secret_key;
            }
            else {
                root["result"]["status"] = "fail";  // 获取失败
                root["result"]["message"] = "File information retrieval failed.";
            }

            // 设置响应内容为 JSON 格式
            res.set_content(root.toStyledString(), "application/json");
        }
        catch (const std::exception& e) {
            // 处理异常
            res.status = 500;  // 设置为服务器错误
            res.set_content("{\"result\": {\"status\": \"error\", \"message\": \"Invalid file ID.\"}}", "application/json");
        }
    }

    void handle_encrypt_file(const httplib::Request& req, httplib::Response& res) {
        if (!verifyToken(req, res)) return;  // 验证令牌
        try {
            // 从请求体中获取加密所需的文件 ID 和密钥
            Json::Value request_data;
            Json::Reader reader;
            if (!reader.parse(req.body, request_data)) {
                res.status = 400;  // 错误的请求
                res.set_content("{\"result\": {\"status\": \"error\", \"message\": \"Invalid request body.\"}}", "application/json");
                return;
            }

            uint64_t file_id = request_data["file_id"].asUInt64();
            std::string key = request_data["key"].asString();

            bool flag = ServerManager::getInstance().getFileInfoService().encryptFile(file_id, key);  // 执行加密操作
            Json::Value root;
            if (flag) {
                root["result"]["status"] = "success";
                root["result"]["message"] = "File encrypted successfully.";
            }
            else {
                root["result"]["status"] = "fail";
                root["result"]["message"] = "File encryption failed.";
            }

            res.set_content(root.toStyledString(), "application/json");
        }
        catch (const std::exception& e) {
            // 处理异常
            res.status = 500;  // 设置为服务器错误
            res.set_content("{\"result\": {\"status\": \"error\", \"message\": \"An error occurred during file encryption.\"}}", "application/json");
        }
    }

    void handle_decrypt_file(const httplib::Request& req, httplib::Response& res) {
        if (!verifyToken(req, res)) return;  // 验证令牌
        try {
            // 从请求体中获取解密所需的文件 ID
            Json::Value request_data;
            Json::Reader reader;
            if (!reader.parse(req.body, request_data)) {
                res.status = 400;  // 错误的请求
                res.set_content("{\"result\": {\"status\": \"error\", \"message\": \"Invalid request body.\"}}", "application/json");
                return;
            }

            uint64_t file_id = request_data["file_id"].asUInt64();

            bool flag = ServerManager::getInstance().getFileInfoService().decryptFile(file_id);  // 执行解密操作
            Json::Value root;
            if (flag) {
                root["result"]["status"] = "success";
                root["result"]["message"] = "File decrypted successfully.";
            }
            else {
                root["result"]["status"] = "fail";
                root["result"]["message"] = "File decryption failed.";
            }

            res.set_content(root.toStyledString(), "application/json");
        }
        catch (const std::exception& e) {
            // 处理异常
            res.status = 500;  // 设置为服务器错误
            res.set_content("{\"result\": {\"status\": \"error\", \"message\": \"An error occurred during file decryption.\"}}", "application/json");
        }
    }


    void runServer()
    {
        sp::HttpServer svr;
        svr.Get(R"(/api/app_info/(\d+))", handle_get_app_info);
        svr.Get(R"(/api/app_infos)", handle_get_all_app_info);

        svr.Get(R"(/api/monitoring_rule/(\d+))", handle_get_monitoring_rule);
        svr.Get(R"(/api/monitoring_rules)", handle_get_all_monitoring_rules);

        svr.Get(R"(/api/system_monitor/long)", handle_get_system_monitors);
        svr.Get(R"(/api/system_monitor/short)", handle_get_system_monitors_short);

        svr.Get(R"(/api/app_resource_monitors)", handle_get_all_app_resource_monitors);
        svr.Get(R"(/api/app_resource_monitor/(\d+))", handle_get_app_resource_monitor_by_id);
        svr.Get(R"(/api/app_resource_monitors/app/(\d+))", handle_get_app_resource_monitor_by_app_id);
        svr.Post(R"(/api/monitoring_rules)", handle_modify_app_resource_monitor);

        svr.Post(R"(/api/user_operation_log)", handle_create_user_operation_log);
        svr.Get(R"(/api/user_operation_logs)", handle_get_all_user_operation_logs);
        svr.Get(R"(/api/user_operation_logs/(\d+))", handle_get_user_operation_logs);

        svr.Get(R"(/api/system_config)", handle_get_system_config);
        svr.Post(R"(/api/system_config/update)", handle_update_system_config);
        svr.Post(R"(/api/system_config)", handle_create_system_config);
        svr.Post(R"(/api/system_config/delete)", handle_delete_system_config);


        svr.Get(R"(/api/malicious_thread_logs/(\d+))", handle_get_malicious_thread_log_by_app_id);
        svr.Get(R"(/api/malicious_thread_logs)", handle_get_all_malicious_thread_logs);

        svr.Get(R"(/api/file_modification_logs/(\d+))", handle_get_file_modification_log_by_app_id);
        svr.Get(R"(/api/file_modification_logs)", handle_get_all_file_modification_logs);


        svr.Get(R"(/api/ai_analysis_results/(\d+))", handle_get_ai_analysis_result);
        svr.Get(R"(/api/ai_analysis_results/user/(\d+))", handle_get_ai_analysis_results_by_user);
        svr.Post(R"(/api/ai_analysis)", handle_ai_analysis);

        svr.Get(R"(/api/user/(\d+))", handle_get_user_info);
        svr.Post(R"(/api/user/(\d+))", handle_update_user_info);
        svr.Post(R"(/api/user/(\d+)/delete)", handle_delete_user_info);

        svr.Get(R"(/api/files)", handle_get_file_list);
        svr.Get(R"(/api/files/(\d+))", handle_get_file_info);
        svr.Post(R"(/api/files/encrypt)", handle_encrypt_file);
        svr.Post(R"(/api/files/decrypt)", handle_decrypt_file);

        //svr.Post(R"(/api/file_upload)", handle_file_upload);
        //svr.Post(R"(/api/data_import)", handle_data_import);
        svr.Post(R"(/api/login)", handle_user_login);
        //svr.Post(R"(/api/logout)", handle_user_logout);

        svr.Post(R"(/api/verification_code)", handle_send_verification_code);

        svr.Get("/api/get_image/(.*)", handle_get_image);

        svr.Run();
    }


   
}
