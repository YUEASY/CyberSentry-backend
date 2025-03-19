#pragma once
#include <iostream>
#include <fstream>
#include <sstream>
#include <atomic>
#include <random>
#include <chrono>
#include <iomanip>
#include "logger.hpp"
#include <mysql.h>
#include <json/json.h>

namespace sp
{
    class Utils
    {
    public:
        static std::string vcode()
        {
            std::random_device rd;
            std::default_random_engine generator(rd());
            std::uniform_int_distribution<int> distribution(1000, 9999);
            return std::to_string(distribution(generator));
        }

        static std::string token()
        {
            // 生成前8位随机字母数字
            const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            std::string randomPart;
            std::random_device rd;
            std::default_random_engine generator(rd());
            std::uniform_int_distribution<int> distribution(0, sizeof(charset) - 2);

            for (int i = 0; i < 8; ++i)
            {
                randomPart += charset[distribution(generator)];
            }

            // 获取当前时间
            auto now = std::chrono::system_clock::now();
            std::time_t now_c = std::chrono::system_clock::to_time_t(now);
            std::tm now_tm;
            localtime_s(&now_tm,&now_c);
            // 生成后8位（日、时、分、秒）
            std::ostringstream timePart;
            timePart << std::setw(2) << now_tm.tm_mday
                << std::setw(2) << now_tm.tm_hour
                << std::setw(2) << now_tm.tm_min
                << std::setw(2) << now_tm.tm_sec;

            return randomPart + timePart.str();
        }

        static std::string verificationCode()
        {
            // 生成前8位随机字母数字
            const char charset[] = "0123456789";
            std::string randomPart;
            std::random_device rd;
            std::default_random_engine generator(rd());
            std::uniform_int_distribution<int> distribution(0, sizeof(charset) - 2);

            for (int i = 0; i < 4; ++i)
            {
                randomPart += charset[distribution(generator)];
            }
            return randomPart;
        }

        static uint64_t generateUUID(uint64_t sequence) {
            const uint64_t twepoch = 1288834974657L; // 起始时间
            const uint64_t sequenceBits = 12;        // 序列号所占位数
            const uint64_t sequenceMask = (1 << sequenceBits) - 1; // 序列号掩码
            const uint64_t timestampLeftShift = sequenceBits; // 时间戳偏移位数

            static uint64_t lastTimestamp = -1L;  // 上次时间戳

            // 获取当前时间戳（毫秒）
            auto currentMillis = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            uint64_t timestamp = currentMillis;

            // 如果在同一毫秒内，序列号递增
            if (timestamp == lastTimestamp) {
                sequence = (sequence + 1) & sequenceMask; // 保证序列号不会超出最大值
                if (sequence == 0) {  // 如果序列号到达最大值，等待下一毫秒
                    while (timestamp <= lastTimestamp) {
                        timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count();
                    }
                }
            }
            else {
                sequence = 0;  // 重置序列号
            }

            lastTimestamp = timestamp;

            // 生成UUID：时间戳部分 + 序列号部分
            uint64_t id = (timestamp - twepoch) << timestampLeftShift;
            id |= sequence;

            return id;
        }

        static bool readFile(std::string_view filename, std::string &body)
        {
            std::ifstream file(filename.data(), std::ios::binary | std::ios::in);
            if (!file.is_open())
            {
                LOG_ERROR("打开文件{}失败", filename.data());
                return false;
            }

            // body.assign((std::istreambuf_iterator<char>(file)),
            //             std::istreambuf_iterator<char>());
            file.seekg(0, std::ios::end);
            size_t flen = file.tellg();
            file.seekg(0, std::ios::beg);
            body.resize(flen);
            file.read(&body[0], flen);
            if (file.good() == false)
            {
                LOG_ERROR("读取文件{}失败", filename.data());
                file.close();
                return false;
            }
            file.close();
            return true;
        }
        static bool writeFile(std::string_view filename, const std::string &body)
        {
            std::ofstream file(filename.data(), std::ios::binary | std::ios::out | std::ios::trunc);
            if (!file.is_open())
            {
                return false;
            }

            file << body;
            if (file.good() == false)
            {
                LOG_ERROR("写入文件{}失败", filename.data());
                file.close();
                return false;
            }
            file.close();
            return true;
        }

        static MYSQL *mysqlInit(const char *db, const char *host = "127.0.0.1", const char *port = "3306", const char *user = "root", const char *passwd = "123456", const char *unix_socket = nullptr, unsigned long client_flag = 0)
        {
            MYSQL *mysql = mysql_init(NULL);
            if (mysql == nullptr)
            {
                LOG_TRACE("init mysql instance failed!");
                return nullptr;
            }
            if (mysql_real_connect(mysql, host, user, passwd, db, std::stoi(port), unix_socket, client_flag) == nullptr)
            {
                LOG_TRACE("connect mysql sever failed!");
                mysql_close(mysql);
                return nullptr;
            }
            mysql_set_character_set(mysql, "utf8");
            return mysql;
        }

        static void mysqlDestroy(MYSQL *mysql)
        {
            if (mysql != nullptr)
            {
                mysql_close(mysql);
            }
        }

        static bool mysqlQuery(MYSQL *mysql, const std::string &sql)
        {
            if (mysql_query(mysql, sql.c_str()) != 0)
            {
                LOG_ERROR("mysql query error:{}", sql);
                LOG_ERROR(mysql_error(mysql));
                return false;
            }
            return true;
        }

        static std::string timestampToMySQLFormat(int64_t timestamp)
        {
            // 将时间戳转换为结构体tm
            time_t t = static_cast<time_t>(timestamp);
            struct tm tm_info; 
            localtime_s(&tm_info,&t);

            // 使用字符串流格式化日期时间
            std::ostringstream oss;
            oss << std::put_time(&tm_info, "%Y-%m-%d %H:%M:%S");

            return oss.str();
        }

        static int64_t MySQLFormatToTimestamp(const std::string &datetime)
        {
            std::tm tm_info = {};
            std::istringstream ss(datetime);

            // 使用 std::get_time 来解析日期时间字符串
            ss >> std::get_time(&tm_info, "%Y-%m-%d %H:%M:%S");
            if (ss.fail())
            {
                throw std::runtime_error("Failed to parse datetime string");
            }

            // 将 tm 结构转换为 time_t
            time_t t = mktime(&tm_info);
            if (t == -1)
            {
                throw std::runtime_error("Failed to convert tm to time_t");
            }

            // 返回时间戳
            return static_cast<int64_t>(t);
        }
    
        static std::string gbkToUtf8(const std::string& gbkStr) {
            // 先将 GBK 转换为宽字符（UTF-16）
            int wideLen = MultiByteToWideChar(936, 0, gbkStr.c_str(), -1, nullptr, 0);
            if (wideLen == 0) {
                throw std::runtime_error("Failed to convert GBK to wide char");
            }

            std::wstring wideStr(wideLen, L'\0');
            MultiByteToWideChar(936, 0, gbkStr.c_str(), -1, &wideStr[0], wideLen);

            // 然后将宽字符转换为 UTF-8
            int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), -1, nullptr, 0, nullptr, nullptr);
            if (utf8Len == 0) {
                throw std::runtime_error("Failed to convert wide char to UTF-8");
            }

            std::string utf8Str(utf8Len, '\0');
            WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), -1, &utf8Str[0], utf8Len, nullptr, nullptr);

            return utf8Str;
        }

        static std::string utf8ToGbk(const std::string& utf8Str) {
            // 先将 UTF-8 转换为宽字符（UTF-16）
            int wideLen = MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), -1, nullptr, 0);
            if (wideLen == 0) {
                throw std::runtime_error("Failed to convert UTF-8 to wide char");
            }

            std::wstring wideStr(wideLen, L'\0');
            MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), -1, &wideStr[0], wideLen);

            // 然后将宽字符转换为 GBK
            int gbkLen = WideCharToMultiByte(936, 0, wideStr.c_str(), -1, nullptr, 0, nullptr, nullptr); // 936 是 GBK 的代码页
            if (gbkLen == 0) {
                throw std::runtime_error("Failed to convert wide char to GBK");
            }

            std::string gbkStr(gbkLen, '\0');
            WideCharToMultiByte(936, 0, wideStr.c_str(), -1, &gbkStr[0], gbkLen, nullptr, nullptr);

            return gbkStr;
        }

        static std::string withEscape(const std::string& str)
        {
            std::string escapeStr;
            for (std::size_t i = 0; i < str.size(); ++i)
            {
                if (str[i] == '\\' || str[i] == '\'' || str[i] == '\"')
                {
                    escapeStr += '\\';
                }
                escapeStr += str[i];
            }
            return escapeStr;
        }

        static uint16_t getScore(std::string s)
        {
            std::string score = "0";
            int flag = 0;
            for (int i = 0; i < s.size(); i++)
            {
                if (s[i] == '$')
                {
                    flag = 1;
                }
                else if (s[i] == '$')
                {
                    flag = 0;
                    break;
                }
                else if (flag == 1)
                {
                    score += s[i];
                }
            }
            return std::stoi(score);
        }
       /* static bool serialize(const Json::Value& root, std::string& str) {
            try {
                Json::StreamWriterBuilder swb;
                str = Json::writeString(swb, root);
                return true;
            }
            catch (const std::exception& e) {
                LOG_ERROR("Serialize failed: " + std::string(e.what()));
                return false;
            }
        }

        static bool unSerialize(const std::string& str, Json::Value& root) {
            if (str.empty()) {
                LOG_ERROR("Input string is empty");
                return false;
            }
            Json::CharReaderBuilder crb;
            auto cr = crb.newCharReader();
            const char* start = str.c_str();
            const char* end = start + str.size();
            std::string errs;
            if (!cr->parse(start, end, &root, &errs)) {
                LOG_ERROR(std::string("UnSerialize failed: ") + errs);
                return false;
            }
            return true;
        }*/


       static std::string StatusToString(const std::string& type, int value) {
            if (type == "ACLineStatus") {
                switch (value) {
                case AC_LINE_OFFLINE: return gbkToUtf8("电源断开");
                case AC_LINE_ONLINE: return gbkToUtf8("电源在线");
                case AC_LINE_BACKUP_POWER: return gbkToUtf8("备用电源");
                case AC_LINE_UNKNOWN: return gbkToUtf8("电源状态未知");
                default: return gbkToUtf8("未知状态");
                }
            }
            else if (type == "BatteryFlag") {
                switch (value) {
                case BATTERY_FLAG_HIGH: return gbkToUtf8("电池电量高");
                case BATTERY_FLAG_LOW: return gbkToUtf8("电池电量低");
                case BATTERY_FLAG_CRITICAL: return gbkToUtf8("电池电量危急");
                case BATTERY_FLAG_CHARGING: return gbkToUtf8("电池充电中");
                case BATTERY_FLAG_NO_BATTERY: return gbkToUtf8("无电池");
                case BATTERY_FLAG_UNKNOWN: return gbkToUtf8("电池状态未知");
                default: return gbkToUtf8("未知电池标志");
                }
            }
            else if (type == "BatteryPercentage") {
                return (value == BATTERY_PERCENTAGE_UNKNOWN) ? gbkToUtf8("电池百分比未知") : std::to_string(value) + "%";
            }
            else if (type == "SystemStatusFlag") {
                switch (value) {
                case SYSTEM_STATUS_FLAG_POWER_SAVING_ON: return gbkToUtf8("节能模式开启");
                default: return gbkToUtf8("未知系统状态");
                }
            }
            return gbkToUtf8("未知类型");
        }
    };


}

    