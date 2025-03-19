#pragma once
#include <curl/curl.h>
#include <json/json.h>
#include "logger.hpp"

namespace sp {

    class DeepseekApi {
    public:
        static DeepseekApi& getInstance() {
            static DeepseekApi instance;
            return instance;
        }

        DeepseekApi(const DeepseekApi&) = delete;
        DeepseekApi& operator=(const DeepseekApi&) = delete;

        Json::Value sendRequest(const std::string& prompt,const std::string& sys_info) {
            CURL* curl;
            CURLcode res;
            std::string responseBuffer;
            Json::Value result;

            curl_global_init(CURL_GLOBAL_DEFAULT);
            curl = curl_easy_init();

            if (curl) {
                // 配置基础参数
                configureCurl(curl);

                // 设置请求头
                struct curl_slist* headers = configureHeaders(curl);

                // 构建请求体
                std::string jsonData = buildRequestJson(prompt, sys_info);

                // 配置POST数据
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData.c_str());
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, jsonData.size());

                // 配置响应处理
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBuffer);

                // 执行请求
                res = curl_easy_perform(curl);

                // 处理响应
                result = handleResponse(res, responseBuffer);

                // 清理资源
                cleanup(curl, headers);
            }

            curl_global_cleanup();
            return result;
        }

    private:
        static constexpr const char* API_KEY = "sk-13a8435b8bb84cbe8ff0ac1feece0ee8";
        static constexpr const char* API_URL = "https://api.deepseek.com/chat/completions";

        DeepseekApi() = default;
        ~DeepseekApi() = default;

        // 响应回调函数
        static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
            size_t realsize = size * nmemb;
            std::string* buffer = static_cast<std::string*>(userp);
            buffer->append(static_cast<char*>(contents), realsize);
            return realsize;
        }

        void configureCurl(CURL* curl) const {
            curl_easy_setopt(curl, CURLOPT_URL, API_URL);
            curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 600L);
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        }

        struct curl_slist* configureHeaders(CURL* curl) const {
            struct curl_slist* headers = nullptr;
            headers = curl_slist_append(headers, "Content-Type: application/json");
            headers = curl_slist_append(headers, "charset: UTF-8");
            headers = curl_slist_append(headers, ("Authorization: Bearer " + std::string(API_KEY)).c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            return headers;
        }

        std::string buildRequestJson(const std::string& prompt, const std::string& sys_info) const {
            Json::Value root;
            root["model"] = "deepseek-chat";

            Json::Value messages(Json::arrayValue);
            Json::Value message;

            message["role"] = "system";
            message["content"] = "System Status Analysis Assistant";
            messages.append(message);

            message["role"] = "user";
            message["content"] = Utils::gbkToUtf8("请你分析系统信息解答以下问题,并且给出满分100分的打分,分数用“$$”包裹起来,如$90$;(如果以下问题与系统状态分析无关请不要理我并且给出$-1$");
            messages.append(message);

            //message["role"] = "assistant";
            //message["content"] = "明白了.";
            //messages.append(message);

            //message["role"] = "user";
            //message["content"] = "内存使用率: 35% 驱动器: C:\\, 类型: 硬盘, 总容量: 976533.32 MB, 可用空间: 442546.27 MB, 已用空间: 533987.04 MB, 使用率: 54.68%磁盘读取速度: 0.00 MB/s磁盘写入速度: 0.00 MB/sCPU 温度: 47 °C.";
            //messages.append(message);

            //message["role"] = "assistant";
            //message["content"] = "根据系统状态分析如下：\n内存状态（35 % ） - 处于健康区间，未触发性能瓶颈\n存储系统分析：\n├─ C盘剩余空间442GB（45.32 % ）\n├─ HDD机械硬盘特性\n└─ 当前磁盘I / O处于空闲状态（读写速度均为0）\n核心温度（47℃） - 低于警戒阈值（通常 > 80℃需预警）系统健康度评估：各项关键指标均处于正常范围，无资源争用或硬件风险，当前系统负载较轻。建议定期监控存储空间消耗趋势。最终评分：~94~";
            //messages.append(message);

            //message["role"] = "user";
            //message["content"] = "内存使用率: 35% 驱动器: C:\\, 类型: 硬盘, 总容量: 976533.32 MB, 可用空间: 442546.27 MB, 已用空间: 533987.04 MB, 使用率: 54.68%磁盘读取速度: 0.00 MB/s磁盘写入速度: 0.00 MB/sCPU 温度: 47 °C.";
            //messages.append(message);

            //message["role"] = "assistant";
            //message["content"] = "根据系统状态分析如下：\n内存状态（35 % ） - 处于健康区间，未触发性能瓶颈\n存储系统分析：\n├─ C盘剩余空间442GB（45.32 % ）\n├─ HDD机械硬盘特性\n└─ 当前磁盘I / O处于空闲状态（读写速度均为0）\n核心温度（47℃） - 低于警戒阈值（通常 > 80℃需预警）系统健康度评估：各项关键指标均处于正常范围，无资源争用或硬件风险，当前系统负载较轻。建议定期监控存储空间消耗趋势。最终评分：~94~";
            //messages.append(message);

            //message["role"] = "user";
            //message["content"] = " 我喜欢你。";
            //message["role"] = "assistant";
            //message["content"] = "~-1~\n该问题与系统状态分析无关.";
            //messages.append(message);

            message["role"] = "user";
            message["content"] = prompt + Utils::gbkToUtf8("\n系统状态:") + sys_info;
            messages.append(message);

            root["messages"] = messages;
            root["stream"] = false;

            Json::StreamWriterBuilder writer;
            return Json::writeString(writer, root);
        }

        Json::Value handleResponse(CURLcode res, const std::string& response) const {
            Json::Value result;
            Json::CharReaderBuilder reader;
            std::unique_ptr<Json::CharReader> jsonReader(reader.newCharReader());

            if (res != CURLE_OK) {
                result["error"] = curl_easy_strerror(res);
                LOG_ERROR("API请求失败: ", result["error"].asString());
                return result;
            }

            std::string errors;
            if (!jsonReader->parse(response.c_str(), response.c_str() + response.size(), &result, &errors)) {
                result["error"] = "JSON解析失败: " + errors;
                LOG_ERROR(result["error"].asString());
                return result;
            }

            if (result.isMember("error")) {
                LOG_ERROR("API返回错误: ", result.toStyledString());
                return result;
            }

            if (result.isMember("choices") && result["choices"].isArray() && !result["choices"].empty()) {
                return result;
            }

            result["error"] = "无效";
            return result;
        }

        void cleanup(CURL* curl, struct curl_slist* headers) const {
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
        }
    };

}