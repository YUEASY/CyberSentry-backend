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
                // ���û�������
                configureCurl(curl);

                // ��������ͷ
                struct curl_slist* headers = configureHeaders(curl);

                // ����������
                std::string jsonData = buildRequestJson(prompt, sys_info);

                // ����POST����
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData.c_str());
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, jsonData.size());

                // ������Ӧ����
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBuffer);

                // ִ������
                res = curl_easy_perform(curl);

                // ������Ӧ
                result = handleResponse(res, responseBuffer);

                // ������Դ
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

        // ��Ӧ�ص�����
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
            message["content"] = Utils::gbkToUtf8("�������ϵͳ��Ϣ�����������,���Ҹ�������100�ֵĴ��,�����á�$$����������,��$90$;(�������������ϵͳ״̬�����޹��벻Ҫ���Ҳ��Ҹ���$-1$");
            messages.append(message);

            //message["role"] = "assistant";
            //message["content"] = "������.";
            //messages.append(message);

            //message["role"] = "user";
            //message["content"] = "�ڴ�ʹ����: 35% ������: C:\\, ����: Ӳ��, ������: 976533.32 MB, ���ÿռ�: 442546.27 MB, ���ÿռ�: 533987.04 MB, ʹ����: 54.68%���̶�ȡ�ٶ�: 0.00 MB/s����д���ٶ�: 0.00 MB/sCPU �¶�: 47 ��C.";
            //messages.append(message);

            //message["role"] = "assistant";
            //message["content"] = "����ϵͳ״̬�������£�\n�ڴ�״̬��35 % �� - ���ڽ������䣬δ��������ƿ��\n�洢ϵͳ������\n���� C��ʣ��ռ�442GB��45.32 % ��\n���� HDD��еӲ������\n���� ��ǰ����I / O���ڿ���״̬����д�ٶȾ�Ϊ0��\n�����¶ȣ�47�棩 - ���ھ�����ֵ��ͨ�� > 80����Ԥ����ϵͳ����������������ؼ�ָ�������������Χ������Դ���û�Ӳ�����գ���ǰϵͳ���ؽ��ᡣ���鶨�ڼ�ش洢�ռ��������ơ��������֣�~94~";
            //messages.append(message);

            //message["role"] = "user";
            //message["content"] = "�ڴ�ʹ����: 35% ������: C:\\, ����: Ӳ��, ������: 976533.32 MB, ���ÿռ�: 442546.27 MB, ���ÿռ�: 533987.04 MB, ʹ����: 54.68%���̶�ȡ�ٶ�: 0.00 MB/s����д���ٶ�: 0.00 MB/sCPU �¶�: 47 ��C.";
            //messages.append(message);

            //message["role"] = "assistant";
            //message["content"] = "����ϵͳ״̬�������£�\n�ڴ�״̬��35 % �� - ���ڽ������䣬δ��������ƿ��\n�洢ϵͳ������\n���� C��ʣ��ռ�442GB��45.32 % ��\n���� HDD��еӲ������\n���� ��ǰ����I / O���ڿ���״̬����д�ٶȾ�Ϊ0��\n�����¶ȣ�47�棩 - ���ھ�����ֵ��ͨ�� > 80����Ԥ����ϵͳ����������������ؼ�ָ�������������Χ������Դ���û�Ӳ�����գ���ǰϵͳ���ؽ��ᡣ���鶨�ڼ�ش洢�ռ��������ơ��������֣�~94~";
            //messages.append(message);

            //message["role"] = "user";
            //message["content"] = " ��ϲ���㡣";
            //message["role"] = "assistant";
            //message["content"] = "~-1~\n��������ϵͳ״̬�����޹�.";
            //messages.append(message);

            message["role"] = "user";
            message["content"] = prompt + Utils::gbkToUtf8("\nϵͳ״̬:") + sys_info;
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
                LOG_ERROR("API����ʧ��: ", result["error"].asString());
                return result;
            }

            std::string errors;
            if (!jsonReader->parse(response.c_str(), response.c_str() + response.size(), &result, &errors)) {
                result["error"] = "JSON����ʧ��: " + errors;
                LOG_ERROR(result["error"].asString());
                return result;
            }

            if (result.isMember("error")) {
                LOG_ERROR("API���ش���: ", result.toStyledString());
                return result;
            }

            if (result.isMember("choices") && result["choices"].isArray() && !result["choices"].empty()) {
                return result;
            }

            result["error"] = "��Ч";
            return result;
        }

        void cleanup(CURL* curl, struct curl_slist* headers) const {
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
        }
    };

}