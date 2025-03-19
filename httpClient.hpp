#pragma once
#include <string>
#include <map>
#include <curl/curl.h>
#include <iostream>
#include "logger.hpp"

namespace sp {

    class HttpClient {
    public:
        HttpClient() {
            curl_ = curl_easy_init();
            if (!curl_) {
                LOG_CRIT("CURL��ʼ��ʧ��");
                throw std::runtime_error("Failed to initialize CURL");
            }

            LOG_DEBUG("����HttpClientʵ��");
            SetTimeout(10L);
            SetSSLVerify(false);
            SetFollowRedirects(true);
        }

        ~HttpClient() {
            LOG_DEBUG("����HttpClientʵ��");
            if (headers_) {
                curl_slist_free_all(headers_);
                headers_ = nullptr;
            }
            if (curl_) {
                curl_easy_cleanup(curl_);
                curl_ = nullptr;
            }
        }

        HttpClient& SetUrl(const std::string& url) {
            url_ = url;
            LOG_TRACE("��������URL: {}", url_);
            return *this;
        }

        HttpClient& SetTimeout(long seconds) {
            LOG_DEBUG("���ó�ʱʱ��: {}��", seconds);
            curl_easy_setopt(curl_, CURLOPT_TIMEOUT, seconds);
            return *this;
        }

        HttpClient& SetSSLVerify(bool verify) {
            LOG_DEBUG("{}SSL��֤", verify ? "����" : "����");
            curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER, verify ? 1L : 0L);
            curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYHOST, verify ? 2L : 0L);
            return *this;
        }

        HttpClient& SetFollowRedirects(bool follow) {
            LOG_DEBUG("{}�Զ��ض���", follow ? "����" : "����");
            curl_easy_setopt(curl_, CURLOPT_FOLLOWLOCATION, follow ? 1L : 0L);
            return *this;
        }

        HttpClient& AddHeader(const std::string& key, const std::string& value) {
            LOG_TRACE("�������ͷ: {}: {}", key, value);
            headers_ = curl_slist_append(headers_, (key + ": " + value).c_str());
            return *this;
        }

        HttpClient& CustomActions(CURLoption option,const std::string& s) {
            curl_easy_setopt(curl_, option, s);
            return *this;
        }

        std::string Get() {
            LOG_INFO("����GET����: {}", url_);
            return ExecuteRequest();
        }

        std::string Post(const std::string& data = "") {
            LOG_INFO("����POST����: {} (���ݳ���: {})", url_, data.size());
            curl_easy_setopt(curl_, CURLOPT_POST, 1L);
            if (!data.empty()) {
                curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, data.c_str());
                curl_easy_setopt(curl_, CURLOPT_POSTFIELDSIZE, data.size());
            }
            return ExecuteRequest();
        }

    private:
        CURL* curl_ = nullptr;
        std::string url_;
        curl_slist* headers_ = nullptr;
        std::string response_;

        static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
            size_t realsize = size * nmemb;
            static_cast<std::string*>(userp)->append(
                static_cast<char*>(contents), realsize);
            return realsize;
        }

        std::string ExecuteRequest() {
            response_.clear();
            CURLcode res;

            curl_easy_setopt(curl_, CURLOPT_URL, url_.c_str());
            curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headers_);
            curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &response_);

            LOG_DEBUG("��ʼִ������ [{}]", url_);
            res = curl_easy_perform(curl_);

            // ��¼��Ӧ״̬
            if (res == CURLE_OK) {
                long http_code = 0;
                curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &http_code);
                LOG_DEBUG("������� [״̬��: {}] [��Ӧ����: {}]", http_code, response_.size());
            }

            // ����ѡ��
            curl_easy_setopt(curl_, CURLOPT_HTTPGET, 1L);
            curl_easy_setopt(curl_, CURLOPT_POST, 0L);

            if (res != CURLE_OK) {
                const char* err_msg = curl_easy_strerror(res);
                LOG_ERROR("����ʧ��: {} [������: {}]", err_msg, res);
                throw std::runtime_error(err_msg);
            }

            LOG_TRACE("ԭʼ��Ӧ����:\n{}", response_);
            return response_;
        }
    };
}
