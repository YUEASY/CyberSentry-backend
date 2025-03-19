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
                LOG_CRIT("CURL初始化失败");
                throw std::runtime_error("Failed to initialize CURL");
            }

            LOG_DEBUG("创建HttpClient实例");
            SetTimeout(10L);
            SetSSLVerify(false);
            SetFollowRedirects(true);
        }

        ~HttpClient() {
            LOG_DEBUG("销毁HttpClient实例");
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
            LOG_TRACE("设置请求URL: {}", url_);
            return *this;
        }

        HttpClient& SetTimeout(long seconds) {
            LOG_DEBUG("设置超时时间: {}秒", seconds);
            curl_easy_setopt(curl_, CURLOPT_TIMEOUT, seconds);
            return *this;
        }

        HttpClient& SetSSLVerify(bool verify) {
            LOG_DEBUG("{}SSL验证", verify ? "启用" : "禁用");
            curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER, verify ? 1L : 0L);
            curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYHOST, verify ? 2L : 0L);
            return *this;
        }

        HttpClient& SetFollowRedirects(bool follow) {
            LOG_DEBUG("{}自动重定向", follow ? "启用" : "禁用");
            curl_easy_setopt(curl_, CURLOPT_FOLLOWLOCATION, follow ? 1L : 0L);
            return *this;
        }

        HttpClient& AddHeader(const std::string& key, const std::string& value) {
            LOG_TRACE("添加请求头: {}: {}", key, value);
            headers_ = curl_slist_append(headers_, (key + ": " + value).c_str());
            return *this;
        }

        HttpClient& CustomActions(CURLoption option,const std::string& s) {
            curl_easy_setopt(curl_, option, s);
            return *this;
        }

        std::string Get() {
            LOG_INFO("发起GET请求: {}", url_);
            return ExecuteRequest();
        }

        std::string Post(const std::string& data = "") {
            LOG_INFO("发起POST请求: {} (数据长度: {})", url_, data.size());
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

            LOG_DEBUG("开始执行请求 [{}]", url_);
            res = curl_easy_perform(curl_);

            // 记录响应状态
            if (res == CURLE_OK) {
                long http_code = 0;
                curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &http_code);
                LOG_DEBUG("请求完成 [状态码: {}] [响应长度: {}]", http_code, response_.size());
            }

            // 重置选项
            curl_easy_setopt(curl_, CURLOPT_HTTPGET, 1L);
            curl_easy_setopt(curl_, CURLOPT_POST, 0L);

            if (res != CURLE_OK) {
                const char* err_msg = curl_easy_strerror(res);
                LOG_ERROR("请求失败: {} [错误码: {}]", err_msg, res);
                throw std::runtime_error(err_msg);
            }

            LOG_TRACE("原始响应内容:\n{}", response_);
            return response_;
        }
    };
}
