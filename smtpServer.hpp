#pragma once
#include <string.h>
#include <curl/curl.h>
#include "logger.hpp"
#include <iostream>

namespace sp {
	
    class SmtpServer
    {
    public:
        static SmtpServer& getInstance()
        {
            static SmtpServer instance;
            return instance;
        }


        SmtpServer(const SmtpServer&) = delete;
        SmtpServer& operator=(const SmtpServer&) = delete;

        bool sendMail(std::string_view address, std::string_view subject,std::string_view body)
        {
            CURL* curl;
            CURLcode res;

            curl_global_init(CURL_GLOBAL_DEFAULT);
            curl = curl_easy_init();

            if (curl) {
                // SMTP 服务器

                curl_easy_setopt(curl, CURLOPT_LOGIN_OPTIONS, "AUTH=LOGIN");
                curl_easy_setopt(curl, CURLOPT_URL, "smtps://smtp.qq.com:465");
                curl_easy_setopt(curl, CURLOPT_USERNAME, "3298911538@qq.com");  // 发件人邮箱
                curl_easy_setopt(curl, CURLOPT_PASSWORD, "rwiidpdrwzptciid");   // QQ 授权码

                // 发送方 & 接收方
                struct curl_slist* recipients = NULL;
                recipients = curl_slist_append(recipients, address.data());
                curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
                curl_easy_setopt(curl, CURLOPT_MAIL_FROM, "<3298911538@qq.com>");

                // 邮件内容
                std::string email_text =
                    "To: "+std::string(address)+"\r\n"
                    "From: 3298911538@qq.com\r\n"
                    "Subject: " + std::string(subject) + "\r\n"
                    "\r\n"
                    +std::string(body)+"\r\n";

                // 初始化状态结构
                UploadStatus upload_ctx = { email_text.c_str(), 0};

                // 读取回调
                curl_easy_setopt(curl, CURLOPT_READFUNCTION, &payload_callback);
                curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
                curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

                // 证书验证（如果失败，可临时关闭）
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

                // 开启调试模式（输出详细日志）
                curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

                // 发送邮件
                res = curl_easy_perform(curl);
                if (res != CURLE_OK) {
                    LOG_ERROR("邮件发送失败: " , curl_easy_strerror(res));
                }
                else {
                    LOG_DEBUG("邮件已成功发送到:", address);
                }

                // 释放资源
                curl_slist_free_all(recipients);
                curl_easy_cleanup(curl);
            }

            curl_global_cleanup();
            return true;
        }

    private:
        SmtpServer() = default;  
        ~SmtpServer() = default; 

        struct UploadStatus {
            const char* text;
            size_t pos;
        };
        static size_t payload_callback(char* buffer, size_t size, size_t nitems, void* userdata) {
            UploadStatus* upload_ctx = static_cast<UploadStatus*>(userdata);
            size_t buffer_size = size * nitems;

            if (upload_ctx->pos >= strlen(upload_ctx->text)) {
                return 0; // 发送完成
            }

            size_t copy_size = min(buffer_size, strlen(upload_ctx->text) - upload_ctx->pos);
            memcpy(buffer, upload_ctx->text + upload_ctx->pos, copy_size);
            upload_ctx->pos += copy_size;

            return copy_size;
        }
    };

}