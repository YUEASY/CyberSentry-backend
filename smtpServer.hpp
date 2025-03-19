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
                // SMTP ������

                curl_easy_setopt(curl, CURLOPT_LOGIN_OPTIONS, "AUTH=LOGIN");
                curl_easy_setopt(curl, CURLOPT_URL, "smtps://smtp.qq.com:465");
                curl_easy_setopt(curl, CURLOPT_USERNAME, "3298911538@qq.com");  // ����������
                curl_easy_setopt(curl, CURLOPT_PASSWORD, "rwiidpdrwzptciid");   // QQ ��Ȩ��

                // ���ͷ� & ���շ�
                struct curl_slist* recipients = NULL;
                recipients = curl_slist_append(recipients, address.data());
                curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
                curl_easy_setopt(curl, CURLOPT_MAIL_FROM, "<3298911538@qq.com>");

                // �ʼ�����
                std::string email_text =
                    "To: "+std::string(address)+"\r\n"
                    "From: 3298911538@qq.com\r\n"
                    "Subject: " + std::string(subject) + "\r\n"
                    "\r\n"
                    +std::string(body)+"\r\n";

                // ��ʼ��״̬�ṹ
                UploadStatus upload_ctx = { email_text.c_str(), 0};

                // ��ȡ�ص�
                curl_easy_setopt(curl, CURLOPT_READFUNCTION, &payload_callback);
                curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
                curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

                // ֤����֤�����ʧ�ܣ�����ʱ�رգ�
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

                // ��������ģʽ�������ϸ��־��
                curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

                // �����ʼ�
                res = curl_easy_perform(curl);
                if (res != CURLE_OK) {
                    LOG_ERROR("�ʼ�����ʧ��: " , curl_easy_strerror(res));
                }
                else {
                    LOG_DEBUG("�ʼ��ѳɹ����͵�:", address);
                }

                // �ͷ���Դ
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
                return 0; // �������
            }

            size_t copy_size = min(buffer_size, strlen(upload_ctx->text) - upload_ctx->pos);
            memcpy(buffer, upload_ctx->text + upload_ctx->pos, copy_size);
            upload_ctx->pos += copy_size;

            return copy_size;
        }
    };

}