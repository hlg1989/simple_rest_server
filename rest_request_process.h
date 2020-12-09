//
// Created by hlg on 2020/12/8.
//

#ifndef WORKFLOW_REST_REQUEST_PROCESS_H
#define WORKFLOW_REST_REQUEST_PROCESS_H

#include <string>
#include <set>
#include <unordered_map>
#include <mutex>
#include "workflow/HttpMessage.h"
#include "spdlog/spdlog.h"

using namespace protocol;
namespace gwecom {
    namespace network {
        namespace rest {


            enum REST_RESULT_CODE{
                REST_RESULT_CODE_SUCCESS = 0,
                REST_RESULT_CODE_INVALID_STRUCTURE,
                REST_RESULT_CODE_INVALID_METHOD,
                REST_RESULT_CODE_INVALID_PARAM,
                REST_RESULT_CODE_INVALID_HW_ID,
                REST_RESULT_CODE_NO_AVAILABLE_HW_ID,
                REST_RESULT_CODE_NO_AVAILABLE_HW_LICENSE,
                REST_RESULT_CODE_SERVER_INTERNAL_ERROR,
            };

            struct rest_response{
                REST_RESULT_CODE result_code;
                std::string result_message;
                std::string response_data;

                rest_response()
                        : result_code(REST_RESULT_CODE_SUCCESS)
                        , result_message()
                        , response_data()
                {

                }
            };

            enum STATUS_CODE{
                STATUS_CODE_SUCCESS = 200,
                STATUS_CODE_BAD_REQUEST = 400,
                STATUS_CODE_PAGE_NOT_FOUND = 404,
                STATUS_CODE_SERVER_INTERNAL_ERROR = 500,
            };


            class rest_request_process {
            public:
                rest_request_process(const std::string& root_path, const std::string& logger_name = "rest_server");

                ~rest_request_process();


                void process_get_hwid(HttpResponse *resp, const char* request_data);
                void process_get_license(HttpResponse *resp, const char* request_data);
                void process_upload_hwid(HttpResponse *resp, const char* request_data);
                void process_upload_license(HttpResponse *resp, const char* request_data);
                void process_invalid_uri(HttpResponse *resp, const char* request_data);
                void process_invalid_method(HttpResponse *resp, const char* request_data);

            private:
                std::string write_to_json(const rest_response& response);
                void send_response(HttpResponse *resp, const std::string& response_message, STATUS_CODE status_code);
                void process_get_license_by_hwid(HttpResponse *resp, const char* hardware_id);

            private:
                std::mutex m_hwid_mtx;
                std::mutex m_license_mtx;
                std::set<std::string> m_hardware_ids;
                std::unordered_map<std::string, std::string> m_hwid_licenses;
                std::string m_hwid_filename = "hw_id.txt";
                std::string m_hwlicense_filename = "hw_license.txt";

                std::shared_ptr<spdlog::logger> m_logger;

            };
        }
    }
}

#endif //WORKFLOW_REST_REQUEST_PROCESS_H
