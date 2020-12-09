//
// Created by hlg on 2020/12/8.
//

#include "workflow/HttpMessage.h"
#include "rest_request_process.h"
#include <unistd.h>
#include <string>
#include <set>
#include <unordered_map>
#include <mutex>
#include <fstream>
#include <sstream>
#include <nlohmann/json.hpp>

#define ENABLE_GET_LICENSE_IN_UPLOAD_HWID_PROCEDURE 1

using namespace protocol;
using json = nlohmann::json;
namespace gwecom {
    namespace network {
        namespace rest {


            static std::string rest_result_code_to_string(REST_RESULT_CODE code)
            {
                switch(code){
                    case REST_RESULT_CODE_SUCCESS:
                        return "success";
                    case REST_RESULT_CODE_INVALID_STRUCTURE:
                        return "invalid rest api uri structure";
                    case REST_RESULT_CODE_INVALID_METHOD:
                        return "invalid rest api method";
                    case REST_RESULT_CODE_INVALID_PARAM:
                        return "invalid rest api param";
                    case REST_RESULT_CODE_INVALID_HW_ID:
                        return "invalid hardware id";
                    case REST_RESULT_CODE_NO_AVAILABLE_HW_ID:
                        return "no available hardware id";
                    case REST_RESULT_CODE_NO_AVAILABLE_HW_LICENSE:
                        return "no available hardware license";
                    case REST_RESULT_CODE_SERVER_INTERNAL_ERROR:
                        return "rest server internal error";
                    default:
                        return "";
                }
            }

            rest_request_process::rest_request_process(std::string root_path)
                : m_hwid_mtx()
                , m_license_mtx()
                , m_hardware_ids()
                , m_hwid_licenses()
                , m_hwid_filename("hw_id.txt")
                , m_hwlicense_filename("hw_license.txt")
            {
                std::string vaild_path = root_path;
                char cur_path[PATH_MAX];
                if(root_path.empty() || access(root_path.c_str(), F_OK) < 0){
                    if(getcwd(cur_path, PATH_MAX)){
                        vaild_path = cur_path;
                    }else{
                        vaild_path = "/tmp";
                    }
                }

                if(!vaild_path.empty()) {
                    bool last_is_slash = (vaild_path[vaild_path.size() - 1] == '/');
                    m_hwid_filename = last_is_slash ? vaild_path + m_hwid_filename : vaild_path + "/" + m_hwid_filename;
                    m_hwlicense_filename = last_is_slash ? vaild_path + m_hwlicense_filename : vaild_path + "/" + m_hwlicense_filename;
                }

                {
                    std::ifstream hwid_file(m_hwid_filename);
                    if(hwid_file.is_open()) {
                        std::string hwid_value;

                        while (std::getline(hwid_file, hwid_value)) {
                            m_hardware_ids.insert(hwid_value);
                        }
                        hwid_file.close();
                    }
                }

                {
                    std::ifstream hwlicense_file(m_hwlicense_filename);
                    if(hwlicense_file.is_open()) {
                        std::string hwid_license_pair;

                        while (std::getline(hwlicense_file, hwid_license_pair)) {
                            std::string tmp_hwid_value;
                            std::string tmp_license_value;
                            std::istringstream iss(hwid_license_pair);
                            iss >> tmp_hwid_value >> tmp_license_value;
                            if(iss)
                                m_hwid_licenses[tmp_hwid_value] = tmp_license_value;
                        }
                        hwlicense_file.close();
                    }
                }
            }


            rest_request_process::~rest_request_process()
            {
                {
                    std::ostringstream whole_hwid;
                    for (auto &tmp : m_hardware_ids) {
                        whole_hwid << tmp << std::endl;
                    }

                    std::ofstream hwid_file(m_hwid_filename, std::ios_base::out);
                    if(hwid_file) {
                        hwid_file << whole_hwid.str();
                        hwid_file.close();
                    }
                }

                {
                    std::ostringstream whole_hwid_license;
                    for (auto &tmp : m_hwid_licenses) {
                        whole_hwid_license << tmp.first << "    " << tmp.second << std::endl;
                    }

                    std::ofstream hwlicense_file(m_hwlicense_filename, std::ios_base::out);
                    if (hwlicense_file) {
                        hwlicense_file << whole_hwid_license.str();
                        hwlicense_file.close();
                    }
                }
            }


            std::string rest_request_process::write_to_json(const rest_response& response)
            {
                json jobj;
                try {
                    jobj["code"] = response.result_code;
                    jobj["message"] = response.result_message;
                    jobj["data"] = response.response_data;

                    return jobj.dump();
                } catch (json::exception& e) {
                    return std::string();
                }

            }


            void rest_request_process::send_response(HttpResponse *resp, const std::string& response_message, STATUS_CODE status_code)
            {
                std::string status = std::to_string(status_code);
                printf("---- response status_code: %s, message: \n\t\t%s\n\n", status.c_str(), response_message.c_str());
                resp->set_header_pair("Content-Type", "application/json");
                resp->set_status_code(status);
                resp->append_output_body(response_message);
            }


            void rest_request_process::process_get_hwid(HttpResponse *resp, const char* request_data)
            {
                std::set<std::string>tmp_hwids;
                {
                    std::unique_lock<std::mutex>lock(m_hwid_mtx);
                    tmp_hwids = m_hardware_ids;
                    if(tmp_hwids.empty()){
                        std::ifstream file(m_hwid_filename);
                        std::string hwid_value;

                        while(std::getline(file, hwid_value)) {
                            m_hardware_ids.insert(hwid_value);
                        }
                        tmp_hwids = m_hardware_ids;
                    }
                }

                if(tmp_hwids.empty()){
                    rest_response response;
                    response.result_code = REST_RESULT_CODE_NO_AVAILABLE_HW_ID;
                    response.result_message = rest_result_code_to_string(response.result_code);
                    std::string out_response = write_to_json(response);
                    send_response(resp, out_response, STATUS_CODE_PAGE_NOT_FOUND);
                    return;
                }

                std::string available_hwid;
                try {
                    json jobj;
                    for (auto &hwid : tmp_hwids) {
                        jobj["hwid"].push_back(hwid);
                    }
                    available_hwid = jobj.dump();
                } catch (json::exception& e) {
                    available_hwid = std::string("json parse failed: ") + e.what();

                    rest_response response;
                    response.result_code = REST_RESULT_CODE_SERVER_INTERNAL_ERROR;
                    response.result_message = rest_result_code_to_string(response.result_code);
                    response.result_message += ": get_hwid, ";
                    response.response_data = available_hwid;
                    std::string out_response = write_to_json(response);

                    send_response(resp, out_response, STATUS_CODE_SERVER_INTERNAL_ERROR);
                    return;
                }

                rest_response response;
                response.result_code = REST_RESULT_CODE_SUCCESS;
                response.result_message = rest_result_code_to_string(response.result_code);
                response.result_message += ": get_hwid";
                response.response_data = available_hwid;
                std::string out_response = write_to_json(response);

                send_response(resp, out_response, STATUS_CODE_SUCCESS);
            }


            void rest_request_process::process_get_license(HttpResponse *resp, const char* request_data)
            {
                const char* p = request_data;
                const char* id_key = p;
                while (*p && *p != '=')
                    p++;
                std::string hwid_key(id_key, p - id_key);
                if(hwid_key == "hwid") {
                    ++p;
                    const char *id_value = p;
                    while (*p && *p != '=')
                        p++;
                    std::string hwid_value(id_value, p - id_value);
                    process_get_license_by_hwid(resp, hwid_value.c_str());
                }
                else{
                    rest_response response;
                    response.result_code = REST_RESULT_CODE_INVALID_PARAM;
                    response.result_message = rest_result_code_to_string(response.result_code);
                    response.result_message += "  usage: http://127.0.0.1:8080/api/get_license?hwid=xxxxxxx";

                    std::string err_response = write_to_json(response);
                    send_response(resp, err_response, STATUS_CODE_BAD_REQUEST);
                }
            }

            void rest_request_process::process_get_license_by_hwid(HttpResponse *resp, const char* hardware_id)
            {
                std::string hwid_value = hardware_id;
                std::unordered_map<std::string, std::string> tmp_licenses;
                {
                    std::unique_lock<std::mutex> lock(m_license_mtx);
                    tmp_licenses = m_hwid_licenses;
                    if (tmp_licenses.empty()) {
                        std::ifstream file(m_hwlicense_filename);
                        std::string hwid_license_pair;

                        while (std::getline(file, hwid_license_pair)) {
                            std::string hardware_id;
                            std::string license_value;
                            std::istringstream iss(hwid_license_pair);
                            iss >> hardware_id >> license_value;
                            m_hwid_licenses[hardware_id] = license_value;
                        }
                        tmp_licenses = m_hwid_licenses;
                    }
                }

                if(tmp_licenses.find(hwid_value) == tmp_licenses.end()){
                    rest_response response;
                    response.result_code = REST_RESULT_CODE_NO_AVAILABLE_HW_LICENSE;
                    response.result_message = rest_result_code_to_string(response.result_code);
                    std::string err_response = write_to_json(response);
                    send_response(resp, err_response, STATUS_CODE_PAGE_NOT_FOUND);
                    return;
                }


                std::string available_license;
                try {
                    json jobj;
                    jobj["hwid"] = hwid_value;
                    jobj["license"] = m_hwid_licenses[hwid_value];
                    available_license = jobj.dump();
                } catch (json::exception& e) {
                    available_license = std::string("json parse failed: ") + e.what();

                    rest_response response;
                    response.result_code = REST_RESULT_CODE_SERVER_INTERNAL_ERROR;
                    response.result_message = rest_result_code_to_string(response.result_code);
                    response.result_message += ": get_license, ";
                    response.response_data = available_license;
                    std::string out_response = write_to_json(response);

                    send_response(resp, out_response, STATUS_CODE_SERVER_INTERNAL_ERROR);
                    return;
                }

                rest_response response;
                response.result_code = REST_RESULT_CODE_SUCCESS;
                response.result_message = rest_result_code_to_string(response.result_code);
                response.result_message += ": get_license";
                response.response_data = available_license;

                std::string out_response = write_to_json(response);
                send_response(resp, out_response, STATUS_CODE_SUCCESS);
            }

            void rest_request_process::process_upload_hwid(HttpResponse *resp, const char* request_data)
            {
                const char* p = request_data;
                const char* id_key = p;
                while (*p && *p != '=')
                    p++;
                std::string hwid_key(id_key, p - id_key);
                if(hwid_key == "hwid"){
                    ++p;
                    const char* id_value = p;
                    while (*p && *p != '=')
                        p++;
                    std::string hwid_value(id_value, p - id_value);

                    {
                        std::unique_lock<std::mutex>lock(m_hwid_mtx);
                        if(m_hardware_ids.empty()){
                            std::ifstream file(m_hwid_filename, std::ios_base::in);
                            if(file){
                                std::string tmp_hwid_value;
                                while(getline(file, tmp_hwid_value)){
                                    m_hardware_ids.insert(tmp_hwid_value);
                                }
                            }
                            file.close();
                        }

                        if(m_hardware_ids.find(hwid_value) == m_hardware_ids.end()){
                            m_hardware_ids.insert(hwid_value);
                            std::ofstream file(m_hwid_filename, std::ios_base::app);
                            if(file) {
                                file << hwid_value << std::endl;
                                file.close();
                            }
                        }
                    }

#ifdef ENABLE_GET_LICENSE_IN_UPLOAD_HWID_PROCEDURE
                    process_get_license_by_hwid(resp, hwid_value.c_str());
#else

                    rest_response response;
                    response.result_code = REST_RESULT_CODE_SUCCESS;
                    response.result_message = rest_result_code_to_string(response.result_code);
                    response.result_message += ": upload_hwid";

                    std::string out_response = write_to_json(response);
                    send_response(resp, out_response, STATUS_CODE_SUCCESS);
#endif
                }else{
                    rest_response response;
                    response.result_code = REST_RESULT_CODE_INVALID_PARAM;
                    response.result_message = rest_result_code_to_string(response.result_code);
                    response.result_message += "  usage: http://127.0.0.1:8080/api/upload_hwid?hwid=xxxxxxx";

                    std::string err_response = write_to_json(response);

                    send_response(resp, err_response, STATUS_CODE_BAD_REQUEST);
                }
            }

            void rest_request_process::process_upload_license(HttpResponse *resp, const char* request_data)
            {
                const char* p = request_data;
                const char* id_key = p;
                while (*p && *p != '=')
                    p++;
                std::string hwid_key(id_key, p - id_key);
                if(hwid_key == "hwid"){
                    ++p;
                    const char* id_value = p;
                    while (*p && *p != '&')
                        p++;
                    std::string hwid_value(id_value, p - id_value);

                    std::set<std::string>tmp_hwids;
                    {
                        std::unique_lock<std::mutex>lock(m_hwid_mtx);
                        tmp_hwids = m_hardware_ids;
                        if(tmp_hwids.empty()){
                            std::ifstream file(m_hwid_filename);
                            std::string hwid_value;

                            while(std::getline(file, hwid_value)) {
                                m_hardware_ids.insert(hwid_value);
                            }
                            tmp_hwids = m_hardware_ids;
                        }
                    }

                    if(tmp_hwids.find(hwid_value) == tmp_hwids.end()){
                        rest_response response;
                        response.result_code = REST_RESULT_CODE_INVALID_HW_ID;
                        response.result_message = rest_result_code_to_string(response.result_code);
                        std::string tmp_desc = "\nNo such hardware_id: " + hwid_value + " can be licensed\n";
                        tmp_desc += "  the available hardware ids are as follows:\n";
                        for(auto& hwid : tmp_hwids){
                            tmp_desc += hwid + "\n";
                        }
                        response.result_message += tmp_desc;
                        std::string err_response = write_to_json(response);
                        send_response(resp, err_response, STATUS_CODE_PAGE_NOT_FOUND);
                        return;
                    }

                    ++p;
                    const char* lic_key = p;
                    while (*p && *p != '=')
                        p++;
                    std::string license_key(lic_key, p - lic_key);
                    if(license_key == "license") {
                        ++p;
                        const char *lic_value = p;
                        while (*p && *p != '&')
                            p++;
                        std::string license_value(lic_value, p - lic_value);

                        {
                            std::unique_lock<std::mutex> lock(m_license_mtx);
                            if (m_hwid_licenses.empty()) {
                                std::ifstream file(m_hwlicense_filename);
                                std::string hwid_license_pair;

                                while (std::getline(file, hwid_license_pair)) {
                                    std::string tmp_hwid_value;
                                    std::string tmp_license_value;
                                    std::istringstream iss(hwid_license_pair);
                                    iss >> tmp_hwid_value >> tmp_license_value;
                                    m_hwid_licenses[tmp_hwid_value] = tmp_license_value;
                                }
                            }

                            m_hwid_licenses[hwid_value] = license_value;
                            std::ostringstream whole_hwid_license;
                            for(auto& tmp : m_hwid_licenses){
                                whole_hwid_license << tmp.first << "    " << tmp.second << std::endl;
                            }

                            std::ofstream lic_file(m_hwlicense_filename, std::ios_base::out);
                            if(lic_file) {
                                lic_file << whole_hwid_license.str();
                                lic_file.close();
                            }
                        }

                        rest_response response;
                        response.result_code = REST_RESULT_CODE_SUCCESS;
                        response.result_message = rest_result_code_to_string(response.result_code);
                        response.result_message += ": upload_license";

                        std::string out_response = write_to_json(response);
                        send_response(resp, out_response, STATUS_CODE_SUCCESS);
                    }

                }else{
                    rest_response response;
                    response.result_code = REST_RESULT_CODE_INVALID_PARAM;
                    response.result_message = rest_result_code_to_string(response.result_code);
                    response.result_message += "\nusage: http://127.0.0.1:8080/api/upload_license?hwid=xxxxxxx";

                    std::string err_response = write_to_json(response);

                    send_response(resp, err_response, STATUS_CODE_BAD_REQUEST);
                }
            }

            void rest_request_process::process_invalid_uri(HttpResponse *resp, const char* request_data)
            {
                rest_response response;
                response.result_code = REST_RESULT_CODE_INVALID_STRUCTURE;
                response.result_message = rest_result_code_to_string(response.result_code);
                std::string err_response = write_to_json(response);
                send_response(resp, err_response, STATUS_CODE_BAD_REQUEST);
            }

            void rest_request_process::process_invalid_method(HttpResponse *resp, const char* request_data)
            {
                rest_response response;
                response.result_code = REST_RESULT_CODE_INVALID_METHOD;
                response.result_message = rest_result_code_to_string(response.result_code);

                std::string err_response = write_to_json(response);
                send_response(resp, err_response, STATUS_CODE_BAD_REQUEST);
            }

        }
    }
}