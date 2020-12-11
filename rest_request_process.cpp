//
// Created by hlg on 2020/12/8.
//

#include "workflow/HttpMessage.h"
#include "rest_request_process.h"
#include "logger_factory.h"
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
                    case REST_RESULT_CODE_NO_AVAILABLE_HW_ID_OR_LICENSE:
                        return "no available hardware id or license on authenticating license";
                    case REST_RESULT_CODE_AUTH_LICENSE_EXPIRED:
                        return "the licenses are expired";
                    case REST_RESULT_CODE_SERVER_INTERNAL_ERROR:
                        return "rest server internal error";
                    default:
                        return "";
                }
            }

            rest_request_process::rest_request_process(const std::string& root_path, const std::string& logger_name)
                : m_hwid_mtx()
                , m_license_mtx()
                , m_hardware_ids()
                , m_hwid_licenses()
                , m_hwid_filename("hw_id.txt")
                , m_hwlicense_filename("hw_license.txt")
                , m_auth_license(common_ssl_key().private_key, common_ssl_key().public_key)
            {
                std::string vaild_path = root_path;
                char cur_path[PATH_MAX];
                if(root_path.empty() || root_path == "." || access(root_path.c_str(), F_OK) < 0){
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
                        std::string tmp_mac_hwid_pair;
                        while(getline(hwid_file, tmp_mac_hwid_pair)){
                            std::string mac;
                            std::string hwid;
                            std::istringstream iss(tmp_mac_hwid_pair);
                            if(iss >> mac >> hwid && !mac.empty() && !hwid.empty())
                                m_hardware_ids[mac] = hwid;
                        }
                        hwid_file.close();
                    }
                }

                {
                    std::ifstream license_file(m_hwlicense_filename);
                    if(license_file.is_open()) {
                        std::string license_value;

                        while (std::getline(license_file, license_value)) {
                            m_licenses.insert(license_value);
                        }
                        license_file.close();
                    }
                }

                m_logger = logger_factory::make_logger(logger_name, logger_name);
            }


            rest_request_process::~rest_request_process()
            {
                {
                    std::ostringstream whole_hwid;
                    for (auto &tmp : m_hardware_ids) {
                        whole_hwid << tmp.first << " " << tmp.second << std::endl;
                    }

                    std::ofstream hwid_file(m_hwid_filename, std::ios_base::out);
                    if(hwid_file) {
                        hwid_file << whole_hwid.str();
                        hwid_file.close();
                    }
                }

                {
                    std::ostringstream whole_license;
                    for (auto &tmp : m_licenses) {
                        whole_license << tmp << std::endl;
                    }

                    std::ofstream license_file(m_hwlicense_filename, std::ios_base::out);
                    if(license_file) {
                        license_file << whole_license.str();
                        license_file.close();
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
                //printf("---- response status_code: %s, message: \n\t\t%s\n\n", status.c_str(), response_message.c_str());
                if(m_logger){
                    m_logger->info("#### response status_code: {}, message:  {}\n", status, response_message);
                }
                resp->set_header_pair("Content-Type", "application/json");
                resp->set_status_code(status);
                resp->append_output_body(response_message);
            }


            void rest_request_process::process_get_hwids(HttpResponse *resp, const char* request_data)
            {
                std::unordered_map<std::string, std::string>tmp_hwids;
                {
                    std::unique_lock<std::mutex>lock(m_hwid_mtx);
                    tmp_hwids = m_hardware_ids;
                    if(tmp_hwids.empty()){
                        std::ifstream file(m_hwid_filename);
                        if(file){
                            std::string tmp_mac_hwid_pair;
                            while(getline(file, tmp_mac_hwid_pair)){
                                std::string mac;
                                std::string hwid;
                                std::istringstream iss(tmp_mac_hwid_pair);
                                if(iss >> mac >> hwid && !mac.empty() && !hwid.empty())
                                    m_hardware_ids[mac] = hwid;
                            }
                            file.close();
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
                    std::string all_hwids;
                    for (auto &tmp : tmp_hwids) {
                        all_hwids += tmp.second + "-";
                    }
                    if(!all_hwids.empty() && all_hwids[all_hwids.size() - 1] == '-'){
                        all_hwids.erase(all_hwids.size() - 1);
                    }
                    jobj["hwids"] = all_hwids;
                    available_hwid = jobj.dump();
                } catch (json::exception& e) {
                    rest_response response;
                    response.result_code = REST_RESULT_CODE_SERVER_INTERNAL_ERROR;
                    response.result_message = rest_result_code_to_string(response.result_code);
                    response.result_message += std::string(": in method \"get_hwids\", json assemble failed. ");
                    std::string out_response = write_to_json(response);

                    send_response(resp, out_response, STATUS_CODE_SERVER_INTERNAL_ERROR);
                    return;
                }

                rest_response response;
                response.result_code = REST_RESULT_CODE_SUCCESS;
                response.result_message = rest_result_code_to_string(response.result_code);
                response.result_message += ": get_hwids";
                response.response_data = available_hwid;
                std::string out_response = write_to_json(response);

                send_response(resp, out_response, STATUS_CODE_SUCCESS);
            }


            void rest_request_process::process_get_license_by_hwid_with_base64(HttpResponse *resp, const char* hardware_id)
            {
                std::string hwid_value = hardware_id;
                std::set<std::string>tmp_licenses;
                {
                    std::unique_lock<std::mutex> lock(m_license_mtx);
                    tmp_licenses = m_licenses;
                    if (tmp_licenses.empty()) {
                        std::ifstream file(m_hwlicense_filename);
                        std::string tmp_license;

                        while (std::getline(file, tmp_license)) {
                            m_licenses.insert(tmp_license);
                        }
                        tmp_licenses = m_licenses;
                    }
                }


                HWInfo hw_info;
                if(!m_auth_license.decode_hwinfo(hwid_value, &hw_info)){
                    rest_response response;
                    response.result_code = REST_RESULT_CODE_SERVER_INTERNAL_ERROR;
                    response.result_message = rest_result_code_to_string(response.result_code);
                    response.result_message += ": get_license, decode_hwinfo failed";
                    std::string out_response = write_to_json(response);

                    send_response(resp, out_response, STATUS_CODE_SERVER_INTERNAL_ERROR);
                    return;
                }

                bool license_is_found = false;
                std::string current_license;
                for(auto license: tmp_licenses){
                    if(m_auth_license.verify_license(&hw_info, license)){
                        license_is_found = true;
                        current_license = license;
                        break;
                    }
                }

                if(!license_is_found){
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
                    jobj["license"] = current_license;
                    available_license = jobj.dump();
                } catch (json::exception& e) {
                    available_license = std::string("json assemble failed.");

                    rest_response response;
                    response.result_code = REST_RESULT_CODE_SERVER_INTERNAL_ERROR;
                    response.result_message = rest_result_code_to_string(response.result_code);
                    response.result_message += ": upload_hwid is OK, but get_license failed: " + available_license;
                    std::string out_response = write_to_json(response);

                    send_response(resp, out_response, STATUS_CODE_SERVER_INTERNAL_ERROR);
                    return;
                }

                rest_response response;
                response.result_code = REST_RESULT_CODE_SUCCESS;
                response.result_message = rest_result_code_to_string(response.result_code);
                response.result_message += ": upload_hwid and get_license is OK.";
                response.response_data = available_license;

                std::string out_response = write_to_json(response);
                send_response(resp, out_response, STATUS_CODE_SUCCESS);
            }

            void rest_request_process::process_upload_hwid(HttpResponse *resp, const char* request_data)
            {
                try{
                    auto jobj = json::parse(request_data);

                    if(jobj.contains("hwid") && jobj.contains("mac")){
                        std::string mac_value = jobj["mac"];
                        std::string hwid_value = jobj["hwid"];

                        {
                            std::unique_lock<std::mutex>lock(m_hwid_mtx);
                            if(m_hardware_ids.empty()){
                                std::ifstream file(m_hwid_filename, std::ios_base::in);
                                if(file){
                                    std::string tmp_mac_hwid_pair;
                                    while(getline(file, tmp_mac_hwid_pair)){
                                        std::string mac;
                                        std::string hwid;
                                        std::istringstream iss(tmp_mac_hwid_pair);
                                        if(iss >> mac >> hwid && !mac.empty() && !hwid.empty())
                                            m_hardware_ids[mac] = hwid;
                                    }
                                    file.close();
                                }

                            }

                            m_hardware_ids[mac_value] = hwid_value;

                            std::ofstream file(m_hwid_filename, std::ios_base::out);
                            if(file) {
                                for(const auto& tmp : m_hardware_ids){
                                    file << tmp.first << " " << tmp.second << std::endl;
                                }
                                file.close();
                            }
                        }

#ifdef ENABLE_GET_LICENSE_IN_UPLOAD_HWID_PROCEDURE
                        process_get_license_by_hwid_with_base64(resp, hwid_value.c_str());
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
                        response.result_message += "\n  ****USAGE : use the http POST method to access the rest_server URI with json parameter, such as:\n\n";
                        response.result_message += "        URI ---- http://ip:port/api/upload_hwid\n";
                        response.result_message += "        JSON pattern parameter ---- {\"hwid\" : \"xxxxxxxxxx\", \"mac\" : \"oooooooooo\"}\n";

                        std::string err_response = write_to_json(response);

                        send_response(resp, err_response, STATUS_CODE_BAD_REQUEST);
                    }
                } catch (json::exception& e) {
                    rest_response response;
                    response.result_code = REST_RESULT_CODE_SERVER_INTERNAL_ERROR;
                    response.result_message = rest_result_code_to_string(response.result_code);
                    response.result_message += std::string(": in method \"upload_hwid\", json parse failed. \n");
                    response.result_message += "\n  ****USAGE : use the http POST method to access the rest_server URI with json parameter, such as:\n\n";
                    response.result_message += "        URI ---- http://ip:port/api/upload_hwid\n";
                    response.result_message += "        JSON pattern parameter ---- {\"hwid\" : \"xxxxxxxxxx\", \"mac\" : \"oooooooooo\"}\n";
                    std::string out_response = write_to_json(response);

                    send_response(resp, out_response, STATUS_CODE_SERVER_INTERNAL_ERROR);
                    return;
                }
            }

            void rest_request_process::process_upload_multi_licenses(HttpResponse *resp, const char* request_data)
            {
                try {
                    auto jobj = json::parse(request_data);

                    if (jobj.contains("licenses")) {

                        std::unique_lock<std::mutex> lock(m_license_mtx);
                        m_licenses.clear();
                        auto licenses_jobj = jobj["licenses"];
                        std::ofstream lic_file(m_hwlicense_filename, std::ios_base::out);

                        if (licenses_jobj.is_array()) {
                            for (unsigned int i = 0; i < licenses_jobj.size(); ++i) {
                                auto cur_license = licenses_jobj[i].get<std::string>();
                                if(!cur_license.empty()) {
                                    m_licenses.insert(cur_license);
                                    if (lic_file) {
                                        lic_file << cur_license << std::endl;

                                    }
                                }
                            }
                            if(lic_file)
                                lic_file.close();
                        } else {

                            std::string all_licenses_value = licenses_jobj.get<std::string>();

                            for(auto& c : all_licenses_value){
                                if(c == '-' || c == ';' || c == ' '){
                                    c = '\n';
                                }
                            }

                            if (!all_licenses_value.empty() &&
                                all_licenses_value[all_licenses_value.size() - 1] != '\n') {
                                all_licenses_value += "\n";
                            }
                            std::istringstream iss(all_licenses_value);
                            if (lic_file) {
                                lic_file << all_licenses_value;
                                lic_file.close();
                            }

                            std::string license_value;
                            while (std::getline(iss, license_value)) {
                                if (!license_value.empty()) {
                                    m_licenses.insert(license_value);
                                }
                            }
                        }

                        rest_response response;
                        response.result_code = REST_RESULT_CODE_SUCCESS;
                        response.result_message = rest_result_code_to_string(response.result_code);
                        response.result_message += ": upload_licenses";

                        std::string out_response = write_to_json(response);
                        send_response(resp, out_response, STATUS_CODE_SUCCESS);
                    } else {
                        rest_response response;
                        response.result_code = REST_RESULT_CODE_INVALID_PARAM;
                        response.result_message = rest_result_code_to_string(response.result_code);
                        response.result_message += "\n  ****USAGE : use the http POST method to access the rest_server URI with json parameter, such as:\n\n";
                        response.result_message += "        URI ---- http://ip:port/api/upload_licenses\n";
                        response.result_message += "        JSON pattern parameter ---- {\"licenses\" : \"xxxxxxxxxx-oooooooooo\"}\n";

                        std::string err_response = write_to_json(response);

                        send_response(resp, err_response, STATUS_CODE_BAD_REQUEST);
                    }
                }catch (json::exception& e) {
                    rest_response response;
                    response.result_code = REST_RESULT_CODE_SERVER_INTERNAL_ERROR;
                    response.result_message = rest_result_code_to_string(response.result_code);
                    response.result_message += std::string(": in method \"upload_licenses\", json parse failed. \n");
                    response.result_message += "\n  ****USAGE : use the http POST method to access the rest_server URI with json parameter, such as:\n\n";
                    response.result_message += "        URI ---- http://ip:port/api/upload_licenses\n";
                    response.result_message += "        JSON pattern parameter ---- {\"licenses\" : \"xxxxxxxxxx-oooooooooo\"}\n";
                    std::string out_response = write_to_json(response);

                    send_response(resp, out_response, STATUS_CODE_SERVER_INTERNAL_ERROR);
                    return;
                }
            }

            void rest_request_process::process_valid_days(HttpResponse *resp, const char* request_data)
            {
                std::unordered_map<std::string, std::string>tmp_hwids;
                {
                    std::unique_lock<std::mutex>lock(m_hwid_mtx);
                    tmp_hwids = m_hardware_ids;
                    if(tmp_hwids.empty()){
                        std::ifstream file(m_hwid_filename);
                        if(file){
                            std::string tmp_mac_hwid_pair;
                            while(getline(file, tmp_mac_hwid_pair)){
                                std::string mac;
                                std::string hwid;
                                std::istringstream iss(tmp_mac_hwid_pair);
                                if(iss >> mac >> hwid && !mac.empty() && !hwid.empty())
                                    m_hardware_ids[mac] = hwid;
                            }
                            file.close();
                        }
                        tmp_hwids = m_hardware_ids;
                    }
                }


                std::set<std::string>tmp_licenses;
                {
                    std::unique_lock<std::mutex> lock(m_license_mtx);
                    tmp_licenses = m_licenses;
                    if (tmp_licenses.empty()) {
                        std::ifstream file(m_hwlicense_filename);
                        std::string tmp_license;

                        while (std::getline(file, tmp_license)) {
                            m_licenses.insert(tmp_license);
                        }
                        tmp_licenses = m_licenses;
                    }
                }


                if(tmp_hwids.empty() || tmp_licenses.empty()){
                    rest_response response;
                    response.result_code = REST_RESULT_CODE_NO_AVAILABLE_HW_ID_OR_LICENSE;
                    response.result_message = rest_result_code_to_string(response.result_code);
                    std::string out_response = write_to_json(response);
                    send_response(resp, out_response, STATUS_CODE_PAGE_NOT_FOUND);
                    return;
                }

                int valid_days = -1;
                for(const auto& hwid : tmp_hwids){

                    HWInfo hw_info;
                    if(!m_auth_license.decode_hwinfo(hwid.second, &hw_info)){
                        continue;
                    }

                    for(auto license : tmp_licenses){

                        if((valid_days = m_auth_license.valid_rest_days(&hw_info, license)) >= 0){
                            break;
                        }
                    }

                    if(valid_days >= 0){
                        break;
                    }
                }

                std::string valid_days_string;
                try {
                    json jobj;
                    if(valid_days >= 0){
                        jobj["valid_days"] = valid_days;
                    }else{
                        jobj["valid_days"] = -1;
                    }
                    valid_days_string = jobj.dump();
                } catch (json::exception &e) {
                    valid_days_string = std::string("json parse failed: ") + e.what();

                    rest_response response;
                    response.result_code = REST_RESULT_CODE_SERVER_INTERNAL_ERROR;
                    response.result_message = rest_result_code_to_string(response.result_code);
                    response.result_message += ": valid_days, " + std::string("json parse failed: ") ;
                    std::string out_response = write_to_json(response);

                    send_response(resp, out_response, STATUS_CODE_SERVER_INTERNAL_ERROR);
                    return;
                }


                rest_response response;
                if(valid_days >= 0) {
                    response.result_code = REST_RESULT_CODE_SUCCESS;
                    response.result_message = rest_result_code_to_string(response.result_code);
                    response.result_message += ": valid_days";
                    response.response_data = valid_days_string;
                }else{
                    response.result_code = REST_RESULT_CODE_AUTH_LICENSE_EXPIRED;
                    response.result_message = rest_result_code_to_string(response.result_code);
                    response.response_data = valid_days_string;
                }

                std::string out_response = write_to_json(response);
                send_response(resp, out_response, STATUS_CODE_SUCCESS);

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

            void rest_request_process::process_help_usage(HttpResponse *resp, const char* request_data)
            {
                rest_response response;
                response.result_code = REST_RESULT_CODE_SUCCESS;
                std::string help_message = "THE simple rest server provide four rest api: 'help', 'get_hwids', 'valid_days', 'upload_licenses', 'upload_hwid', 'valid_days': \n";
                help_message += "* help/usage * API : to output this usage message. \n        use http GET method to access the URI, such as: http://ip:port/api/help  OR  http://ip:port/api/usage\n";
                help_message += "* get_hwids * API : to get all uploaded haredware ids. \n        use http GET method to access the URI, such as: http://ip:port/api/get_hwids\n";
                help_message += "* valid_days * API : to get license rest valid days. \n        use http GET method to access the URI, such as: http://ip:port/api/valid_days\n";
                help_message += "* upload_licenses * API :  to upload all licenses. \n        use http POST method with JSON pattern parameter {\"licenses\" : \"xxxxxxxxxx-oooooooooo\"} to access the URI: http://ip:port/api/upload_licenses\n";
                help_message += "* upload_hwid * API : to upload hardware id and return its license if fount it in rest server. \n        use http POST method with JSON pattern parameter  {\"hwid\" : \"xxxxxxxxxx\", \"mac\" : \"oooooooooo\"}  to access the URI: http://ip:port/api/upload_hwid\n";
                response.result_message += help_message;

                std::string out_response = write_to_json(response);
                send_response(resp, out_response, STATUS_CODE_SUCCESS);
            }

        }
    }
}