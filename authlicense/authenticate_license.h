//
// Created by hlg on 2020/12/9.
//

#ifndef SIMPLE_REST_SERVER_AUTHENTICATE_LICENSE_H
#define SIMPLE_REST_SERVER_AUTHENTICATE_LICENSE_H
#include <string>
#include "HWInfo.h"
#include "openssl-RSA.h"

namespace gwecom {
    namespace network {
        namespace rest {

            enum LICENSE_AUTH_CODE
            {
                LICENSE_AUTH_CODE_INVALID_LISENCE = -1,
                LICENSE_AUTH_CODE_EXPIRED = -2,
                LICENSE_AUTH_CODE_INVALID_HWINFO = -3,
            };

            class authenticate_license{
            public:
                authenticate_license(const std::string& private_key, const std::string& public_key);
                ~authenticate_license() = default;

                bool decode_hwinfo(const std::string& base64_hwinfo, HWInfo* hw_info);
                bool decode_license(const std::string& base64_license, licenseInfo* license_info);

                bool verify_license(HWInfo* hw_info, licenseInfo* license_info);
                bool verify_license(HWInfo* hw_info, const std::string& base64_license);
                bool verify_license(const std::string& base64_hwinfo, const std::string& base64_license);

                int valid_rest_days(HWInfo* hw_info, licenseInfo* license_info);
                int valid_rest_days(HWInfo* hw_info, const std::string& base64_license);
                int valid_rest_days(const std::string& base64_hwinfo, const std::string& base64_license);

            private:
                std::string m_private_key;
                std::string m_public_key;
            };

        }
    }
}

#endif //SIMPLE_REST_SERVER_AUTHENTICATE_LICENSE_H
