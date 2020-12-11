//
// Created by hlg on 2020/12/9.
//

#include "authenticate_license.h"
#include "base64.h"
#include "openssl-RSA.h"
#include <string>
#include <chrono>
#include <string.h>
#include <iostream>
#include <math.h>

namespace gwecom {
    namespace network {
        namespace rest {
            authenticate_license::authenticate_license(const std::string& private_key, const std::string& public_key)
                : m_private_key(private_key)
                , m_public_key(public_key)
            {

            }

            bool authenticate_license::decode_hwinfo(const std::string& base64_hwinfo, HWInfo* hw_info)
            {
                if(hw_info == nullptr){
                    return false;
                }

                auto string_hwinfo = base64_decode(base64_hwinfo);
                auto decrypted_buffer = allocateRSABuffer(m_private_key, string_hwinfo.length(), RSA_BUFFER_TYPE_DECRYPTION);
                if(!decrypted_buffer){
                    std::cout << "allocate decrypted_buffer failed: " << std::endl;
                    return false;
                }


                int length = decrypt(m_private_key, (unsigned char*)string_hwinfo.c_str(), string_hwinfo.length(), decrypted_buffer->data);
                if (length <= 0) {
                    std::cout << "decrypt hwid failed: " << length << std::endl;
                    freeRSABuffer(decrypted_buffer);
                    return false;
                }

                auto decryptedHWID = (HWInfo *)decrypted_buffer->data;
                std::cout << "=============  Hardware info =============" << std::endl;
                std::cout << "boardManufacturer: " <<decryptedHWID->boardManufacturer << std::endl;
                std::cout << "boardSerialNumber: " << decryptedHWID->boardSerialNumber << std::endl;
                std::cout << "cpuManufacturer: " << decryptedHWID->cpuManufacturer << std::endl;
                std::cout << "cpuVersion: " << decryptedHWID->cpuVersion << std::endl;
                std::cout << "gpuManufacturer: " << decryptedHWID->gpuManufacturer << std::endl;
                std::cout << "gpuVersion: " << decryptedHWID->gpuVersion<< std::endl;
                std::cout << "GPU uuid: ";
                for (unsigned char c: decryptedHWID->gpuUUID)
                {
                    printf("%x", c);
                }
                std::cout << std::endl;

                memcpy(hw_info, decryptedHWID, sizeof(HWInfo));
                freeRSABuffer(decrypted_buffer);
                return true;

            }

            bool authenticate_license::decode_license(const std::string& base64_license, licenseInfo* license_info)
            {
                if(license_info == nullptr){
                    return false;
                }

                auto licenseString = base64_decode(base64_license);
                if(licenseString.empty() || licenseString.length() < sizeof(licenseInfo)){
                    return false;
                }

                memcpy(license_info, licenseString.c_str(), licenseString.length());
                return true;
            }

            bool authenticate_license::verify_license(HWInfo* hw_info, licenseInfo* license_info)
            {
                if(hw_info == nullptr || license_info == nullptr){
                    return false;
                }

                HWInfoWithDays hwinfo_with_days;
                memcpy(&hwinfo_with_days, hw_info, sizeof(HWInfo));
                hwinfo_with_days.expired_date = license_info->expired_date;

                bool verified = verifySignature(m_public_key, (const char*)&hwinfo_with_days, sizeof(HWInfoWithDays), license_info->signedHWInfo, SIGNED_MSG_LENGTH);

                if(verified){
                    auto now = std::chrono::system_clock::now();

                    auto date = license_info->expired_date;
                    std::tm tm = { 0 };
                    tm.tm_year = date / 10000 - 1900;
                    tm.tm_mon = date / 100 % 100 - 1;
                    tm.tm_mday = date % 100;
                    auto expired_date = std::chrono::system_clock::from_time_t(std::mktime(&tm));

                    std::chrono::duration<double> elapsed_seconds = expired_date - now;
                    if (elapsed_seconds.count() > 0) {
                        return true;
                    }else{
                        return false;
                    }
                }

                return false;
            }

            bool authenticate_license::verify_license(HWInfo* hw_info, const std::string& base64_license)
            {
                if(hw_info == nullptr || base64_license.empty()){
                    return false;
                }

                licenseInfo license_info;

                if(!decode_license(base64_license, &license_info))
                    return false;

                return verify_license(hw_info, &license_info);
            }


            bool authenticate_license::verify_license(const std::string& base64_hwinfo, const std::string& base64_license)
            {
                HWInfo hw_info;
                licenseInfo license_info;

                if(!decode_hwinfo(base64_hwinfo, &hw_info))
                    return false;

                if(!decode_license(base64_license, &license_info))
                    return false;

                return verify_license(&hw_info, &license_info);
            }


            int authenticate_license::valid_rest_days(HWInfo* hw_info, licenseInfo* license_info)
            {
                if(hw_info == nullptr || license_info == nullptr){
                    return LICENSE_AUTH_CODE_INVALID_LISENCE;
                }

                HWInfoWithDays hwinfo_with_days;
                memcpy(&hwinfo_with_days, hw_info, sizeof(HWInfo));
                hwinfo_with_days.expired_date = license_info->expired_date;

                bool verified = verifySignature(m_public_key, (const char*)&hwinfo_with_days, sizeof(HWInfoWithDays), license_info->signedHWInfo, SIGNED_MSG_LENGTH);

                if(verified){
                    auto now = std::chrono::system_clock::now();

                    auto date = license_info->expired_date;
                    std::tm tm = { 0 };
                    tm.tm_year = date / 10000 - 1900;
                    tm.tm_mon = date / 100 % 100 - 1;
                    tm.tm_mday = date % 100;
                    auto expired_date = std::chrono::system_clock::from_time_t(std::mktime(&tm));

                    std::chrono::duration<double> elapsed_seconds = expired_date - now;
                    if (elapsed_seconds.count() > 0) {
                        return ceil(elapsed_seconds.count() * 1.0 / 86400);
                    }else{
                        return LICENSE_AUTH_CODE_EXPIRED;
                    }
                }

                return LICENSE_AUTH_CODE_INVALID_LISENCE;
            }

            int authenticate_license::valid_rest_days(HWInfo* hw_info, const std::string& base64_license)
            {
                if(hw_info == nullptr || base64_license.empty()){
                    return LICENSE_AUTH_CODE_INVALID_LISENCE;
                }

                licenseInfo license_info;

                if(!decode_license(base64_license, &license_info))
                    return LICENSE_AUTH_CODE_INVALID_LISENCE;

                return valid_rest_days(hw_info, &license_info);
            }


            int authenticate_license::valid_rest_days(const std::string& base64_hwinfo, const std::string& base64_license)
            {
                HWInfo hw_info;
                licenseInfo license_info;

                if(!decode_hwinfo(base64_hwinfo, &hw_info))
                    return LICENSE_AUTH_CODE_INVALID_HWINFO;

                if(!decode_license(base64_license, &license_info))
                    return LICENSE_AUTH_CODE_INVALID_LISENCE;

                return valid_rest_days(&hw_info, &license_info);
            }


        }
    }
}