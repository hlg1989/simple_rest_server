#pragma once
namespace gwecom {
    namespace network{
        namespace rest {

            const int SIGNED_MSG_LENGTH = 256;
            typedef struct HWInfo {
                char cpuManufacturer[32] = {0};
                char cpuVersion[32] = {0};
                char boardManufacturer[32] = {0};
                char boardSerialNumber[32] = {0};
                char gpuManufacturer[32] = {0};
                char gpuVersion[32] = {0};
                char gpuUUID[16] = {0};
            } HWInfo;

            typedef struct HWInfoWithDays {
                HWInfo info;
                int expired_date;
            } HWInfoWithDays;

            typedef struct licenseInfo {
                int expired_date;
                int length;
                unsigned char signedHWInfo[SIGNED_MSG_LENGTH];
            } licenseInfo;


        }
	}
}
