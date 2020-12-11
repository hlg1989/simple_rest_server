#pragma once
#include <string>

namespace gwecom {
	namespace network{
        namespace rest {

            std::string base64_encode(unsigned char const *, unsigned int len);

            std::string base64_decode(std::string const &s);

        }
	}
}
