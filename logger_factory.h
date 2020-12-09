#ifndef WORKFLOW_LOGGER_FACTORY_H
#define WORKFLOW_LOGGER_FACTORY_H
#include <spdlog/spdlog.h>


namespace gwecom {
	namespace network {
		namespace rest {
			class logger_factory final
			{
			public:
				static void init(spdlog::level::level_enum level = spdlog::level::level_enum::info, const std::string& log_dir = "");
				static void deinit();

				static std::shared_ptr<spdlog::logger> make_logger(const std::string& logger_name, const std::string& file_name = "", const std::string& log_dir = "");

				static void drop_logger(std::shared_ptr<spdlog::logger> logger);

				static std::shared_ptr<spdlog::logger> global_logger();

				static std::shared_ptr<spdlog::logger> get(const std::string& logger_name);
			private:
				logger_factory() = default;
				logger_factory(const logger_factory&) = delete;
				const logger_factory& operator=(const logger_factory&) = delete;
				~logger_factory() = default;

			};

		}
	}
}

#endif