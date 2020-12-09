#include "logger_factory.h"
#include <unistd.h>
#include <sys/stat.h>
#include <spdlog/async.h>
#include <spdlog/sinks/dist_sink.h>
#include <spdlog/sinks/rotating_file_sink.h>

namespace gwecom {
	namespace network {
		namespace rest {
			static std::string logger_default_dir = "";
#ifdef _DEBUG
			static spdlog::level::level_enum logger_default_level = spdlog::level::level_enum::debug;
#else
			static spdlog::level::level_enum logger_default_level = spdlog::level::level_enum::info;
#endif

			void logger_factory::init(spdlog::level::level_enum level, const std::string& log_dir)
			{
				spdlog::shutdown();

				logger_default_level = level;
				if (!log_dir.empty())
				{
					logger_default_dir = log_dir;
				}
				else {
					std::string current_directory;
                    char cur_path[PATH_MAX];
                    if(getcwd(cur_path, PATH_MAX)){
                        current_directory = cur_path;
                    }else{
                        current_directory = "/tmp";
                    }

                    bool last_is_slash = (current_directory[current_directory.size() - 1] == '/');
                    logger_default_dir = last_is_slash ? current_directory + "logs" : current_directory + "/" + "logs";
                    if(access(logger_default_dir.c_str(), F_OK) < 0) {
                        mkdir(logger_default_dir.c_str(), 0755);
                    }
				}

				spdlog::init_thread_pool(8192, 1);
			}

			void logger_factory::deinit()
			{
				spdlog::shutdown();
			}

			static std::shared_ptr<spdlog::logger> make_logger_impl(const std::string& logger_name, const std::string& file_name, const std::string& log_dir)
			{
				auto dist_sink = std::make_shared<spdlog::sinks::dist_sink_mt>();
#if defined _WIN32
				auto sink1 = std::make_shared<spdlog::sinks::wincolor_stdout_sink_mt>();
#else
				auto sink1 = std::make_shared<spdlog::sinks::ansicolor_stdout_sink_mt>();
#endif

				std::string file = (log_dir.empty() ? logger_default_dir : log_dir) + "/" + file_name;
				if(file_name.substr(file_name.size() - 5, 4) != ".log")
					file += ".log";
				auto sink2 = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(file, 1024 * 1024 * 10, 50);

				dist_sink->add_sink(sink1);
				dist_sink->add_sink(sink2);
				auto logger = std::make_shared<spdlog::async_logger>(logger_name, dist_sink, spdlog::thread_pool(), spdlog::async_overflow_policy::block);

				logger->set_level(logger_default_level);
				logger->set_pattern("[%Y:%m:%d %T.%e][%^%L%$][tid-%t] %v");
				spdlog::register_logger(logger);
				spdlog::flush_on(spdlog::level::level_enum::err);
				spdlog::flush_every(std::chrono::seconds(15));
				return logger;
			}

			std::shared_ptr<spdlog::logger> logger_factory::make_logger(const std::string& logger_name, const std::string& file_name, const std::string& log_dir)
			{

				static std::mutex mtx;
				std::unique_lock<std::mutex> lock(mtx);

				auto logger = spdlog::get(logger_name);
				if (!logger)
				{
					auto fixed_file_name = file_name.empty() ? logger_name : file_name;
					int retry = 0;
					while (!logger && retry++ < 9)
					{
						try {
							logger = make_logger_impl(logger_name, fixed_file_name, log_dir);
						}
						catch (const spdlog::spdlog_ex& ex)
						{
							printf("spdlog::spdlog_ex %s\n", ex.what());
							fixed_file_name += "_" + std::to_string(retry);
							std::this_thread::sleep_for(std::chrono::milliseconds(100));
						}
					}
				}
				return logger;
			}


			void logger_factory::drop_logger(std::shared_ptr<spdlog::logger> logger)
			{
				spdlog::drop(logger->name());
			}

			std::shared_ptr<spdlog::logger> logger_factory::global_logger()
			{
#define GLOBAL_LOGGER_NAME "global_logger"
				if (!spdlog::get(GLOBAL_LOGGER_NAME)) {
					make_logger(GLOBAL_LOGGER_NAME, GLOBAL_LOGGER_NAME);
				}
				return get(GLOBAL_LOGGER_NAME);
			}

			std::shared_ptr<spdlog::logger> logger_factory::get(const std::string& logger_name)
			{
				return spdlog::get(logger_name);
			}



		

		}
	}
}