#include <stdarg.h>
#include <string.h>

#include <cstdio>
#include <sstream>
#include <string>

#include "log.hpp"

void __log(int log_level, std::string tag, std::string file_name, int line_num, std::string format, ...)
{
	// Append the file name and line number to the log statement.
	std::ostringstream oss{};
	oss << file_name << ":" << line_num << " ";
	std::string log_format{oss.str()};
	log_format.append(format);

	// Pass the parameters to logcat
	va_list args;
	memset(&args, 0, sizeof(args));
	va_start(args, format);
	__android_log_vprint(log_level, tag.c_str(), log_format.c_str(), args);
	va_end(args);
}