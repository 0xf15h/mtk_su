#ifndef LOG_HPP
#define LOG_HPP

#include <android/log.h>
#include <stdarg.h>

#include <iostream>
#include <string>

#define TAG "MTK_SU"

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

// Do not call directly! Please use the macros listed below.
void __log(int log_level, std::string tag, std::string file_name, int line_num, std::string format, ...);

#define log_info(...) __log(ANDROID_LOG_INFO, TAG, __FILENAME__, __LINE__, __VA_ARGS__)
#define log_debug(...) __log(ANDROID_LOG_DEBUG, TAG, __FILENAME__, __LINE__, __VA_ARGS__)
#define log_error(...) __log(ANDROID_LOG_ERROR, TAG, __FILENAME__, __LINE__, __VA_ARGS__)

#endif  // LOG_HPP