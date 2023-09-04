cmake_minimum_required(VERSION 3.13)

project(mtk_su VERSION 1.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_library(log_lib log)

add_executable(mtk_su src/main.cpp src/kallsyms.cpp src/selinux.cpp src/task.cpp src/disasm.cpp src/mtk_su.cpp src/utils.cpp src/log.cpp)
target_include_directories(mtk_su PRIVATE ./include)
target_link_libraries(mtk_su ${log_lib})
