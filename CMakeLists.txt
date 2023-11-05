cmake_minimum_required(VERSION 3.27)
project(PBA_Tools)

set(CMAKE_CXX_COMPILER g++)
set(CMAKE_CXX_STANDARD 14)

# 添加可执行文件
add_executable(pin_profiles Pin_Profiler/profiler.cpp)

# 添加其他源文件
# add_executable(pin_profiles main.cpp file1.cpp file2.cpp)


include_directories(
	${PROJECT_SOURCE_DIR}/include/
	/opt/pin/source/include/pin/
	/opt/pin/extras/xed-intel64/include/xed/
	/opt/pin/extras/crt/include/
)

# 添加链接库
target_link_libraries(pin_profiles bfd capstone)

# 设置编译选项
add_compile_definitions(TARGET=ia32)
add_compile_options(-Wall -Wextra)

# 设置输出路径
# set(CMAKE_RUNTIME_OUTPUT_DIRECTORY bin/)