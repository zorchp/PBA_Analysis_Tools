cmake_minimum_required(VERSION 3.27)
project(PBA_Tools)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 添加可执行文件
add_executable(pin_profiles Pin_Profiler/profiler.cpp)

# 添加其他源文件
# add_executable(pin_profiles main.cpp file1.cpp file2.cpp)


include_directories(
	${PROJECT_SOURCE_DIR}/include/
	/opt/pin/source/include/pin/
)

# 添加链接库
target_link_libraries(pin_profiles bfd capstone)

# 设置编译选项
add_compile_options(-Wall -Wextra)

# 设置输出路径
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
# set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
# set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)