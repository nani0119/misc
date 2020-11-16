cmake_minimum_required(VERSION 3.10)
# 设置工程名称
project(TestLibUSB)

set(MODULE_NAME TestUSB)

# 设置版本信息，在.in文件中通过@<name>@替换对应值
set(PRIMER_VERSION_MAJOR 1)
set(PRIMER_VERSION_MINOR 0)# 生成编译时的配置文件.h(包含各种宏)

configure_file(
	"${PROJECT_SOURCE_DIR}/config.h.in"
	"${PROJECT_BINARY_DIR}/config.h"
	)

# 检查对应选项是否打开
if (BUILD_DEBUG_TYPE)
    set(CMAKE_BUILD_TYPE "Debug")
    set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -g -ggdb")
    set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
endif (BUILD_DEBUG_TYPE)


option(BUILD_DEBUG_TYPE
	   "build debug type"
	   on)

#指定安装时使用的路径前缀
set(CMAKE_INSTALL_PREFIX "${PROJECT_BINARY_DIR}/install")

# 添加动态或者静态链接库路径
link_directories(${PROJECT_BINARY_DIR}/install/lib)

# 添加头文件路径
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${PROJECT_BINARY_DIR}/install/include)
include_directories(${PROJECT_BINARY_DIR})

# ======================================================
# 自动包含当前目录代码文件
set(SOURCE_FILE "testlibusb.cc" "usbdevice.cc")
set(TARGET_EXEC "test_lib_usb_exe")
set(EXTRA_LIBS "usb-1.0" "pthread")

# 生成可执行文件
add_executable(${TARGET_EXEC} ${SOURCE_FILE})

# 链接库文件
target_link_libraries(${TARGET_EXEC} ${EXTRA_LIBS})

# 指定安装的文件信息
install(TARGETS ${TARGET_EXEC} DESTINATION bin)

# ======================================================