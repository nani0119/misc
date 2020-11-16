cmake_minimum_required(VERSION 3.10)
# 设置工程名称
project(PB)

set(MODULE_NAME protobuf)

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






set(GEN_DIR  "gen/cpp")

# Proto file
get_filename_component(hw_proto "${CMAKE_CURRENT_SOURCE_DIR}/proto/addressbook.proto" ABSOLUTE)
get_filename_component(hw_proto_path "${hw_proto}" PATH)

# Generated sources
find_program(_PROTOBUF_PROTOC protoc)
find_program(_GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin)

set(hw_proto_srcs "${CMAKE_CURRENT_SOURCE_DIR}/${GEN_DIR}/addressbook.pb.cc")
set(hw_proto_hdrs "${CMAKE_CURRENT_SOURCE_DIR}/${GEN_DIR}/addressbook.pb.h")
add_custom_command(
	  OUTPUT "${hw_proto_srcs}" "${hw_proto_hdrs}"
	  PRE_BUILD
      COMMAND ${_PROTOBUF_PROTOC}
      ARGS #--grpc_out "${CMAKE_CURRENT_SOURCE_DIR}/${GEN_DIR}"
        --cpp_out "${CMAKE_CURRENT_SOURCE_DIR}/${GEN_DIR}"
        -I "${hw_proto_path}"
        #--plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${hw_proto}"
	  DEPENDS "${hw_proto}"
	  COMMENT "gen new file......"
	)

# 添加头文件路径
include_directories(${GEN_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${PROJECT_BINARY_DIR}/install/include)
include_directories(${PROJECT_BINARY_DIR})

# ======================================================
# 自动包含当前目录代码文件
#foreach(dir ${GEN_DIR_LIST})
#	aux_source_directory(${dir} files)
#	set(SOURCE_FILES ${SOURCE_FILES} ${files})
#endforeach(dir)

#message(STATUS ${SOURCE_FILES})
set(SOURCE_FILES ${SOURCE_FILES} "AddressBookServiceStub.cc" "AddressBookService.cc" "addAndListAddressbook.cc")

# 编译动态库
find_package(Protobuf)
set(EXTRA_LIBS "pthread"  "protobuf")

# 编译可执行文件
set(TARGET_EXEC "addAndListAddressBook")
add_executable(${TARGET_EXEC} ${SOURCE_FILES} ${hw_proto_srcs} ${hw_grpc_srcs})
target_link_libraries(${TARGET_EXEC} ${EXTRA_LIBS})

# 指定安装的文件信息
install(TARGETS ${TARGET_EXEC}  DESTINATION bin)

