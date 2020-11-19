cmake_minimum_required(VERSION 3.10)
# 设置工程名称
project(GRPC_EXAMPLE)

set(MODULE_NAME Calc)

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

set(CMAKE_PREFIX_PATH "/opt/grpc")
# 代码生成路径
set(GEN_DIR  "gen/cpp")

# 查找依赖包
find_package(Threads REQUIRED)

find_package(Protobuf)
message(STATUS "Using protobuf ${Protobuf_VERSION}")
set(_PROTOBUF_LIBPROTOBUF protobuf::libprotobuf)


find_package(gRPC CONFIG REQUIRED)
set(_GRPC_GRPCPP gRPC::grpc++)
set(_REFLECTION gRPC::grpc++_reflection)
message(STATUS "Using gRPC ${gRPC_VERSION}")

# 添加动态或者静态链接库路径
link_directories(${PROJECT_BINARY_DIR}/install/lib)

# 添加头文件路径
include_directories(${GEN_DIR})
#include_directories(${Protobuf_INCLUDE_DIR})
#include_directories(${gRPC_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${PROJECT_BINARY_DIR}/install/include)
include_directories(${PROJECT_BINARY_DIR})


# Generated sources
find_program(_PROTOBUF_PROTOC protoc)
find_program(_GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin)

message(STATUS "_PROTOBUF_PROTOC:" ${_PROTOBUF_PROTOC})
message(STATUS "_GRPC_CPP_PLUGIN_EXECUTABLE:" ${_GRPC_CPP_PLUGIN_EXECUTABLE})


set(PROTO_FILE_PATH  "${CMAKE_CURRENT_SOURCE_DIR}/proto")
file(GLOB_RECURSE  PROTO_FILES ${PROTO_FILE_PATH}/*.proto)
message(STATUS "PROTO_FILES:" ${PROTO_FILES})



# Proto file
foreach(_proto_file ${PROTO_FILES})
    message(STATUS "================================================")
    get_filename_component(_proto      ${_proto_file}     ABSOLUTE)
    get_filename_component(_proto_path ${_proto_file}     PATH)
    get_filename_component(_proto_wle  ${_proto_file}     NAME_WLE)

    message(STATUS "_proto:" ${_proto})
    message(STATUS "_proto_path:" ${_proto_path})
    message(STATUS "_proto_wle:" ${_proto_wle})

    set(_proto_srcs "${CMAKE_CURRENT_SOURCE_DIR}/${GEN_DIR}/${_proto_wle}.pb.cc")
    set(_proto_hdrs "${CMAKE_CURRENT_SOURCE_DIR}/${GEN_DIR}/${_proto_wle}.pb.h")

    message(STATUS "_proto_srcs:" ${_proto_srcs})
    message(STATUS "_proto_hdrs:" ${_proto_hdrs})

    execute_process(
      COMMAND mkdir -p ${GEN_DIR}
      COMMAND ${_PROTOBUF_PROTOC}
              --grpc_out "${GEN_DIR}"
              --cpp_out "${GEN_DIR}"
              --proto_path "${_proto_path}"
              --plugin protoc-gen-grpc=${_GRPC_CPP_PLUGIN_EXECUTABLE}
              "${_proto}"
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
    message(STATUS "================================================")
endforeach(_proto_file ${PROTO_FILES})

# 添加生成文件
aux_source_directory("${CMAKE_CURRENT_SOURCE_DIR}/${GEN_DIR}" GEN_SOURCE)
message(STATUS "GEN_SOURCE:" ${GEN_SOURCE})

#指定安装时使用的路径前缀
set(CMAKE_INSTALL_PREFIX "${PROJECT_BINARY_DIR}/install")

# 编译可执行文件
foreach(_target "calc_client" "calc_server")
    add_executable(${_target} ${_target}.cc ${GEN_SOURCE})
    target_link_libraries(${_target}     
                                ${_REFLECTION}
                                ${_GRPC_GRPCPP}
                                ${_PROTOBUF_LIBPROTOBUF}
    )
    install(TARGETS ${_target}  DESTINATION bin)
endforeach(_target "calc_client" "calc_server")
