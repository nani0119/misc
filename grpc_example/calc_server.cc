#include <grpcpp/health_check_service_interface.h>
#include <grpcpp/ext/proto_server_reflection_plugin.h>

#include "calc_server.h"


void RunServer()
{
    std::string server_address("0.0.0.0:50051");
    CalculateServiceImpl calcSyncService;

    grpc::EnableDefaultHealthCheckService(true);
    grpc::reflection::ProtoServerReflectionPlugin();

    grpc::ServerBuilder builder;

    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());

    builder.RegisterService(&calcSyncService);

    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    std::cout << "Server listening on " << server_address << std::endl;
    server->Wait();
}

int main(int argc, char const *argv[])
{
    RunServer();
    return 0;
}
