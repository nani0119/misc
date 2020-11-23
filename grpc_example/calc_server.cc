#include <thread>

#include <grpcpp/health_check_service_interface.h>
#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/ext/health_check_service_server_builder_option.h>

#include "calc_server.h"
#include "calc_async_server.h"
#include "custom_health_check_server.h"


#define USE_CUSTOM_HEALTH_CHECK 1

class ServerGlobalCallback:public grpc::Server::GlobalCallbacks 
{
    // Called before server is created
    void UpdateArguments(grpc::ChannelArguments* channelArgs) override
    {
        std::cout << __func__ << ": Called before server is created, set channel args" << std::endl;
    }

    // Called before application callback for each synchronous server request
    void PreSynchronousRequest(grpc::ServerContext *context) override
    {
        std::cout << __func__ << " Called before application callback for each synchronous server request" << std::endl;
    }

    // Called after application callback for each synchronous server request
    void PostSynchronousRequest (grpc::ServerContext *context) override
    {
        std::cout << __func__ << " Called after application callback for each synchronous server request" << std::endl;
    }

    // Called before server is started
    void PreServerStart(grpc::Server* server)
    {
        std::cout << __func__ << " Called before server is started" << std::endl;
    }

    // Called after a server port is added
    void AddPort(grpc::Server* server, const std::string & addr, grpc::ServerCredentials * creds, int port) override
    {
        std::cout << __func__ << ": Called after a server port is added" << addr << std::endl;
    }
};

void handleAsyncRpcs(Calculation::CalculateAsyncService::AsyncService *service, grpc::ServerCompletionQueue *cq)
{
    void *tag;
    bool ok;
    CallData *callDate = new CallData(service, cq);
    while (1)
    {
        cq->Next(&tag, &ok);
        if (ok)
        {
            if(static_cast<CallData *>(tag)->isFinished())
            {
                delete callDate;
                callDate = new CallData(service, cq);
            }
            else
            {
                static_cast<CallData *>(tag)->proceed();
            }
        }
        else
        {
            std::cout <<"cq is not ok"<<std::endl;
        }
        
    }
}

void RunServer()
{
    std::string server_address("0.0.0.0:50051");

    CalculateServiceImpl calcSyncService;

    Calculation::CalculateAsyncService::AsyncService calcAsyncService;

    std::unique_ptr<grpc::ServerCompletionQueue> cq;

    std::cout <<"grpc version:"<< grpc::Version() << std::endl;
    
    grpc::EnableDefaultHealthCheckService(true);
    
    grpc::reflection::ProtoServerReflectionPlugin();

    grpc::ServerBuilder builder;

    grpc::Server::SetGlobalCallbacks(new ServerGlobalCallback);

    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());


#if USE_CUSTOM_HEALTH_CHECK
    HealthCheckServiceImpl health_check_service_impl_;
    // for client check and watch 
    builder.RegisterService(&health_check_service_impl_);

    // for server health check
    grpc::EnableDefaultHealthCheckService(false);
    std::unique_ptr<grpc::HealthCheckServiceInterface> override_default_health_check_service(new CustomHealthCheckService(&health_check_service_impl_));
    std::unique_ptr<grpc::ServerBuilderOption> option(new grpc::HealthCheckServiceServerBuilderOption(std::move(override_default_health_check_service)));
    builder.SetOption(std::move(option));
#endif

    builder.RegisterService(&calcSyncService);
    
    builder.RegisterService(&calcAsyncService);

    cq = builder.AddCompletionQueue();

    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());


#if USE_CUSTOM_HEALTH_CHECK
    grpc::HealthCheckServiceInterface* healthService = server->GetHealthCheckService();
    std::cout << "enable calcSyncService" << std::endl;
    healthService->SetServingStatus("calcSyncService", true);
    //healthService->Shutdown();
#endif
    

    std::thread t{handleAsyncRpcs, &calcAsyncService, cq.get()};

    std::cout << "Server listening on " << server_address << std::endl;



    server->Wait();
    t.join();

    server->Shutdown();
    cq->Shutdown();
}

int main(int argc, char const *argv[])
{
    RunServer();
    
    return 0;
}
