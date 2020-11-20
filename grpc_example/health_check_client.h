#ifndef _HEALTH_CHECK_H_
#define _HEALTH_CHECK_H_

#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>

#include "health.pb.h"
#include "health.grpc.pb.h"

using grpc::health::v1::HealthCheckRequest;
using grpc::health::v1::HealthCheckResponse;
using grpc::health::v1::Health;

class HealthCheck
{
private:
    std::unique_ptr<Health::Stub> stub_;
public:
    HealthCheck(std::shared_ptr<grpc::Channel> channel): stub_(Health::NewStub(channel))
    {

    }
    ~HealthCheck()
    {

    }

    bool check(std::string service_name)
    {
        grpc::ClientContext context;
        HealthCheckResponse response;
        HealthCheckRequest request;

        request.set_service(service_name);
        grpc::Status status = stub_->Check(&context, request, &response);
        if(status.ok())
        {
            if(response.status() == HealthCheckResponse::SERVING)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        else
        {
            std::cout << "rpc error:" << status.error_message() << std::endl;
            return false;
        }
    }

};

#endif