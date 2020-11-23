#ifndef _CUSTOM_HEALTH_CHECK_SERVER_H_
#define _CUSTOM_HEALTH_CHECK_SERVER_H_

#include <grpcpp/server_context.h>
#include <grpcpp/support/status.h>
#include <grpcpp/grpcpp.h>


#include "health.grpc.pb.h"
#include "health.pb.h"

using grpc::health::v1::HealthCheckRequest;
using grpc::health::v1::HealthCheckResponse;
using grpc::health::v1::Health;

class HealthCheckServiceImpl: public Health::Service
{
private:
    std::mutex mu_;
    bool shutdown_ = false;
    std::map<const std::string, HealthCheckResponse::ServingStatus> status_map_;
public:
    grpc::Status Check(grpc::ServerContext* context, const HealthCheckRequest* request, HealthCheckResponse* response) override
    {
        std::lock_guard<std::mutex> lock(mu_);
        auto iter = status_map_.find(request->service());
        if (iter == status_map_.end())
        {
            return grpc::Status(grpc::StatusCode::NOT_FOUND, "");
        }
        response->set_status(iter->second);
        return grpc::Status::OK;
    }

    grpc::Status Watch(grpc::ServerContext* context, const HealthCheckRequest* request, grpc::ServerWriter<HealthCheckResponse>* writer) override
    {
        auto last_state = HealthCheckResponse::UNKNOWN;
        while (!context->IsCancelled())
        {
            {
                std::lock_guard<std::mutex> lock(mu_);
                HealthCheckResponse response;
                auto iter = status_map_.find(request->service());
                if (iter == status_map_.end())
                {
                    response.set_status(response.SERVICE_UNKNOWN);
                }
                else
                {
                    response.set_status(iter->second);
                }
                if (response.status() != last_state)
                {
                    writer->Write(response, grpc::WriteOptions());
                    last_state = response.status();
                }
            }
            gpr_sleep_until(gpr_time_add(gpr_now(GPR_CLOCK_MONOTONIC),
                                         gpr_time_from_millis(1000, GPR_TIMESPAN)));
        }
        return grpc::Status::OK;
    }

    void SetStatus(const std::string& service_name, HealthCheckResponse::ServingStatus status)
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (shutdown_)
        {
            status = HealthCheckResponse::NOT_SERVING;
        }
        status_map_[service_name] = status;
    }

    void SetAll(HealthCheckResponse::ServingStatus status)
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (shutdown_)
        {
            return;
        }
        for (auto iter = status_map_.begin(); iter != status_map_.end(); ++iter)
        {
            iter->second = status;
        }
    }

    void Shutdown()
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (shutdown_)
        {
            return;
        }
        shutdown_ = true;
        for (auto iter = status_map_.begin(); iter != status_map_.end(); ++iter)
        {
            iter->second = HealthCheckResponse::NOT_SERVING;
        }
    }  
};

class CustomHealthCheckService : public grpc::HealthCheckServiceInterface
{
public:
    explicit CustomHealthCheckService(HealthCheckServiceImpl *impl) : impl_(impl)
    {
        impl_->SetStatus("", HealthCheckResponse::SERVING);
    }
    void SetServingStatus(const std::string &service_name, bool serving) override
    {
        std::cout << __func__ << ": " << service_name << "set to " << (serving ? "enable": "disable") << std::endl;
        impl_->SetStatus(service_name, serving ? HealthCheckResponse::SERVING
                                               : HealthCheckResponse::NOT_SERVING);
    }

    void SetServingStatus(bool serving) override
    {
        impl_->SetAll(serving ? HealthCheckResponse::SERVING
                              : HealthCheckResponse::NOT_SERVING);
    }

    void Shutdown() override { impl_->Shutdown(); }

private:
    HealthCheckServiceImpl *impl_; // not owned
};


#endif