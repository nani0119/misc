#ifndef __CALC_ASYNC_SERVER_H_
#define __CALC_ASYNC_SERVER_H_
#include <iostream>
#include <memory>
#include <string>
#include <chrono>
#include <thread>

#include <grpcpp/grpcpp.h>

#include "calc_add.pb.h"
#include "calc_add.grpc.pb.h"

class CallData
{
private:
    Calculation::CalculateAsyncService::AsyncService* service_;
    grpc::ServerCompletionQueue* cq_;
    grpc::ServerContext ctx_;
    grpc::ServerAsyncResponseWriter<Calculation::Num> responder_;
    Calculation::Num request_;
    Calculation::Num reply_;
    bool finished;
public:
    CallData(Calculation::CalculateAsyncService::AsyncService* service, grpc::ServerCompletionQueue* cq)
        : service_(service), cq_(cq), responder_(&ctx_), finished(false)
    {
        service_->RequestgetPlusOne(&ctx_, &request_, &responder_, cq_, cq_, this);
    }

    void proceed()
    {
        std::cout << "calcuate:" << request_.num(0) << " + " << 1 << " = ?" << std::endl;
        std::cout << "I am thinking... ..." << std::endl;
        reply_.add_num(request_.num(0) + 1);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        responder_.Finish(reply_, grpc::Status::OK, this);
        std::cout << "oooh! it is " << request_.num(0) + 1 << std::endl;
        finished = true;
    }

    bool isFinished()
    {
        return finished;
    }
};

#endif