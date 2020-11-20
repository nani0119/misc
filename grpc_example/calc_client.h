#ifndef _CALC_CLIENT_H_
#define _CALC_CLIENT_H_

#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <random>
#include <thread>
#include <chrono>
#include <ctime>

#include <grpcpp/grpcpp.h>


#include "calc_add.pb.h"
#include "calc_add.grpc.pb.h"

class CalculateClient
{
private:
    std::unique_ptr<Calculation::CalculateService::Stub> stub_;
    class ContextCallback: public grpc::ClientContext::GlobalCallbacks
    {
        virtual void DefaultConstructor (grpc::ClientContext *context)
        {
            std::cout << "context create:" << context << std::endl;
        }
 
        virtual void Destructor (grpc::ClientContext *context)
        {
            std::cout << "context destructor:" << context << std::endl;
        }
    };
    ContextCallback* ccb;
public:
    CalculateClient(std::shared_ptr<grpc::Channel> channel):stub_(Calculation::CalculateService::NewStub(channel)), ccb(new ContextCallback)
    {
        grpc::ClientContext::SetGlobalCallbacks(ccb);
    }

    ~CalculateClient()
    {
        delete ccb;
    }

    int addTwoInts(int a, int b)
    {
        grpc::ClientContext context;
        grpc::Status status;
        Calculation::Sum sum;
        Calculation::Addend addend;

        char bytes[8] = {'\0', '\1', '\2', '\3',
                     '\4', '\5', '\6', '\7'};

        addend.set_add1(a);
        addend.set_add2(b);

        context.set_wait_for_ready(true);
        context.AddMetadata("func_name", "addTwoInts");
        context.AddMetadata("custom-header", "Custom Value");
        context.AddMetadata("custom-bin", std::string(bytes, 8));

        
        std::chrono::system_clock::time_point deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(100);
        std::cout<< "set deadline:" << deadline.time_since_epoch().count() << std::endl;
        context.set_deadline(deadline);

        status = stub_->addTwoInts(&context, addend, &sum);

        std::cout << "peer():" << context.peer() << std::endl;
        
        if(status.ok())
        {
            std::cout << "Client received initial metadata from server: " << std::endl;
            auto serverInitContext = context.GetServerInitialMetadata();
            for(auto it = serverInitContext.begin(); it != serverInitContext.end(); ++it)
            {
                std::cout<<'\t'<< it->first << " = " << it->second << std::endl;
            }
            
            std::cout << "Client received trailing metadata from server: " << std::endl;
            auto serverTrailingContext = context.GetServerTrailingMetadata();
            for(auto it = serverTrailingContext.begin(); it != serverTrailingContext.end(); ++it)
            {
                std::cout<<'\t'<< it->first << " = " << it->second << std::endl;
            }
            std::cout << a << " + " << b  << " = " << sum.num() << std::endl;
            return sum.num();
        }
        else
        {
            std::cout << "calc error: " << status.error_code() << ":" << status.error_message() << std::endl;
            return 0;
        }
        
    }

    int addTotal(std::vector<int> v, int retry)
    {
        Calculation::Sum sum;
        Calculation::Num num;
        grpc::ClientContext context;
        grpc::Status status;
        std::unique_ptr<grpc::ClientWriter<Calculation::Num>> writer(stub_->addTotal(&context, &sum));

        while (retry--)
        {
            for (std::vector<int>::iterator it = v.begin(); it != v.end(); ++it)
            {
                auto n = num.mutable_num();
                n->Add(*it);
            }

            if (!writer->Write(num))
            {
                std::cout << __func__ << ":write error" << std::endl;
            }
            num.clear_num();
        }
        writer->WritesDone();
        status = writer->Finish();
        if(status.ok())
        {
            return sum.num();
        }
        else
        {
            std::cout <<__func__<< ":rpc failed." << std::endl;
        }
    }

    int getRandomTotal()
    {
        grpc::ClientContext context;
        grpc::Status status;
        google::protobuf::Empty request;
        Calculation::Num num;
        int result = 0;
        std::unique_ptr<grpc::ClientReader<Calculation::Num>> reader(stub_->getRamdomTotal(&context, request));
        while(reader->Read(&num))
        {
            
            for(auto it = num.num().begin(); it != num.num().end(); ++it)
            {
                result += *it;
            }
        }
        status = reader->Finish();
        if(status.ok())
        {
            return result;
        }
        else
        {
            std::cout <<__func__<< ":rpc failed." << std::endl;
            return 0;
        }
    }

    int exchangeRamdomTotal()
    {
        grpc::ClientContext context;
        Calculation::Num readerNum;

        std::default_random_engine e(1);
        std::uniform_int_distribution<int> u(0, 9);

        int result = 0;
        std::shared_ptr<grpc::ClientReaderWriter<Calculation::Num, Calculation::Num>> stream(stub_->exchangeRamdomTotal(&context));

        // thread
        std::thread writer(
            [&](){
                    Calculation::Num writerNum;
                    for(int i = 0; i < 5; i++)
                    {
                        writerNum.mutable_num()->Add(u(e));
                        writerNum.mutable_num()->Add(u(e));
                        stream->Write(writerNum);
                        writerNum.clear_num();
                    }
                    stream->WritesDone();
            }
        );



        while(stream->Read(&readerNum))
        {
            for(auto it = readerNum.num().begin(); it != readerNum.num().end(); ++it)
            {
                result += *it;
            }
        }
        writer.join();
        grpc::Status status = stream->Finish();

        if (status.ok()) 
        {
            return result;        
        }
        else
        {
            std::cout <<__func__<< ":rpc failed." << std::endl;
            return 0;
        }
        
    }

};


#endif