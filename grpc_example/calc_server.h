#ifndef _CALC_SERVER_H
#define _CALC_SERVER_H

#include <iostream>
#include <memory>
#include <string>
#include <random>

#include <grpcpp/grpcpp.h>

#include "calc_add.pb.h"
#include "calc_add.grpc.pb.h"

class CalculateServiceImpl:public Calculation::CalculateService::Service
{
    grpc::Status addTwoInts(::grpc::ServerContext* context, const ::Calculation::Addend* request, ::Calculation::Sum* response) override
    {
        response->set_num(request->add1() + request->add2());
        return  grpc::Status::OK;
    }

    grpc::Status addTotal(grpc::ServerContext* context, grpc::ServerReader<Calculation::Num>* reader, Calculation::Sum* response)
    {
        Calculation::Num num;
        int result = 0;
        while(reader->Read(&num))
        {
            auto n = num.num();
            for(auto it = n.begin(); it != n.end(); ++it)
            {
                result += *it;
            }  
        }
        response->set_num(result);
        return grpc::Status::OK;
    }

    grpc::Status getRamdomTotal(grpc::ServerContext* context, const google::protobuf::Empty* request, grpc::ServerWriter< ::Calculation::Num>* writer) override
    {
        std::default_random_engine e(1);
        std::uniform_int_distribution<int> u(0, 9);
        Calculation::Num num;
        for(int i = 0; i < 5; i++)
        {
            num.mutable_num()->Add(u(e));
            num.mutable_num()->Add(u(e));
            writer->Write(num);
            num.clear_num();
        }
        return grpc::Status::OK;
    }

    grpc::Status exchangeRamdomTotal(grpc::ServerContext* context, grpc::ServerReaderWriter<Calculation::Num, Calculation::Num>* stream) override
    {
        Calculation::Num readerNum;
        Calculation::Num writerNum;
        while(stream->Read(&readerNum))
        {
            for(auto it = readerNum.num().begin(); it != readerNum.num().end(); ++it)
            {
                writerNum.mutable_num()->Add(*it);
            }
            stream->Write(writerNum);
            writerNum.clear_num();
        }
        return grpc::Status::OK;
    }
};

#endif