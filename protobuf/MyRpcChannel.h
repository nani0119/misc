#ifndef _MYRPCCHANNEL_H_
#define _MYRPCCHANNEL_H_
#include <google/protobuf/service.h>
#include <google/protobuf/descriptor.h>

#include <string>
#include <iostream>
#include "AddressBookService.h"

class MyRpcChannel:public google::protobuf::RpcChannel
{
private:
    std::string mChannelName;
public:
    MyRpcChannel(std::string name):mChannelName(name)
    {}

    void CallMethod(const google::protobuf::MethodDescriptor* method, google::protobuf::RpcController* controller, const google::protobuf::Message* request, google::protobuf::Message* response, google::protobuf::Closure* done)
    {
        std::cout << "MyRpcChannel::"<< method->name() << " called"<<std::endl;
        google::protobuf::Empty empty;
        AddressBookServiceImpl* service = new AddressBookServiceImpl(controller);
        service->CallMethod(method, controller, request, response, done);
        
        delete service;
    }
};


#endif