#ifndef _ADDRESSBOOKSERVICE_H_
#define _ADDRESSBOOKSERVICE_H_

#include <google/protobuf/service.h>
#include "addressbook.pb.h"

class AddressBookServiceImpl: public tutorial::AddressBookService
{
private:
    google::protobuf::RpcController* mController;
private:
    void Done();
public:
    AddressBookServiceImpl(google::protobuf::RpcController* controller);
    ~AddressBookServiceImpl();
    virtual void store(google::protobuf::RpcController* controller, const tutorial::AddressBook* addressBook, google::protobuf::Empty* empty, google::protobuf::Closure* done) override;
    virtual void load(google::protobuf::RpcController* controller, const google::protobuf::Empty* empty, tutorial::AddressBook* addressBook, google::protobuf::Closure* done) override;

};

#endif