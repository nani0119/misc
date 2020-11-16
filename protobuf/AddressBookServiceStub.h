#ifndef _ADDRESSBOOKSERVICESTUB_H_
#define _ADDRESSBOOKSERVICESTUB_H_

#include <google/protobuf/service.h>
#include "addressbook.pb.h"

class AddressBookServiceStub
{
private:
    google::protobuf::RpcChannel* mChannel;
    google::protobuf::RpcController* mController;
    tutorial::AddressBookService::Stub *mService;
    google::protobuf::Empty mEmpty;
private:
    void storeDone();
    void loadDone();
public:
    AddressBookServiceStub(google::protobuf::RpcChannel* channel, google::protobuf::RpcController* controller);
    ~AddressBookServiceStub();
    void store(tutorial::AddressBook& addressBook);
    tutorial::AddressBook load();
};

#endif