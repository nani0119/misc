#include "AddressBookServiceStub.h"
#include <iostream>


AddressBookServiceStub::AddressBookServiceStub(google::protobuf::RpcChannel *channel, google::protobuf::RpcController *controller): mChannel(channel), mController(controller)
{
    mService = new tutorial::AddressBookService::Stub(mChannel);
}

AddressBookServiceStub::~AddressBookServiceStub() {
    delete mService;
}


void AddressBookServiceStub::store(tutorial::AddressBook &addressBook)
{
    mService->store(mController, &addressBook, &mEmpty, google::protobuf::NewCallback(this, &AddressBookServiceStub::storeDone));
}

tutorial::AddressBook AddressBookServiceStub::load()
{

    tutorial::AddressBook response;
    mService->load(mController, &mEmpty, &response, google::protobuf::NewCallback(this, &AddressBookServiceStub::loadDone));

    return response;
}


void AddressBookServiceStub::storeDone()
{
    std::cout << "AddressBookServiceStub::"<<__func__<<" called" << std::endl;
}

void AddressBookServiceStub::loadDone()
{
    std::cout << "AddressBookServiceStub::"<<__func__<<" called" << std::endl;;
}
    