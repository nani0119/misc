#include "AddressBookService.h"
#include <iostream>
#include <fstream>
#include <ios>

AddressBookServiceImpl::AddressBookServiceImpl(google::protobuf::RpcController *controller) : mController(controller)
{
}

AddressBookServiceImpl::~AddressBookServiceImpl()
{
}

void AddressBookServiceImpl::store(google::protobuf::RpcController *controller, const tutorial::AddressBook *addressBook, google::protobuf::Empty *empty, google::protobuf::Closure* done)
{
    tutorial::AddressBook addressBookDB;

    std::fstream input("addressbook.pb", std::ios::in | std::ios::binary);
    if (!input) 
    {
      std::cout << "addressbook.pb: File not found.  Creating a new file." << std::endl;
    } 
    else if (!addressBookDB.ParseFromIstream(&input)) 
    {
      std::cerr << "Failed to parse address book." << std::endl;
    }

    addressBookDB.MergeFrom(*addressBook);

    std::fstream output("addressbook.pb", std::ios::out | std::ios::trunc | std::ios::binary);
    if (!addressBookDB.SerializeToOstream(&output)) {
      std::cerr << "Failed to write address book." << std::endl;
    }
    
    done->Run();
}

void AddressBookServiceImpl::load(google::protobuf::RpcController *controller, const google::protobuf::Empty *empty, tutorial::AddressBook *addressBook, google::protobuf::Closure* done)
{
    tutorial::AddressBook addressBookDB;

    std::fstream input("addressbook.pb", std::ios::in | std::ios::binary);
    if (!input) 
    {
      std::cout << "addressbook.pb: File not found.  Creating a new file." << std::endl;
    } 
    else if (!addressBookDB.ParseFromIstream(&input)) 
    {
      std::cerr << "Failed to parse address book." << std::endl;
    }
    addressBook->CopyFrom(addressBookDB);

    done->Run();
}

void AddressBookServiceImpl::Done()
{
    std::cout << "AddressBookServiceImpl:have already done" << std::endl;
}