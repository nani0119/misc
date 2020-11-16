#ifndef SERVICE_EXAMPLE_ADD_INTS_H
#define SERVICE_EXAMPLE_ADD_INTS_H
#include "ros/ros.h"
#include "service_example/AddTwoInts.h"

bool add(service_example::AddTwoInts::Request& req, service_example::AddTwoInts::Response& res)
{
    res.sum = req.a + req.b;
    ROS_INFO("request: x=%ld, y=%ld", (long int)req.a, (long int)req.b);
    ROS_INFO("sending back response: [%ld]", (long int)res.sum);
    return true;
}

#endif