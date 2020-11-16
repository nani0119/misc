#include "ros/ros.h"
#include "service_example/AddTwoInts.h"

#include <string.h>
#include <random>
#include <ctime>

bool sendRequest(ros::ServiceClient& client, service_example::AddTwoInts& srv)
{
    if(client.call(srv))
    {
        ROS_INFO("Sum: %ld", (long int)srv.response.sum);
        return true;
    }
    else
    {
        ROS_ERROR("Failed to call service add_two_ints");
        return false;
    }
}

int main(int argc, char *argv[])
{
    ros::init(argc, argv, "add_two_ints_client");
    ros::NodeHandle n;
    ros::ServiceClient client = n.serviceClient<service_example::AddTwoInts>("add_two_ints");
    service_example::AddTwoInts srv;
    
    if(argc == 3)
    {
        ROS_INFO("get a and from cmdline param");
        srv.request.a = atoll(argv[1]);
        srv.request.b = atoll(argv[2]);
        sendRequest(client, srv);
    }

    //私有命名空间
    ros::NodeHandle pn("~");
    std::string a;
    std::string b;
    pn.param<std::string>("a", a, "NULL");
    pn.param<std::string>("b", b, "NULL");
    if(a == "NULL" || b == "NULL")
    {
        ROS_INFO("not set param in roslaunch");
    }
    else
    {
        ROS_INFO("get param from roslaunch");
        srv.request.a = std::stol(a);
        srv.request.b = std::stol(b);
        sendRequest(client, srv);
    }
    
    static std::default_random_engine e(time(0));
    static std::uniform_int_distribution<unsigned> u(0, 10);
    int rate = 0;
    pn.param<int>("rate", rate, 10);
    ros::Rate loop_rate(rate);
    while(ros::ok())
    {
        srv.request.a = u(e);
        srv.request.b = u(e);
        sendRequest(client, srv);
        ros::spinOnce();
        loop_rate.sleep();
    }



    return 0;
}
