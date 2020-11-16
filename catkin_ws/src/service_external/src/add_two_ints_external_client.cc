#include "ros/ros.h"
#include "service_example/AddTwoInts.h"

#include <string.h>
#include <random>
#include <ctime>

bool sendRequest(ros::ServiceClient& client, service_example::AddTwoInts& srv)
{
}

int main(int argc, char *argv[])
{
    ros::init(argc, argv, "add_two_ints_external_client");
    ros::NodeHandle n;
    ros::ServiceClient client = n.serviceClient<service_example::AddTwoInts>("add_two_ints");
    service_example::AddTwoInts srv;

    static std::default_random_engine e(time(0));
    static std::uniform_int_distribution<unsigned> u(0, 10);
    
    ros::Rate loop_rate(1);
    while(ros::ok())
    {
        srv.request.a = u(e);
        srv.request.b = u(e);
        if (client.call(srv))
        {
            ROS_INFO("Sum: %ld", (long int)srv.response.sum);
        }
        else
        {
            ROS_ERROR("Failed to call service add_two_ints");
        }
        ros::spinOnce();
        loop_rate.sleep();
    }

    return 0;
}
