#include "ros/ros.h"
#include "service_example/AddTwoInts.h"
#include "service_example/service_example_add_ints.h"

int main(int argc, char*argv[])
{
    ros::init(argc, argv, "add_two_ints_server");
    ros::NodeHandle n;

    ros::ServiceServer service = n.advertiseService("add_two_ints", add);
    ROS_INFO("Ready to add two ints.");
    ros::spin();
    
    return 0;
}
