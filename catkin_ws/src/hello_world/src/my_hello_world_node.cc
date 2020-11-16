#include "ros/ros.h"

int main(int argc, char* argv[])
{
    ros::init(argc, argv, "hello_node");
    ros::NodeHandle n;

    ROS_INFO_STREAM("hello world!");
    return 0;
}
