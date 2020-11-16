#include "ros/ros.h"
#include "std_msgs/String.h"
#include "topic_example/Num.h"

#include <string>

int main(int argc, char* argv[])
{
    ros::init(argc, argv, "talker");
    ros::NodeHandle n;

    ros::Publisher chatterPublisher = n.advertise<topic_example::Num>("chatter", 1000);
    ros::Rate loop_rate(10);

    topic_example::Num msg;
    while(ros::ok())
    {
        ROS_INFO("send num :%ld", msg.num);
        chatterPublisher.publish(msg);
        ros::spinOnce();
        loop_rate.sleep();
        ++msg.num;
    }
    return 0;
}