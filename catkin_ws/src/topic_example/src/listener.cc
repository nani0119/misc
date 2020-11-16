#include "ros/ros.h"
#include "std_msgs/String.h"
#include "topic_example/Num.h"
#include "topic_example/topic_example_listener.h"


int main(int argc, char *argv[])
{
    ros::init(argc, argv, "listener");
    ros::NodeHandle n;

    ros::Subscriber chatterSubscriber = n.subscribe("chatter", 1000, chatterCallback);

    ros::spin();

    return 0;
}
