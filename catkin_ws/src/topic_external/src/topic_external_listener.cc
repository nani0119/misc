#include "ros/ros.h"
#include "topic_example/Num.h"
#include "topic_example/topic_example_listener.h"

int main(int argc, char* argv[])
{
    ros::init(argc, argv, "topic_external_listener");
    ros::NodeHandle n;

    ros::Subscriber chatterSubscriber = n.subscribe("demo/chatter", 1000, chatterCallback);

    ros::spin();

    return 0;
}
