#include "topic_example/topic_example_listener.h"

void chatterCallback(const topic_example::Num::ConstPtr& msg)
{
    ROS_INFO("I heard: [%ld]", msg->num);
}