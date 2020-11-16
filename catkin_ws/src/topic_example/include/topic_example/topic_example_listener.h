#ifndef TOPIC_EXAMPLE_LISTENER_H
#define TOPIC_EXAMPLE_LISTENER_H
#include "ros/ros.h"
#include "topic_example/Num.h"

extern "C" void chatterCallback(const topic_example::Num::ConstPtr& msg);
#endif