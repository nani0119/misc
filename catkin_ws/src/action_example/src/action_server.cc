#include "ros/ros.h"
#include "action_example/DoDishesAction.h"
#include <actionlib/server/simple_action_server.h>


typedef actionlib::SimpleActionServer<action_example::DoDishesAction> Server;

void execute(const action_example::DoDishesGoalConstPtr& goal, Server* as)
{
    ros::Rate rate(1);
    action_example::DoDishesFeedback feedback;
    action_example::DoDishesResult result;
    ROS_INFO("Dishwasher %d is working.", goal->dishwasher_id);

    for(int i = 0; i <=10; i++)
    {
        feedback.percent_complete = i *10;
        as->publishFeedback(feedback);
        result.total_dishes_cleaned =i;
        rate.sleep();
    }

    ROS_INFO("Dishwasher %d finish working.", goal->dishwasher_id);
    as->setSucceeded(result,"ok");
} 

int main(int argc, char* argv[])
{
    ros::init(argc, argv, "do_dishes_server");
    ros::NodeHandle n;

    Server server(n, "do_dishes", std::bind(execute, std::placeholders::_1, &server), false);
    server.start();
    ros::spin();

    return 0;
}