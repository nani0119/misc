#include "ros/ros.h"
#include "action_example/DoDishesAction.h"
#include <actionlib/client/simple_action_client.h>

typedef actionlib::SimpleActionClient<action_example::DoDishesAction> Client;

// 当action完成后会调用该回调函数一次
void doneCb(const actionlib::SimpleClientGoalState& state, const action_example::DoDishesResultConstPtr& result)
{
    ROS_INFO("Yay! The dishes are now clean");
    ROS_INFO("state:%s", state.getText().c_str());
    ROS_INFO("result:%d", result->total_dishes_cleaned);
    ros::shutdown();
}

// 当action激活后会调用该回调函数一次
void activeCb()
{
    ROS_INFO("Goal just went active");
}

// 收到feedback后调用该回调函数
void feedbackCb(const action_example::DoDishesFeedbackConstPtr& feedback)
{
    ROS_INFO("percent_complete : %f ", feedback->percent_complete);
}

int main(int argc, char* argv[])
{
    ros::init(argc, argv, "do_dishes_client");

    Client client("do_dishes", true);
    ROS_INFO("Waiting for action server to start.");
    client.waitForServer();
    ROS_INFO("Action server started, sending goal.");
    
    action_example::DoDishesGoal goal;
    goal.dishwasher_id = 1;

    client.sendGoal(goal, doneCb, activeCb, feedbackCb);

    ros::spin();

    return 0;
}