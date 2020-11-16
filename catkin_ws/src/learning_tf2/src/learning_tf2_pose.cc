#include <ros/ros.h>
#include <geometry_msgs/Pose.h>
#include <tf2/LinearMath/Quaternion.h>

#include "learning_tf2/Pose.h"

int main(int argc, char* argv[])
{
    ros::init(argc, argv, "learning_tf2_pose");
    ros::NodeHandle n;

    ros::Publisher posePublisher = n.advertise<learning_tf2::Pose>("pose", 1000);
    ros::Rate loop_rate(1);

    tf2::Quaternion q;
    q.setRPY(0,0,0);

    learning_tf2::Pose pose;
    pose.Msg.position.x = 1;
    pose.Msg.position.y = 0;
    pose.Msg.position.z = 0;

    pose.Msg.orientation.x = q.x();
    pose.Msg.orientation.y = q.y();
    pose.Msg.orientation.z = q.z();
    pose.Msg.orientation.w = q.w();

    while(ros::ok())
    {
        ROS_INFO("learning_tf2_pose:            Publis pose: [position: (%f %f %f)  orientation: (%f %f %f %f)]", pose.Msg.position.x, pose.Msg.position.y, pose.Msg.position.z,
        pose.Msg.orientation.x, pose.Msg.orientation.y, pose.Msg.orientation.z, pose.Msg.orientation.w);
        posePublisher.publish(pose);
        ros::spinOnce();
        loop_rate.sleep();
    }
    return 0;
}
