#include <ros/ros.h>
#include <geometry_msgs/Pose.h>
#include <tf2/LinearMath/Quaternion.h>
#include <tf2_ros/transform_listener.h>
#include <geometry_msgs/TransformStamped.h>
#include <tf2_geometry_msgs/tf2_geometry_msgs.h>

#include "learning_tf2/Pose.h"

void tf2PoseCallback(const learning_tf2::Pose& pose)
{
    static tf2_ros::Buffer tfBuffer;
    static tf2_ros::TransformListener tfListener(tfBuffer);
    geometry_msgs::TransformStamped transformStamped;
    try{
        transformStamped = tfBuffer.lookupTransform("leaning_tf2_node1_sub1", "leaning_tf2_node2", ros::Time(0));

        ROS_INFO("learning_tf2_listener:        transformStamped: %s--->%s: [position: (%f %f %f)  orientation: (%f %f %f %f)]", transformStamped.header.frame_id.c_str(), transformStamped.child_frame_id.c_str(),
            transformStamped.transform.translation.x, transformStamped.transform.translation.y, transformStamped.transform.translation.z,
            transformStamped.transform.rotation.x, transformStamped.transform.rotation.y, transformStamped.transform.rotation.z, transformStamped.transform.rotation.w);

        geometry_msgs::PoseStamped tmpPose;
        geometry_msgs::PoseStamped p;
        tmpPose.pose.position = pose.Msg.position; 
        tmpPose.pose.orientation = pose.Msg.orientation;
        tmpPose.header.frame_id = "leaning_tf2_node2";

        p = tfBuffer.transform(tmpPose, std::string("leaning_tf2_node1"));

        ROS_INFO("learning_tf2_listener:        from leaning_tf2_node2 to leaning_tf2_node1:[(%f %f %f) (%f %f %f %f)]", p.pose.position.x, p.pose.position.y ,p.pose.position.z,
            p.pose.orientation.x, p.pose.orientation.y, p.pose.orientation.z, p.pose.orientation.w);
    }
    catch (tf2::TransformException &ex) {
      ROS_WARN("%s",ex.what());
      ros::Duration(1.0).sleep();
    }
}

int main(int argc, char *argv[])
{
    ros::init(argc, argv, "learning_tf2_listener");
    ros::NodeHandle n;
    
    //ros::service::waitForService("learning_tf2_broadcaster");
    //ros::service::waitForService("learning_tf2_pose");
    ros::Subscriber poseSubscriber = n.subscribe("pose", 1000, tf2PoseCallback);

    ros::spin();

    return 0;
}
