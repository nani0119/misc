#include <ros/ros.h>
#include <tf2/LinearMath/Quaternion.h>
#include <tf2_ros/transform_broadcaster.h>
#include <geometry_msgs/TransformStamped.h>

void transforBroadcaster(const ros::TimerEvent& timerEvent)
{
    ROS_INFO("learning_tf2_broadcaster:     send tf2 transformStamped info");
    static tf2_ros::TransformBroadcaster br;
    std::vector<geometry_msgs::TransformStamped> transformStampedVec;

    tf2::Quaternion q;
    q.setRPY(0,0,0);
    
    
    //word--->leaning_tf2_node1
    geometry_msgs::TransformStamped transformWN1;
    transformWN1.header.stamp = ros::Time::now();
    transformWN1.header.frame_id = "world";
    transformWN1.child_frame_id = "leaning_tf2_node1";
    transformWN1.transform.translation.x = 1.0;
    transformWN1.transform.translation.y = 0.0;
    transformWN1.transform.translation.z = 0.0;


    transformWN1.transform.rotation.x = q.x();
    transformWN1.transform.rotation.y = q.y();
    transformWN1.transform.rotation.z = q.z();
    transformWN1.transform.rotation.w = q.w();
    transformStampedVec.push_back(transformWN1);


    //word--->leaning_tf2_node2
    geometry_msgs::TransformStamped transformWN2;
    transformWN2.header.stamp = ros::Time::now();
    transformWN2.header.frame_id = "world";
    transformWN2.child_frame_id = "leaning_tf2_node2";
    transformWN2.transform.translation.x = 2.0;
    transformWN2.transform.translation.y = 0.0;
    transformWN2.transform.translation.z = 0.0;


    transformWN2.transform.rotation.x = q.x();
    transformWN2.transform.rotation.y = q.y();
    transformWN2.transform.rotation.z = q.z();
    transformWN2.transform.rotation.w = q.w();
    transformStampedVec.push_back(transformWN2);


    //leaning_tf2_node1--->leaning_tf2_node1_sub1
    geometry_msgs::TransformStamped transformNS;
    transformNS.header.stamp = ros::Time::now();
    transformNS.header.frame_id = "leaning_tf2_node1";
    transformNS.child_frame_id = "leaning_tf2_node1_sub1";
    transformNS.transform.translation.x = 1.0;
    transformNS.transform.translation.y = 0.0;
    transformNS.transform.translation.z = 0.0;


    transformNS.transform.rotation.x = q.x();
    transformNS.transform.rotation.y = q.y();
    transformNS.transform.rotation.z = q.z();
    transformNS.transform.rotation.w = q.w();
    transformStampedVec.push_back(transformNS);

    br.sendTransform(transformStampedVec);
}

int main(int argc, char *argv[])
{
    ros::init(argc, argv, "learning_tf2_broadcaster");
    ros::NodeHandle nh;

    ROS_INFO("==================create timer==================");
    ros::Timer timer = nh.createTimer(ros::Duration(1.0), transforBroadcaster);
    ros::spin();
    return 0;
}