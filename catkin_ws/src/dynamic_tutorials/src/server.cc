#include "ros/ros.h"

#include <dynamic_reconfigure/server.h>
#include "dynamic_tutorials/TutorialsConfig.h"

void callback(dynamic_tutorials::TutorialsConfig& config, uint32_t level)
{
    ROS_INFO("\nReconfigure Request:\nint_param:%d\ndouble_param:%f\nstr_param:%s\nbool_param:%s\nenum:%d\n",
                            config.int_param, 
                            config.double_param, 
                            config.str_param.c_str(), 
                            config.bool_param?"True":"False", 
                            config.size          
    );
}


int main(int argc, char *argv[])
{
    ros::init(argc, argv, "dynamic_tutorials");
    dynamic_reconfigure::Server<dynamic_tutorials::TutorialsConfig> server;
    dynamic_reconfigure::Server<dynamic_tutorials::TutorialsConfig>::CallbackType f;

    server.setCallback(callback);
    ROS_INFO("Spinning node");
    ros::spin();
    return 0;
}
