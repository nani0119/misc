#include "usbdevice.h"
#include <iostream>
#include <iomanip>
#include <thread>
#include <stdio.h>
#include <string.h>
#include <string>
using namespace std;


void run(USBDevice* dev)
{
    libusb_device_handle* handle = nullptr;
    libusb_device* device = nullptr;
    unsigned char sendBuff[256] = {0};
    unsigned char recvBuff[256] = {0};
    unsigned char ctlData[] = {0x01,0x02, 0x03};

    int dataLen;
    int transferred;
    int activeConfig;
    unsigned char buff[256] = {0};
    
    int selectConfig;
    int interface;
    int altSetting;
    uint8_t ep_in_addr;
    uint8_t ep_out_addr;
    int ret;
    int i = 0;
    while(1)
    {
begin:
        while(!dev->isDevicePresent())
        {}
        dev->printDevice();
        handle = dev->getUsbDeviceHandle();
        device = dev->getUsbDevice();
        


        // set config
        struct libusb_device_descriptor desc;
        libusb_get_device_descriptor (device, &desc);
        cout << "===========================================" << endl;
        cout << "config\t\tname"<<endl;
        struct libusb_config_descriptor* config;
        for(int i = 0; i < desc.bNumConfigurations; i++)
        {
            ret = libusb_get_config_descriptor(device, i, &config);
            libusb_get_string_descriptor_ascii(handle, config->iConfiguration, buff, sizeof(buff));
            cout <<(int) config->bConfigurationValue << "\t\t" << buff << endl;
            libusb_free_config_descriptor(config);
        }

        libusb_get_configuration(handle, &activeConfig);
        cout << "===========================================" << endl;
        cout << "current active configuration:" << activeConfig << endl;
        
        if (desc.bNumConfigurations > 1)
        {
            cout << "===========================================" << endl;
            cout << "select your config:";
            cin >> selectConfig;
            cout << endl;

            cout << "set active configuration :" << selectConfig << endl;

            ret = libusb_set_configuration(handle, selectConfig);
            if (ret)
            {
                cout << "config fail:" << libusb_error_name(ret) << endl;
                goto begin;
            }
        }
        else
        {
            selectConfig = activeConfig;
        }
        
        // set interface 
        cout << "===========================================" << endl;
        libusb_get_active_config_descriptor(device, &config);
        cout << "interface\taltsetting\tname"<<endl;
        for (int i = 0; i < config->bNumInterfaces; i++)
        {
            const struct libusb_interface *interface = &config->interface[i];

            for (int j = 0; j < interface->num_altsetting; j++)
            {
                const struct libusb_interface_descriptor *interfaceDesc = &interface->altsetting[j];
                memset(buff, 0 ,256);
                libusb_get_string_descriptor_ascii(handle, interfaceDesc->iInterface, buff, sizeof(buff));
                cout << (int)interfaceDesc->bInterfaceNumber <<"\t\t" << (int)interfaceDesc->bAlternateSetting << "\t\t" << buff << endl;
            }
        }
        

        cout << "select your interface:";
        cin >> interface;
        cout << endl;
        cout << "claim interface:"<<interface << endl;
        ret = libusb_claim_interface(handle, interface);
        if(ret == 0)
        {
            //cout << "claim interface success" << endl;
        }
        else
        {
            cout << "claim interface fail:" <<libusb_error_name(ret)<< endl;
            goto begin;
        }
    
        cout << "select your interface alt setting:";
        cin >> altSetting;
        cout << endl;
        cout << "seletc interface altsetting:"<<altSetting << endl;
        ret = libusb_set_interface_alt_setting(handle, interface, altSetting);
        if(ret)
        {
            cout << "set alt setting fail:"<<libusb_error_name(ret) << endl;
            goto begin;
        }

        for(int i = 0; i < config->bNumInterfaces ;i++)
        {
            const struct libusb_interface *intf = &config->interface[i];
            for (int j = 0; j < intf->num_altsetting; j++)
            {
                const struct libusb_interface_descriptor *intfDesc = &intf->altsetting[j];
		        if(intfDesc->bAlternateSetting == altSetting && intfDesc->bInterfaceNumber == interface)
                {
                    for(int k = 0; k < intfDesc->bNumEndpoints; ++k)
                    {
                        const struct libusb_endpoint_descriptor *endpoint = &intfDesc->endpoint[k];
                        if(endpoint->bEndpointAddress & 0x80)
                        {
                            ep_in_addr = endpoint->bEndpointAddress;
                        }
                        else
                        {
                            ep_out_addr = endpoint->bEndpointAddress;
                        }
                        
                    }
                }
    
            }
        }
        libusb_free_config_descriptor(config);
        cout << "===========================================" << endl;
        //cout << "endpoint out:" << left << hex << showbase << setfill('0') << setw(4) << ep_out_addr << endl;
        //cout << "endpoint  in:" << left << hex << showbase << setfill('0') << setw(4) << ep_in_addr << endl;
        //cout << dec << noshowbase;
        printf("endpoint out: 0x%02xh\n", ep_out_addr);
        printf("endpoint in : 0x%02xh\n", ep_in_addr);
        cout << "===========================================" << endl;
        cout << "transfer data, 'q' for exit" << endl;
        
        memset(sendBuff, 0, 256);
        cin >> sendBuff;
        while(sendBuff[0] != 'q')
        {
            dataLen = strlen((const char*)sendBuff);
            ret = libusb_bulk_transfer(handle, ep_out_addr, sendBuff, dataLen, &transferred, 0);
            if(ret)
            {
                cout <<"send fail:" <<libusb_error_name(ret) << endl;
            }
            cout << "send data size:" << transferred << endl;
            memset(sendBuff, 0, 256);
            cout << "recv data:";
            ret = libusb_bulk_transfer(handle, ep_in_addr, recvBuff, sizeof(recvBuff), &transferred, 0);
            if(ret)
            {
                cout << "recv fail:"<<libusb_error_name(ret) << endl;
            }
            else
            {
                cout << recvBuff << endl;
                memset(recvBuff, 0, 256);
            }
            cin >> sendBuff;
        }
        cout << "release interface:" << interface << endl;
        libusb_release_interface(handle, interface);

        //while(dev->isDevicePresent())
        //{}

        libusb_control_transfer(handle, LIBUSB_REQUEST_TYPE_VENDOR|LIBUSB_RECIPIENT_INTERFACE|LIBUSB_ENDPOINT_OUT,
			                                	0x00, 0x00, 0x00, ctlData, 0x03, 0); 		
    }
}


int main(int argc, char const *argv[])
{
    USBDevice usbDevice(0x18d1, 0x2d08);
    thread t{run, &usbDevice};
    t.join();
    return 0;
}
