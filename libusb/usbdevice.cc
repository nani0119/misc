#include <stdio.h>
#include <string.h>
#include <iostream>
#include <iomanip>
#include "usbdevice.h"

using namespace std;

int USBDevice::usb_hotplug_callback(libusb_context* ctx, libusb_device* device, libusb_hotplug_event event, void* user_data)
{
    USBDevice* usbDevice = static_cast<USBDevice*>(user_data);
    if(event == LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED)
    {
        cout << "device plugin" << endl;
        usbDevice->setDev(device);
    }
    else
    {
        cout << "device unplugin" << endl;
        usbDevice->notifyUnplugIn();
    }
    

    return 0;
}
void USBDevice::notifyUnplugIn()
{
    if(handle != nullptr)
    {
        libusb_close(handle);
        handle = nullptr;
    }
    devicePresent = false;

}

USBDevice::USBDevice(int vid, int pid): idVendor(vid), idProduter(pid)
{
    int cnt;
    libusb_device **devs;
    const struct libusb_version * pVersion = libusb_get_version();
    cout << "libusb version:\t" << pVersion->major <<"." << pVersion->minor <<"." << pVersion->micro
            << "." << pVersion->nano << "." <<pVersion->rc << endl;
    cout << "=====libusb init=====" << endl;
    libusb_init(&ctx);
    cout << "ctx:" << ctx<<endl;

    libusb_hotplug_register_callback(ctx, LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED, LIBUSB_HOTPLUG_NO_FLAGS,
                                          idVendor, idProduter, LIBUSB_HOTPLUG_MATCH_ANY, usb_hotplug_callback, this, &hotplugin_cb_handle);

    libusb_hotplug_register_callback(ctx, LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT, LIBUSB_HOTPLUG_NO_FLAGS,
                                          idVendor, idProduter, LIBUSB_HOTPLUG_MATCH_ANY, usb_hotplug_callback, this, &unhotplugin_cb_handle);

    t = std::thread(&USBDevice::waitPluginEvent, this);
    t.detach();

    // check if usb already plugin
    cnt = libusb_get_device_list(ctx, &devs);
    for(int i = 0; i < cnt; i++)
    {
        struct libusb_device_descriptor desc;
        libusb_get_device_descriptor (devs[i], &desc);
        if(desc.idVendor == idVendor && desc.idProduct == desc.idProduct)
        {
            setDev(devs[i]);
            break;
        }
    }
    libusb_free_device_list(devs, 1);
}
USBDevice::~USBDevice()
{
    libusb_hotplug_deregister_callback(ctx, unhotplugin_cb_handle);
    libusb_hotplug_deregister_callback(ctx, hotplugin_cb_handle);
    libusb_exit(ctx);
    ctx = nullptr;
}

void USBDevice::waitPluginEvent()
{
    cout << "start wait plugin." << endl;
    while(ctx != nullptr)
    {
        libusb_handle_events(ctx);
    }
    cout << "end wait plugin."<< endl; 
}
void USBDevice::setDev(libusb_device* dev)
{
    device = dev;
    int bus = libusb_get_bus_number(device);
    int port = libusb_get_port_number(device);
    id = to_string(bus) + "-" + to_string(port);
    cout << "id" << id << endl;
    libusb_open(dev, &handle);
    devicePresent = true;
}
int USBDevice::printDevice()
{
    if(!isDevicePresent())
    {
        cout << "device is not present" << endl;
        return -1;
    }
    struct libusb_device_descriptor desc;
    unsigned char buff[256] = {0};
    int ret;
    ret = libusb_get_device_descriptor(device, &desc);
    if(ret < 0)
    {
        cout << "failed to get device descriptor" << endl;
        return -1;
    }
    cout << "=======device info=======" << endl;
    cout << left << hex << showbase<< setfill('0');
    cout <<setw(6)<< desc.idVendor<<":"<<setw(6)<<desc.idProduct;
    cout << dec << noshowbase;
    cout <<"@"<<"bus:" << (int)libusb_get_bus_number(device) << "\tport:" << (int)libusb_get_port_number(device) 
              << "\t\tdevice:" << (int)libusb_get_device_address(device) << "\tspeed:" << (int)libusb_get_device_speed(device)<< endl;

    cout <<"device version:\t" << left << hex << showbase << setfill('0') << setw(6) << desc.bcdUSB << endl;
    cout <<"device class:\t" << left << hex << showbase << setfill('0') << setw(4) << desc.bDeviceClass << endl;
    cout <<"device subclass:\t" << left << hex << showbase << setfill('0') << setw(4) << desc.bDeviceSubClass << endl;
    cout <<"device protocol:\t" << left << hex << showbase << setfill('0') << setw(4) << desc.bDeviceProtocol << endl;
    cout << dec << noshowbase;
    libusb_get_string_descriptor_ascii(handle, desc.iManufacturer, buff, sizeof(buff));
    cout <<"Manufacturer:\t" << buff << endl;
    memset(buff, 0, sizeof(buff));
    libusb_get_string_descriptor_ascii(handle, desc.iProduct, buff, sizeof(buff));
    cout <<"Product:\t" <<  buff << endl;
    memset(buff, 0, sizeof(buff));
    libusb_get_string_descriptor_ascii(handle, desc.iSerialNumber, buff, sizeof(buff));
    cout << "SerialNumber:\t" << buff << endl;
    cout << "Num of Configurations:" << (int)desc.bNumConfigurations << endl;
    for(int i = 0; i < desc.bNumConfigurations; i++)
    {
        struct libusb_config_descriptor* config;
        ret = libusb_get_config_descriptor(device, i, &config);
        if(LIBUSB_SUCCESS != ret)
        {
            cout << "couldn't retrieve config descriptor" << endl;
            continue;
        }
        printConfiguration(config);
        libusb_free_config_descriptor(config);
    }
    return 0;
}
void USBDevice::printConfiguration(const struct libusb_config_descriptor *config)
{
    uint8_t i;
    unsigned char buff[256] = {0};
    libusb_get_string_descriptor_ascii(handle, config->iConfiguration, buff, sizeof(buff));

	printf("  Configuration:\n");
	printf("    wTotalLength:         %d\n", config->wTotalLength);
	printf("    bNumInterfaces:       %d\n", config->bNumInterfaces);
	printf("    bConfigurationValue:  %d\n", config->bConfigurationValue);
	printf("    iConfiguration:       %s\n", buff);
	//printf("    iConfiguration:       %d\n", config->iConfiguration);
	printf("    bmAttributes:         %02xh\n", config->bmAttributes);
	printf("    MaxPower:             %d\n", config->MaxPower);

	for (i = 0; i < config->bNumInterfaces; i++)
    {
		printInterface(&config->interface[i]);
    }
}
void USBDevice::printInterface(const struct libusb_interface *interface)
{
    int i;
    printf("    Interface:\n");
	for (i = 0; i < interface->num_altsetting; i++)
    {
		printAltsetting(&interface->altsetting[i]);
    }
}
void USBDevice::printAltsetting(const struct libusb_interface_descriptor *interface)
{
    uint8_t i;
    unsigned char buff[256] = {0};
	printf("      Interface altsetting:\n");
	printf("        bInterfaceNumber:   %d\n", interface->bInterfaceNumber);
	printf("        bAlternateSetting:  %d\n", interface->bAlternateSetting);
	printf("        bNumEndpoints:      %d\n", interface->bNumEndpoints);
	printf("        bInterfaceClass:    %d\n", interface->bInterfaceClass);
	printf("        bInterfaceSubClass: %d\n", interface->bInterfaceSubClass);
	printf("        bInterfaceProtocol: %d\n", interface->bInterfaceProtocol);
    libusb_get_string_descriptor_ascii(handle, interface->iInterface, buff, sizeof(buff));
   // printf("        iInterface:         %d\n", interface->iInterface);
    printf("        iInterface:         %s\n", buff);

	for (i = 0; i < interface->bNumEndpoints; i++)
    {
		printEndpoint(&interface->endpoint[i]);
    }
}
void USBDevice::printEndpoint(const struct libusb_endpoint_descriptor *endpoint)
{
    int i, ret;

	printf("        Endpoint:\n");
	printf("          bEndpointAddress: %02xh\n", endpoint->bEndpointAddress);
	printf("          bmAttributes:     %02xh\n", endpoint->bmAttributes);
	printf("          wMaxPacketSize:   %d\n", endpoint->wMaxPacketSize);
	printf("          bInterval:        %d\n", endpoint->bInterval);
	printf("          bRefresh:         %d\n", endpoint->bRefresh);
	printf("          bSynchAddress:    %d\n", endpoint->bSynchAddress);

	for (i = 0; i < endpoint->extra_length;) {
		if (LIBUSB_DT_SS_ENDPOINT_COMPANION == endpoint->extra[i + 1]) {
			struct libusb_ss_endpoint_companion_descriptor *ep_comp;

			ret = libusb_get_ss_endpoint_companion_descriptor(NULL, endpoint, &ep_comp);
			if (LIBUSB_SUCCESS != ret) {
				continue;
			}

			printEndpointComp(ep_comp);

			libusb_free_ss_endpoint_companion_descriptor(ep_comp);
		}

		i += endpoint->extra[i];
	}
}
void USBDevice::printEndpointComp(const struct libusb_ss_endpoint_companion_descriptor *ep_comp)
{
    printf("        USB 3.0 Endpoint Companion:\n");
	printf("          bMaxBurst:        %d\n", ep_comp->bMaxBurst);
	printf("          bmAttributes:     0x%02x\n", ep_comp->bmAttributes);
	printf("          wBytesPerInterval: %d\n", ep_comp->wBytesPerInterval);
}