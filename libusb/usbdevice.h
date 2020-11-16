#ifndef _USBDEVICE_LIBUSB_H_
#define _USBDEVICE_LIBUSB_H_
#include <string>
#include <thread>
extern "C"
{
#include "libusb-1.0/libusb.h"
}

class USBDevice
{
private:
    int idVendor;
    int idProduter;
    std::string id;
    libusb_hotplug_callback_handle hotplugin_cb_handle;
    libusb_hotplug_callback_handle unhotplugin_cb_handle;
    libusb_context* ctx = nullptr;
    libusb_device* device;
    libusb_device_handle *handle = nullptr;
    std::thread t;
    bool devicePresent = false;
public:
    USBDevice(int vid, int pid);
    ~USBDevice();
    int printDevice();
    libusb_device_handle* getUsbDeviceHandle()
    {
        return handle;
    }
    libusb_device* getUsbDevice()
    {
        return device;
    }
    void notifyUnplugIn();
    bool isDevicePresent()
    {
        return devicePresent;
    }
private:
    static int usb_hotplug_callback(libusb_context* ctx, libusb_device* device, libusb_hotplug_event event, void* user_data);
    void setDev(libusb_device* dev);
    void waitPluginEvent();
    void printConfiguration(const struct libusb_config_descriptor *config);
    void printInterface(const struct libusb_interface *interface);
    void printAltsetting(const struct libusb_interface_descriptor *interface);
    void printEndpoint(const struct libusb_endpoint_descriptor *endpoint);
    void printEndpointComp(const struct libusb_ss_endpoint_companion_descriptor *ep_comp);
};

#endif