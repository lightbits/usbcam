// g++ test_usbcam.cpp -o app -lv4l2 && ./app

#include "usbcam.h"
#include <signal.h>
#include <assert.h>

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

#ifndef USBCAM_OPT_DEVICE
#define USBCAM_OPT_DEVICE "/dev/video0"
#endif
#ifndef USBCAM_OPT_WIDTH
#define USBCAM_OPT_WIDTH 800
#endif
#ifndef USBCAM_OPT_HEIGHT
#define USBCAM_OPT_HEIGHT 600
#endif
#ifndef USBCAM_OPT_BUFFERS
#define USBCAM_OPT_BUFFERS 3
#endif

void ctrlc(int)
{
    exit(0);
}

int main(int argc, char **argv)
{
    signal(SIGINT, ctrlc);

    usbcam_opt_t opt = {0};
    opt.device_name = USBCAM_OPT_DEVICE;
    opt.pixel_format = V4L2_PIX_FMT_MJPEG;
    opt.width = USBCAM_OPT_WIDTH;
    opt.height = USBCAM_OPT_HEIGHT;
    opt.buffers = USBCAM_OPT_BUFFERS;

    usbcam_init(opt);

    for (int i = 0; i < 30; i++)
    {
        unsigned char *data;
        unsigned int size;
        usbcam_lock(&data, &size);

        usbcam_unlock();
    }

    usbcam_cleanup();

    return 0;
}
