// g++ test_usbcam.cpp -o app -lv4l2 && ./app

#include "usbcam.h"
#include <signal.h>
#include <assert.h>
#include <turbojpeg.h>

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

    tjhandle decompressor = tjInitDecompress();

    for (int i = 0; i < 120; i++)
    {
        const int Ix = USBCAM_OPT_WIDTH;
        const int Iy = USBCAM_OPT_HEIGHT;
        static unsigned char rgb[Ix*Iy*3];
        {
            unsigned char *jpg_data;
            unsigned int jpg_size;
            usbcam_lock(&jpg_data, &jpg_size);

            int jpg_subsamples,width,height;
            tjDecompressHeader2(decompressor,
                jpg_data,
                jpg_size,
                &width,
                &height,
                &jpg_subsamples);

            assert(width == Ix);
            assert(height == Iy);

            tjDecompress2(decompressor,
                jpg_data,
                jpg_size,
                rgb,
                width,
                0,
                height,
                TJPF_RGB,
                TJFLAG_FASTDCT);

            #if 0 // WRITE MJPEG TO FILE
            {
                char filename[256];
                sprintf(filename, "video%04d.jpg", i);
                FILE *f = fopen(filename, "w+");
                fwrite(jpg_data, jpg_size, 1, f);
                fclose(f);
            }
            #endif

            usbcam_unlock();
            assert(rgb);

            printf("%d\n", i);
        }
    }

    usbcam_cleanup();

    return 0;
}
