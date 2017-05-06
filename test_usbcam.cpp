// compiling
//   g++ test_usbcam.cpp -o app -lv4l2 -lturbojpeg && ./app

#include "usbcam.h"
#include <stdint.h>
#include <time.h>
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

uint64_t get_nanoseconds()
{
    struct timespec ts = {};
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t result = ((uint64_t)ts.tv_sec)*1000000000 +
                      ((uint64_t)ts.tv_nsec);
    return result;
}

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
            timeval timestamp;
            usbcam_lock(&jpg_data, &jpg_size, &timestamp);

            // decompress jpeg
            #if 1
            {
                uint64_t last_t = get_nanoseconds();

                int jpg_subsamples,width,height;
                int ok = tjDecompressHeader2(decompressor,
                    jpg_data,
                    jpg_size,
                    &width,
                    &height,
                    &jpg_subsamples);

                if (!ok)
                {
                    printf("Failed to decompress JPEG header: %s\n", tjGetErrorStr());
                }

                assert(width == Ix);
                assert(height == Iy);

                ok = tjDecompress2(decompressor,
                    jpg_data,
                    jpg_size,
                    rgb,
                    width,
                    0,
                    height,
                    TJPF_RGB,
                    TJFLAG_FASTDCT);

                if (!ok)
                {
                    printf("Failed to decompress JPEG: %s\n", tjGetErrorStr());
                }

                uint64_t t = get_nanoseconds();
                printf("%6.2f\t", (t-last_t)/1e6);
            }
            #endif

            usbcam_unlock();

            // write mjpeg to file
            #if 0
            {
                char filename[256];
                sprintf(filename, "video%04d.jpg", i);
                FILE *f = fopen(filename, "w+");
                fwrite(jpg_data, jpg_size, 1, f);
                fclose(f);
            }
            #endif

            {
                printf("%3d. ", i);

                // compute frame interval from internal timestamp
                {
                    uint64_t sec = (uint64_t)timestamp.tv_sec;
                    uint64_t usec = (uint64_t)timestamp.tv_usec;
                    uint64_t t = sec*1000*1000 + usec;
                    static uint64_t last_t = t;
                    printf("%6.2f ms\t", (t-last_t)/1e3);
                    last_t = t;
                }

                // compute frame interval from system clock
                {
                    static uint64_t last_t = get_nanoseconds();
                    uint64_t t = get_nanoseconds();
                    printf("%6.2f ms\t", (t-last_t)/1e6);
                    last_t = t;
                }

                printf("\n");
            }
        }
    }

    usbcam_cleanup();

    return 0;
}
