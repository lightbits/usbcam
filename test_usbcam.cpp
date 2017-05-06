// compiling
//   g++ test_usbcam.cpp -o app -lv4l2 -lturbojpeg && ./app

#ifndef NUM_FRAMES
#define NUM_FRAMES       0
#endif
#ifndef DECOMPRESS_JPG
#define DECOMPRESS_JPG   1
#endif
#ifndef STREAM_VIDEO
#define STREAM_VIDEO     0
#endif
#ifndef PRINT_TIMESTAMPS
#define PRINT_TIMESTAMPS 1
#endif
#ifndef WRITE_TO_FILE
#define WRITE_TO_FILE    0
#endif
#ifndef CAMERA_NAME
#define CAMERA_NAME      "/dev/video0"
#endif
#ifndef CAMERA_WIDTH
#define CAMERA_WIDTH     800
#endif
#ifndef CAMERA_HEIGHT
#define CAMERA_HEIGHT    600
#endif
#ifndef CAMERA_BUFFERS
#define CAMERA_BUFFERS   3
#endif

#include "vdb_release.h"
#include "usbcam.h"
#include <stdint.h>
#include <time.h>
#include <signal.h>

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
    opt.device_name = CAMERA_NAME;
    opt.pixel_format = V4L2_PIX_FMT_MJPEG;
    opt.width = CAMERA_WIDTH;
    opt.height = CAMERA_HEIGHT;
    opt.buffers = CAMERA_BUFFERS;

    usbcam_init(opt);

    #if NUM_FRAMES==0
    for (int i = 0; ; i++)
    #else
    for (int i = 0; i < NUM_FRAMES; i++)
    #endif
    {
        const int Ix = CAMERA_WIDTH;
        const int Iy = CAMERA_HEIGHT;
        static unsigned char rgb[Ix*Iy*3];
        {
            unsigned char *jpg_data;
            unsigned int jpg_size;
            timeval timestamp;
            usbcam_lock(&jpg_data, &jpg_size, &timestamp);

            printf("%5d. ", i);

            #if DECOMPRESS_JPG==1
            {
                uint64_t t1 = get_nanoseconds();
                if (!usbcam_jpeg_to_rgb(Ix, Iy, rgb, jpg_data, jpg_size))
                {
                    usbcam_unlock();
                    continue;
                }
                uint64_t t2 = get_nanoseconds();
                printf("Decompressed in %6.2f ms\t", (t2-t1)/1e6);
            }
            #endif

            #if STREAM_VIDEO==1
            {
                static uint64_t last_t = get_nanoseconds();
                uint64_t t = get_nanoseconds();
                float dt = (t-last_t)/1e9;
                if (dt > 1.0f && vdb_begin())
                {
                    vdb_imageRGB8(rgb, Ix, Iy);
                    vdb_end();
                    last_t = t;
                }
            }
            #endif

            #if WRITE_TO_FILE==1
            {
                char filename[256];
                sprintf(filename, "video%04d.jpg", i);
                FILE *f = fopen(filename, "w+");
                fwrite(jpg_data, jpg_size, 1, f);
                fclose(f);
            }
            #endif

            usbcam_unlock();

            #if PRINT_TIMESTAMPS==1
            {
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
            }
            #endif

            printf("\n");
        }
    }

    usbcam_cleanup();

    return 0;
}
