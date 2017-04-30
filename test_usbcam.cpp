// TEGRA X1/TEGRA LINUX DRIVER PACKAGE MULTIMEDIA USER GUIDE
// http://developer2.download.nvidia.com/embedded/L4T/r24_Release_v2.0/Docs/L4T_Tegra_X1_Multimedia_User_Guide_Release_24.2.pdf?nas16vBtpEYXN9Q3_dgD9dZ8msoaqJ3ncR5CVNdqlEnlYt3bPqlKOsRcifhHB02kMNznaxDYRKdtBJg-0xXxHzCbysXTlTMoAwEaFIF3FfHzxlyVQatAbHz-3lkv9FndSDaC8fJUQuKIsAbbFAVRBxYHXbhPXas0BbJga--6wshwIuSTLJK3wFmGmZrgBgpZS9LL9wI

// g++ test_usbcam.cpp -o app -lv4l2

// To convert MJPEG frames to JPEG:
// My laptop's webcamera outputs MJPEG frames, and if I try to open them in Linux
// I get Huffman table 0x00 was not defined, or something. Running xxd on the jpeg
// I see the header is ... AVI1, which is a mjpeg alright.
// ffmpeg -i video%04d.jpg -vcodec mjpeg -f image2 video%04d.jpg

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <linux/videodev2.h>
#include <libv4l2.h>
#include <turbojpeg.h>
#include <assert.h>
#include <signal.h>

// Returns number of nanoseconds since the UNIX epoch
uint64_t get_nanoseconds()
{
    struct timespec ts = {};
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t result = ((uint64_t)ts.tv_sec)*1000000000 +
                      ((uint64_t)ts.tv_nsec);
    return result;
}

bool main_running = true;
void ctrlc(int)
{
    main_running = false;
}

void xioctl(int fh, int request, void *arg)
{
    int r;
    do
    {
        r = v4l2_ioctl(fh, request, arg);
    } while (r == -1 && ((errno == EINTR) || (errno == EAGAIN)));

    if (r == -1)
    {
        printf("[usbcam.h] USB request failed (%d): %s\n", errno, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

#define usbcam_assert(CONDITION, MESSAGE) { if (!(CONDITION)) { printf("[usbcam.h] Error at line %d: %s\n", __LINE__, MESSAGE); exit(EXIT_FAILURE); } }

int main(int argc, char **argv)
{
    signal(SIGINT, ctrlc);

    const char *device_name = "/dev/video0";
    const int device_fps = 30;
    const int device_buffers = 6;
    const int device_width = 800;
    const int device_height = 600;
    const int device_format = V4L2_PIX_FMT_MJPEG;

    // Open the device
    int fd = v4l2_open(device_name, O_RDWR, 0);
    usbcam_assert(fd >= 0, "Failed to open device");

    // set format
    {
        v4l2_format fmt = {0};
        fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        fmt.fmt.pix.pixelformat = device_format;
        fmt.fmt.pix.width = device_width;
        fmt.fmt.pix.height = device_height;
        xioctl(fd, VIDIOC_S_FMT, &fmt);

        usbcam_assert(fmt.fmt.pix.pixelformat == device_format, "Did not get the requested format");
        usbcam_assert(fmt.fmt.pix.width == device_width, "Did not get the requested width");
        usbcam_assert(fmt.fmt.pix.height == device_height, "Did not get the requested height");
    }

    // tell the driver how many buffers we want
    {
        v4l2_requestbuffers request = {0};
        request.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        request.memory = V4L2_MEMORY_MMAP;
        request.count = device_buffers;
        xioctl(fd, VIDIOC_REQBUFS, &request);

        usbcam_assert(request.count == device_buffers, "Did not get the requested number of buffers");
    }

    // allocate buffer
    void *buffer_start[device_buffers] = {0};
    uint32_t buffer_length[device_buffers] = {0};
    for (int i = 0; i < device_buffers; i++)
    {
        v4l2_buffer info = {0};
        info.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        info.memory = V4L2_MEMORY_MMAP;
        info.index = i;
        xioctl(fd, VIDIOC_QUERYBUF, &info);

        buffer_length[i] = info.length;
        buffer_start[i] = mmap(
            NULL,
            info.length,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            fd,
            info.m.offset
        );

        usbcam_assert(buffer_start[i] != MAP_FAILED, "Failed to allocate memory for buffers");
    }

    // start streaming
    {
        int type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        xioctl(fd, VIDIOC_STREAMON, &type);
    }

    // queue buffers
    for (int i = 0; i < device_buffers; i++)
    {
        v4l2_buffer info = {0};
        info.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        info.memory = V4L2_MEMORY_MMAP;
        info.index = i;
        xioctl(fd, VIDIOC_QBUF, &info);
    }

    int num_frames = 60;
    for (int frame = 0; frame < num_frames; frame++)
    {
        #if 1 // dequeue all the buffers and select the one with latest data
        v4l2_buffer buf = {0};
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        {
            // get a buffer
            xioctl(fd, VIDIOC_DQBUF, &buf);

            // check if there are more buffers available
            int r = 1;
            while (r == 1)
            {
                fd_set fds;
                FD_ZERO(&fds);
                FD_SET(fd, &fds);
                timeval tv; // if both fields = 0, select returns immediately
                tv.tv_sec = 0;
                tv.tv_usec = 0;
                r = select(fd + 1, &fds, NULL, NULL, &tv); // todo: what if r == -1?
                if (r == 1)
                {
                    printf(".");

                    // queue the previous buffer
                    xioctl(fd, VIDIOC_QBUF, &buf);

                    // get a new buffer
                    xioctl(fd, VIDIOC_DQBUF, &buf);
                }
            }
        }
        #else // deque whatever frame the driver decides to give us
              // this will not necessarily hold the latest data!
        v4l2_buffer buf = {0};
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        // buf.index; // we don't specify the buffer index
                      // the driver selects one and gives it to us
        xioctl(fd, VIDIOC_DQBUF, &buf);
        #endif

        unsigned char *jpg_data = (unsigned char*)buffer_start[buf.index];
        unsigned int jpg_size = buf.bytesused;

        {
            timeval timestamp = buf.timestamp;
            uint64_t sec = (uint64_t)timestamp.tv_sec;
            uint64_t usec = (uint64_t)timestamp.tv_usec;
            uint64_t t = sec*1000*1000 + usec;

            static uint64_t last_t = t;
            double dt = (t-last_t)/1e6;
            last_t = t;
            printf("FRAME %3.d\t%6.2f MS\t%u BYTES\tBUFFER %d\n", frame, 1000.0f*dt, jpg_size, buf.index);
        }

        {
            static uint64_t t_begin = get_nanoseconds();
            if (frame == num_frames - 1)
            {
                double dt = (get_nanoseconds() - t_begin)/1e9;
                printf("total: %.2f f/s ~ %.2f ms/f\n", num_frames/dt, 1000.0f*dt/num_frames);
            }
        }

        {
            char filename[256];
            sprintf(filename, "video%04d.jpg", frame);
            FILE *f = fopen(filename, "w+");
            fwrite(jpg_data, jpg_size, 1, f);
            fclose(f);
            usleep(110*1000);
        }

        xioctl(fd, VIDIOC_QBUF, &buf);
    }

    // dequeue buffers
    {
        for (int i = 0; i < device_buffers; i++)
            munmap(buffer_start[i], buffer_length[i]);
    }

    // turn off streaming
    {
        int type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        xioctl(fd, VIDIOC_STREAMOFF, &type);
        close(fd);
    }
}
