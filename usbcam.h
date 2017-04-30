//
// Interface
//
struct usbcam_opt_t
{
    // e.g. /dev/video0
    const char *device_name;

    int buffers;

    // Pixel formats specified as codes of four characters, and
    // a predefined list of formats can be found in videodev2.h
    // (http://lxr.free-electrons.com/source/include/uapi/linux/videodev2.h#L616)
    // You can find out what formats your camera supports with
    // $ v4l2-ctl -d /dev/video0 --list-formats-ext
    unsigned int pixel_format;
    unsigned int width;
    unsigned int height;
};
void usbcam_init(usbcam_opt_t opt);
void usbcam_dequeue(unsigned char **data, // points to a data chunk currently locked by you
                    unsigned int *size);  // number of bytes in data
void usbcam_requeue(); // Call this when you finish processing the dequeued data

//
// Implementation
//
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
#define usbcam_assert(CONDITION, MESSAGE) { if (!(CONDITION)) { printf("[usbcam.h] Error at line %d: %s\n", __LINE__, MESSAGE); exit(EXIT_FAILURE); } }
#define usbcam_max_buffers 128
static int usbcam_has_mmap = 0;
static int usbcam_has_dqbuf = 0;
static int usbcam_has_fd = 0;
static int usbcam_has_stream = 0;

static int          usbcam_fd = 0;
static void        *usbcam_buffer_start[usbcam_max_buffers] = {0};
static unsigned int usbcam_buffer_length[usbcam_max_buffers] = {0};
static v4l2_buffer  usbcam_dqbuf = {0};

void usbcam_ioctl(int request, void *arg)
{
    usbcam_assert(usbcam_has_fd, "The camera device has not been opened yet!");
    int r;
    do
    {
        r = v4l2_ioctl(usbcam_fd, request, arg);
    } while (r == -1 && ((errno == EINTR) || (errno == EAGAIN)));
    if (r == -1)
    {
        printf("[usbcam.h] USB request failed (%d): %s\n", errno, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void usbcam_cleanup()
{
    // return any buffers we have dequeued (not sure if this is necessary)
    if (usbcam_has_dqbuf)
    {
        usbcam_ioctl(VIDIOC_QBUF, &buf);
        usbcam_has_dqbuf = 0;
    }

    // free buffers
    if (usbcam_has_mmap)
    {
        for (int i = 0; i < device_buffers; i++)
            munmap(usbcam_buffer_start[i], usbcam_buffer_length[i]);
        usbcam_has_mmap = 0;
    }

    // turn off streaming
    if (usbcam_has_stream)
    {
        int type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        usbcam_ioctl(VIDIOC_STREAMOFF, &type);
        usbcam_has_stream = 0;
    }

    if (usbcam_has_fd)
    {
        close(usbcam_fd);
        usbcam_has_fd = 0;
    }
}

void usbcam_init(usbcam_opt_t opt)
{
    usbcam_cleanup();
    usbcam_assert(opt.buffers <= usbcam_max_buffers, "You requested too many buffers");

    // Open the device
    usbcam_fd = v4l2_open(opt.device_name, O_RDWR, 0);
    usbcam_assert(usbcam_fd >= 0, "Failed to open device");
    usbcam_has_fd = 1;

    atexit(usbcam_atexit);

    // set format
    {
        v4l2_format fmt = {0};
        fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        fmt.fmt.pix.pixelformat = opt.pixel_format;
        fmt.fmt.pix.width = opt.width;
        fmt.fmt.pix.height = opt.height;
        usbcam_ioctl(VIDIOC_S_FMT, &fmt);

        usbcam_assert(fmt.fmt.pix.pixelformat == opt.pixel_format, "Did not get the requested format");
        usbcam_assert(fmt.fmt.pix.width == opt.width, "Did not get the requested width");
        usbcam_assert(fmt.fmt.pix.height == opt.height, "Did not get the requested height");
    }

    // tell the driver how many buffers we want
    {
        v4l2_requestbuffers request = {0};
        request.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        request.memory = V4L2_MEMORY_MMAP;
        request.count = opt.buffers;
        usbcam_ioctl(VIDIOC_REQBUFS, &request);

        usbcam_assert(request.count == opt.buffers, "Did not get the requested number of buffers");
    }

    // allocate buffers
    for (int i = 0; i < opt.buffers; i++)
    {
        v4l2_buffer info = {0};
        info.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        info.memory = V4L2_MEMORY_MMAP;
        info.index = i;
        usbcam_ioctl(VIDIOC_QUERYBUF, &info);

        usbcam_buffer_length[i] = info.length;
        usbcam_buffer_start[i] = mmap(
            NULL,
            info.length,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            fd,
            info.m.offset
        );

        usbcam_assert(buffer_start[i] != MAP_FAILED, "Failed to allocate memory for buffers");
    }

    usbcam_has_mmap = 1;

    // start streaming
    {
        int type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        usbcam_ioctl(VIDIOC_STREAMON, &type);
    }

    usbcam_has_stream = 1;

    // queue buffers
    for (int i = 0; i < opt.buffers; i++)
    {
        v4l2_buffer info = {0};
        info.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        info.memory = V4L2_MEMORY_MMAP;
        info.index = i;
        usbcam_ioctl(VIDIOC_QBUF, &info);
    }
}

int usbcam_requeue()
{
    if (usbcam_has_dqbuf)
    {
        usbcam_ioctl(VIDIOC_QBUF, &usbcam_dqbuf);
        usbcam_has_dqbuf = 0;
        return 1;
    }
    return 0;
}

void usbcam_dequeue(unsigned char **data, unsigned int *size)
{
    if (usbcam_requeue())
    {
        printf("[usbcam.h] Warning at line %d\n", __LINE__);
        // You are not requeuing the buffer manually.
        // You should requeue the buffer manually by calling usbcam_requeue
        // once you are done processing the dequeued buffer.
    }

    // dequeue all the buffers and select the one with latest data
    v4l2_buffer buf = {0};
    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_MMAP;
    {
        // get a buffer
        usbcam_ioctl(VIDIOC_DQBUF, &buf);

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
                // queue the previous buffer
                usbcam_ioctl(VIDIOC_QBUF, &buf);

                // get a new buffer
                usbcam_ioctl(VIDIOC_DQBUF, &buf);
            }
        }
    }

    *data = (unsigned char*)usbcam_buffer_start[buf.index];
    *size = buf.bytesused;

    usbcam_dqbuf = buf;
    usbcam_has_dqbuf = 1;
}
