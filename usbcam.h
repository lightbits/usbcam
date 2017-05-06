// usbcam.h
// github.com/lightbits
//
// Changelog
// (5) Automatically unlock previous frame on usbcam_lock if user forgot (and warn)
// (4) Buffer count is unsigned
// (3) JPEG-RGB decompressor returns true/false instead of crashing
// (2) Added turbojpeg JPEG->RGB decompression
// (1) Beginning of time
//
// See §BUILDING for build instructions

#include <sys/time.h>
struct usbcam_opt_t
{
    const char *device_name;
    unsigned int buffers; // See §BUFFERS
    unsigned int pixel_format; // See §PIXELFORMATS
    unsigned int width;
    unsigned int height;
};

void usbcam_cleanup();
void usbcam_init(usbcam_opt_t opt);
void usbcam_lock(unsigned char **data, unsigned int *size, timeval *timestamp);
void usbcam_unlock();
// See §DECOMPRESSION
bool usbcam_jpeg_to_rgb(int desired_width, int desired_height, unsigned char *rgb, unsigned char *jpg_data, unsigned int jpg_size);

//
// USER MANUAL
//
// §BUFFERS
// The driver does not overwrite buffers with latest data:
// Therefore, you should request as many buffers as you expect
// processing time to take. For example, if you need 100 ms to
// process one frame and the camera gives one frame every 30 ms,
// then it will fill up three buffers while you process. If you
// requested less than three buffers you will not get the latest
// frame when you ask for the next frame!
//
// §PIXELFORMATS
// A common format is V4L2_PIX_FMT_MJPEG.
// Pixel formats are specified as codes of four characters.
// A list of formats can be found in videodev2.h.
//   http://lxr.free-electrons.com/source/include/uapi/linux/videodev2.h#L616
// You can find out what formats your camera supports with
//   v4l2-ctl -d /dev/video0 --list-formats-ext
//
// §DECOMPRESSION
// You can specify a desired resolution which does not need to
// match the resolution given in usbcam_init. This will make
// turbojpeg use its internal downscaling capabilities while
// also reducing decompression time. If you specfy the same
// resolution no downscaling happens.
// http://www.libjpeg-turbo.org/Documentation/Documentation
//
// §BUILDING
// STEP 1) Get the video 4 linux 2 development libraries (v4l2)
//   $ sudo apt-get install libv4l-dev
//   $ sudo apt-get install v4l-utils
// STEP 2) Get the turbojpeg library
//   (See https://github.com/libjpeg-turbo/libjpeg-turbo/blob/master/BUILDING.md)
//   $ git clone https://github.com/libjpeg-turbo/libjpeg-turbo
//   $ cd libjpeg-turbo
//   $ autoreconf -fiv
//   $ mkdir build
//   $ cd build
//   $ sh ../configure
//   $ make
//   $ make install prefix=/usr/local libdir=/usr/local/lib64
// STEP 3) Compiler flags
//   g++ ... -lv4l2 -lturbojpeg

//
// Implementation
//

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <linux/videodev2.h>
#include <libv4l2.h>
#include <turbojpeg.h>

#define usbcam_max_buffers 128
#define usbcam_assert(CONDITION, ...) { if (!(CONDITION)) { printf("[usbcam.h line %d] ", __LINE__); printf(__VA_ARGS__); printf("\n"); exit(EXIT_FAILURE); } }
#define usbcam_warn(...) { printf("[usbcam.h line %d] ", __LINE__); printf(__VA_ARGS__); printf("\n"); }
#ifdef USBCAM_DEBUG
#define usbcam_debug(...) { printf("[usbcam.h line %d] ", __LINE__); printf(__VA_ARGS__); printf("\n"); }
#else
#define usbcam_debug(...) { }
#endif

static int          usbcam_has_mmap = 0;
static int          usbcam_has_lock = 0;
static int          usbcam_has_fd = 0;
static int          usbcam_has_stream = 0;
static int          usbcam_fd = 0;
static int          usbcam_buffers = 0;
static void        *usbcam_buffer_start[usbcam_max_buffers] = {0};
static unsigned int usbcam_buffer_length[usbcam_max_buffers] = {0};
static v4l2_buffer  usbcam_lock_buf = {0};

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
    if (usbcam_has_lock)
    {
        usbcam_debug("Requeuing buffer");
        usbcam_ioctl(VIDIOC_QBUF, &usbcam_lock_buf);
        usbcam_has_lock = 0;
    }

    // free buffers
    if (usbcam_has_mmap)
    {
        usbcam_debug("Deallocating mmap");
        for (int i = 0; i < usbcam_buffers; i++)
            munmap(usbcam_buffer_start[i], usbcam_buffer_length[i]);
        usbcam_has_mmap = 0;
    }

    // turn off streaming
    if (usbcam_has_stream)
    {
        usbcam_debug("Turning off stream (if this freezes send me a message)");
        int type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        usbcam_ioctl(VIDIOC_STREAMOFF, &type);
        usbcam_has_stream = 0;
    }

    if (usbcam_has_fd)
    {
        usbcam_debug("Closing fd");
        close(usbcam_fd);
        usbcam_has_fd = 0;
    }
}

void usbcam_init(usbcam_opt_t opt)
{
    usbcam_cleanup();
    usbcam_assert(opt.buffers <= usbcam_max_buffers, "You requested too many buffers");
    usbcam_assert(opt.buffers > 0, "You need atleast one buffer");

    // Open the device
    usbcam_fd = v4l2_open(opt.device_name, O_RDWR, 0);
    usbcam_assert(usbcam_fd >= 0, "Failed to open device");
    usbcam_has_fd = 1;

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

    usbcam_debug("Opened device (%s %dx%d)", opt.device_name, opt.width, opt.height);

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
            usbcam_fd,
            info.m.offset
        );

        usbcam_assert(usbcam_buffer_start[i] != MAP_FAILED, "Failed to allocate memory for buffers");
    }

    usbcam_buffers = opt.buffers;
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

void usbcam_unlock()
{
    if (usbcam_has_lock)
    {
        usbcam_ioctl(VIDIOC_QBUF, &usbcam_lock_buf);
        usbcam_has_lock = 0;
    }
    else
    {
        usbcam_warn("You already unlocked the frame");
    }
}

void usbcam_lock(unsigned char **data, unsigned int *size, timeval *timestamp)
{
    usbcam_assert(usbcam_has_fd, "Camera device not open");
    usbcam_assert(usbcam_has_mmap, "Buffers not allocated");
    usbcam_assert(usbcam_has_stream, "Stream not begun");

    if (usbcam_has_lock)
    {
        // you should unlock frames as soon as you are done processing them for best performance
        usbcam_warn("You did not unlock the previous frame");
        usbcam_unlock();
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
            FD_SET(usbcam_fd, &fds);
            timeval tv; // if both fields = 0, select returns immediately
            tv.tv_sec = 0;
            tv.tv_usec = 0;
            r = select(usbcam_fd + 1, &fds, NULL, NULL, &tv); // todo: what if r == -1?
            if (r == 1)
            {
                // queue the previous buffer
                usbcam_ioctl(VIDIOC_QBUF, &buf);

                // get a new buffer
                usbcam_ioctl(VIDIOC_DQBUF, &buf);
            }
        }
    }

    *timestamp = buf.timestamp;
    *data = (unsigned char*)usbcam_buffer_start[buf.index];
    *size = buf.bytesused;

    usbcam_lock_buf = buf;
    usbcam_has_lock = 1;
}

bool usbcam_jpeg_to_rgb(int desired_width, int desired_height, unsigned char *destination, unsigned char *jpg_data, unsigned int jpg_size)
{
    static tjhandle decompressor = tjInitDecompress();
    int subsamp,width,height,error;

    error = tjDecompressHeader2(decompressor,
        jpg_data,
        jpg_size,
        &width,
        &height,
        &subsamp);

    if (error)
    {
        usbcam_warn("Failed to decode JPEG: %s", tjGetErrorStr());
        return false;
    }

    error = tjDecompress2(decompressor,
        jpg_data,
        jpg_size,
        destination,
        desired_width,
        0,
        desired_height,
        TJPF_RGB,
        TJFLAG_FASTDCT);

    if (error)
    {
        usbcam_warn("Failed to decode JPEG: %s", tjGetErrorStr());
        return false;
    }

    return true;
}
