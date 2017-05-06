
device=/dev/video0
width=800
height=600
buffers=3

# For ELP fisheye camera (run v4l2-ctl -d/dev/video0 -L)
powerline=0     # (0=off, 1 = 50Hz, 2 = 60Hz)
whitebalance=1  # (0=off, 1=on)
sharpness=2     # (min=0    max=6   step=1 default=2)
brightness=0    # (min=-64  max=64  step=1 default=0)
contrast=32     # (min=0    max=64  step=1 default=32)
saturation=60   # (min=0    max=128 step=1 default=60)
hue=0           # (min=-40  max=40  step=1 default=0)
gamma=72        # (min=72   max=500 step=1 default=100)
gain=0          # (min=0    max=100 step=1 default=0)
exposure=45     # (min=1    max=5000 step=1 default=157)

#
#
#

# echo "Turning off exposure auto priority"
#     v4l2-ctl -d $device -c exposure_auto_priority=0
#     sleep 0.1
echo "Setting exposure to manual"
    v4l2-ctl -d $device -c exposure_auto=1
    sleep 0.1
echo "Setting exposure time to $exposure"
    v4l2-ctl -d $device -c exposure_absolute=$exposure
    sleep 0.1
echo "Setting sharpness to $sharpness"
    v4l2-ctl -d $device -c sharpness=$sharpness
    sleep 0.1
echo "Setting brightness to $brightness"
    v4l2-ctl -d $device -c brightness=$brightness
    sleep 0.1
echo "Setting contrast to $contrast"
    v4l2-ctl -d $device -c contrast=$contrast
    sleep 0.1
echo "Setting saturation to $saturation"
    v4l2-ctl -d $device -c saturation=$saturation
    sleep 0.1
echo "Setting hue to $hue"
    v4l2-ctl -d $device -c hue=$hue
    sleep 0.1
echo "Setting gamma to $gamma"
    v4l2-ctl -d $device -c gamma=$gamma
    sleep 0.1
echo "Setting gain to $gain"
    v4l2-ctl -d $device -c gain=$gain
    sleep 0.1
echo "Setting power line frequency to $powerline"
    v4l2-ctl -d $device -c power_line_frequency=$powerline
    sleep 0.1
echo "Setting automatic white balance to $whitebalance"
    v4l2-ctl -d $device -c white_balance_temperature_auto=$whitebalance
    sleep 0.1

#
# compile and run
#
DEFINES="-DUSBCAM_OPT_DEVICE=\"$device\"
         -DUSBCAM_OPT_WIDTH=$width
         -DUSBCAM_OPT_HEIGHT=$height
         -DUSBCAM_OPT_BUFFERS=$buffers"
g++ test_usbcam.cpp $DEFINES -o app -lv4l2 -lturbojpeg && ./app
