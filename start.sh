num_frames=0
decompress_jpg=0
stream_video=0
print_timestamps=1
write_to_file=0
camera_name=/dev/video0
camera_width=800
camera_height=600
camera_buffers=3

# ELP FISHEYE CAMERA CONTROLS
# (v4l2-ctl -d/dev/video0 -L)
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
#     v4l2-ctl -d $camera_name -c exposure_auto_priority=0
echo "Setting exposure to manual"
    v4l2-ctl -d $camera_name -c exposure_auto=1
echo "Setting exposure time to $exposure"
    v4l2-ctl -d $camera_name -c exposure_absolute=$exposure
# echo "Setting sharpness to $sharpness"
#     v4l2-ctl -d $camera_name -c sharpness=$sharpness
# echo "Setting brightness to $brightness"
#     v4l2-ctl -d $camera_name -c brightness=$brightness
# echo "Setting contrast to $contrast"
#     v4l2-ctl -d $camera_name -c contrast=$contrast
# echo "Setting saturation to $saturation"
#     v4l2-ctl -d $camera_name -c saturation=$saturation
# echo "Setting hue to $hue"
#     v4l2-ctl -d $camera_name -c hue=$hue
# echo "Setting gamma to $gamma"
#     v4l2-ctl -d $camera_name -c gamma=$gamma
# echo "Setting gain to $gain"
#     v4l2-ctl -d $camera_name -c gain=$gain
# echo "Setting power line frequency to $powerline"
#     v4l2-ctl -d $camera_name -c power_line_frequency=$powerline
# echo "Setting automatic white balance to $whitebalance"
#     v4l2-ctl -d $camera_name -c white_balance_temperature_auto=$whitebalance

#
# compile and run
#
DEFINES="-DCAMERA_NAME=\"$camera_name\"
         -DCAMERA_WIDTH=$camera_width
         -DCAMERA_HEIGHT=$camera_height
         -DCAMERA_BUFFERS=$camera_buffers
         -DNUM_FRAMES=$num_frames
         -DDECOMPRESS_JPG=$decompress_jpg
         -DSTREAM_VIDEO=$stream_video
         -DPRINT_TIMESTAMPS=$print_timestamps
         -DWRITE_TO_FILE=$write_to_file"
g++ $DEFINES test_usbcam.cpp -o app -lv4l2 -lturbojpeg && ./app
