
  CAMERA=/dev/video0
   WIDTH=800
  HEIGHT=600
 BUFFERS=3
EXPOSURE=300

# manual exposure
echo "Setting camera to manual exposure"
v4l2-ctl -d $CAMERA -c exposure_auto=3

# set exposure time
echo "Setting exposure time to $EXPOSURE"
v4l2-ctl -d $CAMERA -c exposure_absolute=$EXPOSURE

# compile and run
DEFINES="-DUSBCAM_OPT_DEVICE=\"$CAMERA\"
         -DUSBCAM_OPT_WIDTH=$WIDTH
         -DUSBCAM_OPT_HEIGHT=$HEIGHT
         -DUSBCAM_OPT_BUFFERS=$BUFFERS"
g++ test_usbcam.cpp $DEFINES -o app -lv4l2 -lturbojpeg && ./app
