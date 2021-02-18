# Enable PiOled (ssd1306 chip on the I2C bus) Ubuntu 

## PiOled (ssd1306 chip on the I2C bus)

[PiOled display script/library](https://github.com/activecm/pi_show)

# Enable i2c on raspberry pi Ubuntu

`raspi-config` on the Pi running Ubuntu 18.04 server for ARM64:

```sh
wget https://archive.raspberrypi.org/debian/pool/main/r/raspi-config/raspi-config_20160527_all.deb -P /tmp
apt-get install libnewt0.52 whiptail parted triggerhappy lua5.1 alsa-utils -y
apt-get install -fy
dpkg -i /tmp/raspi-config_20160527_all.deb
```

 **warning ** that it's only meant to work on Raspbian

mount the boot partition: `sudo mount /dev/mmcblk0p1 /boot`

`sudo raspi-config`, following the prompts to enable i2c (in Advanced Settings->i2c)

