 WiFi


[NetworkManager refuses to manage my WLAN interface](https://askubuntu.com/questions/211347/networkmanager-refuses-to-manage-my-wlan-interface)


ERROR: p2p-dev-wlan0 faild

Add the line

`p2p_disabled=1`
in `/etc/wpa_supplicant/wpa_supplicant.conf` to disable the p2p interface.

`rm /var/run/wpa_supplicant/p2p-dev-wanl`
