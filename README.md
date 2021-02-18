
# How to use a Raspberry PI as a Network Sensor with Zeek and Rita

Ideas based on [How to use a Raspberry PI as a Network Sensor](https://activecountermeasures.com/raspberry_pi_sensor/How%20to%20use%20a%20Raspberry%20Pi%20as%20a%20network%20sensor.pdf)

Inspired by Bill Stearns How to use a Raspberry PI as a Network Sensor intial thoughts was that [RITA](https://github.com/activecm/rita) will not run on RPi Rasbian OS as it appears to need MongoDB 64bit. Going to attempt to try to run [Ubuntu 18.04 LTS](https://cdimage.ubuntu.com/releases/18.04/release/)

# Scope

1. Run in headless mode
2. No GUI assuming will save on resources 

# Ubuntu Setup

## Installation 

Folow these steps: [Install Ubuntu Server 20.04 LTS on Raspberry Pi 4 in Headless Mode and SSH Into It](https://linuxhint.com/install_ubuntu_ssh_headless_raspberry_pi_4/) or these [Install Ubuntu on Raspberry Pi](https://janw.me/raspberry-pi/install-ubuntu-on-raspberry-pi-headless/)

Download 18.04 server image [ubuntu-18.04.5-preinstalled-server-arm64+raspi4.img.xz](https://cdimage.ubuntu.com/releases/18.04/release/ubuntu-18.04.5-preinstalled-server-arm64+raspi4.img.xz) to substitute the others mentioned in the articales 

# Updates

`sudo apt update && sudo apt upgrade -y` 

ERROR:

```
E: Could not get lock /var/lib/dpkg/lock-frontend - open (11: Resource temporarily unavailable)
E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), is another process using it?

```

FIX ERROR:

1. Stop the automatic updater.

`sudo dpkg-reconfigure -plow unattended-upgrades`
At the first prompt, choose not to download and install updates.
**reboot**

2. Make sure any packages in an unclean state are installed correctly.

`sudo dpkg --configure -a`

3. Get your system up-top-date.

`sudo apt update && sudo apt -f install && sudo apt full-upgrade`

4. Turn the automatic updater back on or not.

`sudo dpkg-reconfigure -plow unattended-upgrades`
Select the package unattended-upgrades again.

# OR

```sh
$ sudo fuser -v /var/lib/dpkg/lock-frontend
                     USER        PID ACCESS COMMAND
/var/lib/dpkg/lock-frontend:
                     root       2112 F.... unattended-upgr

$ ps aux | grep 2112
root      2112 66.5  8.1 366108 113508 ?       Sl   13:03   0:28 /usr/bin/python3 /usr/bin/unattended-upgrade --download-only

$ dpkg -S /usr/bin/unattended-upgrade
unattended-upgrades: /usr/bin/unattended-upgrade
```

```sh
sudo kill -KILL 2112 

```

```sh
sudo apt install -f
sudo dpkg --configure -a
sudo apt-purge unattended-upgrades
```

# Hostname

`sudo hostnamectl set-hostname urhostname`

`sudo reboot now`


**Referance:** [Ubuntu 18.04: Disable Netplan switch back to networking /etc/network/interfaces](https://tweenpath.net/ubuntu-18-04-disable-netplan-switch-networking-etc-network-interfaces/)

## Configure a network interface into promiscuous mode

>**Note:** 
> On 18.04, we install networkd-dispatcher (see https://netplan.io/faq#use-pre-up-po...c-hook-scripts) which will allow you to run any further command you might need to finish the configuration of services / interfaces. That should allow you to make sure 'ip link set ens192 promisc on' will persist across a reboot.

# Setup & Install ifupdown

## Install

Install the `ifupdown` package and `resolvconf`

```sh
sudo apt-get update
sudo apt-get install -y ifupdown resolvconf

```

## Setup ifupdown

Replace configuration files
Delete all of the Netplan configuration files:

`sudo rm -rf /etc/netplan/*.yml` or back it up until up and running `cp  /etc/netplan/50-cloud-init.yaml  /etc/netplan/50-cloud-init.yaml.bak`

Open the file `/etc/network/interfaces` and copy and paste the following:

```sh
# The loopback network interface
auto lo
iface lo inet loopback

# Mirror
auto eth0
iface eth0 inet manual
  up ifconfig 0.0.0.0 up
  up ip link set eth0 promisc on
  down ip link set eth0 promisc off
  down ip link set eth0 down

# Mgmt
allow-hotplug eth1
auto eth1
iface eth1 inet static
  address 192.168.1.30
  netmask 255.255.255.0
  broadcast 192.168.1.255
  gateway 192.168.1.1
  dns-nameservers 192.168.1.1 8.8.8.8

source /etc/network/interfaces.d/*.cfg
```

## Setup resolv.conf

Find out whether /etc/resolv.conf is a static file or symlink by the following command:

```sh
$ ls -l /etc/resolv.conf

 /etc/resolv.conf -> ../run/resolvconf/stub-resolv.conf
```

Need to remove the symlink between `/etc/resolv.conf` and `stub-resolv.conf `

Issue the following command to change the symlink `/etc/resolv.conf` to point default dns server `192.168.1.1` instead of `127.0.0.53`.

```sh
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf

ls -l /etc/resolv.conf
```

Reboot 
```sh
reboot
```

### Promiscuous Mode

**Enable promiscuous mode:**

```sh

sudo ifconfig eth0 promisc
```

**Validate mode insabled:**

```sh
ip -d link show eth0 
2: eth0: mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000
link/ether 14:fe:b5:d5:51:9e brd ff:ff:ff:ff:ff:ff promiscuity 1 addrgenmode eui64 numtxqueues 8 numrxqueues 8 gso_max_size 65536 gso_max_segs 65535
```

`promiscuity 1` means that the interface is in promiscuous mode
`promiscuity 0` means that the interface is not in promiscuous mode

```sh
netstat -i
Kernel Interface table
Iface   MTU Met   RX-OK RX-ERR RX-DRP RX-OVR    TX-OK TX-ERR TX-DRP TX-OVR  Flg
eth0       1500 0     26631      0      0 0         27143      0      0      0 BMPR
```

**Disable promiscuous mode**

```sh
sudo ifconfig eth0 -promisc
sudo tail -f /var/log/syslog
kernel: [ 2155.176013] device eth0 left promiscuous mode

netstat -i
Kernel Interface table
Iface   MTU Met   RX-OK RX-ERR RX-DRP RX-OVR    TX-OK TX-ERR TX-DRP TX-OVR Flg
eth0       1500 0     29172      0      0 0         29850      0      0      0 BMRU

```

# Enable /etc/rc.local on Systemd


`sudo systemctl status rc-local`



# Enable `/etc/rc.local`

Note: Starting with 16.10, Ubuntu doesn’t ship with `/etc/rc.local` file anymore. You can create the file by executing this command.

You may get this output:

```sh
● rc-local.service - /etc/rc.local Compatibility
 Loaded: loaded (/lib/systemd/system/rc-local.service; static; vendor preset: enabled)
 Active: failed (Result: exit-code) since Thu 2015-11-26 23:54:58 CST; 59s ago
 Process: 1001 ExecStart=/etc/rc.local start (code=exited, status=1/FAILURE)
....
....
....
```

Output my very, but might not get anything. 

## Solution

create a file:

`sudo vim /etc/systemd/system/rc-local.service`

Add content to it.

```sh
[Unit]
 Description=/etc/rc.local Compatibility
 ConditionPathExists=/etc/rc.local

[Service]
 Type=forking
 ExecStart=/etc/rc.local start
 TimeoutSec=0
 StandardOutput=tty
 RemainAfterExit=yes
 SysVStartPriority=99

[Install]
 WantedBy=multi-user.target
```

Run the following command to make sure `/etc/rc.local` file is executable.

`sudo chmod +x /etc/rc.local`

Might need to create  `/etc/rc.local` create the file by executing this command.

```sh
printf '%s\n' '#!/bin/bash' 'exit 0' | sudo tee -a /etc/rc.local
```

Execute permission to `/etc/rc.local` file.

`sudo chmod +x /etc/rc.local`

Enable the service on system boot:

`sudo systemctl enable rc-local`

Output:

```sh
Created symlink from /etc/systemd/system/multi-user.target.wants/rc-local.service to /etc/systemd/system/rc-local.service.
```

start the service and check its status:

```sh
sudo systemctl start rc-local.service
sudo systemctl status rc-local.service
``

Output:

```sh
● rc-local.service - /etc/rc.local Compatibility
 Loaded: loaded (/etc/systemd/system/rc-local.service; enabled; vendor preset: enabled)
 Active: active (running) since Fri 2015-11-27 00:32:56 CST; 14min ago
 Process: 879 ExecStart=/etc/rc.local start (code=exited, status=0/SUCCESS)
 Main PID: 880 (watch)
 CGroup: /system.slice/rc-local.service
```

Final output:

```
#!/bin/bash

#ethtool command to reduce processing at eth0
ethtool -K eth0 gro off rx off tx off gso off
mkdir -p /opt/bro/pcaps

screen -S capture -t capture -d -m bash -c "nice -n 15 tcpdump -i eth0 -G 3600 -w '/opt/bro/pcaps/'`hostname -s`'.%Y%m%d%H%M%S.pcap' -z bzip2 '(tcp[13] & 0x17 != 0x10) or not tcp'"

ip link set eth0 promisc on
/usr/local/zeek/bin/zeekctl start


exit 0

```

> Note: ethtool has a fixed parameter for `large-receive-offload`, so needed to edit this in the `rc.local` 

**fixed** parameter like `large-receive-offload`:

```sh
sudo ethtool -K eth0 lro on
Cannot change large-receive-offload
Could not change any device features
```

```sh
ethtool -k eth0 | grep large-receive-offload
large-receive-offload: off [fixed]
```


**Referance:** [How to Enable /etc/rc.local with Systemd](https://www.linuxbabe.com/linux-server/how-to-enable-etcrc-local-with-systemd)


# Zeek IDS Installation on Raspberry PI

Downloading and installing pre-requisites to Zeek from source

```sh
sudo apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev

```

Addtional Packages 

```sh
sudo apt-get install libmaxminddb-dev postfix curl git

```

## Download and Install Zeek From git Source

```sh
git clone --recursive https://github.com/zeek/zeek

```

```sh
cd zeek
./configure
make
```

If everything goes right and no issues

```
sudo make install

```

Set the PATH

```sh
export PATH=/usr/local/zeek/bin:$PATH
vim ~/.profile
export PATH=/usr/local/zeek/bin:$PATH

```

### Setting up Zeek

All the Zeek files should be installed in `/usr/local/zeek`

Edit `/usr/local/zeek/etc/node.cfg` to set the interface to monitor; usually interface `eth0`

```sh
[zeek]
type=standalone
host=localhost
interface=eth0
```

Edit `/usr/local/zeek/networks.cfg` to add the IP addresses and short descriptions of your different routed networks. For example:

```sh
10.0.0.0/8 Private IP space
172.16.0.0/12 Private IP space 
192.168.0.0/16 Private IP space
Edit /usr/local/zeek/etc/zeekctl.cfg and set the
```

Edit `/usr/local/zeek/etc/zeekctl.cfg` and set the

`MailTo  = blah@blah.com`

Replace to your email address to receive reports from your Zeek instance and set the `LogRotationInterval `to the log archiving frequency.

### Starting up Zeek

Start the Zeek control shell with

`zeekctl`

On the first time use – we need to do the initial installation

`[ZeekControl] > install`
Then to start the zeek process

`[ZeekControl] > start`
I also like using

`[ZeekControl] > deploy`
to refresh settings when starting

To stop the Zeek process

`[ZeekControl] > stop`
Other commands in zeekctl are available with the ? notation

Also check

`/usr/local/zeek/logs/current`
for the latest log files and

`/var/log/mail.log`
to troubleshoot Zeek e-mail reports to your e-mail address.


Add the following to `/etc/rc.local` file before the `exit 0` line. IDS functionality is better with promiscuous mode on for the network interface. This will forward all packets to the CPU and not just the ones destined for the host.


```sh
ip link set eth0 promisc on
/usr/local/zeek/bin/zeekctl start

exit 0
```

Zeek needs to occasionally perform some scheduled maintenance:

```sh
crontab -e 
(select an editor and enter the following line)
 */5 * * * * /usr/local/zeek/bin/zeekctl
```

### Changing the log file format for better ingestion

The best way for external software to ingest your zeek logs is to convert them to `JSON` format. In the original config, Zeek creates human readable text tables for each kind of log file created in `/usr/local/zeek/logs/current` such as:

```sh
 cat capture_loss.log
#separator \x09
#set_separator  ,
#empty_field    (empty)
#unset_field    -
#path   capture_loss
#open   2019-08-31-02-04-06
#fields ts      ts_delta        peer    gaps    acks    percent_lost
#types  time    interval        string  count   count   double
1567213446.308621       900.000053      zeek    0       0       0.0
```

Edit /`usr/local/zeek/share/zeek/site/local.zeek`;

Add the following to the end of the file;

```sh
#JSON Output
@load policy/tuning/json-logs.zeek
```

Save and close the site file;
From the command-line restart zeek as the configuration has changed.
`zeekctl deploy`
Check to make sure your logs are now in JSON format.

```sh
 cat /usr/local/zeek/logs/current/packet_filter.log
{"ts":1567213927.478291,"node":"zeek","filter":"ip or not ip","init":true,"success":true}
```

**Referance:** [Zeek IDS Installation on Raspberry PI Part 1](https://www.secognition.com/?p=190)

# Installing MongoDB to the Raspberry Pi

## 1. Upgrade all existing packages by running the command below.

```sh
sudo apt update
sudo apt upgrade
```

## 2. Install the MongoDB server from the Raspbian repository

`sudo apt install mongodb`

## 3. Start the MongoDB service.

```sh
sudo systemctl enable mongodb
sudo systemctl start mongodb
```

Might get error about unable to resolve host (none)”

`/etc/hosts` has an entry for localhost. It should have something like:

```sh
127.0.0.1    localhost.localdomain localhost
127.0.1.1    my-machine
```

## 4. Fun the following command to interact with the database by using the command line.

`mongo`

# Checking the Mongo Service and Database

## 1. Check the status of our MongoDB server.

`sudo systemctl status mongodb`

Response as we have shown below.

```sh
● mongodb.service - An object/document-oriented database
   Loaded: loaded (/lib/systemd/system/mongodb.service; enabled; vendor
   Active: active (running) since Thu 2021-02-18 01:22:45 UTC; 1h 34min
     Docs: man:mongod(1)
 Main PID: 2066 (mongod)
    Tasks: 23 (limit: 4443)
   CGroup: /system.slice/mongodb.service
           └─2066 /usr/bin/mongod --unixSocketPrefix=/run/mongodb --con

```

## 2. Check the status of Mongo itself by retrieving its connection status.

```sh
mongo --eval 'db.runCommand({ connectionStatus: 1 })'

MongoDB shell version v3.6.3
connecting to: mongodb://127.0.0.1:27017
MongoDB server version: 3.6.3
{
        "authInfo" : {
                "authenticatedUsers" : [ ],
                "authenticatedUserRoles" : [ ]
        },
        "ok" : 1
}

```

**Referance:** [Installing MongoDB to the Raspberry Pi](https://pimylifeup.com/mongodb-raspberry-pi/)

# install Golang (Go) on Raspberry Pi

Current stable version available at [Golang official website](https://golang.org/dl/) is v1.16 and there is a distribution packaged for ARMv8 CPU [go1.16.linux-arm64.tar.gz](https://golang.org/dl/go1.16.linux-arm64.tar.gz)

`wget https://golang.org/dl/go1.16.linux-arm64.tar.gz`

```sh
sudo tar -C /usr/local -xzf o1.16.linux-arm64.tar.g
rm go1.12.6.linux-armv6l.tar.gz
```

Set `PATH` environment variable Golang is installed. To do that, edit the `~/.profile file`:

Scroll all the way down to the end of the file and add the following:

```sh
vim ~/.profile

PATH=$PATH:/usr/local/go/bin
GOPATH=$HOME/golang

```

Re-load profile 

`source ~/.profile`

`which` go to find out where the Golang installed and go version to see the installed version and platform.

```sh
which go
/usr/local/go/bin/go
go version
go version go1.12.6 linux/arm
```

**Referance:** [install Golang (Go) on Raspberry Pi](https://www.e-tinkers.com/2019/06/better-way-to-install-golang-go-on-raspberry-pi/)

# Building RITA

Aa `root` build RITA from source code see addtional setps [here](https://github.com/activecm/rita/blob/master/docs/Manual%20Installation.md) or summary below. 

1. `git clone https://github.com/activecm/rita.git`
2. `cd rita`
3. `make`
4. `make install` to install the binary to `/usr/local/bin/rita`


## Configuring the system

RITA requires some directories to be created for it to function correctly.

`sudo mkdir /etc/rita && sudo chmod 755 /etc/rita`
`sudo mkdir -p /var/lib/rita/logs && sudo chmod -R 755 /var/lib/rita`

Copy config file RITA source code dir.

`sudo cp etc/rita.yaml /etc/rita/config.yaml && sudo chmod 666 /etc/rita/config.yaml`

**Test ** using the `rita test-config` 


```sh
UserConfig:
  UpdateCheckFrequency: 14
MongoDB:
  ConnectionString: mongodb://localhost:27017
  AuthenticationMechanism: ""
  SocketTimeout: 2h0m0s
  TLS:
    Enable: false
    VerifyCertificate: false
    CAFile: ""
  MetaDB: MetaDatabase
Rolling:
  DefaultChunks: 24
  rolling: false
  currentchunk: 0
.......
.......
.......
```
