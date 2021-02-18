# Netplan

## Configuring Static IP address on Ubuntu Server (Here for Referance)

Do not connect the network and WiFi at the same time might not work on who ever get's an IP first as.

`sudo vim /etc/netplan/50-cloud-init.yaml`

```
network:
    ethernets:
        eth0:
            dhcp4: true
            optional: true
    version: 2
    ethernets:
        eth1:
            dhcp4: false
            optional: true
            addresses:
              - 192.168.1.30/24
            gateway4: 192.168.1.1
            nameservers:
                addresses: [192.168.1.1, 8.8.8.8]
    wifis:
        wlan0:
            optional: true
            access-points:
                 "SSID-NAME-HERE":
                    password: "PASSWORD-HERE"
            dhcp4: false
            addresses:
              - 192.168.1.31/24
            gateway4: 192.168.1.1
            nameservers:
                addresses: [192.168.1.1, 8.8.8.8]


```

**Referance:** [Promiscuous Mode](https://discourse.ubuntu.com/t/netplan-multiple-interfaces/20662) 

**Example 3 Interfaces:** 

The script defines `P_IFACES`, a bash array of interfaces. That can be modified to include multiple interface names. Here is a practical on a device with 5 interfaces in promiscuous mode 

`P_IFACES=( eno2 eno3 eno4 eno5 eno6 )`
Here is the full file to be deployed, which adds some hacky logging from 

```sh
# cat /etc/networkd-dispatcher/unmanaged.d/50promisc
#!/usr/bin/env bash

echo "promisc $(date)" >> /var/tmp/promisc.log
echo "$IFACE : $AdministrativeState : $OperationalState" >> /var/tmp/promisc.log
P_IFACES=( eno2 eno3 eno4 eno5 eno6 )
for P_IFACE in ${P_IFACES[@]}; do
    if [[ "${IFACE}" == "${P_IFACE}" ]]; then
        echo "doit" >> /var/tmp/promisc.log
        ip link set ${IFACE} up promisc on
    fi
done
```

**Referance:** Intresting Read: [How To Configure Netplan Network? – Examples](https://getlabsdone.com/how-to-configure-netplan-network/)
