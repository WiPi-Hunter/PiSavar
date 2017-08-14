   # PiSavar  - [ - PineAP - Analysis, Detect, Kill - ]

<p align="center">
<img src="https://github.com/besimaltnok/pineAPhunter/blob/master/pineapple.png" width="200" height="300">
</p>

<p align="center">
<img src="https://img.shields.io/badge/Python-2-yellow.svg"></a> <img src="https://img.shields.io/badge/license-GPLv3-red.svg">
</p>

### About Project

The goal of this project is to find out the fake access points opened by the WiFi pineapple device using the PineAP module and to prevent clients from being affected by initiating a deauthentication attack on the attacking device.


### How PineAP Work

* Collect SSID information
* Creates SSID pool with collected SSID information
* Creates fake access points using information in the SSID pool

<img src="images/pineap.png" width="50%"></img>

### Where is the problem?

- ![#f03c15](https://placehold.it/15/f03c15/000000?text=+) `One MAC address, more than one SSID information .... ..- -. - . .-. `


### Features of PiSavar

* Detects PineAP activities 
* Detects networks opened by PineAP.
* Starts deauthentication attack for PineAP.

### Features to add

* List of clients connected to fake access points
* Record activities - Logging

#### Diagram

<img src="images/info.png" width="50%"></img>

### --------------------------------------------------------------------------------

### Usage

#### Requirements

* **Hardware:** TP LINK TL-WN722N
* **Modules:** scapy, time, termcolor

#### Kali Linux:

Download pisavar:

`git clone https://github.com/besimaltnok/PiSavar.git`

Install Python librarie(s):

`pip install termcolor`

It's done!

Run the program with following command: 

Monitor mode:

```python
airmon-ng start interface(wlan0,wlan1) (Monitor mode)

or 

ifconfig wlan0 down
iwconfig wlan0 mode Monitor
ifconfig wlan0 up
```

Run:

```python
cd PiSavar
python pisavar.py wlan0mon
```

### Screenshots
<img src="images/pisavarnew.png" width="28%"></img>
<img src="images/dosnew.png" width="39%"></img>


### Demo Video

https://youtu.be/P7mfh37NZc0

### Authors
This project is written by Besim ALTINOK
