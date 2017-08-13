# PiSavar  - [ - PineAP Suite - Analysis, Detect, Kill - ]

<center><img src="https://github.com/besimaltnok/pineAPhunter/blob/master/pineapple.png" width="300" height="400"/></center>


### How to work PineAP Suite

* Collect SSID information
* Creates SSID pool with collected SSID information
* Creates fake access points using information in the SSID pool

### Where is the problem?

- ![#f03c15](https://placehold.it/15/f03c15/000000?text=+) `One MAC address, more than one SSID information .... ..- -. - . .-. `


### Features of PiSavar

* Detects PineAP Suite 
* Detects networks opened by PineAP Suite.
* List of clients connected to fake access points
* Starts deauthentication attack for PineAP Suite.


### --------------------------------------------------------------------------------

### Usage
Run the program with following command: 

```python
airmon-ng start wlan0
python pisavar.py wlan0mon

```


### Screenshots

<img src="images/pisavar2.png" width="50%"></img>

### Demo Video

### Authors
This project is written by Besim ALTINOK
