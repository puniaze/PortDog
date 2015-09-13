# PortDog

PortDog is a network anomaly detector aimed to detect port scanning techniques. It is entirely written in python and has easy-to-use interface. It was tested on Ubuntu 15. Please note that, it is not working on Windows OS due to suffering from capturing RAW packets.I am working on to write this script to work both platforms. In future , I'm thinking about adding firewall options that could block malicious attempts. It is using Raw packets for analysis. For this reason, please ensure that you have run this script from privileged session.

![alt tag](http://s019.radikal.ru/i620/1508/3d/36458b3536c5.jpg)
![alt tag](http://s017.radikal.ru/i426/1508/ab/555d29bbf346.jpg)
![alt tag](http://s018.radikal.ru/i512/1508/51/b933525686ed.jpg)

Usage:
```
sudo python portdog.py -t time_for_sniff_in_minutes
```
For example, if you want to detect for 5 minutes use:
```
sudo python portdog.py -t 5
```
For infinite detection use:
```
sudo python portdog.py -t 0
```
If you want to get list of scanned ports , press CTRL+C to get port list at runtime (If scan was happened).
You can share it or use it in your own scripts!
Please test it as much as possible , and give me feedback!
Thank u!

//Azerbaijanian WhiteHats 
