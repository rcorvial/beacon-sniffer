## BEACON SNIFFER

#### CONFIGURING AND RUNNING

To allow sniffing wireless traffic in monitor mode, you have to configure the wireless interface in monitor mode:<br/>

sudo rfkill unblock all<br/>
sudo ifconfig $INTERFACE down<br/>
sudo iwconfig $INTERFACE mode monitor<br/>
sudo ifconfig $INTERFACE up<br/>

Then, you can run the application with no problems (like wireshark):<br/>

sudo ./beacon-sniffer $INTERFACE<br/>


#### COMPILING

To compile the application for your platform you only have to run the command "make".<br/>


#### RELATED LINKS

http://wifinigel.blogspot.com.es/2013/11/what-are-radiotap-headers.html<br/>
https://www.kernel.org/doc/Documentation/networking/radiotap-headers.txt
