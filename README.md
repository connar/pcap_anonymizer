# What is pcap_anonymizer about
This tool is about anonymizing IP and MAC Addresses of a given pcap file.

# Purpose
I initially made this script when I was creating CTF forensic challenges and wanted to change my localhost traffic IP and MAC to a random one to make the traffic look real.
I assume this tool might be useful for either that scenario or for someone that wants to anonymize traffic generated from IP, MAC or just change the overall info of a pcap file.

# Overview - Making a CTF
Let's assume the following simple scenario. You open a webserver with python (```python3 -m http.server```), hosting a file named ```fileForTransfer.txt```.  

Using wget/curl or manually going to your browser to get the file - while capturing the traffic with Wireshark - would yield the following traffic:  

![image](https://github.com/user-attachments/assets/66880141-bce6-413b-bd08-754dcbe3a7b1)  

Obviously, for a CTF challenge this traffic would normally not be acceptable. We would like to change the IP addresses and MAC addresses to make it look more realistic.  

