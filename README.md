# 1. What is pcap_anonymizer about
This tool is about anonymizing IP and MAC Addresses of a given pcap file. This can either be used for:
- Anynomizing a legitimate pcap file.  
- Anynomizing a localhost traffic pcap file to make it look real-world.  

# 2. Purpose
The purpose for this script is to modify IP and MAC addresses from a pcap file.  
I initially made this script when I was creating CTF challenges, specifically forensic ones, and wanted to change the IP and MAC addresses of my localhost traffic into random ones to make the traffic look real. I then thought to further develop it with more options, identification of Ip address classes and more. Whether you want to use it to make a CTF challenge or anonymize a pre-existing pcap file is up to you.

# 3. Overview
I will present both cases of using the tool:
- (1) Making localhost traffic look real: CTF case.
- (2) Anonymizing real traffic: Pre-existing pcap. 

## Overview - (1) Making localhost traffic look real
Assume we want to make a very simple CTF challenge. We want to:
- Send a file containing a flag (or some secret credentials) over the internet.
- Capture the traffic.

To do that, we would open a webserver with python like ```python3 -m http.server``` hosting a file named ```secrets.txt```.  

Using wget/curl or manually going to your browser to get the file - while capturing the traffic with Wireshark - would yield the following traffic:  

![image](https://github.com/user-attachments/assets/1ff1de4f-2bc1-4c05-8db9-c76afbc1a9b4)

Obviously, for a CTF challenge this traffic would normally not be acceptable. We would like to change the IP addresses and MAC addresses to make it look more realistic.  
Viewing the available options and the use of the tool:  
```sh
─$ python pcap_anonymizer.py --help
Usage: python script.py --inpcap <input_pcap_file> --outpcap <output_pcap_file> [--whitelist <file>] [--mod_null_mac <yes|no>] [--mod_localhost <yes|no>]

Options:
    --inpcap            Input PCAP file to anonymize.
    --outpcap           Output PCAP file name for anonymized packets.
    --whitelist         Optional file containing IP addresses to exclude from anonymization.
    --mod_null_mac      Set to 'yes' to anonymize MAC address '00:00:00:00:00:00', 'no' to preserve it. Default: no.
    --mod_localhost     Set to 'yes' to anonymize localhost IPs ('127.0.0.1'), 'no' to preserve them. Default: no.
```

If we want to change both the localhost IP and MAC, the address we would run to fully anonymize our localhost traffic would be:
```python pcap_anonymizer.py --inpcap localhost_traffic.pcapng --outpcap randomized.pcapng --mod_null_mac yes --mod_localhost yes```

Let's see the results:  

![randomize_localhost](https://github.com/user-attachments/assets/e1b442c0-68c0-47fa-8cca-9c711290d732)

By now you would have a fully randomized pcap file looking completely real world, all by running just this script. Let's also see the case of anonymizing real world traffic.

## Overview - (2) Anonymizing real traffic
For this purpose 

