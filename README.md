# Sharlock

This is a helpful python script users can use to filter brute-force attempts, files and URLs, and/or FIN/NULL/XMAS scans from a .pcap file in one execution. 

# Pre-requisites

* Wireshark (application)

* pyfiglet (command)

# Packet Analyzer

* Stealthy Scan
  * Alerts against port (FIN/NULL/XMAS flag) scanning
* Too many login attempts (poss. Brute Force)
  * Checks if login attempts exceeds more than five attempts
     (attempts can be changed to a higher or lower number in script in accordance to user’s preference)

# Files and URLs

* Extracts URLs from HTTP GET Requests
* Checks for reverse shell(s)


# Command Line (Linux)

./sharlock.py [PCAPFILE]

**Example:** 
      ./sharlock.py network.pcap
