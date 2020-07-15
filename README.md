# Sharlock.py

This is a helpful python script users can use to filter brute-force attempts, files and URLs, and/or FIN/NULL/XMAS scans from a .pcap file in one execution. 

# Pre-requisites

Wireshark

# Packet Analyzer

* Stealthy Scan
  * Alerts against FIN/NULL/XMAS flag scan
* Too many login attempts (poss. Brute Force)
  * Checks if login attempts exceeds more than five attempts
   * (attempts can be changed to a higher or lower number according to user’s preference)

# Files and URLs

# Running

./sharlock.py [-r PCAPFILE]
