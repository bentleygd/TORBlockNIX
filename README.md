# TORBlockNIX
This project utilizes Python to block all traffic from TOR exit nodes using a host-based firewall.  All code is reviewed for conformance with PEP-8 and for common security vulnerabilities via the use of SWAMP (https://www.mir-swamp.org)

ExitNodeBlockNIX.py - This is a Python script designed to collect a list of TOR exit nodes and block them on NIX hosts using iptables. The iptables syntax has been tested on Linux systems only.  Ideally, you would want to run this script on a regular interval (i.e., scheduled by cron or anacron) on all of your publicly facing servers to deny would be attackers the ability to scan/abuse any publicly facing servers from TOR.

ListExitNode.py - This script writes a list of all TOR exit nodes to a text file.
