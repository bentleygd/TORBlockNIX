# TORBlockNIX
This project utilizes Python to block all traffic from TOR exit nodes using a host-based firewall.  This script can be easily modified to create lists of TOR exit nodes for other purposes.  All code is reviewed for conformance with PEP-8 and for common security vulnerabilities.

ExitNodeBlockNIX.py - This is a Python script designed to collect a list of TOR exit nodes and block them using iptables.  Ideally, you would want to run this script on a regular interval (i.e., scheduled by cron or anacron) on all of your publicly facing servers to deny would be attackers the ability to scan/abuse any publicly facing servers from TOR.
