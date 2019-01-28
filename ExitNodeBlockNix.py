#!/usr/bin/python
import stem.descriptor.remote
from re import match
from subprocess import Popen


# VARIABLE DECLARATION
ip_pattern = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
tor_exit_list = []
block_list = []

# Connecting to TOR's directory servers and looking for all exit relays.  If
# the relay is an exit relay, we are going to store the IP address in a list.

for desc in stem.descriptor.remote.get_server_descriptors():
    if desc.exit_policy.is_exiting_allowed():
        tor_exit_list.append(desc.address)

# Sort the list to make it neat, and for ease of comparison if that becomes
# a desired feature later.  After we validate whethor not each entry is an
# actual IP address, we will block the IP addresses using iptables.
tor_exit_list.sort()

for ip_addr in set(tor_exit_list):
    if match(ip_pattern, ip_addr):
        Popen('/usr/bin/echo' + ip_addr)
