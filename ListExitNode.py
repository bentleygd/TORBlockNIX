#!/usr/bin/python
import stem.descriptor.remote
from re import match


# VARIABLE DECLARATION
file_path = '/path/to/output.txt'
ip_pattern = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
tor_exit_list = []

# Obtain a list of exit nodes and write them to a file after verifying
# that each entry is an IP addres.
for desc in stem.descriptor.remote.get_server_descriptors():
    if desc.exit_policy.is_exiting_allowed():
        tor_exit_list.append(desc.address)
tor_exit_list.sort()
exit_node_file = open(file_path, 'w')
for ip_addr in set(tor_exit_list):
    if match(ip_pattern, ip_addr):
        exit_node_file.write(ip_addr + '/32' + '\n')
exit_node_file.close()
