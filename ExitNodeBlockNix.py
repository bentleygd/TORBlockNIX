#!/usr/bin/python
import stem.descriptor.remote
from re import match, search, split
from subprocess import check_output, CalledProcessError, STDOUT, Popen
from sys import exc_info
from time import sleep


# This function sets up iptables by creating a specific chain to block
# TOR exit nodes.  It also modifies the INPUT chain to jump to this chain
# first and sets the last rule of this chain to jump back to INPUT.

def TORChainSetup():
    try:
        check_output('/sbin/iptables -N TOR-BLOCK', shell=True, sterr=STDOUT)
    except CalledProcessError as CreateChain:
        if match('iptables: Chain already exists\.', CreateChain.output):
            pass
        if search('Permssion Denied', CreateChain.output):
            print 'Error:', CreateChain.output
            print 'Try executing the script as root.'
            sys.exit(1)
        else:
            print 'The error given by iptables is:', CreateChain.output
            print 'Error:', exc_info[1]

# Obtain a list of iptables rules for the TOR-BLOCK chain.
    list_block_chain = split('\n', check_output('/sbin/iptables -L TOR-BLOCK',
                             shell=True, stderr=STDOUT))

# Check to see if there is a return rule, and if there isn't create one.
    for entry in list_block_chain:
        if search('^RETURN', entry):
            pass
        else:
            Popen('/sbin/iptables -A -j RETURN', shell=True)

# Create a count of iptables rules that are not the return rule in the
# TOR-BLOCK chain.  Once we have this we will iterate a process toe delete
# all the rules that have a range between 1 and n, where n equals the number
# of iptables rules that are not a return rule.
    block_chain_num = 0
    for entry in list_block_chain:
        if search('^RETURN', entry):
            pass
        else:
            block_chain_num = block_chain num + 1

    del_num = block_chain_num + 1
    del counter = 0
    for rule_num in range(1, del_num):
        if del_counter <= 10:
            Popen('/sbin/iptables -D ' + str(del_num) + 'TOR-BLOCK',
                  shell=True)
        else:
            del_counter = 0
            sleep(1)


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
        block_list.append(ip_addr)
