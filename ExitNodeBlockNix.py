#!/usr/bin/python
# Created by Gabriel Bentley
# Licensed under GPLv3
import stem.descriptor.remote
from re import match, search, split
from subprocess import check_output, CalledProcessError, STDOUT, Popen
from sys import exc_info
from time import sleep


# This function sets up iptables by creating a specific chain to block
# TOR exit nodes.  It also modifies the INPUT chain to jump to this chain
# first and sets the last rule of this chain to jump back to INPUT.

def TORChainSetup():
    """Sets up iptables for blocking TOR exit nodes."""
    try:
        check_output(['/sbin/iptables', '-N', 'TOR-BLOCK'], sterr=STDOUT)
    except CalledProcessError as CreateChain:
        if match('iptables: Chain already exists\.', CreateChain.output):
            pass
        if search('Permssion Denied', CreateChain.output):
            print 'Error:', CreateChain.output
            print 'Try executing the script as root.'
            exit(1)
        else:
            print 'Unrecognized error!'
            print 'The error given by iptables is:', CreateChain.output
            print 'Error:', exc_info[1]
            exit(1)

# Obtain a list of iptables rules that are the current TOR-BLOCK chain.
    list_block_chain = split('\n', check_output(['/sbin/iptables', '-L',
                             'TOR-BLOCK']))

# Check to see if there is a return rule, and if there isn't create one.
    for entry in list_block_chain:
        if search('^RETURN', entry):
            break
        else:
            Popen(['/sbin/iptables', '-A', '-j', 'RETURN'])

# Set up the INPUT chain to jump to TOR-BLOCK.
    input_chain = split('\n', check_output(['/sbin/iptables', '-L', 'INPUT']))
    for entry in input_chain:
        if search('^TOR-BLOCK', entry):
            break
        else:
            Popen(['/sbin/iptables', '-I', 'INPUT', '1', '-j', 'TOR-BLOCK'])

# Create a count of iptables rules that are not the RETURN rule in the
# TOR-BLOCK chain.  Once we have this we will iterate a process to delete
# all the rules that have a range between 1 and n, where n equals the
# number of iptables rules that are not a return rule. Note the sleep
# statement that is used to prevent iptables from not being able to keep
# up with deleting chain entries.
    block_chain_num = 0
    for entry in list_block_chain:
        if search('^RETURN', entry):
            pass
        else:
            block_chain_num = block_chain_num + 1
    del_num = block_chain_num + 1
    del_counter = 0
    for rule_num in range(1, del_num):
        del_counter = del_counter + 1
        if del_counter <= 10:
            Popen(['/sbin/iptables', '-D', str(rule_num), 'TOR-BLOCK'])
        else:
            del_counter = 0
            sleep(1)


def FetchExitNodes():
    """Returns a TOR exit node list."""
# Connecting to TOR's directory servers and looking for all exit relays.
# If the relay is an exit relay, we are going to store the IP address
# in a list. After we validate whether or not a each entry is a valid IP
# address, we will return the valid IPs.
    tor_exit_list = []
    for desc in stem.descriptor.remote.get_server_descriptors():
        if desc.exit_policy.is_exiting_allowed():
            tor_exit_list.append(desc.address)
    block_list = []
    tor_exit_list.sort()
    for ip_addr in set(tor_exit_list):
        try:
            if match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip_addr):
                block_list.append(ip_addr)
            else:
                raise ValueError
        except ValueError:
            print 'Invalid IP address encountered.  Exiting.'
            exit(1)
    return block_list


def BlockExitNodes(ExitNodeList):
    """Calls iptables to block exit nodes."""
# Setting up iptables to log and block all TOR exit node traffic. The
# log level is being set to info, so modify your logging/syslog
# configurations to not log informational events if you don't want to
# log such traffic to a log collector/SIEM.
    Popen(['/sbin/iptables', '-I', 'TOR-BLOCK', '1', '-j', 'LOG',
           '--log-level', '6'])
    block_counter = 0
    for ip in ExitNodeList:
        block_counter = block_counter + 1
        if block_counter <= 10:
            Popen(['/sbin/iptables', '-I', 'TOR-BLOCK', '2', '-s ', ip, '-j',
                   'DROP'])
        else:
            block_counter = 0
            sleep(1)


TORChainSetup()
ExitNodes = FetchExitNodes()
BlockExitNodes(ExitNodes)
