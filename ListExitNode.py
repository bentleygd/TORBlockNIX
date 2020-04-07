#!/usr/bin/python
import stem.descriptor.remote
from re import match
from logging import basicConfig, getLogger, INFO


def validate_ip(ip_addr):
    """Takes a string input and returns true if it is a valid IP.

    Keyword Arguments:
    ip_addr - a string (ip address) to validate.

    Raies:
    ValueError - Rasies when input string does not pass validation."""
    valid_ip = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if match(valid_ip, ip_addr):
        return True
    else:
        raise ValueError


def get_exit_relays():
    """Connects to TOR and returns a list of exit relays.

    Keyword Arguments:
    None

    Outputs:
    tor_exit_list - A list of exit relays.

    Raises:
    ValueError - Occurs when IP address does not pass input validation.
    Exception - Generic exception that occurs when attempting to retrieve a
    list of exit relays."""
    tor_exit_list = []
    log = getLogger('tor_exit_log')
    try:
        for desc in stem.descriptor.remote.get_server_descriptors():
            if (desc.exit_policy.is_exiting_allowed() and
                    validate_ip(desc.address)):
                tor_exit_list.append(desc.address)
    except ValueError:
        log.error(
            'Exit relay address did not pass input validation', exc_info=1
        )
    except Exception:
        log.error('Error occurred retrieving exit relays.', exc_info=1)
        exit(1)
    return tor_exit_list


def main():
    """Doing the thing."""
    log = getLogger('tor_exit_log')
    basicConfig(
        format='%(asctime)s %(name)s %(levelname)s: %(message)s',
        datefmt='%m/%d/%Y %H:%M:%S',
        level=INFO,
        filename='tor_exit_log.log'
    )
    try:
        exit_node_file = open('tor_list.txt', 'w', encoding='ascii')
    except OSError:
        log.error('Unable to open exit relay results file.', excinfo=1)
    log.debug('Retrieving list of exit relays from the TOR mirrors.')
    exit_relays = get_exit_relays()
    log.info('%d exit relays retrieved.' % len(exit_relays))
    log.debug('Writing exit relays to file.')
    for relay in set(exit_relays):
        exit_node_file.write(relay + '/32' + '\n')
    exit_node_file.close()
    log.debug('Completed attempt to retrieve exit relays.')


if __name__ == '__main__':
    main()
