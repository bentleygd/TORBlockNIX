from TORBlockNIX.ListExitNode import get_exit_relays
from os.path import exists
from os import remove


class TestTORStuff:
    """A class for testing retrieving things via the stem module.

    Keyword aguments:
    None

    Methods:
    test_exit_list - Tests connecting to TOR and populating a list of exit
    relays.
    """

    def test_exit_list(self):
        """Tests retrieving a list of exit relays."""
        tor_exit_list = get_exit_relays()
        assert len(tor_exit_list) > 10


class TestUserPrivs:
    """A class for testing permissions of current user.

    Keyword arguments:
    None.

    Methods:
    test_file_create - Tests writing to files.
    test_file_remove - Tests file deletion."""

    def test_file_create(self):
        """Tests writing to files."""
        test_file_name = 'test_file.txt'
        test_file = open(test_file_name, 'w', encoding='ascii')
        test_file.write('Some string.')
        test_file.close()
        if exists(test_file_name):
            test = True
        else:
            test = False
        assert test is True
    
    def test_file_remove(self):
        """Tests file deletion."""
        test_file_name = 'test_file.txt'
        remove(test_file_name)
        if not exists(test_file_name):
            test = True
        else:
            test = False
