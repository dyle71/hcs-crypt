#!@Python3_EXECUTABLE@

# ------------------------------------------------------------
# This script runs an integraton test.
#
#   EXIT-CODE == 0 --> Success, test succeeded.
#   EXIT-CODE != 0 --> Failure. The exit code value may indicate the reason of failure.
# ------------------------------------------------------------

import os.path
import re
import subprocess
import sys


def expected_algorithms() -> list:
    """Returns the sorted list of expected algorithms.

    :return:    The sorted list of expected algorithms.
    """
    expected = ['copy', 'ltc-aes-128-cbc-decryptor', 'ltc-aes-128-cbc-encryptor', 'ltc-aes-128-ecb-decryptor',
                'ltc-aes-128-ecb-encryptor', 'ltc-aes-192-cbc-decryptor', 'ltc-aes-192-cbc-encryptor',
                'ltc-aes-192-ecb-decryptor', 'ltc-aes-192-ecb-encryptor', 'ltc-aes-256-cbc-decryptor',
                'ltc-aes-256-cbc-encryptor', 'ltc-aes-256-ecb-decryptor', 'ltc-aes-256-ecb-encryptor',
                'openssl-aes-128-cbc-decryptor', 'openssl-aes-128-cbc-encryptor', 'openssl-aes-128-ecb-decryptor',
                'openssl-aes-128-ecb-encryptor', 'openssl-aes-192-cbc-decryptor', 'openssl-aes-192-cbc-encryptor',
                'openssl-aes-192-ecb-decryptor', 'openssl-aes-192-ecb-encryptor', 'openssl-aes-256-cbc-decryptor',
                'openssl-aes-256-cbc-encryptor', 'openssl-aes-256-ecb-decryptor', 'openssl-aes-256-ecb-encryptor',
                'ltc-md5', 'ltc-ripemd128', 'ltc-ripemd160', 'ltc-ripemd256', 'ltc-ripemd320', 'ltc-sha1', 'ltc-sha224',
                'ltc-sha256', 'ltc-sha384', 'ltc-sha512', 'ltc-tiger192', 'nohash', 'openssl-md5', 'openssl-ripemd160',
                'openssl-sha1', 'openssl-sha224', 'openssl-sha256', 'openssl-sha384', 'openssl-sha512']
    expected.sort()
    return expected


def get_crypt_path() -> str:
    """Returns the path to the crypt executable.

    :return:    The path to the current compiled executbale.
    """
    return os.path.join('@CMAKE_BINARY_DIR@', 'src', 'bin', 'crypt')


def prepare() -> bool:
    """Prepares the test environment.

    :return:    True, if all is set up properly.
    """
    sys.stderr.write('Preparing test environment...\n')
    return True


def run(out_name: str, err_name: str) -> bool:
    """Runs the test.

    :param out_name:    name of the output file.
    :param err_name:    name of the error information file.
    :return:            True, if all went well.
    """
    sys.stderr.write('Running test...\n')
    out = open(out_name, 'w')
    err = open(err_name, 'w')
    p = subprocess.Popen([get_crypt_path(), '--list'], stdout=out, stderr=err)
    p.communicate(timeout=1.0)
    out.close()
    err.close()

    return True


def test() -> int:
    """Runs the test.

    :return:    Exit code of test process.
    """

    if not prepare():
        sys.stderr.write('Failed to prepare test environment. Test aborted.\n')
        return 1

    success = run(out_name='stdout', err_name='stderr')
    if success:
        success = verify(out_name='stdout', err_name='stderr')
    wind_down()

    if not success:
        sys.stderr.write('Test Failed.\n')
        return 1

    sys.stderr.write('==== TEST SUCCESS ====\n')
    return 0


def verify(out_name: str, err_name: str) -> bool:
    """Verifies the test results.

    :param out_name:    name of the output file.
    :param err_name:    name of the error information file.
    :return:            True, if the test results matches the expected values.
    """

    sys.stderr.write('Verifying test results...\n')
    try:
        out = open(out_name, 'r')
    except FileNotFoundError as e:
        sys.stderr.write('Failed to examine output: ' + str(e) + '\n')
        return False

    try:
        err = open(err_name, 'r')
    except FileNotFoundError as e:
        sys.stderr.write('Failed to examine error info: ' + str(e) + '\n')
        return False

    # optimistic
    res = True

    known_algorithms = []
    pattern = re.compile(r'^\s\s*(..*)')
    line = out.readline()
    while line is not None and len(line) > 0:
        m = pattern.match(line)
        if m is not None:
            known_algorithms.append(m.group(1))
        line = out.readline()
    known_algorithms.sort()

    res = known_algorithms == expected_algorithms()
    if not res:
        sys.stderr.write('List of algorithms differ from what is expected.\n')

    line = err.readline()
    if line is not None and len(line) > 0:
        sys.stderr.write('Discovered an error when expected none.\n')
        res = False

    out.close()
    err.close()

    return res


def wind_down() -> None:
    """Cleanup after tests."""
    sys.stderr.write('Cleaning up...\n')


if __name__ == '__main__':
    sys.exit(test())
