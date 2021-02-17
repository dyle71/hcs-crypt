#!@Python3_EXECUTABLE@

# ------------------------------------------------------------
# This script runs an integraton test.
#
#   EXIT-CODE == 0 --> Success, test succeeded.
#   EXIT-CODE != 0 --> Failure. The exit code value may indicate the reason of failure.
# ------------------------------------------------------------

import os.path
import subprocess
import sys


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
    p = subprocess.Popen([get_crypt_path(), '--help'], stdout=out, stderr=err)
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

    line_count = 0
    line = out.readline()
    while line is not None and len(line) > 0:
        line_count = line_count + 1
        line = out.readline()

    if line_count == 0:
        sys.stderr.write('Result of --help is empty.\n')
        res = False

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
