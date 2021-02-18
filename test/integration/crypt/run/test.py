#!@Python3_EXECUTABLE@

# ------------------------------------------------------------
# This script runs an integraton test.
#
#   EXIT-CODE == 0 --> Success, test succeeded.
#   EXIT-CODE != 0 --> Failure. The exit code value may indicate the reason of failure.
# ------------------------------------------------------------

import hashlib
import os.path
import re
import subprocess
import sys


def get_catalog() -> dict:
    """Returns the catalog of to be tested algorithms, input and output.

    :return:    **TODO: TBD**
    """
    input_file_paths = get_input_file_paths()
    return {
        'copy': [(input_file_paths[0], 'sha256:015d60fac720421198c39bc637e25435188085d83911e790e734fb2bfdc99032'),
                 (input_file_paths, 'bar')]
    }


def get_crypt_path() -> str:
    """Returns the path to the crypt executable.

    :return:    The path to the current compiled executbale.
    """
    return os.path.join('@CMAKE_BINARY_DIR@', 'src', 'bin', 'crypt')


def get_input_file_paths() -> list:
    """Returns a list of input files to perform an algorithm on.

    :return:    a list of input file.
    """
    return [os.path.join('@TEST_BASE_DIR@', 'shared', f) for f in
            ['ipsum-lorem-1.txt', 'ipsum-lorem-2.txt', 'ipsum-lorem-3.txt']]


def prepare() -> bool:
    """Prepares the test environment.

    :return:    True, if all is set up properly.
    """
    sys.stderr.write('Preparing test environment...\n')
    return True


def run() -> bool:
    """Runs the test.

    :param out_name:    name of the output file.
    :param err_name:    name of the error information file.
    :return:            True, if all went well.
    """

    res = True
    catalog = get_catalog()
    for algorithm in catalog:
        single_file = catalog[algorithm][0]
        res = res and run_single_file_argument(algorithm, single_file[0], single_file[1])

    return res


def run_single_file_argument(algorithm: str, file_path: str, expected: str) -> bool:
    """Runs crypt with a single file argument

    If 'expected' starts with 'sha256:' then the result file is hashed with sha256 and
    compared against the rest of expected.

    :param algorithm:       the algorithm to be used.
    :param file_path:       the file path.
    :param expected:        the expected value.
    :return:                True if the result of crypt is the expected value.
    """
    if len(algorithm) == 0 or len(file_path) == 0 or len(expected) == 0:
        sys.stderr.write('Invalid arguments for run_single_file_argument()\n')
        return False

    sys.stderr.write(f'Running test: {algorithm} - single file argument...\n')

    out_name = os.path.join(algorithm + '.single_file_argument.stdout')
    err_name = os.path.join(algorithm + '.single_file_argument.stderr')
    out = open(out_name, 'w')
    err = open(err_name, 'w')
    p = subprocess.Popen([get_crypt_path(), algorithm, file_path], stdout=out, stderr=err)
    p.communicate(timeout=5.0)
    out.close()
    err.close()

    res = verify(out_name, err_name, expected)
    res = res

    return res


def test() -> int:
    """Runs the test.

    :return:    Exit code of test process.
    """

    if not prepare():
        sys.stderr.write('Failed to prepare test environment. Test aborted.\n')
        return 1

    success = run()
    wind_down()

    if not success:
        sys.stderr.write('Test Failed.\n')
        return 1

    sys.stderr.write('==== TEST SUCCESS ====\n')
    return 0


def verify(out_name: str, err_name: str, expected: str) -> bool:
    """Verifies the test results.

    If 'expected' starts with 'sha256:' then the result file is hashed with sha256 and
    compared against the rest of expected.

    :param out_name:    name of the output file.
    :param err_name:    name of the error information file.
    :param expected:    the expected value.
    :return:            True, if the test results matches the expected values.
    """

    sys.stderr.write('Verifying test results...\n')
    try:
        err = open(err_name, 'r')
    except FileNotFoundError as e:
        sys.stderr.write('Failed to examine error info: ' + str(e) + '\n')
        return False

    # optimistic
    res = True

    line = err.readline()
    if line is not None and len(line) > 0:
        sys.stderr.write('Discovered an error when expected none.\n')
        res = False
    err.close()

    if expected.startswith('sha256:'):

        try:
            out = open(out_name, 'rb')
        except FileNotFoundError as e:
            sys.stderr.write('Failed to examine output: ' + str(e) + '\n')
            return False

        sha256 = hashlib.sha256()
        block = out.read(64 * 1024)
        while block is not None and len(block) > 0:
            sha256.update(block)
            block = out.read(64 * 1024)

        res = sha256.hexdigest() == expected[7:]
        out.close()

    return res


def wind_down() -> None:
    """Cleanup after tests."""
    sys.stderr.write('Cleaning up...\n')


if __name__ == '__main__':
    sys.exit(test())
