#
# Wireshark tests
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
"""Every synthetic capture a tools/gen-*-test-capture.py writes is the one in
test/captures: a generator edited without regenerating, or the reverse, fails
here instead of leaving frame numbers in the suites and comments to drift.

Each generator runs in a scratch tree laid out like the repository, so it
writes its captures there and the committed ones are only read.
"""

import gzip
import pathlib
import shutil
import subprocess
import sys

import pytest

TOOLS = pathlib.Path(__file__).resolve().parent.parent / 'tools'
CAPTURES = pathlib.Path(__file__).resolve().parent / 'captures'
GENERATORS = ('gen-mctp-test-capture.py', 'gen-mctp-smbus-test-capture.py',
              'gen-mctp-control-test-capture.py', 'gen-nvme-tcp-test-capture.py',
              'gen-nvme-mi-test-capture.py')


def content(path):
    return gzip.open(path).read() if path.suffix == '.gz' else path.read_bytes()


@pytest.mark.parametrize('generator', GENERATORS)
def test_committed_captures_are_generated(generator, tmp_path):
    (tmp_path / 'tools').mkdir()
    (tmp_path / 'test' / 'captures').mkdir(parents=True)
    for name in (*GENERATORS, 'pcapng_testgen.py'):
        shutil.copy(TOOLS / name, tmp_path / 'tools' / name)
    subprocess.run([sys.executable, str(tmp_path / 'tools' / generator)], cwd=tmp_path,
                   check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    written = sorted((tmp_path / 'test' / 'captures').iterdir())
    assert written, f'{generator} wrote no capture'
    stale = [p.name for p in written
             if not (CAPTURES / p.name).exists() or content(p) != content(CAPTURES / p.name)]
    assert not stale, f'{generator}: not what test/captures holds: {stale}'
