# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Run the reproducer scripts that some generators take frames from.

Several coverage captures include the frames of small reproducers written
for the bugs fixed in their dissector. The reproducers are kept as they
were written (each writes its pcap to its own directory, the current one
or the directory given as an argument); reproducer() runs one in a
temporary directory and returns the path of the file it wrote.
"""

import os
import shutil
import subprocess
import sys
import tempfile

_TMP = tempfile.TemporaryDirectory(prefix='repro-')


def reproducer(script, output, args=()):
    """Run script (a path; its directory is on the module path) in a
    temporary directory with args ('{out}' is replaced by that directory)
    and return the path of the file named output that it wrote there."""
    here = os.path.dirname(os.path.abspath(script))
    work = tempfile.mkdtemp(dir=_TMP.name)
    copy = os.path.join(work, os.path.basename(script))
    shutil.copy(script, copy)
    env = dict(os.environ)
    env['PYTHONPATH'] = os.pathsep.join(
        [here, os.path.dirname(os.path.abspath(__file__))] +
        ([env['PYTHONPATH']] if env.get('PYTHONPATH') else []))
    subprocess.run([sys.executable, copy] + [a.replace('{out}', work) for a in args],
                   cwd=work, env=env, check=True, stdout=subprocess.DEVNULL)
    path = os.path.join(work, output)
    if not os.path.exists(path):
        raise FileNotFoundError(f'{os.path.basename(script)} did not write {output}')
    return path


def reproducer_dir(here, scripts):
    """Run the reproducer scripts in here (each a file name, or a (file
    name, args) pair) in one temporary directory and return that
    directory, which then holds what they wrote."""
    work = tempfile.mkdtemp(dir=_TMP.name)
    env = dict(os.environ)
    env['PYTHONPATH'] = os.pathsep.join(
        [here, os.path.dirname(os.path.abspath(__file__))] +
        ([env['PYTHONPATH']] if env.get('PYTHONPATH') else []))
    for s in scripts:
        name, args = (s, ()) if isinstance(s, str) else s
        shutil.copy(os.path.join(here, name), work)
        subprocess.run([sys.executable, os.path.join(work, name)] + list(args),
                       cwd=work, env=env, check=True, stdout=subprocess.DEVNULL)
    return work
