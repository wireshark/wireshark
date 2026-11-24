# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""The NDR description of a DCE/RPC interface from the tree's PIDL files.

pidl_json('samr') runs idl2json.pl (Pidl from tools/pidl, Perl with JSON::PP)
on epan/dissectors/pidl/samr/samr.idl and returns the path of the JSON file
it wrote, which ndrgen.Gen and the DCE/RPC generators read.
"""

import functools
import os
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PIDL_DIR = os.path.join(HERE, '..', '..', '..', '..', 'epan', 'dissectors', 'pidl')
_TMP = tempfile.TemporaryDirectory(prefix='pidljson-')


@functools.cache
def pidl_json(name):
    """Path of the JSON for epan/dissectors/pidl/<name>/<name>.idl."""
    out = os.path.join(_TMP.name, name + '.json')
    with open(out, 'wb') as f:
        subprocess.run(['perl', os.path.join(HERE, 'idl2json.pl'), os.path.join(name, name + '.idl'), '.'],
                       cwd=PIDL_DIR, stdout=f, check=True)
    return out


@functools.cache
def pidl_ndr_json(name):
    """Path of the JSON dump of the whole Pidl NDR tree (ndrdump.pl) of
    epan/dissectors/pidl/<name>/<name>.idl."""
    out = os.path.join(_TMP.name, name + '_ndr.json')
    with open(out, 'wb') as f:
        subprocess.run(['perl', os.path.join(HERE, 'ndrdump.pl'), os.path.join(name, name + '.idl'), '.'],
                       cwd=PIDL_DIR, stdout=f, check=True)
    return out
