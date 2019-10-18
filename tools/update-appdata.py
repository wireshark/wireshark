#!/usr/bin/env python3
#
# update-appdata.py - Update the <releases/> section of wireshark.appdata.xml.
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
'''Update the <release> tag in wireshark.appdata.xml

According to https://www.freedesktop.org/software/appstream/docs/chap-Metadata.html
the <releases/> tag in wireshark.appdata.xml should contain release
information sorted newest to oldest.

As part of our release process, when we create release tag x.y.z, we tag
the next commit x.y.z+1rc0, e.g.

v3.0.0      2019-02-28 release tag
v3.0.1rc0   2019-02-28 next commit after v3.0.0
v3.0.1      2019-04-08 release tag
v3.0.2rc0   2019-04-08 next commit after v3.0.1

Find a list of release versions based on our most recent rc0 tag and
update the <releases/> section of wireshark.appdata.xml accordingly.
Assume that the tag for the most recent release doesn't exist and use
today's date for it.
'''

from datetime import date
import io
import os.path
import re
import subprocess
import sys
import time

def main():
    if sys.version_info[0] < 3:
        print("This requires Python 3")
        sys.exit(2)

    this_dir = os.path.dirname(__file__)
    appdata_xml = os.path.join(this_dir, '..', 'wireshark.appdata.xml')

    try:
        tag_cp = subprocess.run(
            ['git', 'tag', '-l', 'wireshark-*'],
            encoding='UTF-8',
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if not 'wireshark-' in tag_cp.stdout:
            print('Wireshark release tag not found')
            sys.exit(1)
    except:
        print('`git tag` returned {}:'.format(tag_cp.returncode))
        raise

    try:
        cur_rc0 = subprocess.run(
            ['git', 'describe', '--match', 'v*rc0'],
            check=True,
            encoding='UTF-8',
            stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    except:
        print('Unable to fetch most recent rc0.')
        raise

    try:
        ver_m = re.match('v(\d+\.\d+)\.(\d+)rc0.*', cur_rc0)
        maj_min = ver_m.group(1)
        next_micro = ver_m.group(2)
    except:
        print('Unable to fetch major.minor version.')
        raise

    # https://www.freedesktop.org/software/appstream/docs/chap-Metadata.html#tag-releases
    release_tag_fmt = '''\
        <release version="{0}.{1}" date="{2}">
            <url>https://www.wireshark.org/docs/relnotes/wireshark-{0}.{1}.html</url>
        </release>
'''
    release_tag_l = [
        release_tag_fmt.format(maj_min, next_micro, date.fromtimestamp(time.time()).isoformat())
    ]
    for micro in range(int(next_micro) - 1, -1, -1):
        try:
            tag_date = subprocess.run(
                ['git', 'log', '-1', '--format=%cd', '--date=format:%F', 'v{}.{}'.format(maj_min, micro)],
                check=True,
                encoding='UTF-8',
                stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()
            release_tag_l.append(release_tag_fmt.format(maj_min, micro, tag_date))
        except:
            print('Unable to fetch release tag')
            raise

    ax_lines = []
    with io.open(appdata_xml, 'r', encoding='UTF-8') as ax_fd:
        in_releases = False
        for line in ax_fd:
            if '</releases>' in line:
                in_releases = False
            if in_releases:
                continue
            ax_lines.append(line)
            if '<releases>' in line:
                in_releases = True
                ax_lines.extend(release_tag_l)

    with io.open(appdata_xml, 'w', encoding='UTF-8') as ax_fd:
        ax_fd.write(''.join(ax_lines))

if __name__ == '__main__':
    main()
