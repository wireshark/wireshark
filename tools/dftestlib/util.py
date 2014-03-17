# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


import subprocess

SUCCESS = 0
def exec_cmdv(cmdv, cwd=None, stdin=None):
    """Run the commands in cmdv, returning (retval, output),
    where output is stdout and stderr combined.
    If cwd is given, the child process runs in that directory.
    If a filehandle is passed as stdin, it is used as stdin.
    If there is an OS-level error, None is the retval."""

    try:
        output = subprocess.check_output(cmdv, stderr=subprocess.STDOUT,
                cwd=cwd, stdin=stdin)
        retval = SUCCESS

    # If file isn't executable
    except OSError, e:
        output = str(e)
        retval = None

    # If process returns non-zero
    except subprocess.CalledProcessError, e:
        output = e.output
        retval = e.returncode

    return (retval, output)

