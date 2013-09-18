# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>

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

