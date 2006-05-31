#!/usr/bin/env python
"""
Check the sanity of field definitions in Wireshark.
"""
import sys

try:
    from optparse import OptionParser
except ImportError:
    sys.exit("Need python 2.3.")

try:
    import commands
except ImportError:
    sys.exit("Need to run on Unix.")


errors = 0

class Proto:
    """Data for a protocol."""
    def __init__(self, line):
        data = line.split("\t")
        assert len(data) == 3
        assert data[0] == "P"
        self.name = data[1]
        self.abbrev = data[2]

class Field:
    """Data for a field."""
    def __init__(self, line):
        data = line.split("\t")
        assert len(data) == 8
        assert data[0] == "F"
        self.name = data[1]
        self.abbrev = data[2]
        self.ftype = data[3]
        self.parent = data[4]
        self.blurb = data[5]
        self.base = data[6]
        self.bitmask = int(data[7])

    

def gather_data(tethereal):
    """Calls tethereal and gathers data."""
    cmd = "%s -G fields3" % (tethereal,)
    (status, output) = commands.getstatusoutput(cmd)

    if status != 0:
        sys.exit("Failed: " + cmd)

    lines = output.split("\n")
    protos = [Proto(x) for x in lines if x[0] == "P"]
    fields = [Field(x) for x in lines if x[0] == "F"]

    return protos, fields


def check_fields(fields):
    """Looks for problems in field definitions."""
    global errors
    for field in fields:
        if field.bitmask != 0:
            if field.ftype.find("FT_UINT") != 0 and \
                    field.ftype.find("FT_INT") != 0 and \
                    field.ftype != "FT_BOOLEAN":
                print "%s has a bitmask 0x%x but is type %s" % \
                        (field.abbrev, field.bitmask, field.ftype)
                errors += 1

def run(tethereal):
    """Run the tests."""
    global errors
    protos, fields = gather_data(tethereal)

    check_fields(fields)

    if errors > 0:
        sys.exit("%d errors found" % (errors,))
    else:
        print "Success."

def main():
    """Parse the command-line."""
    usage = "%prog tethereal"
    parser = OptionParser(usage=usage)

    (options, args) = parser.parse_args()

    if len(args) != 1:
        parser.error("Need location of tethereal.")

    run(args[0])

if __name__ == "__main__":
    main()
