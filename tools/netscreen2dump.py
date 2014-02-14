#!/usr/bin/env python
"""
Converts netscreen snoop hex-dumps to a hex-dump that text2pcap can read.

Copyright (c) 2004 by Gilbert Ramirez <gram@alumni.rice.edu>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
"""

import sys
import re
import os
import stat
import time

class OutputFile:
    TIMER_MAX = 99999.9

    def __init__(self, name, base_time):
        try:
            self.fh = open(name, "w")
        except IOError, err:
            sys.exit(err)

        self.base_time = base_time
        self.prev_timestamp = 0.0

    def PrintPacket(self, timestamp, datalines):
        # What do to with the timestamp? I need more data about what
        # the netscreen timestamp is, then I can generate one for the text file.
#        print "TS:", timestamp.group("time")
        try:
            timestamp = float(timestamp.group("time"))
        except ValueError:
            sys.exit("Unable to convert '%s' to floating point." % \
                    (timestamp,))

        # Did we wrap around the timeer max?
        if timestamp < self.prev_timestamp:
            self.base_time += self.TIMER_MAX

        self.prev_timestamp = timestamp

        packet_timestamp = self.base_time + timestamp

        # Determine the time string to print
        gmtime = time.gmtime(packet_timestamp)
        subsecs = packet_timestamp - int(packet_timestamp)
        assert subsecs <= 0
        subsecs = int(subsecs * 10)

        print >> self.fh, "%s.%d" % (time.strftime("%Y-%m-%d %H:%M:%S", gmtime), \
                subsecs)

        # Print the packet data
        offset = 0
        for lineno, hexgroup in datalines:
            hexline = hexgroup.group("hex")
            hexpairs = hexline.split()
            print >> self.fh, "%08x   %s" % (offset, hexline)
            offset += len(hexpairs)

        # Blank line
        print >> self.fh

# Find a timestamp line
re_timestamp = re.compile(r"^(?P<time>\d+\.\d): [\w/]+\((?P<io>.)\)(:| len=)")

# Find a hex dump line
re_hex_line = re.compile(r"(?P<hex>([0-9a-f]{2} ){1,16})\s+(?P<ascii>.){1,16}")

def run(input_filename, output_filename):
    try:
        ifh = open(input_filename, "r")
    except IOError, err:
        sys.exit(err)

    # Get the file's creation time.
    try:
        ctime = os.stat(input_filename)[stat.ST_CTIME]
    except OSError, err:
        sys.exit(err)

    output_file = OutputFile(output_filename, ctime)

    timestamp = None
    datalines = []
    lineno = 0

    for line in ifh.xreadlines():
        lineno += 1
        # If we have no timestamp yet, look for one
        if not timestamp:
            m = re_timestamp.search(line)
            if m:
                timestamp = m

        # Otherwise, look for hex dump lines
        else:
            m = re_hex_line.search(line)
            if m:
                datalines.append((lineno, m))
            else:
                # If we have been gathering hex dump lines,
                # and this line is not a hex dump line, then the hex dump
                # has finished, and so has the packet. So print the packet
                # and reset our variables so we can look for the next packet.
                if datalines:
                    output_file.PrintPacket(timestamp, datalines)
                    timestamp = None
                    datalines = []

    # At the end of the file we may still have hex dump data in memory.
    # If so, print the packet
    if datalines:
        output_file.PrintPacket(timestamp, datalines)
        timestamp = None
        datalines = []


def usage():
    print >> sys.stderr, "Usage: netscreen2dump.py netscreen-dump-file new-dump-file"
    sys.exit(1)

def main():
    if len(sys.argv) != 3:
        usage()

    run(sys.argv[1], sys.argv[2])

if __name__ == "__main__":
    main()
