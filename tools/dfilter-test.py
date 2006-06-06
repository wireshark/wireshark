#!/usr/bin/env python
"""
Test-suite to test wireshark's dfilter mechanism.
"""

#
# $Id$
#
# Copyright (C) 2003 by Gilbert Ramirez <gram@alumni.rice.edu>
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

import os
import sys
import atexit
import tempfile
import types
import getopt

# Global variables that can be overridden by user

REMOVE_TEMP_FILES = 1
VERBOSE = 0
TEXT2PCAP = os.path.join(".", "text2pcap")
TSHARK = os.path.join(".", "tshark")

# Some DLT values. Add more from <net/bpf.h> if you need to.

DLT_NULL	= 0       # no link-layer encapsulation
DLT_EN10MB	= 1       # Ethernet (10Mb)
DLT_EN3MB	= 2       # Experimental Ethernet (3Mb)
DLT_AX25	= 3       # Amateur Radio AX.25
DLT_PRONET	= 4       # Proteon ProNET Token Ring
DLT_CHAOS	= 5       # Chaos
DLT_IEEE802	= 6       # IEEE 802 Networks
DLT_ARCNET	= 7       # ARCNET
DLT_SLIP	= 8       # Serial Line IP
DLT_PPP		= 9       # Point-to-point Protocol
DLT_FDDI	= 10      # FDDI
DLT_FRELAY	= 107     # Frame Relay

################################################################################

class RunCommandError:
	"""The exception that run_cmd can produce."""
	pass

def run_cmd(cmd):
	"""Run a command. 'cmd' is either a string or
	a tuple/array of strings. Returns a tuple of
	the output of the command and the return value.
	If an error did not occur, the return value is None, not 0.
	If an error occured while trying to run the command,
	RunCommandError is raised.
	Both, or either, the output and the return value, may
	be None if RunCommandError is raised.."""

	if type(cmd) == types.TupleType:
		cmd = ' '.join(cmd)

	output = None
	error = None

	if VERBOSE:
		print "Running", cmd

	try:
		pipe = os.popen(cmd)
		output = pipe.readlines()
		error = pipe.close()

	except OSError:
		raise RunCommandError

	return (output, error)


def remove_file(filename):
	"""Remove a file. No exceptions are produced even
	when the file cannot be removed."""
	try:
		os.remove(filename)
	except OSError:
		pass


class Packet:
	"""Knows how to convert a string representing the
	hex-dump of packet into a libpcap file."""

	def __init__(self, linklayer):
		"""Linklayer is a DLT value."""
		self.linklayer = linklayer
		self.data = None
		self.filename = None
		self.time_fmt = None

	def Filename(self):
		"""Returns the filename of the packet trace.
		The first time this is called, the libpcap trace
		file is created. During subsequent calls, the libpcap
		tracee file already exists, so the filename is simply
		returned.  Care is taken so that the libpcap trace file
		is automatically deleted when this Python process
		exits."""
		if not self.filename:
			# Create the temporary text file.
			hex_filename = tempfile.mktemp("-dfilter-test.txt")

			# Tell Python to remove the file when exiting
			if REMOVE_TEMP_FILES:
				atexit.register(remove_file, hex_filename)

			try:
				hex_fh = open(hex_filename, "w")
				hex_fh.write(self.data)
				hex_fh.write("\n")
				hex_fh.close()
			except IOError, err:
				sys.exit("Could not write to %s: %s" % \
					(hex_filename, err))


			# Create the pcap file
			self.filename = tempfile.mktemp("-dfilter-test.cap")

			# Tell Python to remove the file when exiting
			if REMOVE_TEMP_FILES:
				atexit.register(remove_file, self.filename)

			cmd = (TEXT2PCAP, "-q -l", str(self.linklayer))

			if self.time_fmt:
				cmd = cmd + ("-t", "'" + self.time_fmt + "'")

			cmd = cmd + (hex_filename, self.filename)

			try:
				(output, error) = run_cmd(cmd)
			except RunCommandError:
				sys.exit("Could not produce trace file.")

			if error != None:
				sys.exit("Could not produce trace file.")


		if not REMOVE_TEMP_FILES:
			print "(", self.filename, ") ...",

		return self.filename
			
	
OK = 0
FAILED = 1

class Test:
	"""Base class for test classes."""

	def Run(self):
		"""Run the tests listed in self.tests.
		Return the score."""

		num_run = 0
		num_succeeded = 0

		for test in self.tests:
			print "\t", test.__name__ , "...",
			retval = test(self)
			if retval == OK:
				print "OK"
				num_succeeded += 1
			else:
				print "FAILED"
			num_run += 1

		return (num_run, num_succeeded)


	def DFilterCount(self, packet, dfilter, num_lines_expected):
		"""Run a dfilter on a packet file and expect
		a certain number of output lines. If num_lines_expected
		is None, then the tshark command is expected to fail
		with a non-zero return value."""

		packet_file = packet.Filename()

		cmd = (TSHARK, "-n -r", packet_file, "-R '", dfilter, "'")

		tshark_failed = 0

		try:
			(output, retval) = run_cmd(cmd)
		except RunCommandError:
			tshark_failed = 1

#		print "GOT", len(output), "lines:", output, retval

		if retval:
			tshark_failed = 1

		if tshark_failed:
			if num_lines_expected == None:
				if VERBOSE:
					print "\nGot:", output
				return OK
			else:
				print "\nGot:", output
				return FAILED

		elif len(output) == num_lines_expected:
			if VERBOSE:
				print "\nGot:", output
			return OK
		else:
			print "\nGot:", output
			return FAILED


################################################################################
# Add packets here
# Watch out for trailing backslashes. If the last character in the line is a
# backslash, the data won't convert properly. Just remove the backslash or
# replace it with another character. I haven't determined if this is due to
# Python's "here-document" parsing, or due to text2pcap.
################################################################################

# IPX RIP Response
pkt_ipx_rip = Packet(DLT_EN10MB)
pkt_ipx_rip.data = """
0000  ff ff ff ff ff ff 00 aa  00 a3 e3 a4 00 28 ff ff   ........ .....(..
0010  00 28 00 01 00 00 00 28  ff ff ff ff ff ff 04 53   .(.....( .......S
0020  00 00 00 28 00 aa 00 a3  e3 a4 04 53 00 02 39 17   ...(.... ...S..9.
0030  29 e2 00 01 00 02 00 00  00 00 00 00               )....... ....
"""

# IPv6
pkt_ipv6 = Packet(DLT_EN10MB)
pkt_ipv6.data = """
0000  33 33 00 00 99 99 00 00  86 05 80 fa 86 dd 60 00   33...... ......`.
0010  00 00 00 20 00 01 fe 80  00 00 00 00 00 00 02 00   ... .... ........
0020  86 ff fe 05 80 fa ff 05  00 00 00 00 00 00 00 00   ........ ........
0030  00 00 00 00 99 99 3a 00  01 00 05 02 00 00 83 00   ......:. ........
0040  44 ed 00 00 00 00 ff 05  00 00 00 00 00 00 00 00   D....... ........
0050  00 00 00 00 99 99                                  ......           
"""

# ARP
pkt_arp = Packet(DLT_FRELAY)
pkt_arp.data = """
0000  18 41 03 00 80 00 00 00  08 06 00 0f 08 00 02 04   .A...... ........
0010  00 08 00 00 0a ce 01 02  00 64 00 00 00 00         ........ .d....  
"""

# NFS
pkt_nfs = Packet(DLT_FDDI)
pkt_nfs.time_fmt = "%Y-%m-%d %H:%M:%S."
pkt_nfs.data = """
2002-12-31 07:55:31.3
0000  51 10 00 d4 cd 59 6f 00  07 4a 01 6e 00 aa aa 03   Q....Yo. .J.n....
0010  00 00 00 08 00 45 00 00  b4 1c cf 40 00 fc 11 a4   .....E.. ...@....
0020  cd ac 19 64 0e c6 5f e6  14 03 ff 08 01 00 a0 79   ...d.._. .......y
0030  f9 7b 55 8a eb 00 00 00  00 00 00 00 02 00 01 86   .{U..... ........
0040  a3 00 00 00 03 00 00 00  01 00 00 00 01 00 00 00   ........ ........
0050  4c 36 db 91 97 00 00 00  0a 61 74 6d 63 6c 69 65   L6...... .atmclie
0060  6e 74 32 00 00 00 00 00  00 00 00 00 01 00 00 00   nt2..... ........
0070  0b 00 00 00 01 00 00 00  00 00 00 00 02 00 00 00   ........ ........
0080  03 00 00 00 04 00 00 00  05 00 00 00 06 00 00 00   ........ ........
0090  07 00 00 00 08 00 00 00  09 00 00 00 0c 00 00 00   ........ ........
00a0  00 00 00 00 00 00 00 00  20 21 92 13 00 a7 92 59   ........  !.....Y
00b0  07 20 00 00 00 00 02 4a  77 db b5 19 01 19 00 00   . .....J w.......
00c0  00 01 a4 06 00 97 1b 05  00                        ........ .       

2002-12-31 07:55:32.0
0000  51 00 07 4a 01 6e 00 10  00 d4 cd 59 6f aa aa 03   Q..J.n.. ...Yo...
0010  00 00 00 08 00 45 00 00  8c 6d 3c 00 00 40 11 50   .....E.. .m<..@.P
0020  89 c6 5f e6 14 ac 19 64  0e 08 01 03 ff 00 78 1d   .._....d ......x.
0030  99 7b 55 8a eb 00 00 00  01 00 00 00 00 00 00 00   .{U..... ........
0040  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ........ ........
0050  01 00 00 01 ed 00 00 00  01 00 00 00 00 00 00 00   ........ ........
0060  1e 00 00 00 00 00 04 07  60 00 00 00 00 00 04 20   ........ `...... 
0070  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ........ ........
0080  19 00 00 00 00 00 02 4a  77 36 db 94 da 0c 84 5c   .......J w6......
0090  68 32 1e 28 e9 00 00 00  00 32 23 d4 10 0a 21 fe   h2.(.... .2#...!.
00a0  80  
"""

# NTP
pkt_ntp = Packet(DLT_EN10MB)
pkt_ntp.data = """
0000  08 00 2b 91 e8 3a 08 00  2b e4 c4 43 08 00 45 00   ..+..:.. +..C..E.
0010  00 4c 64 4c 00 00 1e 11  02 47 82 dc 18 3e 82 dc   .LdL.... .G...>..
0020  18 18 00 7b 00 7b 00 38  ee 1c 1b 04 06 f5 00 00   ...{.{.8 ........
0030  10 0d 00 00 05 57 82 dc  18 18 ba 29 66 36 7d d0   .....W.. ...)f6}.
0040  00 00 ba 29 66 36 7d 58  40 00 ba 29 66 36 7d d0   ...)f6}X @..)f6}.
0050  00 00 ba 29 66 76 7d 50  50 00                     ...)fv}P P.      
"""


# HTTP
pkt_http = Packet(DLT_EN10MB)
pkt_http.time_fmt = "%Y-%m-%d %H:%M:%S."
pkt_http.data = """
2002-12-31 07:55:31.3
0000  00 e0 81 00 b0 28 00 09  6b 88 f5 c9 08 00 45 00   .....(.. k.....E.
0010  00 c1 d2 49 40 00 80 06  c8 5b 0a 00 00 05 cf 2e   ...I@... .[......
0020  86 5e 0c c3 00 50 a8 00  76 87 7d e0 14 02 50 18   .^...P.. v.}...P.
0030  fa f0 ad 62 00 00 48 45  41 44 20 2f 76 34 2f 69   ...b..HE AD /v4/i
0040  75 69 64 65 6e 74 2e 63  61 62 3f 30 33 30 37 30   uident.c ab?03070
0050  31 31 32 30 38 20 48 54  54 50 2f 31 2e 31 0d 0a   11208 HT TP/1.1..
0060  41 63 63 65 70 74 3a 20  2a 2f 2a 0d 0a 55 73 65   Accept:  */*..Use
0070  72 2d 41 67 65 6e 74 3a  20 49 6e 64 75 73 74 72   r-Agent:  Industr
0080  79 20 55 70 64 61 74 65  20 43 6f 6e 74 72 6f 6c   y Update  Control
0090  0d 0a 48 6f 73 74 3a 20  77 69 6e 64 6f 77 73 75   ..Host:  windowsu
00a0  70 64 61 74 65 2e 6d 69  63 72 6f 73 6f 66 74 2e   pdate.mi crosoft.
00b0  63 6f 6d 0d 0a 43 6f 6e  6e 65 63 74 69 6f 6e 3a   com..Con nection:
00c0  20 4b 65 65 70 2d 41 6c  69 76 65 0d 0a 0d 0a       Keep-Al ive....
"""


# TFTP
pkt_tftp = Packet(DLT_IEEE802)
pkt_tftp.data = """
0000  10 40 00 20 35 01 2b 59  00 06 29 17 93 f8 aa aa   .@. 5.+Y ..).....
0010  03 00 00 00 08 00 45 00  00 37 f9 39 00 00 40 11   ......E. .7.9..@.
0020  a6 db c0 a8 2c 7b c0 a8  2c d5 f9 39 00 45 00 23   ....,{.. ,..9.E.#
0030  8d 73 00 01 43 3a 5c 49  42 4d 54 43 50 49 50 5c   .s..C:\I BMTCPIP.
0040  6c 63 63 6d 2e 31 00 6f  63 74 65 74 00            lccm.1.o ctet.   
"""


################################################################################
# Add tests here
################################################################################

class Bytes(Test):
	"""Tests routines in ftype-bytes.c"""

	def __init__(self):
		print "Note: Bytes test does not yet test FT_INT64."

	def ck_eq_1(self):
		return self.DFilterCount(pkt_ipx_rip,
			"eth.dst == ff:ff:ff:ff:ff:ff", 1)

	def ck_eq_2(self):
		return self.DFilterCount(pkt_ipx_rip,
			"eth.src == ff:ff:ff:ff:ff:ff", 0)

	def ck_ne_1(self):
		return self.DFilterCount(pkt_ipx_rip,
			"eth.dst != ff:ff:ff:ff:ff:ff", 0)

	def ck_ne_2(self):
		return self.DFilterCount(pkt_ipx_rip,
			"eth.src != ff:ff:ff:ff:ff:ff", 1)

	def ck_gt_1(self):
		return self.DFilterCount(pkt_ipx_rip,
			"eth.src > 00:aa:00:a3:e3:ff", 0)

	def ck_gt_2(self):
		return self.DFilterCount(pkt_ipx_rip,
			"eth.src > 00:aa:00:a3:e3:a4", 0)

	def ck_gt_3(self):
		return self.DFilterCount(pkt_ipx_rip,
			"eth.src > 00:aa:00:a3:e3:00", 1)

	def ck_ge_1(self):
		return self.DFilterCount(pkt_ipx_rip,
			"eth.src >= 00:aa:00:a3:e3:ff", 0)

	def ck_ge_2(self):
		return self.DFilterCount(pkt_ipx_rip,
			"eth.src >= 00:aa:00:a3:e3:a4", 1)

	def ck_ge_3(self):
		return self.DFilterCount(pkt_ipx_rip,
			"eth.src >= 00:aa:00:a3:e3:00", 1)

	def ck_lt_1(self):
		return self.DFilterCount(pkt_ipx_rip,
			"eth.src < 00:aa:00:a3:e3:ff", 1)

	def ck_lt_2(self):
		return self.DFilterCount(pkt_ipx_rip,
			"eth.src < 00:aa:00:a3:e3:a4", 0)

	def ck_lt_3(self):
		return self.DFilterCount(pkt_ipx_rip,
			"eth.src < 00:aa:00:a3:e3:00", 0)

	def ck_le_1(self):
		return self.DFilterCount(pkt_ipx_rip,
			"eth.src <= 00:aa:00:a3:e3:ff", 1)

	def ck_le_2(self):
		return self.DFilterCount(pkt_ipx_rip,
			"eth.src <= 00:aa:00:a3:e3:a4", 1)

	def ck_le_3(self):
		return self.DFilterCount(pkt_ipx_rip,
			"eth.src <= 00:aa:00:a3:e3:00", 0)

	def ck_slice_1(self):
		return self.DFilterCount(pkt_ipx_rip,
			"eth.src[0:3] == 00:aa:00", 1)

	def ck_slice_2(self):
		return self.DFilterCount(pkt_ipx_rip,
			"eth.src[-3:3] == a3:e3:a4", 1)

	def ck_slice_3(self):
		return self.DFilterCount(pkt_ipx_rip,
			"eth.src[1:4] == aa:00:a3:e3", 1)

	def ck_slice_4(self):
		return self.DFilterCount(pkt_ipx_rip,
			"eth.src[0] == 00", 1)

	def ck_ipv6_1(self):
		return self.DFilterCount(pkt_ipv6,
			"ipv6.dst == ff05::9999", 1)

	def ck_ipv6_2(self):
		return self.DFilterCount(pkt_ipv6,
			"ipv6.dst == ff05::9990", 0)

	# ck_eq_1 checks FT_ETHER; this checks FT_BYTES
	def ck_bytes_1(self):
		return self.DFilterCount(pkt_arp,
			"arp.dst.hw == 00:64", 1)

	# ck_eq_2 checks FT_ETHER; this checks FT_BYTES
	def ck_bytes_2(self):
		return self.DFilterCount(pkt_arp,
			"arp.dst.hw == 00:00", 0)

	# ck_eq_1 checks FT_ETHER; this checks FT_UINT64
	def ck_uint64_1(self):
		return self.DFilterCount(pkt_nfs,
			"nfs.fattr3.size == 264032", 1)

	# ck_eq_2 checks FT_ETHER; this checks FT_UINT64
	def ck_uint64_2(self):
		return self.DFilterCount(pkt_nfs,
			"nfs.fattr3.size == 264000", 0)

        def ck_contains_1(self):
		return self.DFilterCount(pkt_ipx_rip,
			"ipx.src.node contains a3", 1)

	def ck_contains_2(self):
		return self.DFilterCount(pkt_ipx_rip,
			"ipx.src.node contains a3:e3", 1)

	def ck_contains_3(self):
		return self.DFilterCount(pkt_ipx_rip,
			"ipx.src.node contains 00:aa:00:a3:e3:a4", 1)

	def ck_contains_4(self):
		return self.DFilterCount(pkt_ipx_rip,
			"ipx.src.node contains aa:e3", 0)


	tests = [
		ck_eq_1,
		ck_eq_2,
		ck_ne_1,
		ck_ne_2,
		ck_gt_1,
		ck_gt_2,
		ck_gt_3,
		ck_ge_1,
		ck_ge_2,
		ck_ge_3,
		ck_lt_1,
		ck_lt_2,
		ck_lt_3,
		ck_le_1,
		ck_le_2,
		ck_le_3,
		ck_slice_1,
		ck_slice_2,
		ck_slice_3,
		ck_slice_4,
		ck_ipv6_1,
		ck_ipv6_2,
		ck_bytes_1,
		ck_bytes_2,
		ck_uint64_1,
		ck_uint64_2,
		ck_contains_1,
		ck_contains_2,
		ck_contains_3,
		ck_contains_4,
		]


class Double(Test):
	"""Tests routines in ftype-double.c"""

	def ck_eq_1(self):
		# This works on ia32/Linux
		# http://www.cslab.vt.edu/manuals/glibc-2.2.3/html_node/libc_673.html
		return self.DFilterCount(pkt_ntp,
			"ntp.rootdelay == 0.0626983642578125", 1)

	def ck_eq_2(self):
		return self.DFilterCount(pkt_ntp,
			"ntp.rootdelay == 0.0626", 0)

	def ck_gt_1(self):
		return self.DFilterCount(pkt_ntp,
			"ntp.rootdelay > 1.0626", 0)

	def ck_gt_2(self):
		return self.DFilterCount(pkt_ntp,
			"ntp.rootdelay > 0.0626983642578125", 0)

	def ck_gt_3(self):
		return self.DFilterCount(pkt_ntp,
			"ntp.rootdelay > 0.0026", 1)

	def ck_ge_1(self):
		return self.DFilterCount(pkt_ntp,
			"ntp.rootdelay >= 1.0626", 0)

	def ck_ge_2(self):
		return self.DFilterCount(pkt_ntp,
			"ntp.rootdelay >= 0.0626983642578125", 1)

	def ck_ge_3(self):
		return self.DFilterCount(pkt_ntp,
			"ntp.rootdelay > 0.0026", 1)

	def ck_lt_1(self):
		return self.DFilterCount(pkt_ntp,
			"ntp.rootdelay < 1.0626", 1)

	def ck_lt_2(self):
		return self.DFilterCount(pkt_ntp,
			"ntp.rootdelay < 0.0626983642578125", 0)

	def ck_lt_3(self):
		return self.DFilterCount(pkt_ntp,
			"ntp.rootdelay < 0.0026", 0)

	def ck_le_1(self):
		return self.DFilterCount(pkt_ntp,
			"ntp.rootdelay <= 1.0626", 1)

	def ck_le_2(self):
		return self.DFilterCount(pkt_ntp,
			"ntp.rootdelay <= 0.0626983642578125", 1)

	def ck_le_3(self):
		return self.DFilterCount(pkt_ntp,
			"ntp.rootdelay <= 0.0026", 0)


	tests = [
		ck_eq_1,
		ck_eq_2,
		ck_gt_1,
		ck_gt_2,
		ck_gt_3,
		ck_ge_1,
		ck_ge_2,
		ck_ge_3,
		ck_lt_1,
		ck_lt_2,
		ck_lt_3,
		ck_le_1,
		ck_le_2,
		ck_le_3,
		]

class Integer(Test):
	"""Tests routines in ftype-integer.c"""

	def ck_eq_1(self):
		return self.DFilterCount(pkt_ntp,
			"ip.version == 4", 1)

	def ck_eq_2(self):
		return self.DFilterCount(pkt_ntp,
			"ip.version == 6", 0)

	def ck_ne_1(self):
		return self.DFilterCount(pkt_ntp,
			"ip.version != 0", 1)

	def ck_ne_2(self):
		return self.DFilterCount(pkt_ntp,
			"ip.version != 4", 0)

	def ck_u_gt_1(self):
		return self.DFilterCount(pkt_ntp,
			"ip.version > 3", 1)

	def ck_u_gt_2(self):
		return self.DFilterCount(pkt_ntp,
			"ip.version > 4", 0)

	def ck_u_gt_3(self):
		return self.DFilterCount(pkt_ntp,
			"ip.version > 5", 0)

	def ck_u_ge_1(self):
		return self.DFilterCount(pkt_ntp,
			"ip.version >= 3", 1)

	def ck_u_ge_2(self):
		return self.DFilterCount(pkt_ntp,
			"ip.version >= 4", 1)

	def ck_u_ge_3(self):
		return self.DFilterCount(pkt_ntp,
			"ip.version >= 5", 0)

	def ck_u_lt_1(self):
		return self.DFilterCount(pkt_ntp,
			"ip.version < 3", 0)

	def ck_u_lt_2(self):
		return self.DFilterCount(pkt_ntp,
			"ip.version < 4", 0)

	def ck_u_lt_3(self):
		return self.DFilterCount(pkt_ntp,
			"ip.version < 5", 1)

	def ck_u_le_1(self):
		return self.DFilterCount(pkt_ntp,
			"ip.version <= 3", 0)

	def ck_u_le_2(self):
		return self.DFilterCount(pkt_ntp,
			"ip.version <= 4", 1)

	def ck_u_le_3(self):
		return self.DFilterCount(pkt_ntp,
			"ip.version <= 5", 1)

	def ck_s_gt_1(self):
		return self.DFilterCount(pkt_ntp,
			"ntp.precision > -12", 1)

	def ck_s_gt_2(self):
		return self.DFilterCount(pkt_ntp,
			"ntp.precision > -11", 0)

	def ck_s_gt_3(self):
		return self.DFilterCount(pkt_ntp,
			"ntp.precision > -10", 0)

	def ck_s_ge_1(self):
		return self.DFilterCount(pkt_ntp,
			"ntp.precision >= -12", 1)

	def ck_s_ge_2(self):
		return self.DFilterCount(pkt_ntp,
			"ntp.precision >= -11", 1)

	def ck_s_ge_3(self):
		return self.DFilterCount(pkt_ntp,
			"ntp.precision >= -10", 0)

	def ck_s_lt_1(self):
		return self.DFilterCount(pkt_ntp,
			"ntp.precision < -12", 0)

	def ck_s_lt_2(self):
		return self.DFilterCount(pkt_ntp,
			"ntp.precision < -11", 0)

	def ck_s_lt_3(self):
		return self.DFilterCount(pkt_ntp,
			"ntp.precision < -10", 1)

	def ck_s_le_1(self):
		return self.DFilterCount(pkt_ntp,
			"ntp.precision <= -12", 0)

	def ck_s_le_2(self):
		return self.DFilterCount(pkt_ntp,
			"ntp.precision <= -11", 1)

	def ck_s_le_3(self):
		return self.DFilterCount(pkt_ntp,
			"ntp.precision <= -10", 1)

	def ck_bool_eq_1(self):
		return self.DFilterCount(pkt_ntp,
			"ip.flags.df == 0", 1)

	def ck_bool_eq_2(self):
		return self.DFilterCount(pkt_ntp,
			"ip.flags.df == 1", 0)

	def ck_bool_ne_1(self):
		return self.DFilterCount(pkt_ntp,
			"ip.flags.df != 1", 1)

	def ck_bool_ne_2(self):
		return self.DFilterCount(pkt_ntp,
			"ip.flags.df != 0", 0)

	def ck_ipx_1(self):
		return self.DFilterCount(pkt_ipx_rip,
			"ipx.src.net == 0x28", 1)

	def ck_ipx_2(self):
		return self.DFilterCount(pkt_ipx_rip,
			"ipx.src.net == 0x29", 0)


	tests = [
		ck_eq_1,
		ck_eq_2,
		ck_ne_1,
		ck_ne_2,
		ck_u_gt_1,
		ck_u_gt_2,
		ck_u_gt_3,
		ck_u_ge_1,
		ck_u_ge_2,
		ck_u_ge_3,
		ck_u_lt_1,
		ck_u_lt_2,
		ck_u_lt_3,
		ck_u_le_1,
		ck_u_le_2,
		ck_u_le_3,
		ck_s_gt_1,
		ck_s_gt_2,
		ck_s_gt_3,
		ck_s_ge_1,
		ck_s_ge_2,
		ck_s_ge_3,
		ck_s_lt_1,
		ck_s_lt_2,
		ck_s_lt_3,
		ck_s_le_1,
		ck_s_le_2,
		ck_s_le_3,
		ck_bool_eq_1,
		ck_bool_eq_2,
		ck_bool_ne_1,
		ck_bool_ne_2,
		ck_ipx_1,
		ck_ipx_2,
		]

class IPv4(Test):
	"""Tests routines in ftype-ipv4.c"""

	def ck_eq_1(self):
		return self.DFilterCount(pkt_nfs,
			"ip.src == 172.25.100.14", 1)

	def ck_eq_2(self):
		return self.DFilterCount(pkt_nfs,
			"ip.src == 255.255.255.255", 0)

	def ck_ne_1(self):
		return self.DFilterCount(pkt_nfs,
			"ip.src != 172.25.100.14", 1)

	def ck_ne_2(self):
		return self.DFilterCount(pkt_nfs,
			"ip.src != 255.255.255.255", 2)

	def ck_gt_1(self):
		return self.DFilterCount(pkt_nfs,
			"ip.dst > 198.95.230.200", 0)

	def ck_gt_2(self):
		return self.DFilterCount(pkt_nfs,
			"ip.dst > 198.95.230.20", 0)

	def ck_gt_3(self):
		return self.DFilterCount(pkt_nfs,
			"ip.dst > 198.95.230.10", 1)

	def ck_ge_1(self):
		return self.DFilterCount(pkt_nfs,
			"ip.dst >= 198.95.230.200", 0)

	def ck_ge_2(self):
		return self.DFilterCount(pkt_nfs,
			"ip.dst >= 198.95.230.20", 1)

	def ck_ge_3(self):
		return self.DFilterCount(pkt_nfs,
			"ip.dst >= 198.95.230.10", 1)

	def ck_lt_1(self):
		return self.DFilterCount(pkt_nfs,
			"ip.src < 172.25.100.140", 1)

	def ck_lt_2(self):
		return self.DFilterCount(pkt_nfs,
			"ip.src < 172.25.100.14", 0)

	def ck_lt_3(self):
		return self.DFilterCount(pkt_nfs,
			"ip.src < 172.25.100.10", 0)

	def ck_le_1(self):
		return self.DFilterCount(pkt_nfs,
			"ip.src <= 172.25.100.140", 1)

	def ck_le_2(self):
		return self.DFilterCount(pkt_nfs,
			"ip.src <= 172.25.100.14", 1)

	def ck_le_3(self):
		return self.DFilterCount(pkt_nfs,
			"ip.src <= 172.25.100.10", 0)

	def ck_cidr_eq_1(self):
		return self.DFilterCount(pkt_nfs,
			"ip.src == 172.25.100.14/32", 1)

	def ck_cidr_eq_2(self):
		return self.DFilterCount(pkt_nfs,
			"ip.src == 172.25.100.0/24", 1)

	def ck_cidr_eq_3(self):
		return self.DFilterCount(pkt_nfs,
			"ip.src == 172.25.0.0/16", 1)

	def ck_cidr_eq_4(self):
		return self.DFilterCount(pkt_nfs,
			"ip.src == 172.0.0.0/8", 1)

	def ck_cidr_ne_1(self):
		return self.DFilterCount(pkt_nfs,
			"ip.src != 172.25.100.14/32", 1)

	def ck_cidr_ne_2(self):
		return self.DFilterCount(pkt_nfs,
			"ip.src != 172.25.100.0/24", 1)

	def ck_cidr_ne_3(self):
		return self.DFilterCount(pkt_nfs,
			"ip.src != 172.25.0.0/16", 1)

	def ck_cidr_ne_4(self):
		return self.DFilterCount(pkt_nfs,
			"ip.src != 200.0.0.0/8", 2)

	tests = [
		ck_eq_1,
		ck_eq_2,
		ck_ne_1,
		ck_ne_2,
		ck_gt_1,
		ck_gt_2,
		ck_gt_3,
		ck_ge_1,
		ck_ge_2,
		ck_ge_3,
		ck_lt_1,
		ck_lt_2,
		ck_lt_3,
		ck_le_1,
		ck_le_2,
		ck_le_3,
		ck_cidr_eq_1,
		ck_cidr_eq_2,
		ck_cidr_eq_3,
		ck_cidr_eq_4,
		ck_cidr_ne_1,
		ck_cidr_ne_2,
		ck_cidr_ne_3,
		ck_cidr_ne_4,
		]

class String(Test):
	"""Tests routines in ftype-string.c"""

	def ck_eq_1(self):
		return self.DFilterCount(pkt_http,
			'http.request.method == "HEAD"', 1)

	def ck_eq_2(self):
		return self.DFilterCount(pkt_http,
			'http.request.method == "POST"', 0)

	def ck_gt_1(self):
		return self.DFilterCount(pkt_http,
			'http.request.method > "HEAC"', 1)

	def ck_gt_2(self):
		return self.DFilterCount(pkt_http,
			'http.request.method > "HEAD"', 0)

	def ck_gt_3(self):
		return self.DFilterCount(pkt_http,
			'http.request.method > "HEAE"', 0)

	def ck_ge_1(self):
		return self.DFilterCount(pkt_http,
			'http.request.method >= "HEAC"', 1)

	def ck_ge_2(self):
		return self.DFilterCount(pkt_http,
			'http.request.method >= "HEAD"', 1)

	def ck_ge_3(self):
		return self.DFilterCount(pkt_http,
			'http.request.method >= "HEAE"', 0)

	def ck_lt_1(self):
		return self.DFilterCount(pkt_http,
			'http.request.method < "HEAC"', 0)

	def ck_lt_2(self):
		return self.DFilterCount(pkt_http,
			'http.request.method < "HEAD"', 0)

	def ck_lt_3(self):
		return self.DFilterCount(pkt_http,
			'http.request.method < "HEAE"', 1)

	def ck_le_1(self):
		return self.DFilterCount(pkt_http,
			'http.request.method <= "HEAC"', 0)

	def ck_le_2(self):
		return self.DFilterCount(pkt_http,
			'http.request.method <= "HEAD"', 1)

	def ck_le_3(self):
		return self.DFilterCount(pkt_http,
			'http.request.method <= "HEAE"', 1)

	# XXX - this isn't handled in wireshark yet
	def ck_slice_1(self):
		return self.DFilterCount(pkt_http,
			'http.request.method[0] == "H"', 1)

	def ck_slice_2(self):
		return self.DFilterCount(pkt_http,
			'http.request.method[0] == "P"', 0)

	def ck_slice_3(self):
		return self.DFilterCount(pkt_http,
			'http.request.method[0:4] == "HEAD"', 1)

	def ck_slice_4(self):
		return self.DFilterCount(pkt_http,
			'http.request.method[0:4] != "HEAD"', 0)

	def ck_slice_5(self):
		return self.DFilterCount(pkt_http,
			'http.request.method[1:2] == "EA"', 1)

	def ck_slice_6(self):
		return self.DFilterCount(pkt_http,
			'http.request.method[1:2] > "EA"', 0)

	def ck_slice_7(self):
		return self.DFilterCount(pkt_http,
			'http.request.method[-1] == "D"', 1)

	def ck_slice_8(self):
		return self.DFilterCount(pkt_http,
			'http.request.method[-2] == "D"', 0)

	def ck_stringz_1(self):
		return self.DFilterCount(pkt_tftp,
			'tftp.type == "octet"', 1)

	def ck_stringz_2(self):
		return self.DFilterCount(pkt_tftp,
			'tftp.type == "junk"', 0)

        def ck_contains_1(self):
		return self.DFilterCount(pkt_http,
			'http.request.method contains "E"', 1)

	def ck_contains_2(self):
		return self.DFilterCount(pkt_http,
			'http.request.method contains "EA"', 1)

	def ck_contains_3(self):
		return self.DFilterCount(pkt_http,
			'http.request.method contains "HEAD"', 1)

	def ck_contains_4(self):
		return self.DFilterCount(pkt_http,
			'http.request.method contains "POST"', 0)

	def ck_contains_5(self):
		return self.DFilterCount(pkt_http,
			'http.request.method contains 50:4f:53:54"', None) # "POST"

	def ck_contains_6(self):
		return self.DFilterCount(pkt_http,
	'http.request.method contains 48:45:41:44"', 1) # "HEAD"

	def ck_contains_fail_0(self):
		return self.DFilterCount(pkt_http,
			'http.user_agent contains "update"', 0)

	def ck_contains_fail_1(self):
		return self.DFilterCount(pkt_http,
			'http.user_agent contains "UPDATE"', 0)

	def ck_contains_upper_0(self):
		return self.DFilterCount(pkt_http,
			'upper(http.user_agent) contains "UPDATE"', 1)

	def ck_contains_upper_1(self):
		return self.DFilterCount(pkt_http,
			'upper(http.user_agent) contains "update"', 0)

	def ck_contains_upper_2(self):
		return self.DFilterCount(pkt_http,
			'upper(tcp.seq) == 4', None)

	def ck_contains_lower_0(self):
		return self.DFilterCount(pkt_http,
			'lower(http.user_agent) contains "UPDATE"', 0)

	def ck_contains_lower_1(self):
		return self.DFilterCount(pkt_http,
			'lower(http.user_agent) contains "update"', 1)

	def ck_contains_lower_2(self):
		return self.DFilterCount(pkt_http,
			'lower(tcp.seq) == 4', None)


	tests = [
		ck_eq_1,
		ck_eq_2,
		ck_gt_1,
		ck_gt_2,
		ck_gt_3,
		ck_ge_1,
		ck_ge_2,
		ck_ge_3,
		ck_lt_1,
		ck_lt_2,
		ck_lt_3,
		ck_le_1,
		ck_le_2,
		ck_le_3,
# XXX
#		ck_slice_1,
#		ck_slice_2,
#		ck_slice_3,
#		ck_slice_4,
#		ck_slice_5,
#		ck_slice_6,
#		ck_slice_7,
#		ck_slice_8,
		ck_stringz_1,
		ck_stringz_2,
		ck_contains_1,
		ck_contains_2,
		ck_contains_3,
		ck_contains_4,
		ck_contains_5,
		ck_contains_fail_0,
		ck_contains_fail_1,
		ck_contains_upper_0,
		ck_contains_upper_1,
		ck_contains_upper_2,
		ck_contains_lower_0,
		ck_contains_lower_1,
		ck_contains_lower_2,
		]


class Time(Test):
	"""Tests routines in ftype-time.c"""

	def ck_eq_1(self):
		return self.DFilterCount(pkt_http,
			'frame.time == "Dec 31, 2002 07:55:31.3"', 1)

	def ck_eq_2(self):
		return self.DFilterCount(pkt_http,
			'frame.time == "Jan 31, 2002 07:55:31.3"', 0)

	def ck_ne_1(self):
		return self.DFilterCount(pkt_http,
			'frame.time != "Dec 31, 2002 07:55:31.3"', 0)

	def ck_ne_2(self):
		return self.DFilterCount(pkt_http,
			'frame.time != "Jan 31, 2002 07:55:31.3"', 1)

	def ck_gt_1(self):
		return self.DFilterCount(pkt_http,
			'frame.time > "Dec 31, 2002 07:54:31.3"', 1)

	def ck_gt_2(self):
		return self.DFilterCount(pkt_http,
			'frame.time > "Dec 31, 2002 07:55:31.3"', 0)

	def ck_gt_3(self):
		return self.DFilterCount(pkt_http,
			'frame.time > "Dec 31, 2002 07:56:31.3"', 0)

	def ck_ge_1(self):
		return self.DFilterCount(pkt_http,
			'frame.time >= "Dec 31, 2002 07:54:31.3"', 1)

	def ck_ge_2(self):
		return self.DFilterCount(pkt_http,
			'frame.time >= "Dec 31, 2002 07:55:31.3"', 1)

	def ck_ge_3(self):
		return self.DFilterCount(pkt_http,
			'frame.time >= "Dec 31, 2002 07:56:31.3"', 0)

	def ck_lt_1(self):
		return self.DFilterCount(pkt_http,
			'frame.time < "Dec 31, 2002 07:54:31.3"', 0)

	def ck_lt_2(self):
		return self.DFilterCount(pkt_http,
			'frame.time < "Dec 31, 2002 07:55:31.3"', 0)

	def ck_lt_3(self):
		return self.DFilterCount(pkt_http,
			'frame.time < "Dec 31, 2002 07:56:31.3"', 1)

	def ck_le_1(self):
		return self.DFilterCount(pkt_http,
			'frame.time <= "Dec 31, 2002 07:54:31.3"', 0)

	def ck_le_2(self):
		return self.DFilterCount(pkt_http,
			'frame.time <= "Dec 31, 2002 07:55:31.3"', 1)

	def ck_le_3(self):
		return self.DFilterCount(pkt_http,
			'frame.time <= "Dec 31, 2002 07:56:31.3"', 1)

	def ck_relative_time_1(self):
		return self.DFilterCount(pkt_nfs,
			"frame.time_delta == 0.7", 1)

	def ck_relative_time_2(self):
		return self.DFilterCount(pkt_nfs,
			"frame.time_delta > 0.7", 0)

	def ck_relative_time_3(self):
		return self.DFilterCount(pkt_nfs,
			"frame.time_delta < 0.7", 1)

	tests = [
		ck_eq_1,
		ck_eq_2,
		ck_ne_1,
		ck_ne_2,
		ck_gt_1,
		ck_gt_2,
		ck_gt_3,
		ck_ge_1,
		ck_ge_2,
		ck_ge_3,
		ck_lt_1,
		ck_lt_2,
		ck_lt_3,
		ck_le_1,
		ck_le_2,
		ck_le_3,
		ck_relative_time_1,
		ck_relative_time_2,
		ck_relative_time_3,
		]

class TVB(Test):
	"""Tests routines in ftype-tvb.c"""

	def ck_eq_1(self):
		# We expect 0 because even though this byte
		# string matches the 'eth' protocol, protocols cannot
		# work in an '==' comparison yet.
		return self.DFilterCount(pkt_http,
			"eth == 00:e0:81:00:b0:28:00:09:6b:88:f6:c9:08:00", None)

	def ck_eq_2(self):
		# We expect 0 because even though this byte
		# string matches the 'eth' protocol, protocols cannot
		# work in an '==' comparison yet.
		return self.DFilterCount(pkt_http,
			"00:e0:81:00:b0:28:00:09:6b:88:f6:c9:08:00 == eth", None)

	def ck_slice_1(self):
		return self.DFilterCount(pkt_http,
			"ip[0:2] == 45:00", 1)

	def ck_slice_2(self):
		return self.DFilterCount(pkt_http,
			"ip[0:2] == 00:00", 0)

	def ck_slice_3(self):
		return self.DFilterCount(pkt_http,
			"ip[2:2] == 00:c1", 1)

	# These don't work yet in Wireshark
	def ck_slice_4(self):
		return self.DFilterCount(pkt_http,
			"ip[-5] == 0x86", 1)

	def ck_slice_5(self):
		return self.DFilterCount(pkt_http,
			"ip[-1] == 0x86", 0)


        def ck_contains_1(self):
		return self.DFilterCount(pkt_http,
			"eth contains 6b", 1)

	def ck_contains_2(self):
		return self.DFilterCount(pkt_http,
			"eth contains 09:6b:88", 1)

	def ck_contains_3(self):
		return self.DFilterCount(pkt_http,
			"eth contains 00:e0:81:00:b0:28:00:09:6b:88:f5:c9:08:00", 1)

	def ck_contains_4(self):
		return self.DFilterCount(pkt_http,
			"eth contains ff:ff:ff", 0)

	def ck_contains_5(self):
		return self.DFilterCount(pkt_http,
			'http contains "HEAD"', 1)


	tests = [
		ck_eq_1,
		ck_eq_2,

		ck_slice_1,
		ck_slice_2,
		ck_slice_3,
# XXX
#		ck_slice_4,
#		ck_slice_5,
		ck_contains_1,
		ck_contains_2,
		ck_contains_3,
		ck_contains_4,
		ck_contains_5,
		]


class Scanner(Test):
	"""Tests routines in scanner.l"""

	def __init__(self):
		print "Note: Scanner test does not yet test embedded double-quote."

	def ck_dquote_1(self):
		return self.DFilterCount(pkt_http,
			'http.request.method == "HEAD"', 1)

	def ck_dquote_2(self):
		return self.DFilterCount(pkt_http,
			'http.request.method == "\\x48EAD"', 1)

	def ck_dquote_3(self):
		return self.DFilterCount(pkt_http,
			'http.request.method == "\\x58EAD"', 0)

	def ck_dquote_4(self):
		return self.DFilterCount(pkt_http,
			'http.request.method == "\\110EAD"', 1)

	def ck_dquote_5(self):
		return self.DFilterCount(pkt_http,
			'http.request.method == "\\111EAD"', 0)

	def ck_dquote_6(self):
		return self.DFilterCount(pkt_http,
			'http.request.method == "\\HEAD"', 1)

	tests = [
		ck_dquote_1,
		ck_dquote_2,
		ck_dquote_3,
		ck_dquote_4,
		ck_dquote_5,
		]

################################################################################

# These are the test objects to run.
# Keep these in alphabetical order so the help message
# shows them in order.
all_tests = [
	Bytes(),
	Double(),
	Integer(),
	IPv4(),
	Scanner(),
	String(),
	Time(),
	TVB(),
	]

def usage():
	print "usage: %s [OPTS] [TEST ...]" % (sys.argv[0],)
	print "\t-p PATH : path to find both tshark and text2pcap (DEFAULT: . )"
	print "\t-t FILE : location of tshark binary"
	print "\t-x FILE : location of text2pcap binary"
	print "\t-k      : keep temporary files"
	print "\t-v      : verbose"
	print
	print "By not mentioning a test name, all tests are run."
	print "Available tests are:"
	for test in all_tests:
		print "\t", test.__class__.__name__
	sys.exit(1)

def main():

	global TSHARK
	global TEXT2PCAP
	global VERBOSE
	global REMOVE_TEMP_FILES

	# Parse the command-line options
	optstring = "p:t:x:kv"
	longopts = []
	
	try:
		opts, specific_tests = getopt.getopt(sys.argv[1:], optstring, longopts)
	except getopt.GetoptError:
		usage()

	for opt, arg in opts:
		if opt == "-t":
			TSHARK = arg
		elif opt == "-x":
			TEXT2PCAP = arg
		elif opt == "-v":
			VERBOSE = 1
		elif opt == "-p":
			TEXT2PCAP = os.path.join(arg, "text2pcap")
			TSHARK = os.path.join(arg, "tshark")
		elif opt == "-k":
			REMOVE_TEMP_FILES = 0
		else:
			print "Un-handled option:", opt
			usage()

	# Sanity test
	if not os.path.exists(TSHARK):
		sys.exit("tshark program '%s' does not exist." % (TSHARK,))

	if not os.path.exists(TEXT2PCAP):
		sys.exit("text2pcap program '%s' does not exist." % (TEXT2PCAP,))


	# Determine which tests to run.
	tests_to_run = []
	if specific_tests:
		# Go through the tests looking for the ones whose names
		# match the command-line arguments.
		all_ok = 1
		for test_name in specific_tests:
			for test in all_tests:
				if test_name == test.__class__.__name__:
					tests_to_run.append(test)
					break
			else:
				print >> sys.stderr, "%s is unrecognized as a test." % \
					(test_name,)
				all_ok = 0

		if not all_ok:
			sys.exit(1)
	else:
		tests_to_run = all_tests

	# Run the tests and keep score.
	tot_run = 0
	tot_succeeded = 0
	for test in tests_to_run:
		print test.__class__.__name__
		(run, succeeded) = test.Run()
		tot_run += run
		tot_succeeded += succeeded
		print

	print
	print "Total Tests Run:", tot_run
	print "Total Tests Succeeded:", tot_succeeded
	print "Total Tests Failed:", tot_run - tot_succeeded

	if tot_succeeded == tot_run:
		sys.exit(0)
	else:
		sys.exit(1)

if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		print "\nInterrupted by user."
