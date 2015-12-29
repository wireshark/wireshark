#!/usr/bin/env python

# Copyright 2014 Roland Knall <rknall [AT] gmail.com>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
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

"""
This is a generic example, which produces pcap packages every n seconds, and
is configurable via extcap options.

@note
{
To use this script on Windows, please generate an extcap_example.bat inside
the extcap folder, with the following content:

-------
@echo off
<Path to python interpreter> <Path to script file> %*
-------

Windows is not able to execute Python scripts directly, which also goes for all
other script-based formates beside VBScript
}

"""

import os
import sys
import signal
import re
import argparse
import time
import struct
import binascii
from threading import Thread

ERROR_USAGE		= 0
ERROR_ARG 		= 1
ERROR_INTERFACE = 2
ERROR_FIFO 		= 3

doExit = False
globalinterface = 0

def signalHandler(signal, frame):
	global doExit
	doExit = True

#### EXTCAP FUNCTIONALITY

"""@brief Extcap configuration
This method prints the extcap configuration, which will be picked up by the
interface in Wireshark to present a interface specific configuration for
this extcap plugin
"""
def extcap_config(interface):
	args = []
	values = []

	args.append ( (0, '--delay', 'Time delay', 'Time delay between packages', 'integer', '{range=1,15}{default=5}') )
	args.append ( (1, '--message', 'Message', 'Package message content', 'string', '{required=true}') )
	args.append ( (2, '--verify', 'Verify', 'Verify package content', 'boolflag', '{default=yes}') )
	args.append ( (3, '--remote', 'Remote Channel', 'Remote Channel Selector', 'selector', ''))
	args.append ( (4, '--fake_ip', 'Fake IP Address', 'Use this ip address as sender', 'string', '{save=false}{validation=\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b}'))
	args.append ( (5, '--ltest', 'Long Test', 'Long Test Value', 'long', '{default=123123123123123123}'))
	args.append ( (6, '--d1test', 'Double 1 Test', 'Long Test Value', 'double', '{default=123.456}'))
	args.append ( (7, '--d2test', 'Double 2 Test', 'Long Test Value', 'double', '{default= 123,456}'))
	args.append ( (8, '--password', 'Password', 'Package message password', 'password', '') )

	values.append ( (3, "if1", "Remote1", "true" ) )
	values.append ( (3, "if2", "Remote2", "false" ) )

	for arg in args:
		print ("arg {number=%d}{call=%s}{display=%s}{tooltip=%s}{type=%s}%s" % arg)

	for value in values:
		print ("value {arg=%d}{value=%s}{display=%s}{default=%s}" % value)


def extcap_interfaces():
	print ("extcap {version=1.0}")
	print ("interface {value=example1}{display=Example interface usage for extcap}")

def extcap_dlts(interface):
	if ( interface == '1' ):
		print ("dlt {number=147}{name=USER0}{display=Demo Implementation for Extcap}")

"""

### FAKE DATA GENERATOR

Extcap capture routine
 This routine simulates a capture by any kind of user defined device. The parameters
 are user specified and must be handled by the extcap.

 The data captured inside this routine is fake, so change this routine to present
 your own input data, or call your own capture program via Popen for example. See

 for more details.

"""
def unsigned(n):
	return int(n) & 0xFFFFFFFF

def append_bytes(ba, blist):
	for c in range(0, len(blist)):
		ba.append(blist[c])
	return ba

def pcap_fake_header():

	header = bytearray()
	header = append_bytes(header, struct.pack('<L', int ('a1b2c3d4', 16) ))
	header = append_bytes(header, struct.pack('<H', unsigned(2)) ) # Pcap Major Version
	header = append_bytes(header, struct.pack('<H', unsigned(4)) ) # Pcap Minor Version
	header = append_bytes(header, struct.pack('<I', int(0))) # Timezone
	header = append_bytes(header, struct.pack('<I', int(0))) # Accurancy of timestamps
	header = append_bytes(header, struct.pack('<L', int ('0000ffff', 16) )) # Max Length of capture frame
	header = append_bytes(header, struct.pack('<L', unsigned(1))) # Ethernet
	return header

# Calculates and returns the IP checksum based on the given IP Header
def ip_checksum(iph):
	#split into bytes
	words = splitN(''.join(iph.split()),4)
	csum = 0;
	for word in words:
		csum += int(word, base=16)
	csum += (csum >> 16)
	csum = csum & 0xFFFF ^ 0xFFFF
	return csum

def pcap_fake_package ( message, fake_ip ):

	pcap = bytearray()
	#length = 14 bytes [ eth ] + 20 bytes [ ip ] + messagelength

	caplength = len(message) + 14 + 20
	timestamp = int(time.time())

	pcap = append_bytes(pcap, struct.pack('<L', unsigned(timestamp) ) ) # timestamp seconds
	pcap = append_bytes(pcap, struct.pack('<L', 0x00 ) ) # timestamp nanoseconds
	pcap = append_bytes(pcap, struct.pack('<L', unsigned(caplength) ) ) # length captured
	pcap = append_bytes(pcap, struct.pack('<L', unsigned(caplength) ) ) # length in frame

# ETH
	pcap = append_bytes(pcap, struct.pack('h', 0 )) # source mac
	pcap = append_bytes(pcap, struct.pack('h', 0 )) # source mac
	pcap = append_bytes(pcap, struct.pack('h', 0 )) # source mac
	pcap = append_bytes(pcap, struct.pack('h', 0 )) # dest mac
	pcap = append_bytes(pcap, struct.pack('h', 0 )) # dest mac
	pcap = append_bytes(pcap, struct.pack('h', 0 )) # dest mac
	pcap = append_bytes(pcap, struct.pack('<h', unsigned(8) )) # protocol (ip)

# IP
	pcap = append_bytes(pcap, struct.pack('b', int ( '45', 16) )) # IP version
	pcap = append_bytes(pcap, struct.pack('b', int ( '0', 16) )) #
	pcap = append_bytes(pcap, struct.pack('>H', unsigned(len(message)+20) )) # length of data + payload
	pcap = append_bytes(pcap, struct.pack('<H', int ( '0', 16) )) # Identification
	pcap = append_bytes(pcap, struct.pack('b', int ( '40', 16) )) # Don't fragment
	pcap = append_bytes(pcap, struct.pack('b', int ( '0', 16) )) # Fragment Offset
	pcap = append_bytes(pcap, struct.pack('b', int ( '40', 16) ))
	pcap = append_bytes(pcap, struct.pack('B', 0xFE )) # Protocol (2 = unspecified)
	pcap = append_bytes(pcap, struct.pack('<H', int ( '0000', 16) )) # Checksum

	parts = fake_ip.split('.')
	ipadr = (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
	pcap = append_bytes(pcap, struct.pack('>L', ipadr )) # Source IP
	pcap = append_bytes(pcap, struct.pack('>L', int ( '7F000001', 16) )) # Dest IP

	pcap = append_bytes(pcap, message)
	return pcap

def extcap_capture(interface, fifo, delay, verify, message, remote, fake_ip):
	global doExit

	signal.signal(signal.SIGINT, signalHandler)
	signal.signal(signal.SIGTERM , signalHandler)

	tdelay = delay if delay != 0 else 5

	try:
		os.stat(fifo)
	except OSError:
		doExit = True
		print ( "Fifo does not exist, exiting!" )

	fh = open(fifo, 'w+b', 0 )
	fh.write (pcap_fake_header())

	while doExit == False:
		out = str( "%s|%04X%s|%s" % ( remote.strip(), len(message), message, verify ) )
		try:
			fh.write (pcap_fake_package(out, fake_ip))
			time.sleep(tdelay)
		except IOError:
			doExit = True

	fh.close()

####

def usage():
	print ( "Usage: %s <--extcap-interfaces | --extcap-dlts | --extcap-interface | --extcap-config | --capture | --extcap-capture-filter | --fifo>" % sys.argv[0] )

if __name__ == '__main__':
	interface = ""

	# Capture options
	delay = 0
	message = ""
	fake_ip = ""

	parser = argparse.ArgumentParser(
		prog="Extcap Example",
		description="Extcap example program for python"
		)

	# Extcap Arguments
	parser.add_argument("--capture", help="Start the capture routine", action="store_true" )
	parser.add_argument("--extcap-interfaces", help="Provide a list of interfaces to capture from", action="store_true")
	parser.add_argument("--extcap-interface", help="Provide the interface to capture from")
	parser.add_argument("--extcap-dlts", help="Provide a list of dlts for the given interface", action="store_true")
	parser.add_argument("--extcap-config", help="Provide a list of configurations for the given interface", action="store_true")
	parser.add_argument("--extcap-capture-filter", help="Used together with capture to provide a capture filter")
	parser.add_argument("--fifo", help="Use together with capture to provide the fifo to dump data to")

	# Interface Arguments
	parser.add_argument("--verify", help="Demonstrates a verification bool flag", action="store_true" )
	parser.add_argument("--delay", help="Demonstrates an integer variable", type=int, default=0, choices=[0, 1, 2, 3, 4, 5] )
	parser.add_argument("--remote", help="Demonstrates a selector choice", default="if1", choices=["if1", "if2"] )
	parser.add_argument("--message", help="Demonstrates string variable", nargs='?', default="" )
	parser.add_argument("--fake_ip", help="Add a fake sender IP adress", nargs='?', default="127.0.0.1" )

	args, unknown = parser.parse_known_args()
	if ( len(sys.argv) <= 1 ):
		parser.exit("No arguments given!")

	if ( args.extcap_interfaces == False and args.extcap_interface == None ):
		parser.exit("An interface must be provided or the selection must be displayed")

	if ( args.extcap_interfaces == True or args.extcap_interface == None ):
		extcap_interfaces()
		sys.exit(0)

	if ( len(unknown) > 1 ):
		print("Extcap Example %d unknown arguments given" % len(unknown) )

	m = re.match ( 'example(\d+)', args.extcap_interface )
	if not m:
		sys.exit(ERROR_INTERFACE)
	interface = m.group(1)

	message = args.message
	if ( args.message == None or len(args.message) == 0 ):
		message = "Extcap Test"

	fake_ip = args.fake_ip
	if ( args.fake_ip == None or len(args.fake_ip) < 7 or len(args.fake_ip.split('.')) != 4 ):
		fake_ip = "127.0.0.1"

	if args.extcap_config:
		extcap_config(interface)
	elif args.extcap_dlts:
		extcap_dlts(interface)
	elif args.capture:
		if args.fifo is None:
			sys.exit(ERROR_FIFO)
		extcap_capture(interface, args.fifo, args.delay, args.verify, message, args.remote, fake_ip)
	else:
		usage()
		sys.exit(ERROR_USAGE)
