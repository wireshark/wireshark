#!/usr/bin/env python3

# Copyright 2014 Roland Knall <rknall [AT] gmail.com>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

"""
This is a generic example, which produces pcap packages every n seconds, and
is configurable via extcap options.

@note
{
To use this script on Windows, please generate an extcap_example.bat inside
the extcap folder, with the following content:

-------
@echo off
C:\Windows\py.exe C:\Path\to\extcap_example.py %*
-------

Windows is not able to execute Python scripts directly, which also goes for all
other script-based formats beside VBScript
}

"""

from __future__ import print_function

import sys
import re
import argparse
import time
import struct
import array
from threading import Thread

ERROR_USAGE          = 0
ERROR_ARG            = 1
ERROR_INTERFACE      = 2
ERROR_FIFO           = 3
ERROR_DELAY          = 4

CTRL_CMD_INITIALIZED = 0
CTRL_CMD_SET         = 1
CTRL_CMD_ADD         = 2
CTRL_CMD_REMOVE      = 3
CTRL_CMD_ENABLE      = 4
CTRL_CMD_DISABLE     = 5
CTRL_CMD_STATUSBAR   = 6
CTRL_CMD_INFORMATION = 7
CTRL_CMD_WARNING     = 8
CTRL_CMD_ERROR       = 9

CTRL_ARG_MESSAGE     = 0
CTRL_ARG_DELAY       = 1
CTRL_ARG_VERIFY      = 2
CTRL_ARG_BUTTON      = 3
CTRL_ARG_HELP        = 4
CTRL_ARG_RESTORE     = 5
CTRL_ARG_LOGGER      = 6
CTRL_ARG_NONE        = 255

initialized = False
message = ''
delay = 0.0
verify = False
button = False
button_disabled = False

"""
This code has been taken from http://stackoverflow.com/questions/5943249/python-argparse-and-controlling-overriding-the-exit-status-code - originally developed by Rob Cowie http://stackoverflow.com/users/46690/rob-cowie
"""
class ArgumentParser(argparse.ArgumentParser):
    def _get_action_from_name(self, name):
        """Given a name, get the Action instance registered with this parser.
        If only it were made available in the ArgumentError object. It is
        passed as it's first arg...
        """
        container = self._actions
        if name is None:
            return None
        for action in container:
            if '/'.join(action.option_strings) == name:
                return action
            elif action.metavar == name:
                return action
            elif action.dest == name:
                return action

    def error(self, message):
        exc = sys.exc_info()[1]
        if exc:
            exc.argument = self._get_action_from_name(exc.argument_name)
            raise exc
        super(ArgumentParser, self).error(message)

#### EXTCAP FUNCTIONALITY

"""@brief Extcap configuration
This method prints the extcap configuration, which will be picked up by the
interface in Wireshark to present a interface specific configuration for
this extcap plugin
"""
def extcap_config(interface, option):
    args = []
    values = []
    multi_values = []

    args.append((0, '--delay', 'Time delay', 'Time delay between packages', 'integer', '{range=1,15}{default=5}'))
    args.append((1, '--message', 'Message', 'Package message content', 'string', '{required=true}{placeholder=Please enter a message here ...}'))
    args.append((2, '--verify', 'Verify', 'Verify package content', 'boolflag', '{default=yes}'))
    args.append((3, '--remote', 'Remote Channel', 'Remote Channel Selector', 'selector', '{reload=true}{placeholder=Load interfaces ...}'))
    args.append((4, '--fake_ip', 'Fake IP Address', 'Use this ip address as sender', 'string', '{save=false}{validation=\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b}'))
    args.append((5, '--ltest', 'Long Test', 'Long Test Value', 'long', '{default=123123123123123123}{group=Numeric Values}'))
    args.append((6, '--d1test', 'Double 1 Test', 'Long Test Value', 'double', '{default=123.456}{group=Numeric Values}'))
    args.append((7, '--d2test', 'Double 2 Test', 'Long Test Value', 'double', '{default= 123,456}{group=Numeric Values}'))
    args.append((8, '--password', 'Password', 'Package message password', 'password', ''))
    args.append((9, '--ts', 'Start Time', 'Capture start time', 'timestamp', '{group=Time / Log}'))
    args.append((10, '--logfile', 'Log File Test', 'The Log File Test', 'fileselect', '{group=Time / Log}'))
    args.append((11, '--radio', 'Radio Test', 'Radio Test Value', 'radio', '{group=Selection}'))
    args.append((12, '--multi', 'MultiCheck Test', 'MultiCheck Test Value', 'multicheck', '{group=Selection}'))

    if option == "remote":
        values.append((3, "if1", "Remote Interface 1", "false"))
        values.append((3, "if2", "Remote Interface 2", "true"))
        values.append((3, "if3", "Remote Interface 3", "false"))
        values.append((3, "if4", "Remote Interface 4", "false"))

    if option == "radio":
        values.append((11, "r1", "Radio Option 1", "false"))
        values.append((11, "r2", "Radio Option 2", "false"))
        values.append((11, "r3", "Radio Option 3", "true"))


    if len(option) <= 0:
        for arg in args:
            print("arg {number=%d}{call=%s}{display=%s}{tooltip=%s}{type=%s}%s" % arg)

        values.append((3, "if1", "Remote1", "true"))
        values.append((3, "if2", "Remote2", "false"))

        values.append((11, "r1", "Radio1", "false"))
        values.append((11, "r2", "Radio2", "true"))

    if len(option) <= 0:
        multi_values.append(((12, "m1", "Checkable Parent 1", "false", "true"), None))
        multi_values.append(((12, "m1c1", "Checkable Child 1", "false", "true"), "m1"))
        multi_values.append(((12, "m1c1g1", "Uncheckable Grandchild", "false", "false"), "m1c1"))
        multi_values.append(((12, "m1c2", "Checkable Child 2", "false", "true"), "m1"))
        multi_values.append(((12, "m2", "Checkable Parent 2", "false", "true"), None))
        multi_values.append(((12, "m2c1", "Checkable Child 1", "false", "true"), "m2"))
        multi_values.append(((12, "m2c1g1", "Checkable Grandchild", "false", "true"), "m2c1"))
        multi_values.append(((12, "m2c2", "Uncheckable Child 2", "false", "false"), "m2"))
        multi_values.append(((12, "m2c2g1", "Uncheckable Grandchild", "false", "false"), "m2c2"))

    for value in values:
        print("value {arg=%d}{value=%s}{display=%s}{default=%s}" % value)

    for (value, parent) in multi_values:
        sentence = "value {arg=%d}{value=%s}{display=%s}{default=%s}{enabled=%s}" % value
        extra = "{parent=%s}" % parent if parent else ""
        print("".join((sentence, extra)))


def extcap_version():
    print("extcap {version=1.0}{help=https://www.wireshark.org}{display=Example extcap interface}")

def extcap_interfaces():
    print("extcap {version=1.0}{help=https://www.wireshark.org}{display=Example extcap interface}")
    print("interface {value=example1}{display=Example interface 1 for extcap}")
    print("interface {value=example2}{display=Example interface 2 for extcap}")
    print("control {number=%d}{type=string}{display=Message}{tooltip=Package message content. Must start with a capital letter.}{placeholder=Enter package message content here ...}{validation=^[A-Z]+}" % CTRL_ARG_MESSAGE)
    print("control {number=%d}{type=selector}{display=Time delay}{tooltip=Time delay between packages}" % CTRL_ARG_DELAY)
    print("control {number=%d}{type=boolean}{display=Verify}{default=true}{tooltip=Verify package content}" % CTRL_ARG_VERIFY)
    print("control {number=%d}{type=button}{display=Turn on}{tooltip=Turn on or off}" % CTRL_ARG_BUTTON)
    print("control {number=%d}{type=button}{role=help}{display=Help}{tooltip=Show help}" % CTRL_ARG_HELP)
    print("control {number=%d}{type=button}{role=restore}{display=Restore}{tooltip=Restore default values}" % CTRL_ARG_RESTORE)
    print("control {number=%d}{type=button}{role=logger}{display=Log}{tooltip=Show capture log}" % CTRL_ARG_LOGGER)
    print("value {control=%d}{value=1}{display=1}" % CTRL_ARG_DELAY)
    print("value {control=%d}{value=2}{display=2}" % CTRL_ARG_DELAY)
    print("value {control=%d}{value=3}{display=3}" % CTRL_ARG_DELAY)
    print("value {control=%d}{value=4}{display=4}" % CTRL_ARG_DELAY)
    print("value {control=%d}{value=5}{display=5}{default=true}" % CTRL_ARG_DELAY)
    print("value {control=%d}{value=60}{display=60}" % CTRL_ARG_DELAY)


def extcap_dlts(interface):
    if interface == '1':
        print("dlt {number=147}{name=USER0}{display=Demo Implementation for Extcap}")
    elif interface == '2':
        print("dlt {number=148}{name=USER1}{display=Demo Implementation for Extcap}")

def validate_capture_filter(capture_filter):
    if capture_filter != "filter" and capture_filter != "valid":
        print("Illegal capture filter")

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

def pcap_fake_header():

    header = bytearray()
    header += struct.pack('<L', int('a1b2c3d4', 16))
    header += struct.pack('<H', unsigned(2))  # Pcap Major Version
    header += struct.pack('<H', unsigned(4))  # Pcap Minor Version
    header += struct.pack('<I', int(0))  # Timezone
    header += struct.pack('<I', int(0))  # Accuracy of timestamps
    header += struct.pack('<L', int('0000ffff', 16))  # Max Length of capture frame
    header += struct.pack('<L', unsigned(1))  # Ethernet
    return header

# Calculates and returns the IP checksum based on the given IP Header
def ip_checksum(iph):
    #split into bytes
    words = splitN(''.join(iph.split()), 4)  # TODO splitN() func undefined, this code will fail
    csum = 0
    for word in words:
        csum += int(word, base=16)
    csum += (csum >> 16)
    csum = csum & 0xFFFF ^ 0xFFFF
    return csum

iterateCounter = 0

def pcap_fake_package(message, fake_ip):
    global iterateCounter
    pcap = bytearray()
    #length = 14 bytes [ eth ] + 20 bytes [ ip ] + messagelength

    caplength = len(message) + 14 + 20
    timestamp = int(time.time())

    pcap += struct.pack('<L', unsigned(timestamp))  # timestamp seconds
    pcap += struct.pack('<L', 0x00)  # timestamp nanoseconds
    pcap += struct.pack('<L', unsigned(caplength))  # length captured
    pcap += struct.pack('<L', unsigned(caplength))  # length in frame

# ETH
    destValue = '2900'
    srcValue = '3400'
    if (iterateCounter % 2 == 0):
        x = srcValue
        srcValue = destValue
        destValue = x

    pcap += struct.pack('h', int(destValue, 16))  # dest mac
    pcap += struct.pack('h', int(destValue, 16))  # dest mac
    pcap += struct.pack('h', int(destValue, 16))  # dest mac
    pcap += struct.pack('h', int(srcValue, 16))  # source mac
    pcap += struct.pack('h', int(srcValue, 16))  # source mac
    pcap += struct.pack('h', int(srcValue, 16))  # source mac
    pcap += struct.pack('<h', unsigned(8))  # protocol (ip)
    iterateCounter += 1

# IP
    pcap += struct.pack('b', int('45', 16))  # IP version
    pcap += struct.pack('b', int('0', 16))  #
    pcap += struct.pack('>H', unsigned(len(message)+20))  # length of data + payload
    pcap += struct.pack('<H', int('0', 16))  # Identification
    pcap += struct.pack('b', int('40', 16))  # Don't fragment
    pcap += struct.pack('b', int('0', 16))  # Fragment Offset
    pcap += struct.pack('b', int('40', 16))
    pcap += struct.pack('B', 0xFE)  # Protocol (2 = unspecified)
    pcap += struct.pack('<H', int('0000', 16))  # Checksum

    parts = fake_ip.split('.')
    ipadr = (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    pcap += struct.pack('>L', ipadr)  # Source IP
    pcap += struct.pack('>L', int('7F000001', 16))  # Dest IP

    pcap += message

    return pcap

def control_read(fn):
    try:
        header = fn.read(6)
        sp, _, length, arg, typ = struct.unpack('>sBHBB', header)
        if length > 2:
            payload = fn.read(length - 2).decode('utf-8', 'replace')
        else:
            payload = ''
        return arg, typ, payload
    except Exception:
        return None, None, None

def control_read_thread(control_in, fn_out):
    global initialized, message, delay, verify, button, button_disabled
    with open(control_in, 'rb', 0) as fn:
        arg = 0
        while arg is not None:
            arg, typ, payload = control_read(fn)
            log = ''
            if typ == CTRL_CMD_INITIALIZED:
                initialized = True
            elif arg == CTRL_ARG_MESSAGE:
                message = payload
                log = "Message = " + payload
            elif arg == CTRL_ARG_DELAY:
                delay = float(payload)
                log = "Time delay = " + payload
            elif arg == CTRL_ARG_VERIFY:
                # Only read this after initialized
                if initialized:
                    verify = (payload[0] != '\0')
                    log = "Verify = " + str(verify)
                    control_write(fn_out, CTRL_ARG_NONE, CTRL_CMD_STATUSBAR, "Verify changed")
            elif arg == CTRL_ARG_BUTTON:
                control_write(fn_out, CTRL_ARG_BUTTON, CTRL_CMD_DISABLE, "")
                button_disabled = True
                if button:
                    control_write(fn_out, CTRL_ARG_BUTTON, CTRL_CMD_SET, "Turn on")
                    button = False
                    log = "Button turned off"
                else:
                    control_write(fn_out, CTRL_ARG_BUTTON, CTRL_CMD_SET, "Turn off")
                    button = True
                    log = "Button turned on"

            if len(log) > 0:
                control_write(fn_out, CTRL_ARG_LOGGER, CTRL_CMD_ADD, log + "\n")

def control_write(fn, arg, typ, payload):
    packet = bytearray()
    packet += struct.pack('>sBHBB', b'T', 0, len(payload) + 2, arg, typ)
    if sys.version_info[0] >= 3 and isinstance(payload, str):
        packet += payload.encode('utf-8')
    else:
        packet += payload
    fn.write(packet)

def control_write_defaults(fn_out):
    global initialized, message, delay, verify

    while not initialized:
        time.sleep(.1)  # Wait for initial control values

    # Write startup configuration to Toolbar controls
    control_write(fn_out, CTRL_ARG_MESSAGE, CTRL_CMD_SET, message)
    control_write(fn_out, CTRL_ARG_DELAY, CTRL_CMD_SET, str(int(delay)))
    control_write(fn_out, CTRL_ARG_VERIFY, CTRL_CMD_SET, struct.pack('B', verify))

    for i in range(1, 16):
        item = '%d\x00%d sec' % (i, i)
        control_write(fn_out, CTRL_ARG_DELAY, CTRL_CMD_ADD, item)

    control_write(fn_out, CTRL_ARG_DELAY, CTRL_CMD_REMOVE, str(60))

def extcap_capture(interface, fifo, control_in, control_out, in_delay, in_verify, in_message, remote, fake_ip):
    global message, delay, verify, button_disabled
    delay = in_delay if in_delay != 0 else 5
    message = in_message
    verify = in_verify
    counter = 1
    fn_out = None

    data = """Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor
           incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nost
           rud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis
           aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugi
           at nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culp
           a qui officia deserunt mollit anim id est laborum. """

    with open(fifo, 'wb', 0) as fh:
        fh.write(pcap_fake_header())

        if control_out is not None:
            fn_out = open(control_out, 'wb', 0)
            control_write(fn_out, CTRL_ARG_LOGGER, CTRL_CMD_SET, "Log started at " + time.strftime("%c") + "\n")

        if control_in is not None:
            # Start reading thread
            thread = Thread(target=control_read_thread, args=(control_in, fn_out))
            thread.start()

        if fn_out is not None:
            control_write_defaults(fn_out)

        dataPackage = int(0)
        dataTotal = int(len(data) / 20) + 1

        while True:
            if fn_out is not None:
                log = "Received packet #" + str(counter) + "\n"
                control_write(fn_out, CTRL_ARG_LOGGER, CTRL_CMD_ADD, log)
                counter = counter + 1

                if button_disabled:
                    control_write(fn_out, CTRL_ARG_BUTTON, CTRL_CMD_ENABLE, "")
                    control_write(fn_out, CTRL_ARG_NONE, CTRL_CMD_INFORMATION, "Turn action finished.")
                    button_disabled = False

            if (dataPackage * 20 > len(data)):
                dataPackage = 0
            dataSub = data[dataPackage * 20:(dataPackage + 1) * 20]
            dataPackage += 1

            out = ("%c%s%c%c%c%s%c%s%c" % (len(remote), remote.strip(), dataPackage, dataTotal, len(dataSub), dataSub.strip(), len(message), message.strip(), verify)).encode("utf8")
            fh.write(pcap_fake_package(out, fake_ip))
            time.sleep(delay)

    thread.join()
    if fn_out is not None:
        fn_out.close()

def extcap_close_fifo(fifo):
    # This is apparently needed to workaround an issue on Windows/macOS
    # where the message cannot be read. (really?)
    fh = open(fifo, 'wb', 0)
    fh.close()

####

def usage():
    print("Usage: %s <--extcap-interfaces | --extcap-dlts | --extcap-interface | --extcap-config | --capture | --extcap-capture-filter | --fifo>" % sys.argv[0] )

if __name__ == '__main__':
    interface = ""
    option = ""

    # Capture options
    delay = 0
    message = ""
    fake_ip = ""
    ts = 0

    parser = ArgumentParser(
            prog="Extcap Example",
            description="Extcap example program for Python"
            )

    # Extcap Arguments
    parser.add_argument("--capture", help="Start the capture routine", action="store_true" )
    parser.add_argument("--extcap-interfaces", help="Provide a list of interfaces to capture from", action="store_true")
    parser.add_argument("--extcap-interface", help="Provide the interface to capture from")
    parser.add_argument("--extcap-dlts", help="Provide a list of dlts for the given interface", action="store_true")
    parser.add_argument("--extcap-config", help="Provide a list of configurations for the given interface", action="store_true")
    parser.add_argument("--extcap-capture-filter", help="Used together with capture to provide a capture filter")
    parser.add_argument("--fifo", help="Use together with capture to provide the fifo to dump data to")
    parser.add_argument("--extcap-control-in", help="Used to get control messages from toolbar")
    parser.add_argument("--extcap-control-out", help="Used to send control messages to toolbar")
    parser.add_argument("--extcap-version", help="Shows the version of this utility", nargs='?', default="")
    parser.add_argument("--extcap-reload-option", help="Reload elements for the given option")

    # Interface Arguments
    parser.add_argument("--verify", help="Demonstrates a verification bool flag", action="store_true" )
    parser.add_argument("--delay", help="Demonstrates an integer variable", type=int, default=0, choices=[0, 1, 2, 3, 4, 5, 6] )
    parser.add_argument("--remote", help="Demonstrates a selector choice", default="if1", choices=["if1", "if2", "if3", "if4"] )
    parser.add_argument("--message", help="Demonstrates string variable", nargs='?', default="" )
    parser.add_argument("--fake_ip", help="Add a fake sender IP address", nargs='?', default="127.0.0.1" )
    parser.add_argument("--ts", help="Capture start time", action="store_true" )

    try:
        args, unknown = parser.parse_known_args()
    except argparse.ArgumentError as exc:
        print("%s: %s" % (exc.argument.dest, exc.message), file=sys.stderr)
        fifo_found = 0
        fifo = ""
        for arg in sys.argv:
            if arg == "--fifo" or arg == "--extcap-fifo":
                fifo_found = 1
            elif fifo_found == 1:
                fifo = arg
                break
        extcap_close_fifo(fifo)
        sys.exit(ERROR_ARG)

    if len(sys.argv) <= 1:
        parser.exit("No arguments given!")

    if args.extcap_version and not args.extcap_interfaces:
        extcap_version()
        sys.exit(0)

    if not args.extcap_interfaces and args.extcap_interface is None:
        parser.exit("An interface must be provided or the selection must be displayed")
    if args.extcap_capture_filter and not args.capture:
        validate_capture_filter(args.extcap_capture_filter)
        sys.exit(0)

    if args.extcap_interfaces or args.extcap_interface is None:
        extcap_interfaces()
        sys.exit(0)

    if len(unknown) > 1:
        print("Extcap Example %d unknown arguments given" % len(unknown))

    m = re.match('example(\d+)', args.extcap_interface)
    if not m:
        sys.exit(ERROR_INTERFACE)
    interface = m.group(1)

    message = args.message
    if args.message is None or len(args.message) == 0:
        message = "Extcap Test"

    fake_ip = args.fake_ip
    if args.fake_ip is None or len(args.fake_ip) < 7 or len(args.fake_ip.split('.')) != 4:
        fake_ip = "127.0.0.1"

    ts = args.ts

    if args.extcap_reload_option and len(args.extcap_reload_option) > 0:
        option = args.extcap_reload_option

    if args.extcap_config:
        extcap_config(interface, option)
    elif args.extcap_dlts:
        extcap_dlts(interface)
    elif args.capture:
        if args.fifo is None:
            sys.exit(ERROR_FIFO)
        # The following code demonstrates error management with extcap
        if args.delay > 5:
            print("Value for delay [%d] too high" % args.delay, file=sys.stderr)
            extcap_close_fifo(args.fifo)
            sys.exit(ERROR_DELAY)

        try:
            extcap_capture(interface, args.fifo, args.extcap_control_in, args.extcap_control_out, args.delay, args.verify, message, args.remote, fake_ip)
        except KeyboardInterrupt:
            pass
    else:
        usage()
        sys.exit(ERROR_USAGE)
