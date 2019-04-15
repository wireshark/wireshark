#!/usr/bin/env python3
#
# Wireshark test dummy extcap
#
# Copyright (c) 2018-2019 Peter Wu <peter@lekensteyn.nl>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
import argparse, codecs, os, sys

parser = argparse.ArgumentParser()

# Actions
parser.add_argument('--extcap-interfaces', action='store_true')
parser.add_argument('--extcap-dlts', action='store_true')
parser.add_argument('--extcap-config', action='store_true')
parser.add_argument('--capture', action='store_true')
parser.add_argument('--extcap-version')

parser.add_argument('--extcap-interface', metavar='IFACE')

parser.add_argument('--extcap-capture-filter', metavar='CFILTER')
parser.add_argument('--fifo', metavar='FIFO')


def extcap_interfaces():
    print("extcap {version=1.0}")
    print("interface {value=sampleif}{display=Remote dumpcap}")


def extcap_dlts():
    # Required for the interface to show up in the interface list
    print("dlt {number=147}{name=USER0}{display=Remote capture dependent DLT}")


def extcap_config():
    print("arg {number=0}{call=--test1}{display=Remote SSH server address}{type=string}{tooltip=bla}{required=true}{group=Server}")
    print("arg {number=1}{call=--test2}{display=[7] Urządzenie kompozytowe USB}{type=string}{tooltip=X}{group=Capture}")


def main():
    # In Python 3.6 and older, the encoding of stdout depends on the locale.
    # Do not rely on that and force a sane encoding instead. Python 3.7 has
    # improved, see https://www.python.org/dev/peps/pep-0540/
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach())

    args = parser.parse_args()
    if args.extcap_interfaces:
        return extcap_interfaces()

    if args.extcap_dlts:
        return extcap_dlts()
    elif args.extcap_config:
        return extcap_config()
    else:
        parser.error('Unsupported')
        return 1

sys.exit(main())
