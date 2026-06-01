/* capture_filter_completer.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/models/capture_filter_completer.h>

#include <QStringListModel>

static const QString libpcap_primitive_chars_ = "-0123456789abcdefghijklmnopqrstuvwxyz";

// Primitives are from pcap-filter.manmisc (carried over from the old
// SyntaxLineEdit-based capture filter edit so completion offers the same
// closed set).
QStringList CaptureFilterCompleter::primitives()
{
    static const QStringList list = QStringList()
        // "Abbreviations for..."
        << "ether proto"
        << "ip" << "ip6" << "arp" << "rarp" << "atalk" << "aarp" << "decnet" << "iso" << "stp" << "ipx" << "netbeui"
        << "moprc" << "mopdl"
        // ip proto
        << "tcp" << "udp" << "icmp"
        // iso proto
        << "clnp" << "esis" << "isis"
        // IS-IS PDU types
        << "l1" << "l2" << "iih" << "lsp" << "snp" << "csnp" << "psnp"
        // Per-primitive forms
        << "action"
        << "clnp"
        << "decnet dst"
        << "decnet host"
        << "decnet src"
        << "dir"
        << "dst host"
        << "dst net"
        << "dst port"
        << "dst portrange"
        << "ether broadcast"
        << "ether dst"
        << "ether host"
        << "ether multicast"
        << "ether src"
        << "gateway"
        << "greater"
        << "host"
        << "ifname"
        << "ip broadcast"
        << "ip multicast"
        << "ip proto"
        << "ip protochain"
        << "ip6 multicast"
        << "ip6 proto"
        << "ip6 protochain"
        << "iso proto"
        << "l1"
        << "lat"
        << "less"
        << "mpls"
        << "net"
        << "on"
        << "port"
        << "portrange"
        << "reason"
        << "rnr"
        << "rset"
        << "rulenum"
        << "ruleset"
        << "src host"
        << "src net"
        << "src port"
        << "src portrange"
        << "srnr"
        << "subrulenum"
        << "subtype"
        << "type"
        << "vlan"
        << "wlan addr1"
        << "wlan addr2"
        << "wlan addr3"
        << "wlan addr4"
        << "wlan ra"
        << "wlan ta";
    return list;
}

CaptureFilterCompleter::CaptureFilterCompleter(QObject *parent) :
    FilterCompleter(parent),
    primitives_(new QStringListModel(primitives(), this))
{
    setTokenChars(libpcap_primitive_chars_);
}
