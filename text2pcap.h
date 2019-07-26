/**-*-C-*-**********************************************************************
 *
 * text2pcap.h
 *
 * Utility to convert an ASCII hexdump into a libpcap-format capture file
 *
 * (c) Copyright 2001 Ashok Narayanan <ashokn@cisco.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef TEXT2PCAP_H
#define TEXT2PCAP_H

typedef enum {
    T_BYTE = 1,
    T_OFFSET,
    T_DIRECTIVE,
    T_TEXT,
    T_EOL
} token_t;

int parse_token(token_t token, char *str);

int text2pcap_scan(void);

#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
