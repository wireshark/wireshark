/* packet-tftp.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_TFTP_H__
#define __PACKET_TFTP_H__

/* Private data passed from the TFTP dissector to subdissectors. */
struct tftpinfo {
    const char *filename;
};

#endif /* __PACKET_TFTP_H__ */
