/* packet-ntp.h
 * Definitions for packet disassembly structures and routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_NTP_H
#define PACKET_NTP_H

extern const char *tvb_ntp_fmt_ts_sec(tvbuff_t *tvb, int offset);
extern void ntp_to_nstime(tvbuff_t *tvb, int offset, nstime_t *nstime);

#endif
