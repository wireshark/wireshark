/* packet-ndmp.h
 *
 * (c) 2007 Ronnie Sahlberg
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_NDMP_H__
#define __PACKET_NDMP_H__

extern gboolean check_if_ndmp(tvbuff_t *tvb, packet_info *pinfo);

#endif /* packet-ndmp.h */

