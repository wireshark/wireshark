/* packet-btle.h
 * Structures for determining the dissection context for BTLE.
 *
 * Copyright 2014, Christopher D. Kilgour, techie at whiterocker dot com
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef __PACKET_BTLE_H__
#define __PACKET_BTLE_H__

/*
 * These structures are meant to support the provision of contextual
 * metadata to the BTLE dissector.
 */
typedef struct {
    guint64 InitA;
    guint64 AdvA;
    guint32 LinkAA;
    guint32 CRCInit;
    guint8  WinSize;
    guint16 WinOffset;
    guint16 Interval;
    guint16 Latency;
    guint16 Timeout;
    guint64 ChM;
    guint8  Hop;
    guint8  SCA;
} btle_CONNECT_REQ_t;

typedef enum {
    E_AA_NO_COMMENT = 0,
    E_AA_MATCHED,
    E_AA_BIT_ERRORS,
    E_AA_ILLEGAL
} btle_AA_category_t;

typedef struct {
    btle_AA_category_t aa_category;
    btle_CONNECT_REQ_t connection_info;
    gint connection_info_valid: 1;
    gint crc_checked_at_capture: 1;
    gint crc_valid_at_capture: 1;
    gint mic_checked_at_capture: 1;
    gint mic_valid_at_capture: 1;
} btle_context_t;

#endif /* __PACKET_BTLE_H__ */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
