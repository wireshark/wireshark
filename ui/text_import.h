/**-*-C-*-**********************************************************************
 * text_import.h
 * State machine for text import
 * November 2010, Jaap Keuter <jaap.keuter@xs4all.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Based on text2pcap.h by Ashok Narayanan <ashokn@cisco.com>
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
 *
 *******************************************************************************/


#ifndef __TEXT_IMPORT_H__
#define __TEXT_IMPORT_H__

#include <glib.h>

#include <wiretap/wtap.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define IMPORT_MAX_PACKET 65535

/* The parameter interface */

enum offset_type
{
    OFFSET_NONE = 0,
    OFFSET_HEX,
    OFFSET_OCT,
    OFFSET_DEC
};

enum dummy_header_type
{
    HEADER_NONE,
    HEADER_ETH,
    HEADER_IPV4,
    HEADER_UDP,
    HEADER_TCP,
    HEADER_SCTP,
    HEADER_SCTP_DATA
};

typedef struct
{
    /* Input info */
    char *import_text_filename;
    FILE *import_text_file;
    enum offset_type offset_type;
    gboolean date_timestamp;
    gboolean has_direction;
    char *date_timestamp_format;

    /* Import info */
    guint encapsulation;
    wtap_dumper* wdh;

    /* Dummy header info (if encapsulation == 1) */
    enum dummy_header_type dummy_header_type;
    guint pid;
    guint protocol;
    guint src_port;
    guint dst_port;
    guint tag;
    guint ppi;

    guint max_frame_length;
} text_import_info_t;

int text_import(text_import_info_t *info);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TEXT_IMPORT_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
