/* osi-utils.h
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

#ifndef __OSI_UTILS_H__
#define __OSI_UTILS_H__

/* OSI Global defines, common for all OSI protocols */

#define MAX_NSAP_LEN          30
#define MAX_SYSTEMID_LEN      15
#define MAX_AREA_LEN          30

#define RFC1237_NSAP_LEN      20
#define RFC1237_FULLAREA_LEN  13
#define RFC1237_SYSTEMID_LEN   6
#define RFC1237_SELECTOR_LEN   1

#define RFC1237_IDI_LEN        2
#define RFC1237_AFI_LEN        1
#define RFC1237_DFI_LEN        1
#define RFC1237_ORG_LEN        3
#define RFC1237_AA_LEN         3
#define RFC1237_RSVD_LEN       2
#define RFC1237_RD_LEN         2
#define RFC1237_AREA_LEN       3

#define NSAP_IDI_ISODCC       0x39
#define NSAP_IDI_GOSIP2       0x47

gchar*     print_nsap_net ( tvbuff_t *, const gint, int );
void       print_nsap_net_buf( const guint8 *, int, gchar *, int);
gchar*     print_area     ( tvbuff_t *, const gint, int );
void       print_area_buf ( const guint8 *, int, gchar *, int);
gchar*     print_system_id(wmem_allocator_t *, const guint8 *, int );
gchar*     tvb_print_system_id( tvbuff_t *, const gint, int );
void       print_system_id_buf( const guint8 *, int, gchar *, int);

int        get_osi_address_type(void);
void       register_osi_address_type(void);

#endif /* __OSI_UTILS_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
