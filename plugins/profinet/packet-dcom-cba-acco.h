/* packet-dcom-cba-acco.h
 * Routines for DCOM CBA
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

#ifndef __PACKET_DCERPC_DCOM_CBA_ACCO_H
#define __PACKET_DCERPC_DCOM_CBA_ACCO_H

typedef struct cba_pdev_s {
    GList           *ldevs;
    dcom_object_t   *object;
    gint            first_packet;

    const guint8    ip[4];
} cba_pdev_t;

typedef struct cba_ldev_s {
    GList           *provframes;
    GList           *consframes;
    GList           *provconns;
    GList           *consconns;
    dcom_object_t   *ldev_object;
    dcom_object_t   *acco_object;
    cba_pdev_t      *parent;
    gint            first_packet;

    const char      *name;
} cba_ldev_t;


extern GList *cba_pdevs;

extern cba_pdev_t *
cba_pdev_find(packet_info *pinfo, const guint8 *ip, e_uuid_t *ipid);

extern void
cba_pdev_link(packet_info *pinfo, cba_pdev_t *pdev, dcom_interface_t *pdev_interf);

extern cba_pdev_t *
cba_pdev_add(packet_info *pinfo, const guint8 *ip);

extern void
cba_ldev_link(packet_info *pinfo, cba_ldev_t *ldev, dcom_interface_t *ldev_interf);

extern void
cba_ldev_link_acco(packet_info *pinfo, cba_ldev_t *ldev, dcom_interface_t *acco_interf);

extern cba_ldev_t *
cba_ldev_find(packet_info *pinfo, const void *ip, e_uuid_t *ipid);

extern cba_ldev_t *
cba_ldev_add(packet_info *pinfo, cba_pdev_t *pdev, const char *name);

#endif /* packet-dcerpc-dcom-cba-acco.h */
