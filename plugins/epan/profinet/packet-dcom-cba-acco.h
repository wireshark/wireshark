/* packet-dcom-cba-acco.h
 * Routines for DCOM CBA
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_DCERPC_DCOM_CBA_ACCO_H
#define __PACKET_DCERPC_DCOM_CBA_ACCO_H

#define CBA_KIND_PDEV 0x50444556U
#define CBA_KIND_LDEV 0x4c444556U

typedef struct cba_pdev_s {
    uint32_t        kind;
    GList           *ldevs;
    dcom_object_t   *object;
    int             first_packet;

    uint8_t         ip[4];
} cba_pdev_t;

typedef struct cba_ldev_s {
    uint32_t        kind;
    GList           *provframes;
    GList           *consframes;
    GList           *provconns;
    GList           *consconns;
    dcom_object_t   *ldev_object;
    dcom_object_t   *acco_object;
    cba_pdev_t      *parent;
    int             first_packet;
    unsigned        nprovconns;
    unsigned        nconsconns;

    const char      *name;
} cba_ldev_t;


extern GList *cba_pdevs;

/* Free all CBA device, frame and connection lists (file cleanup). */
extern void
cba_free_all(void);

extern cba_pdev_t *
cba_pdev_find(packet_info *pinfo, const address *addr, e_guid_t *ipid);

extern void
cba_pdev_link(packet_info *pinfo, cba_pdev_t *pdev, dcom_interface_t *pdev_interf);

extern cba_pdev_t *
cba_pdev_add(packet_info *pinfo, const address *addr);

extern void
cba_ldev_link(packet_info *pinfo, cba_ldev_t *ldev, dcom_interface_t *ldev_interf);

extern void
cba_ldev_link_acco(packet_info *pinfo, cba_ldev_t *ldev, dcom_interface_t *acco_interf);

extern cba_ldev_t *
cba_ldev_find(packet_info *pinfo, const address *addr, e_guid_t *ipid);

extern cba_ldev_t *
cba_ldev_add(packet_info *pinfo, cba_pdev_t *pdev, const char *name);

#endif /* packet-dcerpc-dcom-cba-acco.h */
