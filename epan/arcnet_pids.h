/* arcnet_pids.h
 * ARCNET protocol ID values
 * Copyright 2001-2002, Peter Fales <ethereal@fales-lorenz.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __ARCNET_PIDS_H__
#define __ARCNET_PIDS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* RFC 1051 */
#define ARCNET_PROTO_IP_1051	240
#define ARCNET_PROTO_ARP_1051	241

/* RFC 1201 */
#define ARCNET_PROTO_IP_1201	212
#define ARCNET_PROTO_ARP_1201	213
#define ARCNET_PROTO_RARP_1201	214

#define ARCNET_PROTO_IPX	250
#define ARCNET_PROTO_NOVELL_EC	236

#define ARCNET_PROTO_IPv6	196	/* or so BSD's arcnet.h claims */

/*
 * Raw Ethernet over ARCNET - Linux's "if_arcnet.h" calls this
 * "MS LanMan/WfWg 'NDIS' encapsuation".
 */
#define ARCNET_PROTO_ETHERNET	232

#define ARCNET_PROTO_DATAPOINT_BOOT	0
#define ARCNET_PROTO_DATAPOINT_MOUNT	1
#define ARCNET_PROTO_POWERLAN_BEACON	8
#define ARCNET_PROTO_POWERLAN_BEACON2	243
#define ARCNET_PROTO_LANSOFT	251

#define ARCNET_PROTO_APPLETALK	221
#define ARCNET_PROTO_BANYAN	247	/* Banyan VINES */

#define ARCNET_PROTO_DIAGNOSE	128	/* as per ANSI/ATA 878.1 */

#define ARCNET_PROTO_BACNET	205

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* arcnet_pids.h */
