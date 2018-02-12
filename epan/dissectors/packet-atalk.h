/* packet-atalk.h
 * Definitions for Appletalk packet disassembly (DDP, currently).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_ATALK_H__
#define __PACKET_ATALK_H__

/*
 * DDP packet types.
 */
#define DDP_RTMPDATA	0x01
#define DDP_NBP		0x02
#define DDP_ATP		0x03
#define DDP_AEP		0x04
#define DDP_RTMPREQ	0x05
#define DDP_ZIP		0x06
#define DDP_ADSP	0x07
#define DDP_EIGRP	0x58

#endif
