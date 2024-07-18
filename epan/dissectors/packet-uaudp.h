/* packet-uaudp.h
 * Routines for UA/UDP (Universal Alcatel over UDP) packet dissection.
 * Copyright 2012, Alcatel-Lucent Enterprise <lars.ruoff@alcatel-lucent.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _PACKET_UAUDP_H_
#define _PACKET_UAUDP_H_

#define UAUDP_CONNECT           0
#define UAUDP_CONNECT_ACK       1
#define UAUDP_RELEASE           2
#define UAUDP_RELEASE_ACK       3
#define UAUDP_KEEPALIVE         4
#define UAUDP_KEEPALIVE_ACK     5
#define UAUDP_NACK              6
#define UAUDP_DATA              7
#define UAUDP_START_SIG        64
#define UAUDP_START_SIG_ACK    65

#define UAUDP_CONNECT_VERSION           0x00
#define UAUDP_CONNECT_WINDOW_SIZE       0x01
#define UAUDP_CONNECT_MTU               0x02
#define UAUDP_CONNECT_UDP_LOST          0x03
#define UAUDP_CONNECT_UDP_LOST_REINIT   0x04
#define UAUDP_CONNECT_KEEPALIVE         0x05
#define UAUDP_CONNECT_QOS_IP_TOS        0x06
#define UAUDP_CONNECT_QOS_8021_VLID     0x07
#define UAUDP_CONNECT_QOS_8021_PRI      0x08
#define UAUDP_CONNECT_SUPERFAST_CONNECT 0x09

extern value_string_ext uaudp_opcode_str_ext;
extern value_string_ext uaudp_connect_vals_ext;

typedef enum _e_ua_direction {
	SYS_TO_TERM,  /* system -> terminal */
	TERM_TO_SYS,  /* terminal -> system */
	DIR_UNKNOWN   /* unknown direction */
} e_ua_direction;

/* struct for tap wireshark */
typedef struct _tap_struct_uaudp {
	unsigned opcode;
	unsigned expseq; /* expected sequence number */
	unsigned sntseq; /* sent sequence number */
} tap_struct_uaudp;

#endif /* _PACKET_UAUDP_H_ */
