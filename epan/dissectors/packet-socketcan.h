/* packet-socketcan.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_SOCKETCAN_H__
#define __PACKET_SOCKETCAN_H__

/* Structure that gets passed between dissectors. */
struct can_identifier
{
	guint32 id;
};

typedef struct can_identifier can_identifier_t;

/* controller area network (CAN) kernel definitions
 * These masks are usually defined within <linux/can.h> but are not
 * available on non-Linux platforms; that's the reason for the
 * redefinitions below
 *
 * special address description flags for the CAN_ID */
#define CAN_EFF_FLAG 0x80000000 /* EFF/SFF is set in the MSB */
#define CAN_RTR_FLAG 0x40000000 /* remote transmission request */
#define CAN_ERR_FLAG 0x20000000 /* error frame */

#define CAN_FLAG_MASK (CAN_EFF_FLAG | CAN_RTR_FLAG | CAN_ERR_FLAG)

#define CAN_EFF_MASK 0x1FFFFFFF /* extended frame format (EFF) has a 29 bit identifier */
#define CAN_SFF_MASK 0x000007FF /* standard frame format (SFF) has a 11 bit identifier */

#endif /* __PACKET_SOCKETCAN_H__ */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
