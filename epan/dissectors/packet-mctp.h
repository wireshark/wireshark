/* packet-mctp.c
 * Definitions for Management Component Transport Protocol (MCTP) packet
 * disassembly
 * Copyright 2022, Jeremy Kerr <jk@codeconstruct.com.au>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_MCTP_H__
#define __PACKET_MCTP_H__

/* MCTP type values */

#define MCTP_TYPE_CONTROL   0
#define MCTP_TYPE_PLDM      1
#define MCTP_TYPE_NCSI      2
#define MCTP_TYPE_ETHERNET  3
#define MCTP_TYPE_NVME      4

#endif /* __PACKET_MCTP_H__ */
