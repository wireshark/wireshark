/* packet-mtp3.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __PACKET_MTP3_H__
#define __PACKET_MTP3_H__

#include "ws_symbol_export.h"

typedef enum {
  ITU_STANDARD  = 1,
  ANSI_STANDARD = 2,
  CHINESE_ITU_STANDARD = 3,
  JAPAN_STANDARD = 4
} Standard_Type;
#define HEURISTIC_FAILED_STANDARD 0xffff

extern int mtp3_standard;
extern bool mtp3_heuristic_standard;

WS_DLL_PUBLIC const value_string mtp3_standard_vals[];

typedef enum {
  MTP3_ADDR_FMT_DEC	= 1,
  MTP3_ADDR_FMT_HEX	= 2,
  MTP3_ADDR_FMT_NI_DEC	= 3,
  MTP3_ADDR_FMT_NI_HEX	= 4,
  MTP3_ADDR_FMT_DASHED	= 5
} mtp3_net_addr_fmt_e;

typedef struct _mtp3_addr_pc_t {
  Standard_Type		type;
  uint32_t		pc;
  uint8_t		ni;
} mtp3_addr_pc_t;

typedef struct _mtp3_tap_rec_t {
  mtp3_addr_pc_t	addr_opc;
  mtp3_addr_pc_t	addr_dpc;
  uint8_t		mtp3_si_code;
  uint16_t		size;
} mtp3_tap_rec_t;

#define ITU_PC_LENGTH     2
#define ITU_PC_MASK       0x3FFF

#define ANSI_PC_LENGTH    3
#define ANSI_NCM_LENGTH   1
#define ANSI_NETWORK_OFFSET 2
#define ANSI_CLUSTER_OFFSET 1
#define ANSI_MEMBER_OFFSET 0
#define ANSI_PC_MASK      0xFFFFFF
#define ANSI_NETWORK_MASK 0xFF0000
#define ANSI_CLUSTER_MASK 0x00FF00
#define ANSI_MEMBER_MASK  0x0000FF
#define ANSI_PC_STRING_LENGTH 16

#define JAPAN_PC_LENGTH   2
#define JAPAN_PC_MASK     0xffff

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

extern char*   mtp3_pc_to_str(const uint32_t pc);
extern bool mtp3_pc_structured(void);
extern uint32_t mtp3_pc_hash(const mtp3_addr_pc_t *addr_pc_p);
extern int mtp3_addr_len(void);

#ifdef __PROTO_H__
/* epan/to_str.c includes this file, but it does not include proto.h so
 * it doesn't know about things like proto_tree.  This function is not
 * needed by to_str.c, so just don't prototype it there (or anywhere
 * without proto.h).
 */
extern void dissect_mtp3_3byte_pc(tvbuff_t *tvb, unsigned offset,
				  proto_tree *tree, int ett_pc,
				  int hf_pc_string, int hf_pc_network,
				  int hf_pc_cluster, int hf_pc_member,
				  int hf_dpc, int hf_pc);
#endif

/*
 * the following allows TAP code access to the messages
 * without having to duplicate it. With MSVC and a
 * libwireshark.dll, we need a special declaration.
 */
WS_DLL_PUBLIC const value_string mtp3_service_indicator_code_short_vals[];

#define MTP_SI_SNM	0x0
#define MTP_SI_MTN	0x1
#define MTP_SI_MTNS	0x2
#define MTP_SI_SCCP	0x3
#define MTP_SI_TUP	0x4
#define MTP_SI_ISUP	0x5
#define MTP_SI_DUP_CC	0x6
#define MTP_SI_DUP_FAC	0x7
#define MTP_SI_MTP_TEST	0x8
#define MTP_SI_ISUP_B	0x9
#define MTP_SI_ISUP_S	0xa
#define MTP_SI_AAL2	0xc
#define MTP_SI_BICC	0xd
#define MTP_SI_GCP	0xe

/*
 * I only want to gather stats for non-spare SI codes
 */
#define	MTP3_NUM_SI_CODE	9

#define MTP3_NI_INT0 0x0
#define MTP3_NI_INT1 0x1
#define MTP3_NI_NAT0 0x2
#define MTP3_NI_NAT1 0x3
WS_DLL_PUBLIC const value_string mtp3_network_indicator_vals[];

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PACKET_MTP3_H__ */
