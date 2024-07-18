/* packet-rmt-common.h
 * Reliable Multicast Transport (RMT)
 * Common RMT function definitions
 * Copyright 2005, Stefano Pettini <spettini@users.sourceforge.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_RMT_COMMON__
#define __PACKET_RMT_COMMON__

#include <epan/params.h>

/* LCT preferences */

#define LCT_PREFS_EXT_192_NONE 0
#define LCT_PREFS_EXT_192_FLUTE 1

#define LCT_PREFS_EXT_193_NONE 0
#define LCT_PREFS_EXT_193_FLUTE 1

#define LCT_ATSC3_MODE_DISABLED 0
#define LCT_ATSC3_MODE_AUTO 1
#define LCT_ATSC3_MODE_FORCE 2

extern const enum_val_t enum_lct_ext_192[];
extern const enum_val_t enum_lct_ext_193[];
extern const enum_val_t enum_lct_atsc3_mode[];

/* String tables external references */
extern const value_string string_fec_encoding_id[];


/* Structures to exchange data between RMT dissectors */
/* ============================= */
typedef struct lct_data_exchange
{
	/* inputs */
	int ext_192;
	int ext_193;
	bool is_atsc3;

	/* outputs */
	uint8_t codepoint;
	bool is_flute;
	bool is_sp; /* is Source Packet? Source Packet Indicator is defined in RFC 5775 */

} lct_data_exchange_t;

typedef struct fec_data_exchange
{
	/* inputs */
	uint8_t encoding_id;

} fec_data_exchange_t;


/* Common RMT exported functions */
/* ============================= */
extern int lct_ext_decode(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, unsigned offset, unsigned offset_max, lct_data_exchange_t *data_exchange,
                   int hfext, int ettext);
extern void fec_decode_ext_fti(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, uint8_t encoding_id);

extern double rmt_decode_send_rate(uint16_t send_rate );

#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
