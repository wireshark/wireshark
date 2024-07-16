/*
 * packet-diameter.h
 *
 * Definitions for Diameter packet disassembly
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_DIAMETER_H__
#define __PACKET_DIAMETER_H__

/* Request-Answer Pair */
typedef struct _diameter_req_ans_pair_t
{
	uint32_t		hop_by_hop_id;
	uint32_t		end_to_end_id;
	uint32_t		cmd_code;
	uint32_t		result_code;
	const char*	cmd_str;
	uint32_t 	req_frame; 	/* frame number in which request was seen */
	uint32_t		ans_frame;	/* frame number in which answer was seen */
	nstime_t	req_time;
	nstime_t	srt_time;
	bool	processing_request; /* true if processing request, false if processing answer. */
} diameter_req_ans_pair_t;

/* Info needed by AVP sub dissectors */
typedef struct _diam_sub_dis_t {
	uint32_t application_id;
	uint32_t cmd_code;
	uint32_t feature_list_id;
	bool dis_gouped;       /**< Set during dissection of grouped AVP */
	uint32_t vendor_id;
	char *avp_str;
	proto_item* item;          /**< The item created for this AVP*/
	uint32_t subscription_id_type;     /* Store the Subscription-Id-Type for use when we dissect Subscription-Id-Data */
	uint32_t user_equipment_info_type; /* Store the User-Equipment-Info-Type for use when we dissect User-Equipment-Info-Value */
	bool parent_message_is_request; /* Whether the Diameter message that contains your AVP is a request */
} diam_sub_dis_t;

#define DIAM_APPID_3GPP_CX      16777216
#define DIAM_APPID_3GPP_SH      16777217
#define DIAM_APPID_3GPP_RX      16777236
#define DIAM_APPID_3GPP_GX      16777238
#define DIAM_APPID_3GPP_STA     16777250
#define DIAM_APPID_3GPP_S6A_S6D 16777251
#define DIAM_APPID_3GPP_S13     16777252
#define DIAM_APPID_3GPP_SWM     16777264
#define DIAM_APPID_3GPP_SWX     16777265
#define DIAM_APPID_3GPP_S6B     16777272
#define DIAM_APPID_3GPP_SLH     16777291
#define DIAM_APPID_3GPP_SD      16777303
#define DIAM_APPID_3GPP_S7A     16777308
#define DIAM_APPID_3GPP_S6T     16777345

#endif /* __PACKET_DIAMETER_H__ */
