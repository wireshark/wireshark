/* Packet-rdp_drdynvc.c
 * Routines for Dynamic Virtual channel RDP packet dissection
 * Copyright 2021, David Fort
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>
#include <epan/crc32-tvb.h>
#include "packet-rdp.h"
#include "packet-rdpudp.h"

void proto_register_rdp_drdynvc(void);
void proto_reg_handoff_drdynvc(void);

static int proto_rdp_drdynvc;

static int hf_rdp_drdynvc_cbId;
static int hf_rdp_drdynvc_sp;
static int hf_rdp_drdynvc_pri;
static int hf_rdp_drdynvc_cmd;
static int hf_rdp_drdynvc_capa_version;
static int hf_rdp_drdynvc_capa_prio0;
static int hf_rdp_drdynvc_capa_prio1;
static int hf_rdp_drdynvc_capa_prio2;
static int hf_rdp_drdynvc_capa_prio3;
static int hf_rdp_drdynvc_channelId;
static int hf_rdp_drdynvc_pad;
static int hf_rdp_drdynvc_channelName;
static int hf_rdp_drdynvc_creationStatus;
static int hf_rdp_drdynvc_createresp_channelname;
static int hf_rdp_drdynvc_length;
static int hf_rdp_drdynvc_softsync_req_length;
static int hf_rdp_drdynvc_softsync_req_flags;
static int hf_rdp_drdynvc_softsync_req_ntunnels;
static int hf_rdp_drdynvc_softsync_req_channel_tunnelType;
static int hf_rdp_drdynvc_softsync_req_channel_ndvc;
static int hf_rdp_drdynvc_softsync_req_channel_dvcid;
static int hf_rdp_drdynvc_softsync_resp_ntunnels;
static int hf_rdp_drdynvc_softsync_resp_tunnel;
static int hf_rdp_drdynvc_data;
static int hf_rdp_drdynvc_data_progress;


static int ett_rdp_drdynvc;
static int ett_rdp_drdynvc_softsync_channels;
static int ett_rdp_drdynvc_softsync_channel;
static int ett_rdp_drdynvc_softsync_dvc;

dissector_handle_t egfx_handle;
dissector_handle_t rail_handle;
dissector_handle_t cliprdr_handle;
dissector_handle_t snd_handle;
dissector_handle_t ear_handle;

#define PNAME  "RDP Dynamic Channel Protocol"
#define PSNAME "DRDYNVC"
#define PFNAME "rdp_drdynvc"

enum {
	DRDYNVC_CREATE_REQUEST_PDU = 0x01,
	DRDYNVC_DATA_FIRST_PDU = 0x02,
	DRDYNVC_DATA_PDU = 0x03,
	DRDYNVC_CLOSE_REQUEST_PDU = 0x04,
	DRDYNVC_CAPABILITY_REQUEST_PDU = 0x05,
	DRDYNVC_DATA_FIRST_COMPRESSED_PDU = 0x06,
	DRDYNVC_DATA_COMPRESSED_PDU = 0x07,
	DRDYNVC_SOFT_SYNC_REQUEST_PDU = 0x08,
	DRDYNVC_SOFT_SYNC_RESPONSE_PDU = 0x09
};

typedef enum {
	DRDYNVC_CHANNEL_UNKNOWN,
	DRDYNVC_CHANNEL_EGFX, /* MS-RDPEGX */
	DRDYNVC_CHANNEL_TELEMETRY, /* MS-RDPET */
	DRDYNVC_CHANNEL_AUDIOUT, /* MS-RDPEA */
	DRDYNVC_CHANNEL_AUDIN, /* MS-RDPEAI */
	DRDYNVC_CHANNEL_VIDEO_CTL, /*MS-RDPEVOR */
	DRDYNVC_CHANNEL_VIDEO_DATA, /*MS-RDPEVOR */
	DRDYNVC_CHANNEL_CAM,	/* MS-RDPECAM */
	DRDYNVC_CHANNEL_DISPLAY, /* MS-RDPEDISP */
	DRDYNVC_CHANNEL_GEOMETRY,/* MS-RDPEGT */
	DRDYNVC_CHANNEL_MULTITOUCH, /* MS-RDPEI */
	DRDYNVC_CHANNEL_AUTH_REDIR, /* MS-RDPEAR */

	DRDYNVC_CHANNEL_RAIL, /* MS-RDPERP */
	DRDYNVC_CHANNEL_CLIPRDR, /* MS-RDPECLIP */
	DRDYNVC_CHANNEL_DR, /* MS-RDPDR */
} drdynvc_known_channel_t;

enum {
	DRDYNVC_CHANNEL_PDUS_KEY = 1,
};


typedef struct {
	bool reassembled;
	bool decodePayload;
	uint32_t progressStart;
	uint32_t progressEnd;
	uint32_t packetLen;
	uint32_t startReassemblyFrame;
	uint32_t endReassemblyFrame;
	tvbuff_t* tvb;
} drdynvc_pdu_info_t;

typedef struct {
	wmem_tree_t *pdus;
} drdynvc_pinfo_t;

typedef struct {
	wmem_array_t *currentPacket;
	uint32_t packetLen;
	uint32_t pendingLen;
	uint32_t startFrame;
	uint32_t endReassemblyFrame;
	wmem_array_t *chunks;
} drdynvc_pending_packet_t;

/** @brief context associated with a dynamic channel */
typedef struct {
	drdynvc_known_channel_t type;
	char *name;
	uint32_t channelId;

	drdynvc_pending_packet_t pending_cs;
	drdynvc_pending_packet_t pending_sc;
} drdynvc_channel_def_t;

typedef struct _drdynvc_conv_info_t {
  wmem_multimap_t *channels;
} drdynvc_conv_info_t;


typedef struct {
	const char *name;
	const char *shortName;
	drdynvc_known_channel_t type;
} drdynvc_know_channel_def;

static drdynvc_know_channel_def knownChannels[] = {
	{"AUDIO_INPUT", "audin",						DRDYNVC_CHANNEL_AUDIN},
	{"AUDIO_PLAYBACK_DVC", "audiout",				DRDYNVC_CHANNEL_AUDIOUT},
	{"AUDIO_PLAYBACK_LOSSY_DVC", "audiout lossy",	DRDYNVC_CHANNEL_AUDIOUT},
	{"RDCamera_Device_Enumerator", "cam",			DRDYNVC_CHANNEL_CAM},
	{"Microsoft::Windows::RDS::Video::Control::v08.01", "videoctl", DRDYNVC_CHANNEL_VIDEO_CTL},
	{"Microsoft::Windows::RDS::Video::Data::v08.01", "videodata", DRDYNVC_CHANNEL_VIDEO_DATA},
	{"Microsoft::Windows::RDS::AuthRedirection", "authredir", DRDYNVC_CHANNEL_AUTH_REDIR},
	{"Microsoft::Windows::RDS::Telemetry", "telemetry",	DRDYNVC_CHANNEL_TELEMETRY},
	{"Microsoft::Windows::RDS::Graphics", "egfx", DRDYNVC_CHANNEL_EGFX},
	{"Microsoft::Windows::RDS::DisplayControl", "display", DRDYNVC_CHANNEL_DISPLAY},
	{"Microsoft::Windows::RDS::Geometry::v08.01", "geometry", DRDYNVC_CHANNEL_GEOMETRY},
	{"Microsoft::Windows::RDS::Input", "input",	DRDYNVC_CHANNEL_MULTITOUCH},

	/* static channels that can be reopened on the dynamic channel */
	{"rail", "rail", DRDYNVC_CHANNEL_RAIL},
	{"cliprdr", "cliprdr", DRDYNVC_CHANNEL_CLIPRDR},
	{"rdpdr", "rdpdr", DRDYNVC_CHANNEL_DR},
};

static const value_string drdynvc_tunneltype_vals[] = {
	{   0x1, 	"reliable" },
	{   0x3, 	"lossy" },
	{   0x0, NULL},
};

static const value_string rdp_drdynvc_cbId_vals[] = {
	{   0x0, "1 byte" },
	{   0x1, "2 bytes" },
	{   0x2, "4 bytes" },
	{   0x0, NULL},
};

static const value_string rdp_drdynvc_prio_vals[] = {
	{   0x0, "PriorityCharge0" },
	{   0x1, "PriorityCharge1" },
	{   0x2, "PriorityCharge2" },
	{   0x3, "PriorityCharge3" },
	{   0x0, NULL},
};

static const value_string rdp_drdynvc_cmd_vals[] = {
	{   DRDYNVC_CREATE_REQUEST_PDU, 	"Create PDU" },
	{   DRDYNVC_DATA_FIRST_PDU, 		"Data first PDU" },
	{   DRDYNVC_DATA_PDU, 			"Data PDU" },
	{   DRDYNVC_CLOSE_REQUEST_PDU, 	"Close PDU" },
	{   DRDYNVC_CAPABILITY_REQUEST_PDU, "Capabilities PDU" },
	{   DRDYNVC_DATA_FIRST_COMPRESSED_PDU, "Data first compressed PDU" },
	{   DRDYNVC_DATA_COMPRESSED_PDU, 	"Data compressed PDU" },
	{   DRDYNVC_SOFT_SYNC_REQUEST_PDU,"Soft-Sync request PDU" },
	{   DRDYNVC_SOFT_SYNC_RESPONSE_PDU,"Soft-Sync response PDU" },
	{   0x0, NULL},
};

static void
drdynvc_pending_packet_init(drdynvc_pending_packet_t *pending, uint32_t startFrame)
{
	pending->packetLen = 0;
	pending->pendingLen = 0;
	pending->startFrame = startFrame;
	pending->endReassemblyFrame = 0;
	pending->currentPacket = NULL;
	pending->chunks = NULL;
}

static drdynvc_known_channel_t
drdynvc_find_channel_type(const char *name)
{
	unsigned i;

	for (i = 0; i < array_length(knownChannels); i++)
	{
		if (strcmp(knownChannels[i].name, name) == 0)
			return knownChannels[i].type;
	}
	return DRDYNVC_CHANNEL_UNKNOWN;
}

static drdynvc_conv_info_t *
drdynvc_get_conversation_data(packet_info *pinfo)
{
	conversation_t  *conversation, *conversation_tcp;
	drdynvc_conv_info_t *info;

	conversation = find_or_create_conversation(pinfo);

	info = (drdynvc_conv_info_t *)conversation_get_proto_data(conversation, proto_rdp_drdynvc);
	if (!info) {
		conversation_tcp = rdp_find_tcp_conversation_from_udp(conversation);
		if (conversation_tcp)
			info = (drdynvc_conv_info_t *)conversation_get_proto_data(conversation_tcp, proto_rdp_drdynvc);
	}

	if (info == NULL) {
		info = wmem_new0(wmem_file_scope(), drdynvc_conv_info_t);
		info->channels = wmem_multimap_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
		conversation_add_proto_data(conversation, proto_rdp_drdynvc, info);
	}

	return info;
}


static int
dissect_rdp_vlength(tvbuff_t *tvb, int hf_index, int offset, uint8_t vlen, proto_tree *tree, uint32_t *ret)
{
	int len;
	uint32_t value;

	switch (vlen) {
	case 0:
		value = tvb_get_uint8(tvb, offset);
		len = 1;
		break;
	case 1:
		value = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
		len = 2;
		break;
	case 2:
		value = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
		len = 4;
		break;
	default:
		if (ret)
			*ret = 0;
		return 0;
	}

	proto_tree_add_uint(tree, hf_index, tvb, offset, len, value);
	if (ret)
		*ret = value;
	return len;
}

static const char *
find_channel_name_by_id(packet_info *pinfo, drdynvc_conv_info_t *dyninfo, uint32_t dvcId) {
	drdynvc_channel_def_t *dynChannel = wmem_multimap_lookup32_le(dyninfo->channels, GUINT_TO_POINTER(dvcId), pinfo->num);
	if (dynChannel)
		return dynChannel->name;

	return NULL;
}

static drdynvc_pinfo_t *getDrDynPacketInfo(packet_info *pinfo)
{
	drdynvc_pinfo_t *ret = p_get_proto_data(wmem_file_scope(), pinfo, proto_rdp_drdynvc, DRDYNVC_CHANNEL_PDUS_KEY);
	if (ret)
		return ret;

	ret = wmem_alloc(wmem_file_scope(), sizeof(*ret));
	ret->pdus = wmem_tree_new(wmem_file_scope());

	p_set_proto_data(wmem_file_scope(), pinfo, proto_rdp_drdynvc, DRDYNVC_CHANNEL_PDUS_KEY, ret);
	return ret;
}

static int
dissect_rdp_drdynvc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	proto_item *item;
	proto_tree *tree;
	int offset = 0;
	uint8_t cbIdSpCmd, cmdId;
	uint8_t cbId, Len;
	bool haveChannelId, havePri, haveLen;
	bool isServerTarget = rdp_isServerAddressTarget(pinfo);
	uint32_t channelId = 0;
	uint32_t fullPduLen = 0;
	drdynvc_conv_info_t *info;
	drdynvc_channel_def_t *channel = NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DRDYNVC");
	col_clear(pinfo->cinfo, COL_INFO);

	parent_tree = proto_tree_get_root(parent_tree);
	item = proto_tree_add_item(parent_tree, proto_rdp_drdynvc, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_rdp_drdynvc);

	cbIdSpCmd = tvb_get_uint8(tvb, offset);
	cmdId = (cbIdSpCmd >> 4) & 0xf;
	cbId = (cbIdSpCmd & 0x3);

	haveChannelId = true;
	havePri = false;
	haveLen = false;
	switch (cmdId) {
		case DRDYNVC_CREATE_REQUEST_PDU:
			havePri = true;
			break;
		case DRDYNVC_DATA_FIRST_PDU:
			haveLen = true;
			break;
		case DRDYNVC_DATA_FIRST_COMPRESSED_PDU:
			haveLen = true;
			break;
		case DRDYNVC_CAPABILITY_REQUEST_PDU:
		case DRDYNVC_SOFT_SYNC_REQUEST_PDU:
		case DRDYNVC_SOFT_SYNC_RESPONSE_PDU:
			haveChannelId = false;
			break;
		default:
			break;
	}

	proto_tree_add_item(tree, hf_rdp_drdynvc_cbId, tvb, offset, 1, ENC_NA);
	if (havePri)
		proto_tree_add_item(tree, hf_rdp_drdynvc_pri, tvb, offset, 1, ENC_NA);
	else
		proto_tree_add_item(tree, hf_rdp_drdynvc_sp, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_rdp_drdynvc_cmd, tvb, offset, 1, ENC_NA);

	offset++;

	info = drdynvc_get_conversation_data(pinfo);
	if (haveChannelId) {
		offset += dissect_rdp_vlength(tvb, hf_rdp_drdynvc_channelId, offset, cbId, tree, &channelId);

		channel = wmem_multimap_lookup32_le(info->channels, GUINT_TO_POINTER(channelId), pinfo->num);
	}

	if (haveLen) {
		Len = (cbIdSpCmd >> 2) & 0x3;
		offset += dissect_rdp_vlength(tvb, hf_rdp_drdynvc_length, offset, Len, tree, &fullPduLen);
	}

	switch (cmdId) {
		case DRDYNVC_CREATE_REQUEST_PDU:
			if (!isServerTarget) {
				unsigned nameLen = tvb_strsize(tvb, offset);

				col_set_str(pinfo->cinfo, COL_INFO, "CreateChannel Request");
				proto_tree_add_item(tree, hf_rdp_drdynvc_channelName, tvb, offset, -1, ENC_ASCII);

				if (!PINFO_FD_VISITED(pinfo)) {
					channel = wmem_alloc(wmem_file_scope(), sizeof(*channel));
					channel->channelId = channelId;
					channel->name = tvb_get_string_enc(wmem_file_scope(), tvb, offset, nameLen, ENC_ASCII);
					channel->type = drdynvc_find_channel_type(channel->name);
					drdynvc_pending_packet_init(&channel->pending_cs, pinfo->num);
					drdynvc_pending_packet_init(&channel->pending_sc, pinfo->num);

					wmem_multimap_insert32(info->channels, GUINT_TO_POINTER(channelId), pinfo->num, channel);
				}

			} else {
				col_set_str(pinfo->cinfo, COL_INFO, "CreateChannel Response");

				if (channel) {
					proto_item_set_generated(
						proto_tree_add_string_format_value(tree, hf_rdp_drdynvc_createresp_channelname, tvb, offset, 0, NULL, "%s", channel->name)
					);
				}
				proto_tree_add_item(tree, hf_rdp_drdynvc_creationStatus, tvb, offset, 4, ENC_NA);

			}
			break;
		case DRDYNVC_CAPABILITY_REQUEST_PDU: {
			/* Pad */
			proto_tree_add_item(tree, hf_rdp_drdynvc_pad, tvb, offset, 1, ENC_NA);
			offset++;

			uint32_t version;
			proto_tree_add_item_ret_uint(tree, hf_rdp_drdynvc_capa_version, tvb, offset, 2, ENC_LITTLE_ENDIAN, &version);
			offset += 2;

			if (!isServerTarget) {
				col_set_str(pinfo->cinfo, COL_INFO, "Capabilities request");

				if (version > 1) {
					proto_tree_add_item(tree, hf_rdp_drdynvc_capa_prio0, tvb, offset, 2, ENC_LITTLE_ENDIAN);
					offset += 2;
					proto_tree_add_item(tree, hf_rdp_drdynvc_capa_prio1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
					offset += 2;
					proto_tree_add_item(tree, hf_rdp_drdynvc_capa_prio2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
					offset += 2;
					proto_tree_add_item(tree, hf_rdp_drdynvc_capa_prio3, tvb, offset, 2, ENC_LITTLE_ENDIAN);
					offset += 2;
				}
			} else {
				col_set_str(pinfo->cinfo, COL_INFO, "Capabilities response");
			}
			break;
		}
		case DRDYNVC_DATA_FIRST_PDU: {
			col_set_str(pinfo->cinfo, COL_INFO, "Data first");

			if (channel) {
				drdynvc_pdu_info_t *pduInfo = NULL;
				drdynvc_pending_packet_t *pendingPacket = isServerTarget ? &channel->pending_cs : &channel->pending_sc;
				int payloadLen = tvb_reported_length_remaining(tvb, offset);
				bool isSinglePacket = (fullPduLen == (uint32_t)payloadLen);
				drdynvc_pinfo_t *drdynvcPinfo = getDrDynPacketInfo(pinfo);
				uint32_t key = crc32_ccitt_tvb_offset(tvb, offset, payloadLen);

				proto_item_set_generated(
					proto_tree_add_string_format_value(tree, hf_rdp_drdynvc_createresp_channelname, tvb, offset, 0, NULL, "%s", channel->name)
				);

				proto_item_set_generated(
					proto_tree_add_string_format_value(tree, hf_rdp_drdynvc_data_progress, tvb, offset, 0, NULL, "0-%d/%d", payloadLen, fullPduLen)
				);

				if (!PINFO_FD_VISITED(pinfo)) {
					if (!isSinglePacket) {
						if (pendingPacket->chunks)
							wmem_destroy_array(pendingPacket->chunks);
						pendingPacket->chunks = wmem_array_new(wmem_file_scope(), sizeof(drdynvc_pdu_info_t*));

						pduInfo = wmem_alloc(wmem_file_scope(), sizeof(*pduInfo));
						pduInfo->reassembled = true;
						pduInfo->startReassemblyFrame = pinfo->num;
						pduInfo->progressStart = 0;
						pduInfo->progressEnd = fullPduLen;
						pduInfo->tvb = NULL;

						wmem_tree_insert32(drdynvcPinfo->pdus, key, pduInfo);
						wmem_array_append(pendingPacket->chunks, &pduInfo, 1);

						pendingPacket->packetLen = fullPduLen;
						pendingPacket->pendingLen = fullPduLen - payloadLen;
						pendingPacket->startFrame = pinfo->num;
						pendingPacket->currentPacket = wmem_array_sized_new(wmem_file_scope(), 1, fullPduLen);
						wmem_array_append(pendingPacket->currentPacket, tvb_get_ptr(tvb, offset, payloadLen), payloadLen);
					} else {
						if (pendingPacket->pendingLen || pendingPacket->chunks)
							printf("(%d) looks like we have a non completed packet...\n", pinfo->num);
						if (pendingPacket->chunks)
							wmem_destroy_array(pendingPacket->chunks);
						memset(pendingPacket, 0, sizeof(*pendingPacket));
					}
				} else {
					pduInfo = (drdynvc_pdu_info_t*)wmem_tree_lookup32(drdynvcPinfo->pdus, key);
				}

				if (isSinglePacket) {
					switch (channel->type) {
					case DRDYNVC_CHANNEL_EGFX:
						call_dissector(egfx_handle, tvb_new_subset_remaining(tvb, offset), pinfo, tree);
						break;
					case DRDYNVC_CHANNEL_RAIL:
						call_dissector(rail_handle, tvb_new_subset_remaining(tvb, offset), pinfo, tree);
						break;
					case DRDYNVC_CHANNEL_CLIPRDR:
						call_dissector(cliprdr_handle, tvb_new_subset_remaining(tvb, offset), pinfo, tree);
						break;
					case DRDYNVC_CHANNEL_AUDIOUT:
						call_dissector(snd_handle, tvb_new_subset_remaining(tvb, offset), pinfo, tree);
						break;
					case DRDYNVC_CHANNEL_AUTH_REDIR:
						call_dissector(ear_handle, tvb_new_subset_remaining(tvb, offset), pinfo, tree);
						break;
					default:
						proto_tree_add_item(tree, hf_rdp_drdynvc_data, tvb, offset, -1, ENC_NA);
						break;
					}

					offset += payloadLen;
					return offset;
				}

			}

			proto_tree_add_item(tree, hf_rdp_drdynvc_data, tvb, offset, -1, ENC_NA);
			break;
		}
		case DRDYNVC_DATA_PDU: {
			col_set_str(pinfo->cinfo, COL_INFO, "Data");

			if (channel) {
				tvbuff_t *targetTvb = NULL;

				proto_item_set_generated(
					proto_tree_add_string_format_value(tree, hf_rdp_drdynvc_createresp_channelname, tvb, offset, 0, NULL, "%s", channel->name)
				);

				drdynvc_pinfo_t *drdynvcPinfo = getDrDynPacketInfo(pinfo);
				drdynvc_pdu_info_t *pduInfo = NULL;
				int payloadLen = tvb_reported_length_remaining(tvb, offset);
				uint32_t key = crc32_ccitt_tvb_offset(tvb, offset, payloadLen);

				if (!PINFO_FD_VISITED(pinfo)) {
					drdynvc_pending_packet_t *pendingPacket = isServerTarget ? &channel->pending_cs : &channel->pending_sc;

					pduInfo = wmem_alloc(wmem_file_scope(), sizeof(*pduInfo));
					wmem_tree_insert32(drdynvcPinfo->pdus, key, pduInfo);

					if (pendingPacket->pendingLen) {
						/* we have a fragmented packet in progress */
						if ((uint32_t)payloadLen > pendingPacket->pendingLen) {
							// TODO: error
							printf("num=%d error payload too big\n", pinfo->num);
							return offset;
						}

						pduInfo->reassembled = true;
						pduInfo->decodePayload = false;
						pduInfo->progressStart = pendingPacket->packetLen - pendingPacket->pendingLen;
						pduInfo->progressEnd = pduInfo->progressStart + payloadLen;
						pduInfo->packetLen = pendingPacket->packetLen;

						wmem_array_append(pendingPacket->chunks, &pduInfo, 1);

						pendingPacket->pendingLen -= payloadLen;
						wmem_array_append(pendingPacket->currentPacket, tvb_get_ptr(tvb, offset, payloadLen), payloadLen);

						if (!pendingPacket->pendingLen) {
							/* last packet of the reassembly */
							int reassembled_len = wmem_array_get_count(pendingPacket->currentPacket);
							pduInfo->tvb = tvb_new_real_data(wmem_array_get_raw(pendingPacket->currentPacket), reassembled_len, reassembled_len);
							pduInfo->decodePayload = true;
							pendingPacket->currentPacket = NULL;

							for (unsigned i = 0; i < wmem_array_get_count(pendingPacket->chunks); i++) {
								drdynvc_pdu_info_t *chunk = *(drdynvc_pdu_info_t **)wmem_array_index(pendingPacket->chunks, i);
								chunk->endReassemblyFrame = pinfo->num;
							}
							wmem_destroy_array(pendingPacket->chunks);
							pendingPacket->chunks = NULL;
						}
					} else {
						/* single data packet */
						pduInfo->reassembled = false;
						pduInfo->decodePayload = true;
						pduInfo->progressStart = 0;
						pduInfo->progressEnd = payloadLen;
						pduInfo->packetLen = payloadLen;
						pduInfo->tvb = NULL;
						pduInfo->startReassemblyFrame = pduInfo->endReassemblyFrame = pinfo->num;
					}
				} else {
					pduInfo = (drdynvc_pdu_info_t*)wmem_tree_lookup32(drdynvcPinfo->pdus, key);
				}

				if (pduInfo) {
					proto_item_set_generated(
						proto_tree_add_string_format_value(tree, hf_rdp_drdynvc_data_progress, tvb, offset, 0, NULL, "%d-%d/%d",
							pduInfo->progressStart, pduInfo->progressEnd, pduInfo->packetLen)
					);

					if (pduInfo->tvb) {
						targetTvb = pduInfo->tvb;
						add_new_data_source(pinfo, targetTvb, "Reassembled DRDYNVC");
					} else {
						targetTvb = tvb_new_subset_remaining(tvb, offset);
					}

					if (pduInfo->endReassemblyFrame && (pduInfo->endReassemblyFrame != pinfo->num)) {
						// TODO: show a link to the end frame ?
					}
				}

				if (pduInfo && pduInfo->decodePayload) {
					switch (channel->type) {
					case DRDYNVC_CHANNEL_EGFX:
						call_dissector(egfx_handle, targetTvb, pinfo, tree);
						break;
					case DRDYNVC_CHANNEL_RAIL:
						call_dissector(rail_handle, targetTvb, pinfo, tree);
						break;
					case DRDYNVC_CHANNEL_CLIPRDR:
						call_dissector(cliprdr_handle, targetTvb, pinfo, tree);
						break;
					case DRDYNVC_CHANNEL_AUDIOUT:
						call_dissector(snd_handle, targetTvb, pinfo, tree);
						break;
					case DRDYNVC_CHANNEL_AUTH_REDIR:
						call_dissector(ear_handle, targetTvb, pinfo, tree);
						break;
					default:
						proto_tree_add_item(tree, hf_rdp_drdynvc_data, targetTvb, 0, -1, ENC_NA);
						break;
					}
					return tvb_reported_length(tvb);
				}
			}

			proto_tree_add_item(tree, hf_rdp_drdynvc_data, tvb, offset, -1, ENC_NA);
			return tvb_reported_length(tvb);
		}
		case DRDYNVC_DATA_FIRST_COMPRESSED_PDU:
			col_set_str(pinfo->cinfo, COL_INFO, "Data compressed first");
			break;
		case DRDYNVC_DATA_COMPRESSED_PDU:
			col_set_str(pinfo->cinfo, COL_INFO, "Data compressed");
			break;
		case DRDYNVC_SOFT_SYNC_REQUEST_PDU: {
			uint32_t ntunnels;
			uint32_t flags;

			col_set_str(pinfo->cinfo, COL_INFO, "SoftSync Request");

			/* Pad */
			proto_tree_add_item(tree, hf_rdp_drdynvc_pad, tvb, offset, 1, ENC_NA);
			offset++;

			proto_tree_add_item(tree, hf_rdp_drdynvc_softsync_req_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item_ret_uint(tree, hf_rdp_drdynvc_softsync_req_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN, &flags);
			offset += 2;
			// XXX: TODO should decode flags but they are always set to SOFT_SYNC_TCP_FLUSHED|SOFT_SYNC_CHANNEL_LIST_PRESENT

			proto_tree_add_item_ret_uint(tree, hf_rdp_drdynvc_softsync_req_ntunnels, tvb, offset, 2, ENC_LITTLE_ENDIAN, &ntunnels);
			offset += 2;

			if (flags & 0x02) { /* SOFT_SYNC_CHANNEL_LIST_PRESENT */
				uint16_t i;
				proto_tree *tunnels_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_rdp_drdynvc_softsync_channels, NULL, "Channels");

				for (i = 0; i < ntunnels; i++) {
					uint16_t j;
					uint32_t tunnelType = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
					uint16_t ndvcs = tvb_get_uint16(tvb, offset + 4, ENC_LITTLE_ENDIAN);
					int channelSz = 4 + 2 + (ndvcs * 4);
					proto_tree *channel_tree;
					const char *label = (tunnelType == 0x1) ? "Reliable channels" : "Lossy channels";

					channel_tree = proto_tree_add_subtree(tunnels_tree, tvb, offset, channelSz, ett_rdp_drdynvc_softsync_channel, NULL, label);

					proto_tree_add_item(channel_tree, hf_rdp_drdynvc_softsync_req_channel_tunnelType, tvb, offset, 4, ENC_LITTLE_ENDIAN);
					offset += 4;

					proto_tree_add_item(channel_tree, hf_rdp_drdynvc_softsync_req_channel_ndvc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
					offset += 2;

					for (j = 0; j < ndvcs; j++, offset += 4) {
						proto_tree *dvc_tree;
						uint32_t dvcId;
						const char *showLabel;

						dvcId = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
						showLabel = label = find_channel_name_by_id(pinfo, info, dvcId);
						if (!label)
							showLabel = "DVC";
						dvc_tree = proto_tree_add_subtree(channel_tree, tvb, offset, 4, ett_rdp_drdynvc_softsync_dvc, NULL, showLabel);
						proto_tree_add_item(dvc_tree, hf_rdp_drdynvc_softsync_req_channel_dvcid, tvb, offset, 4, ENC_LITTLE_ENDIAN);

						if (label) {
							proto_item *pi = proto_tree_add_string_format(dvc_tree, hf_rdp_drdynvc_channelName, tvb, offset, 4, label, "%s", label);
							proto_item_set_generated(pi);
						}
					}
				}
			}
			break;
		}
		case DRDYNVC_SOFT_SYNC_RESPONSE_PDU: {
			uint32_t ntunnels, i;

			col_set_str(pinfo->cinfo, COL_INFO, "SoftSync Response");

			/* Pad */
			proto_tree_add_item(tree, hf_rdp_drdynvc_pad, tvb, offset, 1, ENC_NA);
			offset++;

			proto_tree_add_item_ret_uint(tree, hf_rdp_drdynvc_softsync_resp_ntunnels, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ntunnels);
			offset += 4;

			if (ntunnels) {
				proto_tree *tunnels_tree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_rdp_drdynvc_softsync_dvc, NULL, "TunnelsToSwitch");
				for (i = 0; i < ntunnels; i++, offset += 4) {
					proto_tree_add_item(tunnels_tree, hf_rdp_drdynvc_softsync_resp_tunnel, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				}
			}
			break;
		}
		case DRDYNVC_CLOSE_REQUEST_PDU: {
			col_set_str(pinfo->cinfo, COL_INFO, "Close request");
			if (channel) {
				proto_item_set_generated(
					proto_tree_add_string_format_value(tree, hf_rdp_drdynvc_channelName, tvb, offset, 0, NULL, "%s", channel->name)
				);
			}
			break;
		}
		default:
			break;
	}
	return offset;
}

void proto_register_rdp_drdynvc(void) {

	/* List of fields */
	static hf_register_info hf[] = {
		{ &hf_rdp_drdynvc_cbId,
		  { "ChannelId length", "rdp_drdynvc.cbid",
		    FT_UINT8, BASE_HEX, VALS(rdp_drdynvc_cbId_vals), 0x3,
			NULL, HFILL }},
		{ &hf_rdp_drdynvc_sp,
		  { "Sp", "rdp_drdynvc.sp",
			FT_UINT8, BASE_HEX, NULL, 0xc,
			NULL, HFILL }},
		{ &hf_rdp_drdynvc_pri,
		  { "Pri", "rdp_drdynvc.pri",
			FT_UINT8, BASE_HEX, VALS(rdp_drdynvc_prio_vals), 0xc,
			NULL, HFILL }},
		{ &hf_rdp_drdynvc_cmd,
		  { "PDU type", "rdp_drdynvc.cmd",
			FT_UINT8, BASE_HEX, VALS(rdp_drdynvc_cmd_vals), 0xf0,
			NULL, HFILL }},
		{ &hf_rdp_drdynvc_capa_version,
		  { "Version", "rdp_drdynvc.capabilities.version",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL }},
		{ &hf_rdp_drdynvc_capa_prio0,
		  { "Priority charge 0", "rdp_drdynvc.capabilities.prioritycharge0",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL }},
		{ &hf_rdp_drdynvc_capa_prio1,
		  { "Priority charge 1", "rdp_drdynvc.capabilities.prioritycharge1",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL }},
		{ &hf_rdp_drdynvc_capa_prio2,
		  { "Priority charge 2", "rdp_drdynvc.capabilities.prioritycharge2",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL }},
		{ &hf_rdp_drdynvc_capa_prio3,
		  { "Priority charge 3", "rdp_drdynvc.capabilities.prioritycharge3",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL }},
		{ &hf_rdp_drdynvc_pad,
		  { "Padding", "rdp_drdynvc.pad",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL }},
		{ &hf_rdp_drdynvc_channelId,
		  { "Channel Id", "rdp_drdynvc.channelId",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL }},
		{ &hf_rdp_drdynvc_length,
		  { "Length", "rdp_drdynvc.length",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL }},
		{ &hf_rdp_drdynvc_channelName,
		  { "Channel Name", "rdp_drdynvc.channelName",
			FT_STRINGZ, BASE_NONE, NULL, 0,
			NULL, HFILL }},
		{ &hf_rdp_drdynvc_creationStatus,
		  { "Creation status", "rdp_drdynvc.createresponse.status",
			FT_INT32, BASE_DEC, NULL, 0,
			NULL, HFILL }},
		{ &hf_rdp_drdynvc_softsync_req_length,
		  { "Length", "rdp_drdynvc.softsyncreq.length",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL }},
		{ &hf_rdp_drdynvc_softsync_req_flags,
		  { "Flags", "rdp_drdynvc.softsyncreq.flags",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL }},
		{ &hf_rdp_drdynvc_softsync_req_ntunnels,
		  { "NumberOfTunnels", "rdp_drdynvc.softsyncreq.ntunnels",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL }},
		{ &hf_rdp_drdynvc_softsync_req_channel_tunnelType,
		  { "Tunnel type", "rdp_drdynvc.softsyncreq.channel.tunnelType",
			FT_UINT32, BASE_HEX, VALS(drdynvc_tunneltype_vals), 0,
			NULL, HFILL }},
		{ &hf_rdp_drdynvc_softsync_req_channel_ndvc,
		  { "Number of DVCs", "rdp_drdynvc.softsyncreq.channel.ndvcid",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL }},
		{ &hf_rdp_drdynvc_softsync_req_channel_dvcid,
		  { "DVC Id", "rdp_drdynvc.softsyncreq.channel.dvcid",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL }},
		{ &hf_rdp_drdynvc_softsync_resp_ntunnels,
		  { "Number of tunnels", "rdp_drdynvc.softsyncresp.ntunnels",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL }},
		{ &hf_rdp_drdynvc_softsync_resp_tunnel,
		  { "Number of tunnels", "rdp_drdynvc.softsyncresp.tunnel",
			FT_UINT32, BASE_DEC, VALS(drdynvc_tunneltype_vals), 0,
			NULL, HFILL }},
		{ &hf_rdp_drdynvc_createresp_channelname,
		  { "ChannelName", "rdp_drdynvc.createresp",
			FT_STRINGZ, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_rdp_drdynvc_data_progress,
		  { "DataProgress", "rdp_drdynvc.data_progress",
			FT_STRINGZ, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_rdp_drdynvc_data,
		  { "Data", "rdp_drdynvc.data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL }},
	};

	/* List of subtrees */
	static int *ett[] = {
		&ett_rdp_drdynvc,
		&ett_rdp_drdynvc_softsync_channels,
		&ett_rdp_drdynvc_softsync_channel,
		&ett_rdp_drdynvc_softsync_dvc
	};

	proto_rdp_drdynvc = proto_register_protocol(PNAME, PSNAME, PFNAME);
	/* Register fields and subtrees */
	proto_register_field_array(proto_rdp_drdynvc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("rdp_drdynvc", dissect_rdp_drdynvc, proto_rdp_drdynvc);
}

void proto_reg_handoff_drdynvc(void) {
	egfx_handle = find_dissector("rdp_egfx");
	rail_handle = find_dissector("rdp_rail");
	cliprdr_handle = find_dissector("rdp_cliprdr");
	snd_handle = find_dissector("rdp_snd");
	ear_handle = find_dissector("rdp_ear");
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
