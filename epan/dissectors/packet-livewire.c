/* packet-livewire.c
 * Routines for dissection of Axia Livewire Audio over IP protocols
 * By Dennis Graiani <dennis.graiani@gmail.com>
 * Copyright 2026 Dennis Graiani
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-rtp.h>
#include <epan/expert.h>
#include <epan/dissectors/packet-tcp.h>

#define AXIA_MAGIC_NUMBER 0x03000207

#define AXIA_FAST_CLOCK_ADDR "239.192.255.1"
#define AXIA_FAST_CLOCK_PORT 5004
#define AXIA_SLOW_CLOCK_ADDR "239.192.255.2"
#define AXIA_SLOW_CLOCK_PORT 7000
#define AXIA_CLOCK_RTP_VERSION 0x90
#define AXIA_CLOCK_RTP_PAYLOAD_TYPE 0xff
#define AXIA_CLOCK_RTP_EXTENSION_PROFILE 0xfa1a

#define AXIA_ADV_ADDR "239.192.255.3"
#define AXIA_ADV_PORT 4001

#define AXIA_GPIO_ADDR "239.192.255.4"
#define AXIA_GPIO_CONSOLE_PORT 2060
#define AXIA_GPIO_NODE_PORT 2055
#define AXIA_LWCP_PORT 4010
#define AXIA_LWCP_MODULE_PORT 4011
#define AXIA_LWCP_CONSOLE_PORT 4012

#define AXIA_INTERCOM_ADDR "239.192.255.10"
#define AXIA_INTERCOM_PORT 5000
#define AXIA_RTP_PORT 5004

static int proto_axia_adv;
static int proto_axia_gpio;
static int proto_axia_clock;
static int proto_axia_intercom;
static int proto_axia_lwcp;

static int hf_axia_magic_num;
static int hf_axia_seq;
static int hf_axia_opcode;
static int hf_axia_msg_count;
static int hf_axia_pver;
static int hf_axia_advt;
static int hf_axia_unk_u8;
static int hf_axia_unk_u16;
static int hf_axia_unk_u32;
static int hf_axia_unk_data;
static int hf_axia_unk_str;

static int hf_axia_term;
static int hf_axia_term_inip;
static int hf_axia_term_advv;
static int hf_axia_term_hwid;
static int hf_axia_term_udpc;
static int hf_axia_term_nums;
static int hf_axia_term_atrn;
static int hf_axia_term_type;

static int hf_axia_src;
static int hf_axia_src_psid;
static int hf_axia_src_shab;
static int hf_axia_src_fsid;
static int hf_axia_src_bsid;
static int hf_axia_src_psnm;
static int hf_axia_src_labl;
static int hf_axia_src_lpid;
static int hf_axia_src_setup_frame;
static int hf_axia_src_is_mm;

static int hf_axia_busy;
static int hf_axia_busy_hwid;
static int hf_axia_busy_fader;
static int hf_axia_busy_ip;
static int hf_axia_busy_prefix;

static int hf_axia_gpio_lcid;
static int hf_axia_gpio_state;
static int hf_axia_gpio_state2;
static int hf_axia_gpio_pmult;
static int hf_axia_gpio_plen;

static int hf_axia_clock_prio;
static int hf_axia_clock_hwid;
static int hf_axia_clock_mac;
static int hf_axia_clock_samp;
static int hf_axia_clock_fast;
static int hf_axia_clock_seq;
static int hf_axia_clock_rate;
static int hf_axia_clock_type;

static int hf_axia_lwcp_opcode;
static int hf_axia_lwcp_object;
static int hf_axia_lwcp_property;

static int ett_axia_adv;
static int ett_axia_gpio;
static int ett_axia_clock;
static int ett_axia_lwcp;

static expert_field ei_axia_clock_changed;

// Tree which stores axia_src_info_t structs by PSID (Channel Number)
// All sources picked up from advertisements in this capture should be in here.
// PSID is negated for backfeed sources.
static wmem_tree_t *axia_sources;

// Tree which stores axia_term_info_t structs by HWID (two LSBs from IP address)
// All nodes picked up from advertisements in this capture should be in here.
static wmem_tree_t *axia_nodes;

static address fast_clock_address;
static address slow_clock_address;
static address advertisement_address;
static address gpio_address;
static address intercom_address;

// Enum to keep track of where we are in the advertisement packet
typedef enum
{
    SECTION_ADV_BASE,
    SECTION_TERM,
    SECTION_SOURCE,
    SECTION_GPIO,
} axia_adv_section_e;

// Node information as received from advertisements
typedef struct
{
    uint16_t hwid;                  // Hardware ID (2 LSBs of IP)
    char *atrn;                     // Name of the node
    ws_in4_addr inip;               // IP address of the node
    uint16_t udpc;                  // UDP port on which messages can be sent to the node
    conversation_t *conversation;   // Pointer to the conversation on the IP and UDP port
    uint32_t nums;                  // Number of sources on this node
} axia_term_info_t;

//  Source information as received from advertisements
typedef struct
{
    uint32_t psid;                  // Primary source ID (Livewire channel number)
    ws_in4_addr fsid;               // Multicast IP for RTP audio
    ws_in4_addr bsid;               // Multicast IP for RTP backfeed audio
    char *psnm;                     // Source name
    axia_term_info_t *term;         // The node where this audio originates
    ws_in4_addr rtp_added;          // Stores the RTP address when added to the RTP conversation table
    uint32_t setup_frame;           // The frame number where this RTP source was originally setup
} axia_src_info_t;

// Struct to hold Node and Source information as we go through an advertisement
typedef struct
{
    axia_term_info_t *term_info;
    axia_src_info_t *src_info;
    uint32_t lpid;
    int32_t nums;
} axia_adv_info_t;

// Struct to keep track of master clock properties
typedef struct
{
    address mac_address;
    uint32_t priority;              // 7 = always master. 0 = never master
} axia_clock_t;

// The master clock last dissected
static axia_clock_t axia_master_clock;

static dissector_handle_t axia_adv_handle;
static dissector_handle_t axia_gpio_handle;
static dissector_handle_t axia_clock_handle;
static dissector_handle_t axia_intercom_handle;
static dissector_handle_t json_handle;
static dissector_handle_t lwcp_handle;
static dissector_handle_t lwcp_tcp_handle;

static const value_string advtypenames[] = {
    {0x1, "Verbose announcement"},
    {0x2, "Periodic announcement"},
    {0x3, "Source allocation state"},
    {0, NULL}};
static const value_string clocktypenames[] = {
    {0x0a, "Fast clock, packet A"},
    {0x0b, "Fast clock, packet B"},
    {0x0c, "Slow clock"},
    {0, NULL},
};
static const char *get_opcode_description(const char *opcode)
{
    if (!opcode)
        return NULL;
    if (!opcode[0])
        return NULL;
    if (strcmp(opcode, "INDI") == 0)
        return "Value Indication";
    if (strcmp(opcode, "WRNI") == 0)
        return "Write value - returning the value indication is not requested";
    if (strcmp(opcode, "WRIN") == 0)
        return "Write value - returning the value indication is requested";
    if (strcmp(opcode, "READ") == 0)
        return "Read value";
    if (strcmp(opcode, "STAT") == 0)
        return "Status indication";
    if (strcmp(opcode, "NEST") == 0)
        return "No operation - container for nested messages";
    return NULL;
}
static void setup_axia_transport(packet_info *pinfo, uint16_t psid)
{
    if (pinfo->fd->visited)
    {
        return;
    }
    axia_src_info_t *src_info = (axia_src_info_t *)wmem_tree_lookup32(axia_sources, psid);
    if (src_info && src_info->fsid && src_info->rtp_added != src_info->fsid)
    {
        // set up an rtp stream here
        address rtp_address;
        rtp_dyn_payload_t *dyn_payload = rtp_dyn_payload_new();
        rtp_dyn_payload_insert(dyn_payload, 96, "L24", 48000, 2);
        rtp_dyn_payload_insert(dyn_payload, 99, "L24", 48000, 8);
        rtp_dyn_payload_insert(dyn_payload, 101, "L24", 48000, 1);
        rtp_dyn_payload_insert(dyn_payload, 103, "L24", 48000, 3);
        rtp_dyn_payload_insert(dyn_payload, 104, "L24", 48000, 4);
        rtp_dyn_payload_insert(dyn_payload, 105, "L24", 48000, 5);
        rtp_dyn_payload_insert(dyn_payload, 106, "L24", 48000, 6);
        rtp_dyn_payload_insert(dyn_payload, 107, "L24", 48000, 7);
        rtp_dyn_payload_insert(dyn_payload, 111, "L16", 48000, 1);
        rtp_dyn_payload_insert(dyn_payload, 112, "L16", 48000, 2);
        rtp_dyn_payload_insert(dyn_payload, 113, "L16", 48000, 3);
        rtp_dyn_payload_insert(dyn_payload, 114, "L16", 48000, 4);
        rtp_dyn_payload_insert(dyn_payload, 115, "L16", 48000, 5);
        rtp_dyn_payload_insert(dyn_payload, 116, "L16", 48000, 6);
        rtp_dyn_payload_insert(dyn_payload, 117, "L16", 48000, 7);
        rtp_dyn_payload_insert(dyn_payload, 118, "L16", 48000, 8);
        alloc_address_wmem(wmem_file_scope(), &rtp_address, AT_IPv4, sizeof(ws_in4_addr), &src_info->fsid);
        rtp_add_address(pinfo, PT_UDP, &rtp_address, AXIA_RTP_PORT, 0, "Livewire", pinfo->num, RTP_MEDIA_AUDIO, dyn_payload);
        free_address_wmem(wmem_file_scope(), &rtp_address);
        rtp_dyn_payload_free(dyn_payload);
        src_info->rtp_added = src_info->fsid;
    }
}
static void setup_adv_conversation(packet_info *pinfo, axia_term_info_t *term_info)
{
    if (term_info->conversation)
        return;
    if (term_info->inip && term_info->udpc)
    {
        address node_address;
        alloc_address_wmem(wmem_file_scope(), &node_address, AT_IPv4, sizeof(ws_in4_addr), &term_info->inip);
        term_info->conversation = conversation_new(pinfo->num, &node_address, NULL, CONVERSATION_UDP, term_info->udpc, 0, NO_ADDR2 | NO_PORT2);
        free_address_wmem(wmem_file_scope(), &node_address);
        conversation_set_dissector(term_info->conversation, axia_adv_handle);
    }
}
static bool validate_header(tvbuff_t *tvb)
{
    if (tvb_captured_length(tvb) < 16)
    {
        return false;
    }
    else if (tvb_get_ntohl(tvb, 0) != AXIA_MAGIC_NUMBER)
    {
        return false;
    }
    if (tvb_get_uint64(tvb, 8, ENC_BIG_ENDIAN) != 0)
    {
        return false;
    }
    return true;
}
static void write_src_info(axia_adv_info_t *info)
{
    bool is_backfeed = info->src_info->fsid && info->src_info->bsid &&
                       info->src_info->fsid == info->src_info->bsid;
    if (is_backfeed)
    {
        info->src_info->psid = (uint32_t)(0 - (int32_t)info->src_info->psid);
    }
    axia_src_info_t *existing = (axia_src_info_t *)wmem_tree_lookup32(axia_sources, info->src_info->psid);
    if (existing)
    {
        if (info->src_info->fsid)
            existing->fsid = info->src_info->fsid;
        if (info->src_info->bsid)
            existing->bsid = info->src_info->bsid;
        if (info->src_info->psnm)
            existing->psnm = info->src_info->psnm;
        if (info->src_info->term)
            existing->term = info->src_info->term;
        if (info->src_info->rtp_added)
            existing->rtp_added = info->src_info->rtp_added;
        if (info->src_info->setup_frame)
            existing->setup_frame = info->src_info->setup_frame;
        wmem_free(wmem_file_scope(), info->src_info);
        info->src_info = existing;
    }
    else
    {
        wmem_tree_insert32(axia_sources, info->src_info->psid, (void *)info->src_info);
    }
}
static int axia_adv_tree_add_field(proto_tree *tree, tvbuff_t *tvb, int offset, int hf)
{
    int str_len;
    switch (tvb_get_uint8(tvb, offset))
    {
        case 0x0:
        case 0x7:
            proto_tree_add_item(tree, hf, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
            return 2;
        case 0x1:
            proto_tree_add_item(tree, hf, tvb, offset + 1, 4, ENC_BIG_ENDIAN);
            return 5;
        case 0x3:
            str_len = tvb_get_uint16(tvb, offset + 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf, tvb, offset + 3, str_len, ENC_ASCII);
            return str_len + 3;
        case 0x6:
        case 0x8:
            proto_tree_add_item(tree, hf, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
            return 3;
        case 0x9:
            proto_tree_add_item(tree, hf, tvb, offset + 1, 8, ENC_BIG_ENDIAN);
            return 9;
    }
    return 0;
}
static int dissect_axia_adv_unk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    if (offset < 4)
        return 0;
    int len = 0;
    int str_len;
    unsigned char *msg_type = tvb_get_string_enc(pinfo->pool, tvb, offset - 4, 4, ENC_ASCII);
    proto_item *ti = NULL;
    switch (tvb_get_uint8(tvb, offset))
    {
        case 0x0:
        case 0x7:
            ti = proto_tree_add_item(tree, hf_axia_unk_u8, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
            len = 2;
            break;
        case 0x1:
            ti = proto_tree_add_item(tree, hf_axia_unk_u32, tvb, offset + 1, 4, ENC_BIG_ENDIAN);
            len = 5;
            break;
        case 0x3:
            str_len = tvb_get_uint16(tvb, offset + 1, ENC_BIG_ENDIAN);
            ti = proto_tree_add_item(tree, hf_axia_unk_str, tvb, offset + 3, str_len, ENC_ASCII);
            len = (str_len + 3);
            break;
        case 0x6:
        case 0x8:
            ti = proto_tree_add_item(tree, hf_axia_unk_u16, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
            len = 3;
            break;
        case 0x9:
            ti = proto_tree_add_item(tree, hf_axia_unk_data, tvb, offset + 1, 8, ENC_NA);
            len = 9;
            break;
    }
    if (ti)
        proto_item_append_text(ti, " (%s)", msg_type);
    return len;
}

/*
Implements increment_dissection_depth and decrement_dissection_depth
*/
// NOLINTNEXTLINE(misc-no-recursion)
static int dissect_axia_adv_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, axia_adv_section_e section, axia_adv_info_t *info)
{
    char *msg_type;
    proto_item *ti;
    uint32_t lpid;
    uint32_t lcid;
    uint32_t state;
    uint32_t mult;
    uint32_t plen;
    bool gpi = false;
    bool source_is_new = false;
    msg_type = (char *)tvb_get_string_enc(pinfo->pool, tvb, offset, 4, ENC_ASCII);
    offset += 4;
    if (info == NULL)
    {
        info = wmem_new0(pinfo->pool, axia_adv_info_t);
    }
    if (get_opcode_description(msg_type))
    {
        int msg_count = (int)tvb_get_uint8(tvb, offset + 1);
        proto_tree_add_string_format_value(tree, hf_axia_opcode, tvb, offset - 4, 4, msg_type,
                                     "%s (%s)", get_opcode_description(msg_type), msg_type);
        offset += axia_adv_tree_add_field(tree, tvb, offset, hf_axia_msg_count);
        for (int i = 0; i < msg_count; i++)
        {
            increment_dissection_depth(pinfo);
            offset = dissect_axia_adv_msg(tvb, pinfo, tree, offset, section, info);
            decrement_dissection_depth(pinfo);
        }
        if (section == SECTION_ADV_BASE && info->src_info &&
            info->term_info && info->term_info->nums)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%d of %d Sources)", info->nums, info->term_info->nums);
        }
        return offset;
    }
    else if (section == SECTION_GPIO)
        offset -= 4;
    switch (section)
    {
        case SECTION_ADV_BASE:
            ws_assert(msg_type);
            if (strcmp(msg_type, "PVER") == 0)
            {
                return offset + axia_adv_tree_add_field(tree, tvb, offset, hf_axia_pver);
            }
            else if (strcmp(msg_type, "ADVT") == 0)
            {
                col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_uint8(tvb, offset + 1), advtypenames, "Unknown Livewire Advertisement type"));
                return offset + axia_adv_tree_add_field(tree, tvb, offset, hf_axia_advt);
            }
            else if (strcmp(msg_type, "TERM") == 0)
            {
                int term_len = tvb_get_uint16(tvb, offset + 1, ENC_BIG_ENDIAN);
                ti = proto_tree_add_item(tree, hf_axia_term, tvb, offset - 4, term_len + 7, ENC_NA);
                proto_tree *term_tree = proto_item_add_subtree(ti, ett_axia_adv);
                proto_item_set_text(ti, "Terminal Information");
                info->term_info = wmem_new0(wmem_file_scope(), axia_term_info_t);
                increment_dissection_depth(pinfo);
                dissect_axia_adv_msg(tvb, pinfo, term_tree, offset + 3, SECTION_TERM, info);
                decrement_dissection_depth(pinfo);
                if (info->term_info->inip && info->term_info->atrn)
                {
                    add_ipv4_name(info->term_info->inip, info->term_info->atrn, false);
                }
                if (info->term_info->inip && info->term_info->udpc)
                {
                    setup_adv_conversation(pinfo, info->term_info);
                }
                return offset + term_len + 3;
            }
            else if (msg_type[0] == 'S' &&
                    msg_type[1] >= '0' && msg_type[1] <= '9' &&
                    msg_type[2] >= '0' && msg_type[2] <= '9' &&
                    msg_type[3] >= '0' && msg_type[3] <= '9')
            {
                info->nums++;
                int src_num = ((msg_type[1] - '0') * 100) + ((msg_type[2] - '0') * 10) + (msg_type[3] - '0');
                int src_len = tvb_get_uint16(tvb, offset + 1, ENC_BIG_ENDIAN);
                ti = proto_tree_add_item(tree, hf_axia_src, tvb, offset - 4, src_len + 7, ENC_NA);
                proto_tree *source_tree = proto_item_add_subtree(ti, ett_axia_adv);
                proto_item_set_text(ti, "Source %d", src_num);
                info->src_info = wmem_new0(wmem_file_scope(), axia_src_info_t);
                increment_dissection_depth(pinfo);
                dissect_axia_adv_msg(tvb, pinfo, source_tree, offset + 3, SECTION_SOURCE, info);
                decrement_dissection_depth(pinfo);
                if (info->term_info)
                    info->src_info->term = info->term_info;
                proto_item_append_text(ti, ": %d", info->src_info->psid);
                write_src_info(info);
                if (info->src_info->psnm)
                {
                    proto_item_append_text(ti, " [%s", info->src_info->psnm);
                    if (info->src_info->term && info->src_info->term->atrn)
                    {
                        proto_item_append_text(ti, "@%s", info->src_info->term->atrn);
                    }
                    proto_item_append_text(ti, "]");
                    if (!info->src_info->setup_frame)
                    {
                        info->src_info->setup_frame = pinfo->num;
                    }
                    else if (info->src_info->setup_frame != pinfo->num)
                    {
                        ti = proto_tree_add_uint(source_tree, hf_axia_src_setup_frame, tvb, 0, 0, info->src_info->setup_frame);
                        proto_item_set_generated(ti);
                    }
                    if (info->src_info->fsid && info->src_info->bsid)
                    {
                        bool is_mm = info->src_info->bsid == info->src_info->fsid;
                        ti = proto_tree_add_boolean(source_tree, hf_axia_src_is_mm,
                                                    tvb, 0, 0, is_mm);
                        if (is_mm)
                        {
                            proto_item_set_text(ti, "Source is a backfeed");
                        }
                        else
                        {
                            proto_item_set_hidden(ti);
                        }
                        proto_item_set_generated(ti);
                    }
                }
                setup_axia_transport(pinfo, info->src_info->psid);
                return offset + src_len + 3;
            }
            break;
        case SECTION_TERM:
            ws_assert(msg_type);
            if (strcmp(msg_type, "INIP") == 0)
            {
                info->term_info->inip = tvb_get_ipv4(tvb, offset + 1);
                return offset + axia_adv_tree_add_field(tree, tvb, offset, hf_axia_term_inip);
            }
            else if (strcmp(msg_type, "HWID") == 0)
            {
                info->term_info->hwid = tvb_get_uint16(tvb, offset + 1, ENC_BIG_ENDIAN);
                axia_term_info_t *existing = (axia_term_info_t *)wmem_tree_lookup32(axia_nodes, info->term_info->hwid);
                if (existing)
                {
                    if (info->term_info->atrn)
                        existing->atrn = info->term_info->atrn;
                    if (info->term_info->inip)
                        existing->inip = info->term_info->inip;
                    if (info->term_info->udpc)
                        existing->udpc = info->term_info->udpc;
                    wmem_free(wmem_file_scope(), info->term_info);
                    info->term_info = existing;
                }
                else
                {
                    wmem_tree_insert32(axia_nodes, info->term_info->hwid, (void *)info->term_info);
                }
                return offset + axia_adv_tree_add_field(tree, tvb, offset, hf_axia_term_hwid);
            }
            else if (strcmp(msg_type, "ADVV") == 0)
            {
                return offset + axia_adv_tree_add_field(tree, tvb, offset, hf_axia_term_advv);
            }
            else if (strcmp(msg_type, "UDPC") == 0)
            {
                info->term_info->udpc = tvb_get_uint16(tvb, offset + 1, ENC_BIG_ENDIAN);
                return offset + axia_adv_tree_add_field(tree, tvb, offset, hf_axia_term_udpc);
            }
            else if (strcmp(msg_type, "NUMS") == 0)
            {
                info->term_info->nums = tvb_get_uint16(tvb, offset + 1, ENC_BIG_ENDIAN);
                return offset + axia_adv_tree_add_field(tree, tvb, offset, hf_axia_term_nums);
            }
            else if (strcmp(msg_type, "ATRN") == 0)
            {
                int str_len = tvb_get_uint16(tvb, offset + 1, ENC_BIG_ENDIAN);
                char *atrn = (char *)tvb_get_string_enc(wmem_file_scope(), tvb, offset + 3, str_len, ENC_ASCII);
                info->term_info->atrn = atrn;
                return offset + axia_adv_tree_add_field(tree, tvb, offset, hf_axia_term_atrn);
            }
            else if (strcmp(msg_type, "TYPE") == 0)
            {
                return offset + axia_adv_tree_add_field(tree, tvb, offset, hf_axia_term_type);
            }
            break;
        case SECTION_SOURCE:
            ws_assert(msg_type);
            if (strcmp(msg_type, "PSID") == 0)
            {
                info->src_info->psid = tvb_get_uint32(tvb, offset + 1, ENC_BIG_ENDIAN);
                return offset + axia_adv_tree_add_field(tree, tvb, offset, hf_axia_src_psid);
            }
            else if (strcmp(msg_type, "PSNM") == 0)
            {
                int str_len = tvb_get_uint16(tvb, offset + 1, ENC_BIG_ENDIAN);
                char *psnm = (char *)tvb_get_string_enc(wmem_file_scope(), tvb, offset + 3, str_len, ENC_ASCII);
                info->src_info->psnm = psnm;
                return offset + axia_adv_tree_add_field(tree, tvb, offset, hf_axia_src_psnm);
            }
            else if (strcmp(msg_type, "LABL") == 0)
            {
                return offset + axia_adv_tree_add_field(tree, tvb, offset, hf_axia_src_labl);
            }
            else if (strcmp(msg_type, "FSID") == 0)
            {
                ws_in4_addr fsid = tvb_get_ipv4(tvb, offset + 1);
                info->src_info->fsid = fsid;
                return offset + axia_adv_tree_add_field(tree, tvb, offset, hf_axia_src_fsid);
            }
            else if (strcmp(msg_type, "BSID") == 0)
            {
                info->src_info->bsid = tvb_get_ipv4(tvb, offset + 1);
                return offset + axia_adv_tree_add_field(tree, tvb, offset, hf_axia_src_bsid);
            }
            else if (strcmp(msg_type, "SHAB") == 0)
            {
                return offset + axia_adv_tree_add_field(tree, tvb, offset, hf_axia_src_shab);
            }
            else if (strcmp(msg_type, "LPID") == 0)
            {
                return offset + axia_adv_tree_add_field(tree, tvb, offset, hf_axia_src_lpid);
            }
            else if (strcmp(msg_type, "BUSY") == 0 && tvb_get_uint8(tvb, offset) == 0x9)
            {
                ti = proto_tree_add_item(tree, hf_axia_busy, tvb, offset + 1, 8, ENC_NA);
                if (tvb_get_uint64(tvb, offset + 1, ENC_BIG_ENDIAN) == 0)
                {
                    // free
                    proto_item_append_text(ti, ": Free");
                }
                else
                {
                    ws_in4_addr console_ip;
                    uint32_t prefix;
                    uint32_t hwid;
                    unsigned fader_num;
                    char addr_str[16];
                    proto_tree *busy_tree = proto_item_add_subtree(ti, ett_axia_adv);
                    proto_tree_add_item_ret_uint(busy_tree, hf_axia_busy_hwid, tvb, offset + 3, 2, ENC_BIG_ENDIAN, &hwid);
                    proto_tree_add_item_ret_uint(busy_tree, hf_axia_busy_prefix, tvb, offset + 7, 2, ENC_BIG_ENDIAN, &prefix);
                    console_ip = (ws_in4_addr)((g_htonl(prefix) >> 16) + g_htonl(hwid));
                    ws_inet_ntop4(&console_ip, addr_str, sizeof(addr_str));
                    proto_tree_add_ipv4(busy_tree, hf_axia_busy_ip, tvb, offset + 3, 6, console_ip);
                    proto_item *fader = proto_tree_add_item_ret_uint(busy_tree, hf_axia_busy_fader, tvb, offset + 6, 1, ENC_BIG_ENDIAN, &fader_num);
                    proto_item_set_text(fader, "Fader: %d", fader_num + 1);
                    axia_term_info_t *console = wmem_tree_lookup32(axia_nodes, tvb_get_uint16(tvb, offset + 3, ENC_BIG_ENDIAN));
                    bool have_name = false;
                    if (console && console->atrn)
                        have_name = true;
                    proto_item_append_text(ti, " [Console %s, Fader %d]", have_name ? console->atrn : addr_str, fader_num + 1);
                }
                return offset + 9;
            }
            break;
        case SECTION_GPIO:
            ti = proto_tree_add_item(tree, proto_axia_gpio, tvb, offset + 1, 5, ENC_NA);
            proto_tree *gpio_tree = proto_item_add_subtree(ti, ett_axia_adv);
            proto_item *lpid_item = proto_tree_add_item_ret_uint(gpio_tree, hf_axia_src_lpid, tvb, offset + 1, 2, ENC_BIG_ENDIAN, &lpid);
            if (lpid != 0xff)
            {
                if (info->lpid != lpid)
                    source_is_new = true;
                info->lpid = lpid;
            }
            else
            {
                lpid = info->lpid;
                proto_item_append_text(lpid_item, " (same as previous)");
            }
            axia_src_info_t *source = wmem_tree_lookup32(axia_sources, lpid);
            axia_term_info_t *term;
            if (source)
                term = source->term;
            if (source && source->psnm && term && term->atrn)
            {
                proto_item_append_text(lpid_item, " [%s@%s]", source->psnm, term->atrn);
                proto_tree *setup_tree = proto_item_add_subtree(lpid_item, ett_axia_gpio);
                proto_item *setup_frm = proto_tree_add_uint(setup_tree, hf_axia_src_setup_frame, tvb, 0, 0, source->setup_frame);
                proto_item_set_generated(setup_frm);
            }
            proto_item *lcid_item = proto_tree_add_item_ret_uint(gpio_tree, hf_axia_gpio_lcid, tvb, offset + 3, 1, ENC_BIG_ENDIAN, &lcid);
            if (lcid < 9)
                lcid = 9 - lcid;
            else
            {
                lcid = 14 - lcid;
                gpi = true;
            }
            proto_item_append_text(lcid_item, gpi ? " (GPI Pin %d)" : " (GPO Pin %d)", lcid);
            proto_item *pmult_item = proto_tree_add_item_ret_uint(gpio_tree, hf_axia_gpio_pmult, tvb, offset + 5, 1, ENC_BIG_ENDIAN, &mult);
            proto_item *state_item = proto_tree_add_item_ret_uint(gpio_tree, hf_axia_gpio_state, tvb, offset + 5, 1, ENC_BIG_ENDIAN, &state);
            proto_item *plen_item = proto_tree_add_item_ret_uint(gpio_tree, hf_axia_gpio_plen, tvb, offset + 5, 1, ENC_BIG_ENDIAN, &plen);
            if (!state && !mult && plen <= 1)
            {
                proto_item_set_hidden(state_item);
                proto_item_set_hidden(plen_item);
                proto_item_set_hidden(pmult_item);
                state_item = proto_tree_add_item_ret_uint(gpio_tree, hf_axia_gpio_state2, tvb, offset + 5, 1, ENC_BIG_ENDIAN, &state);
                plen = 0;
            }
            else
            {
                plen *= mult ? 10 : 250;
                proto_item_append_text(pmult_item, " (%s)", mult ? "10 mS" : "250 mS");
            }
            proto_item_append_text(state_item, " (%s)", state ? "Low" : "High");
            if (plen)
                proto_item_append_text(plen_item, " (%d mS)", plen);
            proto_item_append_text(ti, ": LPID=%d ", lpid);
            if (source_is_new)
                col_append_fstr(pinfo->cinfo, COL_INFO, "LPID=%d ", lpid);
            if (source && source->psnm && term && term->atrn)
            {
                proto_item_append_text(ti, "[%s@%s] ", source->psnm, term->atrn);
                if (source_is_new)
                    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s@%s] ", source->psnm, term->atrn);
            }
            proto_item_append_text(ti, "Pin=%s %d State=", gpi ? "GPI" : "GPO", lcid);
            col_append_fstr(pinfo->cinfo, COL_INFO, "Pin=%s %d State=", gpi ? "GPI" : "GPO", lcid);
            if (plen)
            {
                proto_item_append_text(ti, "Pulse ");
                col_append_str(pinfo->cinfo, COL_INFO, "Pulse ");
            }
            proto_item_append_text(ti, "%s ", state ? "Low" : "High");
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", state ? "Low" : "High");
            if (plen)
            {
                proto_item_append_text(ti, "for %dmS ", plen);
                col_append_fstr(pinfo->cinfo, COL_INFO, "for %dmS ", plen);
            }
            return offset + 6;
            break;
        }
    return offset + dissect_axia_adv_unk(tvb, pinfo, tree, offset);
}
static int dissect_lwadv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if (!validate_header(tvb)) /* This is not an Axia packet */
        return 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LWADV");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_axia_adv, tvb, 0, -1, ENC_NA);
    proto_tree *axia_adv_tree = proto_item_add_subtree(ti, ett_axia_adv);
    proto_tree_add_item(axia_adv_tree, hf_axia_magic_num, tvb, 0, 4, ENC_NA);
    proto_tree_add_item(axia_adv_tree, hf_axia_seq, tvb, 4, 4, ENC_BIG_ENDIAN);
    int offset = 16;
    dissect_axia_adv_msg(tvb, pinfo, axia_adv_tree, offset, SECTION_ADV_BASE, NULL);
    return offset;
}
static int dissect_lwgpio(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if (!validate_header(tvb)) /* This is not an Axia packet */
        return 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LWGPIO");
    col_clear(pinfo->cinfo, COL_INFO);
    proto_item *ti = proto_tree_add_item(tree, proto_axia_gpio, tvb, 0, -1, ENC_NA);
    proto_tree *axia_adv_tree = proto_item_add_subtree(ti, ett_axia_gpio);
    proto_tree_add_item(axia_adv_tree, hf_axia_magic_num, tvb, 0, 4, ENC_NA);
    proto_tree_add_item(axia_adv_tree, hf_axia_seq, tvb, 4, 4, ENC_BIG_ENDIAN);
    int offset = 16;
    dissect_axia_adv_msg(tvb, pinfo, axia_adv_tree, offset, SECTION_GPIO, NULL);
    return offset;
}
static int dissect_lwclock(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if (tvb_captured_length(tvb) != 36)
        return 0;
    uint32_t rtp_timestamp;
    uint32_t seq;
    uint32_t type;
    uint32_t priority;
    uint8_t mac_address[FT_ETHER_LEN];
    address current_clock_mac;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LWCLOCK");
    col_clear(pinfo->cinfo, COL_INFO);
    proto_item *ti = proto_tree_add_item(tree, proto_axia_clock, tvb, 0, -1, ENC_NA);
    proto_tree *axia_clock_tree = proto_item_add_subtree(ti, ett_axia_clock);
    proto_tree_add_item_ret_uint(axia_clock_tree, hf_axia_clock_seq, tvb, 2, 2, ENC_BIG_ENDIAN, &seq);
    proto_tree_add_item_ret_uint(axia_clock_tree, hf_axia_clock_samp, tvb, 4, 4, ENC_BIG_ENDIAN, &rtp_timestamp);
    proto_tree_add_item(axia_clock_tree, hf_axia_clock_fast, tvb, 16, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(axia_clock_tree, hf_axia_clock_type, tvb, 20, 1, ENC_NA, &type);
    proto_tree_add_item_ret_uint(axia_clock_tree, hf_axia_clock_prio, tvb, 27, 1, ENC_NA, &priority);
    ti = proto_tree_add_item_ret_ether(axia_clock_tree, hf_axia_clock_mac, tvb, 30, 6, ENC_NA, mac_address);
    alloc_address_wmem(wmem_epan_scope(), &current_clock_mac, AT_ETHER, sizeof(mac_address), mac_address);
    if (cmp_address(&current_clock_mac, &axia_master_clock.mac_address) || axia_master_clock.priority != priority)
    {
        // they do not equal, so the clock has changed... or something
        axia_master_clock.mac_address = current_clock_mac;
        axia_master_clock.priority = priority;
        expert_add_info(pinfo, ti, &ei_axia_clock_changed);
    }
    else
    {
        free_address_wmem(wmem_epan_scope(), &current_clock_mac);
    }

    bool fast_rate = type == 0x0a || type == 0x0b;
    ti = proto_tree_add_boolean(axia_clock_tree, hf_axia_clock_rate, tvb, 0, 0, fast_rate);
    proto_item_set_generated(ti);
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq=%u, Priority=%u, Time=%u",
        val_to_str_const(type, clocktypenames, "Unknown clock packet"), seq, priority, rtp_timestamp);
    return tvb_captured_length(tvb);
}
static int dissect_intercom(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if (json_handle)
    {
        int json_length = tvb_captured_length(tvb) - 37;
        tvbuff_t *json_tvb = tvb_new_subset_length(tvb, 37, tvb_captured_length(tvb) - 37);
        int json_dissected = call_dissector(json_handle, json_tvb, pinfo, tree);
        if (json_length == json_dissected)
        {
            return tvb_reported_length(tvb);
        }
        else
        {
            return 0;
        }
    }
    return tvb_reported_length(tvb);
}
static uint32_t get_lwcp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    int next_offset = offset;
    int tvb_len = tvb_reported_length(tvb);
    bool in_encap = false;
    bool in_quotes = false;
    while(next_offset < tvb_len)
    {
        if (tvb_strneql(tvb, next_offset, "%BeginEncap%", 12) == 0)
        {
            in_encap = true;
            next_offset += 12;
            continue;
        }
        if (tvb_strneql(tvb, next_offset, "%EndEncap%", 10) == 0)
        {
            in_encap = false;
            next_offset += 10;
            continue;
        }
        char c = tvb_get_uint8(tvb, next_offset);
        if (c == '"')
        {
            in_quotes = !in_quotes;
        }
        if (!in_encap && !in_quotes)
        {
            if (c == '\r')
            {
                if ((next_offset + 1 < tvb_len) && (tvb_get_uint8(tvb, next_offset + 1) == '\n'))
                {
                    return next_offset - offset + 2;
                }
            }
            else if (c == '\n')
            {
                return next_offset - offset + 1;
            }
        }
        next_offset++;
    }
    return 0;
}
static int dissect_lwcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LWCP");
    col_clear(pinfo->cinfo, COL_INFO);
    proto_item *ti = proto_tree_add_item(tree, proto_axia_lwcp, tvb, 0, -1, ENC_NA);
    proto_tree *axia_lwcp_tree = proto_item_add_subtree(ti, ett_axia_lwcp);
    unsigned start = 0;
    unsigned offset = 0;
    int field = 0;
    int encap_depth = 0;
    bool in_quotes = false;
    char *op;
    char *obj;
    char *prop;
    while(offset < tvb_reported_length(tvb))
    {
        if (tvb_strneql(tvb, offset, "%BeginEncap%", 12) == 0)
        {
            encap_depth++;
            offset += 12;
            continue;
        }
        if (tvb_strneql(tvb, offset, "%EndEncap%", 10) == 0)
        {
            encap_depth--;
            offset += 10;
            continue;
        }

        char c = tvb_get_uint8(tvb, offset);
        if (c == '"')
        {
            in_quotes = !in_quotes;
        }
        else if (c == '[')
        {
            encap_depth++;
        }
        else if (c == ']')
        {
            encap_depth--;
        }
        if (encap_depth == 0 && !in_quotes)
        {
            int len = offset - start;
            bool over = false;
            if (c == '\n' || c == '\r')
            {
                over = true;
            }
            else if (offset == tvb_reported_length(tvb) - 1)
            {
                over = true;
                len++;
            }
            if (over || c == ' ')
            {
                switch(field)
                {
                    case 0:
                        proto_tree_add_item_ret_display_string(axia_lwcp_tree, hf_axia_lwcp_opcode, tvb, start, len, ENC_ASCII,
                            wmem_file_scope(), &op);
                        col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", op);
                        break;
                    case 1:
                        proto_tree_add_item_ret_display_string(axia_lwcp_tree, hf_axia_lwcp_object, tvb, start, len, ENC_ASCII,
                            wmem_file_scope(), &obj);
                        col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", obj);
                        break;
                    default:
                        proto_tree_add_item_ret_display_string(axia_lwcp_tree, hf_axia_lwcp_property, tvb, start, len, ENC_ASCII,
                            wmem_file_scope(), &prop);
                        col_append_str(pinfo->cinfo, COL_INFO, prop);
                        if (!over)
                        {
                            col_append_str(pinfo->cinfo, COL_INFO, ", ");
                        }
                        break;
                }
                if (over)
                {
                    return tvb_reported_length(tvb);
                }
                field++;
                start = offset + 1;
            }
            else if (c == ',')
            {
                if (tvb_reported_length(tvb) > offset && tvb_get_uint8(tvb, offset + 1) == ' ')
                {
                    proto_tree_add_item(axia_lwcp_tree, hf_axia_lwcp_property, tvb, start, len, ENC_ASCII);
                    start = offset + 2;
                    offset++;
                }
                else
                {
                    proto_tree_add_item(axia_lwcp_tree, hf_axia_lwcp_property, tvb, start, len, ENC_ASCII);
                    start = offset + 1;
                }
            }
        }
        offset++;
    }
    return tvb_reported_length(tvb);
}
static int dissect_lwcp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, true, 1, get_lwcp_pdu_len, dissect_lwcp, data);
    return tvb_reported_length(tvb);
}
static bool test_lwadv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (cmp_address(&pinfo->net_dst, &advertisement_address))
        return false;
    if (!validate_header(tvb))
        return false;
    if (pinfo->destport != AXIA_ADV_PORT)
        return false;
    if (dissect_lwadv(tvb, pinfo, tree, data))
    {
        conversation_t *conversation = find_or_create_conversation(pinfo);
        conversation_set_dissector(conversation, axia_adv_handle);
        return true;
    }
    return false;
}
static bool test_lwgpio(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (cmp_address(&pinfo->net_dst, &gpio_address))
        return false;
    if (pinfo->destport != AXIA_GPIO_CONSOLE_PORT && pinfo->destport != AXIA_GPIO_NODE_PORT)
        return false;
    if (!validate_header(tvb))
        return false;
    if (dissect_lwgpio(tvb, pinfo, tree, data))
    {
        conversation_t *conversation = find_or_create_conversation(pinfo);
        conversation_set_dissector(conversation, axia_gpio_handle);
        return true;
    }
    return false;
}
static bool test_lwcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (cmp_address(&pinfo->net_dst, &gpio_address))
        return false;
    if (pinfo->destport != AXIA_LWCP_CONSOLE_PORT && pinfo->destport != AXIA_LWCP_MODULE_PORT)
        return false;
    if (dissect_lwcp(tvb, pinfo, tree, data))
    {
        conversation_t *conversation = find_or_create_conversation(pinfo);
        conversation_set_dissector(conversation, lwcp_handle);
        return true;
    }
    return false;
}
static bool test_lwclock(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (cmp_address(&pinfo->net_dst, &fast_clock_address) && cmp_address(&pinfo->net_dst, &slow_clock_address))
        return false;
    if (!cmp_address(&pinfo->net_dst, &fast_clock_address) && pinfo->destport != AXIA_FAST_CLOCK_PORT)
        return false;
    if (!cmp_address(&pinfo->net_dst, &slow_clock_address) && pinfo->destport != AXIA_SLOW_CLOCK_PORT)
        return false;
    if (tvb_captured_length(tvb) != 36) /* RTP Header (12 bytes) + Extension profile and length (4 bytes) + 20 bytes of extension */
        return false;
    if (tvb_get_uint8(tvb, 0) != AXIA_CLOCK_RTP_VERSION) /* RTP Version 2, no padding, with Extension and no CSRCs */
        return false;
    if (tvb_get_uint8(tvb, 1) != AXIA_CLOCK_RTP_PAYLOAD_TYPE) /* RTP Payload Type = 127 + Mark bit */
        return false;
    if (tvb_get_uint16(tvb, 12, ENC_BIG_ENDIAN) != AXIA_CLOCK_RTP_EXTENSION_PROFILE) /* RTP Extension Profile 0xfa1a */
        return false;
    if (dissect_lwclock(tvb, pinfo, tree, data))
    {
        conversation_t *conversation = find_or_create_conversation(pinfo);
        conversation_set_dissector(conversation, axia_clock_handle);
        return true;
    }
    return false;
}
static bool test_lwintercom(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (pinfo->destport != AXIA_INTERCOM_PORT || cmp_address(&pinfo->net_dst, &intercom_address))
        return false;
    if (dissect_intercom(tvb, pinfo, tree, data))
    {
        conversation_t *conversation = find_or_create_conversation(pinfo);
        conversation_set_dissector(conversation, axia_intercom_handle);
        return true;
    }
    return false;
}
void proto_register_lwadv(void)
{
    expert_module_t* expert_livewire;
    static hf_register_info hf_adv[] = {
        {&hf_axia_magic_num,        {"Axia Magic Number",           "axia_adv.magic_number",    FT_NONE,        BASE_NONE,  NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_seq,              {"Sequence",                    "axia_adv.seq",             FT_UINT32,      BASE_DEC,   NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_msg_count,        {"Nested message count",        "axia_adv.msgcount",        FT_UINT8,       BASE_DEC,   NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_pver,             {"Protocol Version",            "axia_adv.pver",            FT_UINT16,      BASE_DEC,   NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_advt,             {"Advertisement type",          "axia_adv.advt",            FT_UINT8,       BASE_HEX,   VALS(advtypenames),     0x0,    NULL,                                           HFILL}},
        {&hf_axia_unk_u8,           {"Unknown Byte",                "axia_adv.unknown_u8",      FT_UINT8,       BASE_HEX,   NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_unk_u16,          {"Unknown Int",                 "axia_adv.unknown_u16",     FT_UINT16,      BASE_DEC,   NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_unk_u32,          {"Unknown Int",                 "axia_adv.unknown_u32",     FT_UINT32,      BASE_DEC,   NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_unk_data,         {"Unknown Data",                "axia_adv.unknown_data",    FT_BYTES,       SEP_COLON,  NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_unk_str,          {"Unknown String",              "axia_adv.unknown_string",  FT_STRING,      BASE_NONE,  NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_opcode,           {"Operation",                   "axia_adv.opcode",          FT_STRING,      BASE_NONE,  NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_term,             {"Terminal Information",        "axia_adv.term",            FT_NONE,        BASE_NONE,  NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_term_inip,        {"IP Address",                  "axia_adv.term.inip",       FT_IPv4,        BASE_NONE,  NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_term_hwid,        {"Hardware ID",                 "axia_adv.term.hwid",       FT_UINT16,      BASE_HEX,   NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_term_advv,        {"Advertisement Version",       "axia_adv.term.advv",       FT_UINT32,      BASE_DEC,   NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_term_udpc,        {"UDP Port",                    "axia_adv.term.udpc",       FT_UINT16,      BASE_PT_UDP,NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_term_nums,        {"Number of Sources",           "axia_adv.term.nums",       FT_UINT16,      BASE_DEC,   NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_term_atrn,        {"Terminal Name",               "axia_adv.term.atrn",       FT_STRING,      BASE_NONE,  NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_term_type,        {"Type",                        "axia_adv.term.type",       FT_STRING,      BASE_NONE,  NULL,                   0x0,    NULL,                                           HFILL}},

        {&hf_axia_src,              {"Source Information",          "axia_adv.src",             FT_NONE,        BASE_NONE,  NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_src_psid,         {"Livewire Source ID",          "axia_adv.src.psid",        FT_UINT32,      BASE_DEC,   NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_src_shab,         {"Sharable",                    "axia_adv.src.shab",        FT_BOOLEAN,     BASE_NONE,  NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_src_fsid,         {"Multicast address",           "axia_adv.src.fsid",        FT_IPv4,        BASE_NONE,  NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_src_bsid,         {"Backfeed address",            "axia_adv.src.bsid",        FT_IPv4,        BASE_NONE,  NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_src_psnm,         {"Name",                        "axia_adv.src.psnm",        FT_STRING,      BASE_NONE,  NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_src_labl,         {"Label",                       "axia_adv.src.labl",        FT_STRING,      BASE_NONE,  NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_src_lpid,         {"Logic Port ID",               "axia_adv.src.lpid",        FT_UINT32,      BASE_DEC,   NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_src_setup_frame,  {"Setup Frame",                 "axia_adv.src.setup-frame", FT_FRAMENUM,    BASE_NONE,  NULL,                   0x0,    "First frame that advertised this source",      HFILL}},
        {&hf_axia_src_is_mm,        {"Is Backfeed",                 "axia_adv.src.is-backfeed", FT_BOOLEAN,     BASE_NONE,  NULL,                   0x0,    "Is this source a backfeed from a console?",    HFILL}},

        {&hf_axia_busy,             {"Source Allocation",           "axia_adv.busy",            FT_NONE,        BASE_NONE,  NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_busy_hwid,        {"Console HWID",                "axia_adv.busy.hwid",       FT_UINT16,      BASE_HEX,   NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_busy_fader,       {"Fader",                       "axia_adv.busy.fader",      FT_UINT8,       BASE_DEC,   NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_busy_ip,          {"Console IP Address",          "axia_adv.busy.ip",         FT_IPv4,        BASE_NONE,  NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_busy_prefix,      {"Console IP Prefix",           "axia_adv.busy.prefix",     FT_UINT16,      BASE_HEX,   NULL,                   0x0,    NULL,                                           HFILL}},
    };
    static hf_register_info hf_gpio[] = {
        {&hf_axia_gpio_lcid,        {"Logic Circuit ID",            "axia_gpio.lcid",           FT_UINT8,       BASE_DEC,   NULL,                   0x0f,   NULL,                                           HFILL}},
        {&hf_axia_gpio_state,       {"Logic Circuit State",         "axia_gpio.state",          FT_UINT8,       BASE_DEC,   NULL,                   0x40,   NULL,                                           HFILL}},
        {&hf_axia_gpio_state2,      {"Logic Circuit State",         "axia_gpio.state",          FT_UINT8,       BASE_DEC,   NULL,                   0x01,   NULL,                                           HFILL}},
        {&hf_axia_gpio_pmult,       {"Pulse length multiplier",     "axia_gpio.pulse_len_mult", FT_UINT8,       BASE_DEC,   NULL,                   0x80,   NULL,                                           HFILL}},
        {&hf_axia_gpio_plen,        {"Pulse length",                "axia_gpio.pulse_len",      FT_UINT8,       BASE_DEC,   NULL,                   0x3f,   NULL,                                           HFILL}},
    };
    static hf_register_info hf_clock[] ={
        {&hf_axia_clock_hwid,       {"Clock Hardware ID",           "axia_clock.hwid",          FT_UINT16,      BASE_HEX,   NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_clock_prio,       {"Priority",                    "axia_clock.priority",      FT_UINT8,       BASE_DEC,   NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_clock_mac,        {"Clock MAC Address",           "axia_clock.mac",           FT_ETHER,       BASE_NONE,  NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_clock_samp,       {"RTP Timestamp",               "axia_clock.rtp_ts",        FT_UINT32,      BASE_DEC,   NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_clock_fast,       {"Timstamp in live packets",    "axia_clock.fast",          FT_UINT32,      BASE_DEC,   NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_clock_seq,        {"Sequence",                    "axia_clock.seq",           FT_UINT16,      BASE_DEC,   NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_clock_rate,       {"Is Fast-Rate Clock",          "axia_clock.rate",          FT_BOOLEAN,     BASE_NONE,  NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_clock_type,       {"Clock message type",          "axia_clock.type",          FT_UINT8,       BASE_HEX,   VALS(clocktypenames),   0x0,    NULL,                                           HFILL}},
    };
    static hf_register_info hf_lwcp[] ={
        {&hf_axia_lwcp_opcode,      {"Operation",                   "axia_lwcp.opcode",         FT_STRING,      BASE_NONE,  NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_lwcp_object,      {"Object",                      "axia_lwcp.object",         FT_STRING,      BASE_NONE,  NULL,                   0x0,    NULL,                                           HFILL}},
        {&hf_axia_lwcp_property,    {"Property",                    "axia_lwcp.property",       FT_STRING,      BASE_NONE,  NULL,                   0x0,    NULL,                                           HFILL}},
    };
    static ei_register_info ei[] = {
        { &ei_axia_clock_changed, {"axia_clock.masterchanged", PI_PROTOCOL, PI_WARN, "Livewire Master Clock Changed", EXPFILL }},
    };
    static int *ett[] = {
        &ett_axia_adv,
        &ett_axia_gpio,
        &ett_axia_clock,
        &ett_axia_lwcp,
    };

    uint32_t ip4_addr;
    str_to_ip(AXIA_FAST_CLOCK_ADDR, &ip4_addr);
    alloc_address_wmem(wmem_epan_scope(), &fast_clock_address, AT_IPv4, sizeof(uint32_t), &ip4_addr);
    str_to_ip(AXIA_SLOW_CLOCK_ADDR, &ip4_addr);
    alloc_address_wmem(wmem_epan_scope(), &slow_clock_address, AT_IPv4, sizeof(uint32_t), &ip4_addr);
    str_to_ip(AXIA_ADV_ADDR, &ip4_addr);
    alloc_address_wmem(wmem_epan_scope(), &advertisement_address, AT_IPv4, sizeof(uint32_t), &ip4_addr);
    str_to_ip(AXIA_GPIO_ADDR, &ip4_addr);
    alloc_address_wmem(wmem_epan_scope(), &gpio_address, AT_IPv4, sizeof(uint32_t), &ip4_addr);
    str_to_ip(AXIA_INTERCOM_ADDR, &ip4_addr);
    alloc_address_wmem(wmem_epan_scope(), &intercom_address, AT_IPv4, sizeof(uint32_t), &ip4_addr);

    proto_axia_adv = proto_register_protocol("Livewire Source Advertisement", "LW Advertisement", "axia_adv");
    proto_axia_gpio = proto_register_protocol("Livewire Multicast GPIO", "LW GPIO", "axia_gpio");
    proto_axia_clock = proto_register_protocol("Livewire Clock", "LW Clock", "axia_clock");
    proto_axia_intercom = proto_register_protocol("Telos Infinity Intercom", "Infinity Intercom", "axia_intercom");
    proto_axia_lwcp = proto_register_protocol("Livewire Control Protocol", "LWCP", "axia_lwcp");
    proto_register_field_array(proto_axia_adv, hf_adv, array_length(hf_adv));
    proto_register_field_array(proto_axia_gpio, hf_gpio, array_length(hf_gpio));
    proto_register_field_array(proto_axia_clock, hf_clock, array_length(hf_clock));
    proto_register_field_array(proto_axia_lwcp, hf_lwcp, array_length(hf_lwcp));
    proto_register_subtree_array(ett, array_length(ett));

    expert_livewire = expert_register_protocol(proto_axia_adv);
    expert_register_field_array(expert_livewire, ei, array_length(ei));

    axia_adv_handle = register_dissector("axia_adv", dissect_lwadv, proto_axia_adv);
    axia_gpio_handle = register_dissector("axia_gpio", dissect_lwgpio, proto_axia_gpio);
    axia_clock_handle = register_dissector("axia_clock", dissect_lwclock, proto_axia_clock);
    axia_intercom_handle = register_dissector("axia_intercom", dissect_intercom, proto_axia_intercom);
    lwcp_handle = register_dissector("axia_lwcp", dissect_lwcp, proto_axia_lwcp);
    lwcp_tcp_handle = register_dissector("axia_lwcp-tcp", dissect_lwcp_tcp, proto_axia_lwcp);
}
void proto_reg_handoff_axia(void)
{
    axia_sources = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    axia_nodes = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    heur_dissector_add("udp", test_lwadv, "Livewire Source Advertisement Heuristic Dissector", "axia_adv_heur", proto_axia_adv, HEURISTIC_ENABLE);
    heur_dissector_add("udp", test_lwgpio, "Livewire GPIO Heuristic Dissector", "axia_gpio_heur", proto_axia_gpio, HEURISTIC_ENABLE);
    heur_dissector_add("udp", test_lwclock, "Livewire Clock Heuristic Dissector", "axia_clock_heur", proto_axia_clock, HEURISTIC_ENABLE);
    heur_dissector_add("udp", test_lwintercom, "Telos Infinity Heuristic Dissector", "axia_intercom_heur", proto_axia_intercom, HEURISTIC_ENABLE);
    heur_dissector_add("udp", test_lwcp, "Livewire Control Protocol Heuristic Dissector", "axia_lwcp_heur", proto_axia_lwcp, HEURISTIC_ENABLE);
    dissector_add_for_decode_as("udp.port", axia_adv_handle);
    dissector_add_for_decode_as("udp.port", axia_gpio_handle);
    dissector_add_for_decode_as("udp.port", axia_clock_handle);
    dissector_add_for_decode_as("udp.port", axia_intercom_handle);
    dissector_add_for_decode_as("tcp.port", lwcp_tcp_handle);
    dissector_add_for_decode_as("udp.port", lwcp_handle);
    json_handle = find_dissector("json");
}
