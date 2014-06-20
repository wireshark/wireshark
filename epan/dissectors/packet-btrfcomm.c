/* packet-btrfcomm.c
 * Routines for Bluetooth RFCOMM protocol dissection
 * and RFCOMM based profile dissection:
 *    - Dial-Up Networking Profile (DUN)
 *    - Serial Port Profile (SPP)
 *    - Global Navigation Satellite System (GNSS)
 *
 * Copyright 2002, Wolfgang Hansmann <hansmann@cs.uni-bonn.de>
 *
 * Refactored for wireshark checkin
 *   Ronnie Sahlberg 2006
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/uat.h>
#include <epan/wmem/wmem.h>
#include <epan/decode_as.h>

#include "packet-bluetooth-hci.h"
#include "packet-btsdp.h"
#include "packet-btl2cap.h"
#include "packet-btrfcomm.h"

static int hf_pf = -1;
static int hf_ea = -1;
static int hf_len = -1;
static int hf_frame_type = -1;
static int hf_cr = -1;
static int hf_dlci = -1;
static int hf_channel = -1;
static int hf_direction = -1;
static int hf_priority = -1;
static int hf_error_recovery_mode = -1;
static int hf_max_frame_size = -1;
static int hf_max_retrans = -1;
static int hf_fc_credits = -1;

static int hf_mcc_pn_parameters = -1;
static int hf_pn_i14 = -1;
static int hf_pn_c14 = -1;

static int hf_mcc = -1;
static int hf_mcc_types = -1;
static int hf_mcc_len = -1;
static int hf_mcc_ea = -1;
static int hf_mcc_cr = -1;
static int hf_mcc_cmd = -1;

static int hf_msc_parameters = -1;
static int hf_msc_fc = -1;
static int hf_msc_rtc = -1;
static int hf_msc_rtr = -1;
static int hf_msc_ic = -1;
static int hf_msc_dv = -1;
static int hf_msc_l = -1;
static int hf_msc_break_bits = -1;

static int hf_fcs = -1;

static int hf_dun_at_cmd = -1;
static int hf_spp_data = -1;
static int hf_gnss_data = -1;

static int hf_mcc_dlci = -1;
static int hf_mcc_channel = -1;
static int hf_mcc_direction = -1;
static int hf_mcc_const_1 = -1;

static int hf_mcc_pn_dlci = -1;
static int hf_mcc_pn_channel = -1;
static int hf_mcc_pn_direction = -1;
static int hf_mcc_pn_zeros_padding = -1;

static int hf_acknowledgement_timer_t1 = -1;
static int hf_address = -1;
static int hf_control = -1;

/* Initialize the protocol and registered fields */
int proto_btrfcomm = -1;
static int proto_btdun = -1;
static int proto_btspp = -1;
static int proto_btgnss = -1;

/* Initialize the subtree pointers */
static gint ett_btrfcomm = -1;
static gint ett_btrfcomm_ctrl = -1;
static gint ett_addr = -1;
static gint ett_control = -1;
static gint ett_mcc = -1;
static gint ett_ctrl_pn_ci = -1;
static gint ett_ctrl_pn_v24 = -1;
static gint ett_dlci = -1;
static gint ett_mcc_dlci = -1;

static gint ett_btdun = -1;
static gint ett_btspp = -1;
static gint ett_btgnss = -1;

static expert_field ei_btrfcomm_mcc_length_bad = EI_INIT;

static dissector_handle_t btrfcomm_handle;
static dissector_handle_t btdun_handle;
static dissector_handle_t btspp_handle;
static dissector_handle_t btgnss_handle;

static dissector_table_t rfcomm_service_dissector_table;
static dissector_table_t rfcomm_channel_dissector_table;

static wmem_tree_t *service_directions = NULL;

typedef struct {
    guint32  direction;
    guint32  end_in;
} service_direction_t;

typedef struct {
    guint               channel;
    gchar*              payload_proto_name;
    dissector_handle_t  payload_proto;
} uat_rfcomm_channels_t;

static gboolean               rfcomm_channels_enabled   = FALSE;
static uat_t                  *uat_rfcomm_channels      = NULL;
static uat_rfcomm_channels_t  *rfcomm_channels          = NULL;
static guint                  num_rfcomm_channels       = 0;

UAT_DEC_CB_DEF(rfcomm_channels, channel, uat_rfcomm_channels_t)
UAT_PROTO_DEF(rfcomm_channels, payload_proto, payload_proto, payload_proto_name, uat_rfcomm_channels_t)

static uat_field_t uat_rfcomm_channels_fields[] = {
    UAT_FLD_DEC(rfcomm_channels, channel, "RFCOMM Channel",
            "Range: 0-32"),
    UAT_FLD_PROTO(rfcomm_channels, payload_proto, "Payload protocol",
            "Dissector name used to decode RFCOMM channel"),
    UAT_END_FIELDS
};

static dissector_handle_t data_handle;
static dissector_handle_t ppp_handle;

static const value_string vs_ctl_pn_i[] = {
    {0x0, "use UIH Frames"},
#if 0    /* specified by 07.10, but not used by RFCOMM */
    {0x1, "use UI Frames"},
    {0x2, "use I Frames"},
#endif
    {0, NULL}
};

static const value_string vs_ctl_pn_cl[] = {

    {0x0, "no credit based flow control scheme"},
    {0xe, "support of credit based flow control scheme (resp)"},
    {0xf, "support of credit based flow control scheme (req)"},
#if 0    /* specified by 07.10. Redefined by RFCOMM */
    {0x0, "type 1 (unstructured octet stream)"},
    {0x1, "type 2 (unstructured octet stream with flow control)"},
    {0x2, "type 3 (uninterruptible framed data)"},
    {0x3, "type 4 (interruptible framed data)"},
#endif
    {0, NULL}
};


static const value_string vs_frame_type[] = {
    /* masked 0xef */
    {0x2f, "Set Asynchronous Balanced Mode (SABM)"},
    {0x63, "Unnumbered Acknowledgement (UA)"},
    {0x0f, "Disconnected Mode (DM)"},
    {0x43, "Disconnect (DISC)"},
    {0xef, "Unnumbered Information with Header check (UIH)"},
#if 0    /* specified by 07.10, but not used by RFCOMM */
       {0x03, "Unnumbered Information (UI)"},
#endif
        {0, NULL}
};


static const value_string vs_frame_type_short[] = {
    /* masked 0xef */
    {0x2f, "SABM"},
    {0x63, "UA"},
    {0x0f, "DM"},
    {0x43, "DISC"},
    {0xef, "UIH"},
#if 0    /* specified by 07.10, but not used by RFCOMM */
    {0x03, "UI"},
#endif
        {0, NULL}
};

#define FRAME_TYPE_SABM  0x2F
#define FRAME_TYPE_UIH   0xEF

static const value_string vs_ctl[] = {
       /* masked 0xfc */
    {0x20, "DLC Parameter Negotiation (PN)"},
    {0x08, "Test Command (Test)"},
    {0x28, "Flow Control On Command (FCon)"},
    {0x18, "Flow Control Off Command (FCoff)"},
    {0x38, "Modem Status Command (MSC)"},
    {0x04, "Non Supported Command Response (NSC)"},
    {0x24, "Remote Port Negotiation Command (RPN)"},
    {0x14, "Remote Line Status Command (RLS)"},
#if 0    /* Specified by 07.10, but not used by RFCOMM */
    {0x10, "Power Saving Control (PSC)"},
    {0x30, "Multiplexer close down (CLD)"},
    {0x34, "Service Negotiation Command (SNC)"},
#endif
#if 0     /* old */
    {0x80, "DLC parameter negotiation (PN)"},
    {0x20, "Test Command (Test)"},
    {0xa0, "Flow Control On Command (FCon)"},
    {0x60, "Flow Control Off Command (FCoff)"},
    {0xe0, "Modem Status Command (MSC)"},
    {0x10, "Non Supported Command Response (NSC)"},
    {0x90, "Remote Port Negotiation Command (RPN)"},
    {0x50, "Remote Line Status Command (RLS)"},
    {0x40, "Power Saving Control (PSC)"},
    {0xc0, "Multiplexer close down (CLD)"},
    {0xd0, "Service Negotiation Command (SNC)"},
#endif
    {0x0, NULL}
};

static const value_string vs_ea[] = {
    {1, "Last field octet"},
    {0, "More field octets following"},
    {0, NULL}
};

static const value_string vs_cr[] = {
    {1, "Command"},
    {0, "Response"},
    {0, NULL}
};

void proto_register_btrfcomm(void);
void proto_reg_handoff_btrfcomm(void);
void proto_register_btdun(void);
void proto_reg_handoff_btdun(void);
void proto_register_btspp(void);
void proto_reg_handoff_btspp(void);
void proto_register_btgnss(void);
void proto_reg_handoff_btgnss(void);

#define BTRFCOMM_SERVICE_CONV        0
#define BTRFCOMM_CHANNEL_CONV        1

static void btrfcomm_serv_prompt(packet_info *pinfo, gchar* result)
{
    gulong *value_data;

    value_data = (gulong *) p_get_proto_data(pinfo->pool, pinfo, proto_btrfcomm, BTRFCOMM_SERVICE_CONV);
    if (value_data)
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "RFCOMM SERVICE %d as", (guint) *value_data);
    else
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Unknown RFCOMM SERVICE");
}

static gpointer btrfcomm_serv_value(packet_info *pinfo)
{
    gulong *value_data;

    value_data = (gulong *) p_get_proto_data(pinfo->pool, pinfo, proto_btrfcomm, BTRFCOMM_SERVICE_CONV);

    if (value_data)
        return (gpointer) *value_data;

    return NULL;
}

static void btrfcomm_chan_prompt(packet_info *pinfo, gchar* result)
{
    gulong *value_data;

    value_data = (gulong *) p_get_proto_data(pinfo->pool, pinfo, proto_btrfcomm, BTRFCOMM_CHANNEL_CONV);
    if (value_data)
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "RFCOMM Channel %d as", (guint) *value_data);
    else
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Unknown RFCOMM Channel");
}

static gpointer btrfcomm_chan_value(packet_info *pinfo)
{
    gulong *value_data;

    value_data = (gulong *) p_get_proto_data(pinfo->pool, pinfo, proto_btrfcomm, BTRFCOMM_CHANNEL_CONV);

    if (value_data)
        return (gpointer) *value_data;

    return NULL;
}

static dissector_handle_t
find_proto_by_channel(guint channel) {
    guint i_channel;

    for (i_channel = 0; i_channel < num_rfcomm_channels; ++i_channel) {
        if (rfcomm_channels[i_channel].channel == channel) {
            return rfcomm_channels[i_channel].payload_proto;
        }
    }
    return NULL;
}

static int
get_le_multi_byte_value(tvbuff_t *tvb, int offset, proto_tree *tree, guint32 *val_ptr, int hf_index)
{
    guint8  byte, bc     = 0;
    guint32 val          = 0;
    int     start_offset = offset;

    do {
        byte = tvb_get_guint8(tvb, offset);
        offset += 1;
        val |= ((byte >> 1) & 0xff) << (bc++ * 7);
    } while ((byte & 0x1) == 0);

    *val_ptr = val;

    if (hf_index > 0) {
        proto_tree_add_uint(tree, hf_index, tvb, start_offset, offset - start_offset, val);
    }

    return offset;
}


static int
dissect_ctrl_pn(proto_tree *t, tvbuff_t *tvb, int offset, guint8 *mcc_channel)
{
    proto_tree   *st;
    proto_item   *ti;
    proto_tree   *dlci_tree;
    proto_item   *dlci_item;
    proto_item   *item;
    int           mcc_dlci;
    guint8        flags;

    proto_tree_add_item(t, hf_mcc_pn_zeros_padding, tvb, offset, 1, ENC_LITTLE_ENDIAN);

    /* mcc dlci */
    mcc_dlci = tvb_get_guint8(tvb, offset) & 0x3f;
    *mcc_channel = mcc_dlci >> 1;

    dlci_item = proto_tree_add_item(t, hf_mcc_pn_dlci, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_item_append_text(dlci_item, " (Direction: %d, Channel: %u)", mcc_dlci & 0x01, *mcc_channel);

    dlci_tree = proto_item_add_subtree(dlci_item, ett_mcc_dlci);
    proto_tree_add_item(dlci_tree, hf_mcc_pn_channel, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(dlci_tree, hf_mcc_pn_direction, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    flags = tvb_get_guint8(tvb, offset);

    ti = proto_tree_add_none_format(t, hf_mcc_pn_parameters, tvb, offset, 1, "I1-I4: 0x%x, C1-C4: 0x%x", flags & 0xf, (flags >> 4) & 0xf);
    st = proto_item_add_subtree(ti, ett_ctrl_pn_ci);

    proto_tree_add_item(st, hf_pn_c14, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(st, hf_pn_i14, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* priority */
    proto_tree_add_item(t, hf_priority, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* Ack timer */
    item = proto_tree_add_item(t, hf_acknowledgement_timer_t1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_item_append_text(item, "(%d ms)", (guint32)tvb_get_guint8(tvb, offset) * 100);
    offset += 1;

    /* max frame size */
    proto_tree_add_item(t, hf_max_frame_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* max retrans */
    proto_tree_add_item(t, hf_max_retrans, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* error recovery mode */
    proto_tree_add_item(t, hf_error_recovery_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    return offset;
}

static int
dissect_ctrl_msc(proto_tree *t, tvbuff_t *tvb, int offset, int length, guint8 *mcc_channel)
{

    proto_tree *st;
    proto_item *it;
    proto_tree *dlci_tree;
    proto_item *dlci_item;
    guint8      mcc_dlci;
    guint8      status;
    int         start_offset;

    mcc_dlci = tvb_get_guint8(tvb, offset) >> 2;
    *mcc_channel = mcc_dlci >> 1;

    dlci_item = proto_tree_add_item(t, hf_mcc_dlci, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_item_append_text(dlci_item, " (Direction: %d, Channel: %u)", mcc_dlci & 0x01, *mcc_channel);

    dlci_tree = proto_item_add_subtree(dlci_item, ett_mcc_dlci);
    proto_tree_add_item(dlci_tree, hf_mcc_channel, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(dlci_tree, hf_mcc_direction, tvb, offset, 1, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(t, hf_mcc_const_1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(t, hf_mcc_ea, tvb, offset, 1, ENC_LITTLE_ENDIAN);

    offset += 1;

    start_offset = offset;
    status       = tvb_get_guint8(tvb, offset);
    it = proto_tree_add_none_format(t, hf_msc_parameters, tvb, offset, 1, "V.24 Signals: FC = %d, RTC = %d, RTR = %d, IC = %d, DV = %d", (status >> 1) & 1,
                 (status >> 2) & 1, (status >> 3) & 1,
                 (status >> 6) & 1, (status >> 7) & 1);
    st = proto_item_add_subtree(it, ett_ctrl_pn_v24);

    proto_tree_add_item(st, hf_msc_fc,  tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(st, hf_msc_rtc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(st, hf_msc_rtr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(st, hf_msc_ic,  tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(st, hf_msc_dv,  tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    if (length == 3) {
        proto_tree_add_item(t, hf_msc_break_bits, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(t, hf_msc_l, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
    }

    proto_item_set_len(it, offset - start_offset);

    return offset;
}

static int
dissect_btrfcomm_address(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, guint8 *ea_flagp, guint8 *cr_flagp, guint8 *dlcip)
{
    proto_item *ti;
    proto_tree *addr_tree;
    proto_tree *dlci_tree = NULL;
    proto_item *dlci_item = NULL;
    guint8      dlci, cr_flag, ea_flag, flags, channel;

    flags = tvb_get_guint8(tvb, offset);

    ea_flag = flags & 0x01;
    if (ea_flagp) {
        *ea_flagp = ea_flag;
    }

    cr_flag = (flags & 0x02) ? 1 : 0;
    if (cr_flagp) {
        *cr_flagp = cr_flag;
    }

    dlci = flags >> 2;
    if (dlcip) {
        *dlcip = dlci;
    }

    ti = proto_tree_add_none_format(tree, hf_address, tvb, offset, 1, "Address: E/A flag: %d, C/R flag: %d, Direction: %d, Channel: %u", ea_flag, cr_flag, dlci & 0x01, dlci >> 1);
    addr_tree = proto_item_add_subtree(ti, ett_addr);

    dlci_item = proto_tree_add_item(addr_tree, hf_dlci, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    channel = dlci >> 1;
    proto_item_append_text(dlci_item, " (Direction: %d, Channel: %u)", dlci & 0x01, channel);

    if (p_get_proto_data(pinfo->pool, pinfo, proto_btrfcomm, BTRFCOMM_CHANNEL_CONV) == NULL) {
        gulong *value_data;

        value_data = wmem_new(wmem_file_scope(), gulong);
        *value_data = channel;

        p_add_proto_data(pinfo->pool, pinfo, proto_btrfcomm, BTRFCOMM_CHANNEL_CONV, value_data);
    }

    dlci_tree = proto_item_add_subtree(dlci_item, ett_dlci);
    proto_tree_add_item(dlci_tree, hf_channel, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(dlci_tree, hf_direction, tvb, offset, 1, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(addr_tree, hf_cr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(addr_tree, hf_ea, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    return offset;
}

static int
dissect_btrfcomm_control(tvbuff_t *tvb, int offset, proto_tree *tree, guint8 *pf_flagp, guint8 *frame_typep)
{
    proto_item *ti;
    proto_tree *hctl_tree;
    guint8      frame_type, pf_flag, flags;

    flags = tvb_get_guint8(tvb, offset);

    pf_flag = (flags & 0x10) ? 1 : 0;
    if (pf_flagp) {
        *pf_flagp = pf_flag;
    }

    frame_type = flags & 0xef;
    if (frame_typep) {
        *frame_typep = frame_type;
    }

    ti = proto_tree_add_none_format(tree, hf_control, tvb, offset, 1, "Control: Frame type: %s (0x%x), P/F flag: %d",
                             val_to_str_const(frame_type, vs_frame_type, "Unknown"), frame_type, pf_flag);
    hctl_tree = proto_item_add_subtree(ti, ett_control);

    proto_tree_add_item(hctl_tree, hf_pf,         tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(hctl_tree, hf_frame_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);

    offset += 1;
    return offset;
}



static int
dissect_btrfcomm_payload_length(tvbuff_t *tvb, int offset, proto_tree *tree, guint16 *frame_lenp)
{
    guint16 frame_len;
    int     start_offset = offset;

    frame_len = tvb_get_guint8(tvb, offset);
    offset += 1;

    if (frame_len & 0x01) {
        frame_len >>= 1; /* 0 - 127 */
    } else {
        frame_len >>= 1; /* 128 - ... */
        frame_len |= (tvb_get_guint8(tvb, offset)) << 7;
        offset += 1;
    }

    proto_tree_add_uint(tree, hf_len, tvb, start_offset, offset - start_offset, frame_len);

    if (frame_lenp) {
        *frame_lenp = frame_len;
    }

    return offset;
}

static int
dissect_btrfcomm_MccType(tvbuff_t *tvb, int offset, proto_tree *tree, guint8 *mcc_cr_flagp, guint8 *mcc_ea_flagp, guint32 *mcc_typep)
{
    int         start_offset = offset;
    proto_item *ti;
    proto_tree *mcc_tree;
    guint8      flags, mcc_cr_flag, mcc_ea_flag;
    guint32     mcc_type;

    flags = tvb_get_guint8(tvb, offset);

    mcc_cr_flag = (flags & 0x2) ? 1 : 0;
    if (mcc_cr_flagp) {
        *mcc_cr_flagp = mcc_cr_flag;
    }

    mcc_ea_flag = flags & 0x1;
    if (mcc_ea_flagp) {
        *mcc_ea_flagp = mcc_ea_flag;
    }

    offset = get_le_multi_byte_value(tvb, offset, tree, &mcc_type, -1);
    mcc_type = (mcc_type >> 1) & 0x3f; /* shift c/r flag off */
    if (mcc_typep) {
        *mcc_typep = mcc_type;
    }

    ti = proto_tree_add_none_format(tree, hf_mcc_types, tvb, start_offset, offset - start_offset,
                             "Type: %s (0x%x), C/R flag = %d, E/A flag = %d",
                             val_to_str_const(mcc_type, vs_ctl, "Unknown"),
                             mcc_type, mcc_cr_flag, mcc_ea_flag);
    mcc_tree = proto_item_add_subtree(ti, ett_mcc);

    proto_tree_add_item(mcc_tree, hf_mcc_cmd, tvb, start_offset, offset - start_offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mcc_tree, hf_mcc_cr, tvb, start_offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mcc_tree, hf_mcc_ea, tvb, start_offset, 1, ENC_LITTLE_ENDIAN);

    return offset;
}

static gint
dissect_btrfcomm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item          *ti;
    proto_tree          *rfcomm_tree;
    gint                 offset     = 0;
    gint                 fcs_offset;
    guint8               dlci, cr_flag, ea_flag;
    guint8               frame_type, pf_flag;
    guint16              frame_len;
    btl2cap_data_t      *l2cap_data;
    service_info_t      *service_info = NULL;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    l2cap_data = (btl2cap_data_t *) data;

    ti = proto_tree_add_item(tree, proto_btrfcomm, tvb, offset, -1, ENC_NA);
    rfcomm_tree = proto_item_add_subtree(ti, ett_btrfcomm);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RFCOMM");

    switch (pinfo->p2p_dir) {
        case P2P_DIR_SENT:
            col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
            break;
        case P2P_DIR_RECV:
            col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
            break;
        default:
            col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction %d ",
                pinfo->p2p_dir);
            break;
    }

    /* flags and dlci */
    offset = dissect_btrfcomm_address(tvb, pinfo, offset, rfcomm_tree, &ea_flag, &cr_flag, &dlci);
    /* pf and frame type */
    offset = dissect_btrfcomm_control(tvb, offset, rfcomm_tree, &pf_flag, &frame_type);
    /* payload length */
    offset = dissect_btrfcomm_payload_length(tvb, offset, rfcomm_tree, &frame_len);

    if (dlci && (frame_len || (frame_type == FRAME_TYPE_UIH) || (frame_type == FRAME_TYPE_SABM))) {
        wmem_tree_key_t       key[10];
        guint32               k_interface_id;
        guint32               k_adapter_id;
        guint32               k_psm;
        guint32               k_direction;
        guint32               k_bd_addr_oui;
        guint32               k_bd_addr_id;
        guint32               k_service_type;
        guint32               k_frame_number;
        guint32               k_chandle;
        guint32               k_channel;
        service_direction_t  *service_direction;
        wmem_tree_t          *subtree;

        k_interface_id    = l2cap_data->interface_id;
        k_adapter_id      = l2cap_data->adapter_id;
        k_chandle         = l2cap_data->chandle;
        k_psm             = l2cap_data->psm;
        k_channel         = dlci >> 1;
        k_frame_number    = pinfo->fd->num;

        key[0].length = 1;
        key[0].key = &k_interface_id;
        key[1].length = 1;
        key[1].key = &k_adapter_id;
        key[2].length = 1;
        key[2].key = &k_chandle;
        key[3].length = 1;
        key[3].key = &k_psm;
        key[4].length = 1;
        key[4].key = &k_channel;

        if (!pinfo->fd->flags.visited && frame_type == FRAME_TYPE_SABM) {
            key[5].length = 0;
            key[5].key = NULL;

            subtree = (wmem_tree_t *) wmem_tree_lookup32_array(service_directions, key);
            service_direction = (subtree) ? (service_direction_t *) wmem_tree_lookup32_le(subtree, k_frame_number) : NULL;
            if (service_direction && service_direction->end_in == G_MAXUINT32) {
                service_direction->end_in = k_frame_number;
            }

            key[5].length = 1;
            key[5].key = &k_frame_number;
            key[6].length = 0;
            key[6].key = NULL;

            service_direction = wmem_new(wmem_file_scope(), service_direction_t);
            service_direction->direction = (pinfo->p2p_dir == P2P_DIR_RECV) ? P2P_DIR_SENT : P2P_DIR_RECV;
            service_direction->end_in = G_MAXUINT32;

            wmem_tree_insert32_array(service_directions, key, service_direction);
        }

        key[5].length = 0;
        key[5].key = NULL;

        subtree = (wmem_tree_t *) wmem_tree_lookup32_array(service_directions, key);
        service_direction = (subtree) ? (service_direction_t *) wmem_tree_lookup32_le(subtree, k_frame_number) : NULL;
        if (service_direction && service_direction->end_in > k_frame_number) {
            k_direction = service_direction->direction;
        } else {
            k_direction = (l2cap_data->is_local_psm) ? P2P_DIR_SENT : P2P_DIR_RECV;
        }

        k_psm = SDP_PSM_DEFAULT;
        if (k_direction == P2P_DIR_RECV) {
            k_bd_addr_oui     = l2cap_data->remote_bd_addr_oui;
            k_bd_addr_id      = l2cap_data->remote_bd_addr_id;
        } else {
            k_bd_addr_oui     = 0;
            k_bd_addr_id      = 0;
        }
        k_service_type    = BTSDP_RFCOMM_PROTOCOL_UUID;

        key[2].length = 1;
        key[2].key = &k_psm;
        key[3].length = 1;
        key[3].key = &k_direction;
        key[4].length = 1;
        key[4].key = &k_bd_addr_oui;
        key[5].length = 1;
        key[5].key = &k_bd_addr_id;
        key[6].length = 1;
        key[6].key = &k_service_type;
        key[7].length = 1;
        key[7].key = &k_channel;
        key[8].length = 1;
        key[8].key = &k_frame_number;
        key[9].length = 0;
        key[9].key = NULL;

        service_info = btsdp_get_service_info(key);

        if (service_info && service_info->interface_id == l2cap_data->interface_id &&
                service_info->adapter_id == l2cap_data->adapter_id &&
                service_info->sdp_psm == SDP_PSM_DEFAULT &&
                ((service_info->direction == P2P_DIR_RECV &&
                service_info->bd_addr_oui == l2cap_data->remote_bd_addr_oui &&
                service_info->bd_addr_id == l2cap_data->remote_bd_addr_id) ||
                (service_info->direction != P2P_DIR_RECV &&
                service_info->bd_addr_oui == 0 &&
                service_info->bd_addr_id == 0)) &&
                service_info->type == BTSDP_RFCOMM_PROTOCOL_UUID &&
                service_info->channel == (dlci >> 1)) {

        } else {
            service_info = wmem_new0(wmem_packet_scope(), service_info_t);
        }
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s Channel=%u ",
                    val_to_str_const(frame_type, vs_frame_type_short, "Unknown"), dlci >> 1);
    if (dlci && (frame_type == FRAME_TYPE_SABM))
        col_append_fstr(pinfo->cinfo, COL_INFO, "(%s) ",
                        val_to_str_ext_const(service_info->uuid.bt_uuid, &bt_sig_uuid_vals_ext, "Unknown"));

    /* UID frame */
    if ((frame_type == FRAME_TYPE_UIH) && dlci && pf_flag) {
        col_append_str(pinfo->cinfo, COL_INFO, "UID ");

        /* add credit based flow control byte */
        proto_tree_add_item(rfcomm_tree, hf_fc_credits, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

    }

    fcs_offset = offset + frame_len;

    /* multiplexer control command */
    if (!dlci && frame_len) {
        proto_item *mcc_ti;
        proto_tree *ctrl_tree;
        proto_tree *dlci_tree;
        proto_item *dlci_item;
        guint32     mcc_type, length;
        guint8      mcc_cr_flag, mcc_ea_flag;
        guint8      mcc_channel;
        guint8      mcc_dlci;
        int         start_offset = offset;

        mcc_ti = proto_tree_add_item(rfcomm_tree, hf_mcc, tvb, offset, 1, ENC_NA);
        ctrl_tree = proto_item_add_subtree(mcc_ti, ett_btrfcomm_ctrl);

        /* mcc type */
        offset = dissect_btrfcomm_MccType(tvb, offset, ctrl_tree, &mcc_cr_flag, &mcc_ea_flag, &mcc_type);

        /* len */
        offset = get_le_multi_byte_value(tvb, offset, ctrl_tree, &length, hf_mcc_len);

        if (length > (guint32) tvb_length_remaining(tvb, offset)) {
            expert_add_info_format(pinfo, ctrl_tree, &ei_btrfcomm_mcc_length_bad, "Huge MCC length: %u", length);
            return offset;
        }

        switch(mcc_type) {
        case 0x20: /* DLC Parameter Negotiation */
            dissect_ctrl_pn(ctrl_tree, tvb, offset, &mcc_channel);
            break;
        case 0x24: /* Remote Port Negotiation */
            mcc_dlci = tvb_get_guint8(tvb, offset) >> 2;
            mcc_channel = mcc_dlci >> 1;

            dlci_item = proto_tree_add_item(ctrl_tree, hf_mcc_dlci, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_item_append_text(dlci_item, " (Direction: %d, Channel: %u)", mcc_dlci & 0x01, mcc_channel);

            dlci_tree = proto_item_add_subtree(dlci_item, ett_mcc_dlci);
            proto_tree_add_item(dlci_tree, hf_mcc_channel, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(dlci_tree, hf_mcc_direction, tvb, offset, 1, ENC_LITTLE_ENDIAN);

            proto_tree_add_item(ctrl_tree, hf_mcc_const_1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ctrl_tree, hf_mcc_ea, tvb, offset, 1, ENC_LITTLE_ENDIAN);

            break;
        case 0x38: /* Modem Status Command */
            dissect_ctrl_msc(ctrl_tree, tvb, offset, length, &mcc_channel);
            break;
        default:
            mcc_channel = -1;
        }

        if (mcc_channel > 0) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "-> %d ", mcc_channel);
        }

        col_append_str(pinfo->cinfo, COL_INFO, "MPX_CTRL ");

        if(mcc_type){
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str_const(mcc_type, vs_ctl, "Unknown"));
        }

        offset += length;

        proto_item_set_len(mcc_ti, offset - start_offset);
    }

    /* try to find a higher layer dissector that has registered to handle data
     * for this kind of service, if none is found dissect it as raw "data"
     */
    if (dlci && frame_len) {
        dissector_handle_t  decode_by_dissector;
        tvbuff_t           *next_tvb;
        btrfcomm_data_t    *rfcomm_data;

        next_tvb = tvb_new_subset_length(tvb, offset, frame_len);

        rfcomm_data = (btrfcomm_data_t *) wmem_new(wmem_packet_scope(), btrfcomm_data_t);
        rfcomm_data->interface_id       = l2cap_data->interface_id;
        rfcomm_data->adapter_id         = l2cap_data->adapter_id;
        rfcomm_data->chandle            = l2cap_data->chandle;
        rfcomm_data->cid                = l2cap_data->cid;
        rfcomm_data->is_local_psm       = l2cap_data->is_local_psm;
        rfcomm_data->dlci               = dlci;
        rfcomm_data->remote_bd_addr_oui = l2cap_data->remote_bd_addr_oui;
        rfcomm_data->remote_bd_addr_id  = l2cap_data->remote_bd_addr_id;

        if (p_get_proto_data(pinfo->pool, pinfo, proto_btrfcomm, BTRFCOMM_SERVICE_CONV ) == NULL) {
            gulong *value_data;

            value_data = wmem_new(wmem_file_scope(), gulong);
            *value_data = service_info->uuid.bt_uuid;

            p_add_proto_data(pinfo->pool, pinfo, proto_btrfcomm, BTRFCOMM_SERVICE_CONV, value_data);
        }

        if (!dissector_try_uint_new(rfcomm_channel_dissector_table, (guint32) dlci >> 1,
                next_tvb, pinfo, tree, TRUE, rfcomm_data)) {
            if (!dissector_try_uint_new(rfcomm_service_dissector_table, service_info->uuid.bt_uuid,
                        next_tvb, pinfo, tree, TRUE, rfcomm_data)) {
                decode_by_dissector = find_proto_by_channel(dlci >> 1);
                if (rfcomm_channels_enabled && decode_by_dissector) {
                    call_dissector_with_data(decode_by_dissector, next_tvb, pinfo, tree, rfcomm_data);
                } else {
                    /* unknown service, let the data dissector handle it */
                    call_dissector(data_handle, next_tvb, pinfo, tree);
                }
            }
        }
    }

    proto_tree_add_item(rfcomm_tree, hf_fcs, tvb, fcs_offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    return offset;
}

void
proto_register_btrfcomm(void)
{
    module_t *module;
    expert_module_t *expert_btrfcomm;

    static hf_register_info hf[] = {
        { &hf_dlci,
          { "DLCI", "btrfcomm.dlci",
            FT_UINT8, BASE_HEX, NULL, 0xFC,
            "RFCOMM Data Link Connection Identifier", HFILL}
        },
        { &hf_channel,
           { "Channel", "btrfcomm.channel",
            FT_UINT8, BASE_DEC, NULL, 0xF8,
            "RFCOMM Channel", HFILL}
        },
        { &hf_direction,
           {"Direction", "btrfcomm.direction",
            FT_UINT8, BASE_HEX, NULL, 0x04,
            NULL, HFILL}
        },
        { &hf_priority,
          { "Priority", "btrfcomm.priority",
            FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL}
        },
        { &hf_max_frame_size,
          { "Max Frame Size", "btrfcomm.max_frame_size",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Maximum Frame Size", HFILL}
        },
        { &hf_max_retrans,
          { "Maximum number of retransmissions", "btrfcomm.max_retrans",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL}
        },
        { &hf_error_recovery_mode,
          { "Error Recovery Mode", "btrfcomm.error_recovery_mode",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL}
        },
        { &hf_ea,
          { "EA Flag", "btrfcomm.ea",
            FT_UINT8, BASE_HEX, VALS(vs_ea), 0x01,
            "EA flag (should be always 1)", HFILL}
        },
        { &hf_cr,
          { "C/R Flag", "btrfcomm.cr",
            FT_UINT8, BASE_HEX, VALS(vs_cr), 0x02,
            "Command/Response flag", HFILL}
        },
        { &hf_mcc,
          { "Multiplexer Control Command", "btrfcomm.mcc",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_mcc_pn_parameters,
          { "Parameters", "btrfcomm.mcc.pn_parameters",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_mcc_types,
          { "Types", "btrfcomm.mcc.types",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_mcc_ea,
          { "EA Flag", "btrfcomm.mcc.ea",
            FT_UINT8, BASE_HEX, VALS(vs_ea), 0x01,
            "RFCOMM MCC EA flag", HFILL}
        },
        { &hf_mcc_cr,
          { "C/R Flag", "btrfcomm.mcc.cr",
            FT_UINT8, BASE_HEX, VALS(vs_cr), 0x02,
            "Command/Response flag", HFILL}
        },
        { &hf_mcc_const_1,
          { "Ones padding", "btrfcomm.mcc.padding",
            FT_UINT8, BASE_HEX, NULL, 0x02,
            NULL, HFILL}
        },
        { &hf_mcc_dlci,
          { "MCC DLCI", "btrfcomm.mcc.dlci",
            FT_UINT8, BASE_HEX, NULL, 0xFC,
            "RFCOMM MCC Data Link Connection Identifier", HFILL}
        },
        { &hf_mcc_channel,
          { "MCC Channel", "btrfcomm.mcc.channel",
            FT_UINT8, BASE_DEC, NULL, 0xF8,
            "RFCOMM MCC Channel", HFILL}
        },
        { &hf_mcc_direction,
          { "MCC Direction", "btrfcomm.mcc.direction",
            FT_UINT8, BASE_HEX, NULL, 0x04,
            "RFCOMM MCC Direction", HFILL}
        },
        { &hf_mcc_pn_dlci,
          { "MCC DLCI", "btrfcomm.mcc.dlci",
            FT_UINT8, BASE_HEX, NULL, 0x3F,
            "RFCOMM MCC Data Link Connection Identifier", HFILL}
        },
        { &hf_mcc_pn_channel,
          { "MCC Channel", "btrfcomm.mcc.channel",
            FT_UINT8, BASE_DEC, NULL, 0x3E,
            "RFCOMM MCC Channel", HFILL}
        },
        { &hf_mcc_pn_direction,
          { "MCC Direction", "btrfcomm.mcc.direction",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            "RFCOMM MCC Direction", HFILL}
        },
        { &hf_mcc_pn_zeros_padding,
          { "Zeros padding", "btrfcomm.mcc.padding",
            FT_UINT8, BASE_HEX, NULL, 0xC0,
            "RFCOMM MSC Zeros padding", HFILL}
        },
        { &hf_mcc_cmd,
          { "MCC Command Type", "btrfcomm.mcc.cmd",
            FT_UINT8, BASE_HEX, VALS(vs_ctl), 0xFC,
            "Command Type", HFILL}
        },
        { &hf_frame_type,
          { "Frame type", "btrfcomm.frame_type",
            FT_UINT8, BASE_HEX, VALS(vs_frame_type), 0xEF,
            "Command/Response flag", HFILL}
        },
        { &hf_acknowledgement_timer_t1,
          { "Acknowledgement Timer T1", "btrfcomm.acknowledgement_timer_t1",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_pf,
          { "P/F flag", "btrfcomm.pf",
            FT_UINT8, BASE_HEX, NULL, 0x10,
            "Poll/Final bit", HFILL}
        },
        { &hf_pn_i14,
          { "Type of frame", "btrfcomm.pn.i",
            FT_UINT8, BASE_HEX, VALS(vs_ctl_pn_i), 0x0F,
            "Type of information frames used for that particular DLCI",
            HFILL}
        },
        { &hf_pn_c14,
          { "Convergence layer", "btrfcomm.pn.cl",
            FT_UINT8, BASE_HEX, VALS(vs_ctl_pn_cl), 0xF0,
            "Convergence layer used for that particular DLCI", HFILL}
        },
        { &hf_len,
          { "Payload length", "btrfcomm.len",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Frame length", HFILL}
        },
        { &hf_mcc_len,
          { "MCC Length", "btrfcomm.mcc.len",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Length of MCC data", HFILL}
        },
        { &hf_fcs,
          { "Frame Check Sequence", "btrfcomm.fcs",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Checksum over frame", HFILL}
        },
        { &hf_msc_parameters,
          { "Parameters", "btrfcomm.mcc.msc_parameters",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_msc_fc,
          { "Flow Control (FC)", "btrfcomm.msc.fc",
            FT_UINT8, BASE_HEX, NULL, 0x02,
            "Flow Control", HFILL}
        },
        { &hf_msc_rtc,
          { "Ready To Communicate (RTC)", "btrfcomm.msc.rtc",
            FT_UINT8, BASE_HEX, NULL, 0x04,
            "Ready To Communicate", HFILL}
        },
        { &hf_msc_rtr,
          { "Ready To Receive (RTR)", "btrfcomm.msc.rtr",
            FT_UINT8, BASE_HEX, NULL, 0x08,
            "Ready To Receive", HFILL}
        },
        { &hf_msc_ic,
          { "Incoming Call Indicator (IC)", "btrfcomm.msc.ic",
            FT_UINT8, BASE_HEX, NULL, 0x40,
            "Incoming Call Indicator", HFILL}
        },
        { &hf_msc_dv,
          { "Data Valid (DV)", "btrfcomm.msc.dv",
            FT_UINT8, BASE_HEX, NULL, 0x80,
            "Data Valid", HFILL}
        },
        { &hf_msc_l,
          { "Length of break in units of 200ms", "btrfcomm.msc.bl",
            FT_UINT8, BASE_DEC, NULL, 0xF0,
            NULL, HFILL}
        },
        { &hf_msc_break_bits,
          { "Break Bits", "btrfcomm.msc.break_bits",
            FT_UINT8, BASE_DEC, NULL, 0xE0,
            NULL, HFILL}
        },
        { &hf_address,
          { "Address", "btrfcomm.address",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_control,
          { "Control", "btrfcomm.control",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_fc_credits,
          { "Credits", "btrfcomm.credits",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Flow control: number of UIH frames allowed to send", HFILL}
        }

    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_btrfcomm,
        &ett_btrfcomm_ctrl,
        &ett_addr,
        &ett_control,
        &ett_mcc,
        &ett_ctrl_pn_ci,
        &ett_ctrl_pn_v24,
        &ett_dlci,
        &ett_mcc_dlci
    };

    static ei_register_info ei[] = {
        { &ei_btrfcomm_mcc_length_bad, { "btrfcomm.mcc_length_bad", PI_MALFORMED, PI_ERROR, "Huge MCC length", EXPFILL }},
    };

    /* Decode As handling */
    static build_valid_func btrfcomm_serv_da_build_value[1] = {btrfcomm_serv_value};
    static decode_as_value_t btrfcomm_serv_da_values = {btrfcomm_serv_prompt, 1, btrfcomm_serv_da_build_value};
    static decode_as_t btrfcomm_serv_da = {"btrfcomm", "RFCOMM SERVICE", "btrfcomm.service", 1, 0, &btrfcomm_serv_da_values, NULL, NULL,
                                 decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    static build_valid_func btrfcomm_chan_da_build_value[1] = {btrfcomm_chan_value};
    static decode_as_value_t btrfcomm_chan_da_values = {btrfcomm_chan_prompt, 1, btrfcomm_chan_da_build_value};
    static decode_as_t btrfcomm_chan_da = {"btrfcomm", "RFCOMM Channel", "btrfcomm.channel", 1, 0, &btrfcomm_chan_da_values, NULL, NULL,
                                 decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    /* Register the protocol name and description */
    proto_btrfcomm = proto_register_protocol("Bluetooth RFCOMM Protocol", "BT RFCOMM", "btrfcomm");
    btrfcomm_handle = new_register_dissector("btrfcomm", dissect_btrfcomm, proto_btrfcomm);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_btrfcomm, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_btrfcomm = expert_register_protocol(proto_btrfcomm);
    expert_register_field_array(expert_btrfcomm, ei, array_length(ei));

    service_directions = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    rfcomm_service_dissector_table = register_dissector_table("btrfcomm.service", "BT RFCOMM Service", FT_UINT16, BASE_HEX);
    rfcomm_channel_dissector_table = register_dissector_table("btrfcomm.channel", "BT RFCOMM Channel", FT_UINT16, BASE_DEC);

    module = prefs_register_protocol(proto_btrfcomm, NULL);
    prefs_register_static_text_preference(module, "rfcomm.version",
            "Bluetooth Protocol RFCOMM version: 1.1", "Version of protocol supported by this dissector.");

    prefs_register_bool_preference(module, "rfcomm.decode_by.enabled",
            "Enable Force Decode by Channel",
            "Turn on/off decode by next rules",
            &rfcomm_channels_enabled);

    uat_rfcomm_channels = uat_new("Force Decode by Channel",
            sizeof(uat_rfcomm_channels_t),
            "rfcomm_channels",
            TRUE,
            &rfcomm_channels,
            &num_rfcomm_channels,
            UAT_AFFECTS_DISSECTION,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            uat_rfcomm_channels_fields);

    prefs_register_uat_preference(module, "rfcomm.channels",
            "Force Decode by channel",
            "Decode by channel",
            uat_rfcomm_channels);

    register_decode_as(&btrfcomm_serv_da);
    register_decode_as(&btrfcomm_chan_da);
}

void
proto_reg_handoff_btrfcomm(void)
{
    dissector_add_uint("btl2cap.psm", BTL2CAP_PSM_RFCOMM, btrfcomm_handle);
    dissector_add_for_decode_as("btl2cap.cid", btrfcomm_handle);

    data_handle = find_dissector("data");
}

/* Bluetooth Dial-Up Networking (DUN) profile dissection */
static gint
dissect_btdun(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *st;
    gboolean    is_at_cmd;
    guint       i, length;

    length = tvb_length(tvb);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DUN");

    ti = proto_tree_add_item(tree, proto_btdun, tvb, 0, -1, ENC_NA);
    st = proto_item_add_subtree(ti, ett_btdun);

    is_at_cmd = TRUE;
    for(i = 0; i < length && is_at_cmd; i++) {
        is_at_cmd = tvb_get_guint8(tvb, i) < 0x7d;
    }

    if (is_at_cmd) {
        /* presumably an AT command */
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s \"%s\"",
                     (pinfo->p2p_dir == P2P_DIR_SENT) ? "Sent" : "Rcvd",
                     tvb_format_text(tvb, 0, length));

           proto_tree_add_item(st, hf_dun_at_cmd, tvb, 0, -1, ENC_ASCII|ENC_NA);
    }
    else {
        /* ... or raw PPP */
        if (ppp_handle)
            call_dissector(ppp_handle, tvb, pinfo, tree);
        else {
            /* TODO: remove the above 'if' and this 'else-body' when "ppp_raw_hdlc" is available, requires that it is
                made non-anonymous in ppp dissector to use */
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP");
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s <PPP frame>", (pinfo->p2p_dir == P2P_DIR_SENT) ? "Sent" : "Rcvd");

            call_dissector(data_handle, tvb, pinfo, tree);
        }
    }

    return length;
}

void
proto_register_btdun(void)
{
    static hf_register_info hf[] = {
        { &hf_dun_at_cmd,
          { "AT Cmd", "btdun.atcmd",
            FT_STRING, BASE_NONE, NULL, 0,
            "AT Command", HFILL}
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_btdun
    };

    proto_btdun = proto_register_protocol("Bluetooth DUN Packet", "BT DUN", "btdun");
    btdun_handle = new_register_dissector("btdun", dissect_btdun, proto_btdun);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_btdun, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_btdun(void)
{
    dissector_add_uint("btrfcomm.service", BTSDP_DUN_SERVICE_UUID, btdun_handle);
    dissector_add_for_decode_as("btrfcomm.channel", btdun_handle);

    ppp_handle = find_dissector("ppp_raw_hdlc");
}

/* Bluetooth Serial Port profile (SPP) dissection */
static gint
dissect_btspp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *st;
    gboolean    ascii_only;
    guint       i, length = tvb_length(tvb);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SPP");

    ti = proto_tree_add_item(tree, proto_btspp, tvb, 0, -1, ENC_NA);
    st = proto_item_add_subtree(ti, ett_btspp);

    length = MIN(length, 60);
    ascii_only = TRUE;
    for(i = 0; i < length && ascii_only; i++) {
        ascii_only = tvb_get_guint8(tvb, i) < 0x80;
    }

    if (ascii_only) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s \"%s%s\"",
                     (pinfo->p2p_dir == P2P_DIR_SENT) ? "Sent" : "Rcvd",
                     tvb_format_text(tvb, 0, length),
                     (tvb_length(tvb) > length) ? "..." : "");
    }

    proto_tree_add_item(st, hf_spp_data, tvb, 0, -1, ENC_NA);

    return tvb_length(tvb);
}

void
proto_register_btspp(void)
{
    static hf_register_info hf[] = {
        { &hf_spp_data,
          { "Data", "btspp.data",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_btspp
    };

    proto_btspp = proto_register_protocol("Bluetooth SPP Packet", "BT SPP", "btspp");
    btspp_handle = new_register_dissector("btspp", dissect_btspp, proto_btspp);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_btspp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_btspp(void)
{
    dissector_add_uint("btrfcomm.service", BTSDP_SPP_SERVICE_UUID, btspp_handle);
    dissector_add_for_decode_as("btrfcomm.channel", btspp_handle);
}


/* Bluetooth Global Navigation Satellite System profile (GNSS) dissection */
static gint
dissect_btgnss(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *main_item;
    proto_tree *main_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GNSS");

    main_item = proto_tree_add_item(tree, proto_btgnss, tvb, 0, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_btgnss);

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
            (pinfo->p2p_dir == P2P_DIR_SENT) ? "Sent" : "Rcvd",
            tvb_format_text(tvb, 0, tvb_length(tvb)));

    /* GNSS using NMEA-0183 protocol, but it is not available */
    proto_tree_add_item(main_tree, hf_gnss_data, tvb, 0, -1, ENC_NA | ENC_ASCII);

    return tvb_length(tvb);
}

void
proto_register_btgnss(void)
{
    static hf_register_info hf[] = {
        { &hf_gnss_data,
        { "Data", "btgnss.data",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_btgnss
    };

    proto_btgnss = proto_register_protocol("Bluetooth GNSS Profile", "BT GNSS", "btgnss");
    btgnss_handle = new_register_dissector("btgnss", dissect_btgnss, proto_btgnss);

    proto_register_field_array(proto_btgnss, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_btgnss(void)
{
    dissector_add_uint("btrfcomm.service", BTSDP_GNSS_UUID, btgnss_handle);
    dissector_add_uint("btrfcomm.service", BTSDP_GNSS_SERVER_UUID, btgnss_handle);
    dissector_add_for_decode_as("btrfcomm.channel", btgnss_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
