/* packet-socketcan.c
 * Routines for disassembly of packets from SocketCAN
 * Felix Obenhuber <felix@obenhuber.de>
 *
 * Added support for the DeviceNet Dissector
 * Hans-Joergen Gunnarsson <hag@hms.se>
 * Copyright 2013
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
#include <epan/expert.h>
#include <epan/decode_as.h>
#include <epan/uat.h>
#include <wiretap/wtap.h>

#include "packet-sll.h"
#include "packet-socketcan.h"

void proto_register_socketcan(void);
void proto_reg_handoff_socketcan(void);

static int hf_can_len = -1;
static int hf_can_infoent_ext = -1;
static int hf_can_infoent_std = -1;
static int hf_can_extflag = -1;
static int hf_can_rtrflag = -1;
static int hf_can_errflag = -1;
static int hf_can_reserved = -1;
static int hf_can_padding = -1;

static int hf_can_err_tx_timeout = -1;
static int hf_can_err_lostarb = -1;
static int hf_can_err_ctrl = -1;
static int hf_can_err_prot = -1;
static int hf_can_err_trx = -1;
static int hf_can_err_ack = -1;
static int hf_can_err_busoff = -1;
static int hf_can_err_buserror = -1;
static int hf_can_err_restarted = -1;
static int hf_can_err_reserved = -1;

static int hf_can_err_lostarb_bit_number = -1;

static int hf_can_err_ctrl_rx_overflow = -1;
static int hf_can_err_ctrl_tx_overflow = -1;
static int hf_can_err_ctrl_rx_warning = -1;
static int hf_can_err_ctrl_tx_warning = -1;
static int hf_can_err_ctrl_rx_passive = -1;
static int hf_can_err_ctrl_tx_passive = -1;
static int hf_can_err_ctrl_active = -1;

static int hf_can_err_prot_error_type_bit = -1;
static int hf_can_err_prot_error_type_form = -1;
static int hf_can_err_prot_error_type_stuff = -1;
static int hf_can_err_prot_error_type_bit0 = -1;
static int hf_can_err_prot_error_type_bit1 = -1;
static int hf_can_err_prot_error_type_overload = -1;
static int hf_can_err_prot_error_type_active = -1;
static int hf_can_err_prot_error_type_tx = -1;

static int hf_can_err_prot_error_location = -1;

static int hf_can_err_trx_canh = -1;
static int hf_can_err_trx_canl = -1;

static int hf_can_err_ctrl_specific = -1;

static int hf_canxl_priority = -1;
static int hf_canxl_vcid = -1;
static int hf_canxl_secflag = -1;
static int hf_canxl_sdu_type = -1;
static int hf_canxl_len = -1;
static int hf_canxl_acceptance_field = -1;

static expert_field ei_can_err_dlc_mismatch = EI_INIT;

static int hf_canfd_brsflag = -1;
static int hf_canfd_esiflag = -1;

static gint ett_can = -1;
static gint ett_can_fd = -1;
static gint ett_can_xl = -1;

static int proto_can = -1;
static int proto_canfd = -1;
static int proto_canxl = -1;

static gboolean byte_swap = FALSE;
static gboolean heuristic_first = FALSE;

static heur_dissector_list_t heur_subdissector_list;
static heur_dtbl_entry_t *heur_dtbl_entry;

#define LINUX_CAN_STD   0
#define LINUX_CAN_EXT   1
#define LINUX_CAN_ERR   2

#define CAN_LEN_OFFSET     4
#define CAN_DATA_OFFSET    8

#define CANFD_FLAG_OFFSET  5

#define CANFD_BRS 0x01 /* bit rate switch (second bitrate for payload data) */
#define CANFD_ESI 0x02 /* error state indicator of the transmitting node */

#define CANXL_LEN_OFFSET   6
#define CANXL_DATA_OFFSET  12

static dissector_table_t can_id_dissector_table = NULL;
static dissector_table_t can_extended_id_dissector_table = NULL;
static dissector_table_t subdissector_table = NULL;
static dissector_table_t canxl_sdu_type_dissector_table = NULL;
static dissector_handle_t socketcan_classic_handle;
static dissector_handle_t socketcan_fd_handle;
static dissector_handle_t socketcan_xl_handle;
static dissector_handle_t socketcan_bigendian_handle;


static const value_string can_err_prot_error_location_vals[] = {
    { 0x00, "unspecified" },
    { 0x02, "ID bits 28 - 21 (SFF: 10 - 3)" },
    { 0x03, "start of frame" },
    { 0x04, "substitute RTR (SFF: RTR)" },
    { 0x05, "identifier extension" },
    { 0x06, "ID bits 20 - 18 (SFF: 2 - 0)" },
    { 0x07, "ID bits 17-13" },
    { 0x08, "CRC sequence" },
    { 0x09, "reserved bit 0" },
    { 0x0A, "data section" },
    { 0x0B, "data length code" },
    { 0x0C, "RTR" },
    { 0x0D, "reserved bit 1" },
    { 0x0E, "ID bits 4-0" },
    { 0x0F, "ID bits 12-5" },
    { 0x12, "intermission" },
    { 0x18, "CRC delimiter" },
    { 0x19, "ACK slot" },
    { 0x1A, "end of frame" },
    { 0x1B, "ACK delimiter" },
    { 0, NULL }
};

static const value_string can_err_trx_canh_vals[] = {
    { 0x00, "unspecified" },
    { 0x04, "no wire" },
    { 0x05, "short to BAT" },
    { 0x06, "short to VCC" },
    { 0x07, "short to GND" },
    { 0, NULL }
};

static const value_string can_err_trx_canl_vals[] = {
    { 0x00, "unspecified" },
    { 0x04, "no wire" },
    { 0x05, "short to BAT" },
    { 0x06, "short to VCC" },
    { 0x07, "short to GND" },
    { 0x08, "short to CANH" },
    { 0, NULL }
};

static const value_string canxl_sdu_type_vals[] = {
    { 0x00, "Reserved" },
    { CANXL_SDU_TYPE_CONTENT_BASED_ADDRESSING, "Content-based Addressing" },
    { 0x02, "Reserved for future use" },
    { CANXL_SDU_TYPE_CLASSICAL_CAN_AND_CAN_FD_MAPPED_TUNNELING, "Classical CAN/CAN FD mapped tunneling" },
    { CANXL_SDU_TYPE_IEEE_802_3_MAC_FRAME_TUNNELLING, "IEEE 802.3 (MAC frame) tunneling" },
    { CANXL_SDU_TYPE_IEEE_802_3_MAC_FRAME_MAPPED_TUNNELING, "IEEE 802.3 (MAC frame) mapped tunneling" },
    { CANXL_SDU_TYPE_CLASSICAL_CAN_MAPPED_TUNNELING, "Classical CAN mapped tunneling" },
    { CANXL_SDU_TYPE_CAN_FD_MAPPED_TUNNELING, "CAN FD mapped tunneling" },
    { 0xFF, "Reserved" },
    { 0, NULL }
};

/********* UATs *********/

/* Interface Config UAT */
typedef struct _interface_config {
    guint   interface_id;
    gchar  *interface_name;
    guint   bus_id;
} interface_config_t;

#define DATAFILE_CAN_INTERFACE_MAPPING "CAN_interface_mapping"

static GHashTable *data_can_interfaces_by_id = NULL;
static GHashTable *data_can_interfaces_by_name = NULL;
static interface_config_t *interface_configs = NULL;
static guint interface_config_num = 0;

UAT_HEX_CB_DEF(interface_configs, interface_id, interface_config_t)
UAT_CSTRING_CB_DEF(interface_configs, interface_name, interface_config_t)
UAT_HEX_CB_DEF(interface_configs, bus_id, interface_config_t)

static void *
copy_interface_config_cb(void *n, const void *o, size_t size _U_) {
    interface_config_t *new_rec = (interface_config_t *)n;
    const interface_config_t *old_rec = (const interface_config_t *)o;

    new_rec->interface_id = old_rec->interface_id;
    new_rec->interface_name = g_strdup(old_rec->interface_name);
    new_rec->bus_id = old_rec->bus_id;
    return new_rec;
}

static bool
update_interface_config(void *r, char **err) {
    interface_config_t *rec = (interface_config_t *)r;

    if (rec->interface_id > 0xffffffff) {
        *err = ws_strdup_printf("We currently only support 32 bit identifiers (ID: %i  Name: %s)",
                                rec->interface_id, rec->interface_name);
        return FALSE;
    }

    if (rec->bus_id > 0xffff) {
        *err = ws_strdup_printf("We currently only support 16 bit bus identifiers (ID: %i  Name: %s  Bus-ID: %i)",
                                rec->interface_id, rec->interface_name, rec->bus_id);
        return FALSE;
    }

    return TRUE;
}

static void
free_interface_config_cb(void *r) {
    interface_config_t *rec = (interface_config_t *)r;

    /* freeing result of g_strdup */
    g_free(rec->interface_name);
    rec->interface_name = NULL;
}

static interface_config_t *
ht_lookup_interface_config_by_id(unsigned int identifier) {
    interface_config_t *tmp = NULL;
    unsigned int       *id = NULL;

    if (interface_configs == NULL) {
        return NULL;
    }

    id = wmem_new(wmem_epan_scope(), unsigned int);
    *id = (unsigned int)identifier;
    tmp = (interface_config_t *)g_hash_table_lookup(data_can_interfaces_by_id, id);
    wmem_free(wmem_epan_scope(), id);

    return tmp;
}

static interface_config_t *
ht_lookup_interface_config_by_name(const gchar *name) {
    interface_config_t *tmp = NULL;
    gchar              *key = NULL;

    if (interface_configs == NULL) {
        return NULL;
    }

    key = wmem_strdup(wmem_epan_scope(), name);
    tmp = (interface_config_t *)g_hash_table_lookup(data_can_interfaces_by_name, key);
    wmem_free(wmem_epan_scope(), key);

    return tmp;
}

static void
can_free_key(gpointer key) {
    wmem_free(wmem_epan_scope(), key);
}

static void
post_update_can_interfaces_cb(void) {
    guint  i;
    int   *key_id = NULL;
    gchar *key_name = NULL;

    /* destroy old hash tables, if they exist */
    if (data_can_interfaces_by_id) {
        g_hash_table_destroy(data_can_interfaces_by_id);
        data_can_interfaces_by_id = NULL;
    }
    if (data_can_interfaces_by_name) {
        g_hash_table_destroy(data_can_interfaces_by_name);
        data_can_interfaces_by_name = NULL;
    }

    /* create new hash table */
    data_can_interfaces_by_id = g_hash_table_new_full(g_int_hash, g_int_equal, &can_free_key, NULL);
    data_can_interfaces_by_name = g_hash_table_new_full(g_str_hash, g_str_equal, &can_free_key, NULL);

    if (data_can_interfaces_by_id == NULL || data_can_interfaces_by_name == NULL || interface_configs == NULL || interface_config_num == 0) {
        return;
    }

    for (i = 0; i < interface_config_num; i++) {
        if (interface_configs[i].interface_id != 0xfffffff) {
            key_id = wmem_new(wmem_epan_scope(), int);
            *key_id = interface_configs[i].interface_id;
            g_hash_table_insert(data_can_interfaces_by_id, key_id, &interface_configs[i]);
        }

        if (interface_configs[i].interface_name != NULL && interface_configs[i].interface_name[0] != 0) {
            key_name = wmem_strdup(wmem_epan_scope(), interface_configs[i].interface_name);
            g_hash_table_insert(data_can_interfaces_by_name, key_name, &interface_configs[i]);
        }
    }
}

/* We match based on the config in the following order:
 * - interface_name matches and interface_id matches
 * - interface_name matches and interface_id = 0xffffffff
 * - interface_name = ""    and interface_id matches
 */
static guint
get_bus_id(packet_info *pinfo) {
    guint32             interface_id = pinfo->rec->rec_header.packet_header.interface_id;
    const char         *interface_name = epan_get_interface_name(pinfo->epan, interface_id);
    interface_config_t *tmp = NULL;

    if (!(pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID)) {
        return 0;
    }

    if (interface_name != NULL && interface_name[0] != 0) {
        tmp = ht_lookup_interface_config_by_name(interface_name);

        if (tmp != NULL && (tmp->interface_id == 0xffffffff || tmp->interface_id == interface_id)) {
            /* name + id match or name match and id = any */
            return tmp->bus_id;
        }

        tmp = ht_lookup_interface_config_by_id(interface_id);

        if (tmp != NULL && (tmp->interface_name == NULL || tmp->interface_name[0] == 0)) {
            /* id matches and name is any */
            return tmp->bus_id;
        }
    }

    /* we found nothing */
    return 0;
}

/* Senders and Receivers UAT */
typedef struct _sender_receiver_config {
    guint   bus_id;
    guint   can_id;
    gchar  *sender_name;
    gchar  *receiver_name;
} sender_receiver_config_t;

#define DATAFILE_CAN_SENDER_RECEIVER "CAN_senders_receivers"

static GHashTable *data_sender_receiver = NULL;
static sender_receiver_config_t *sender_receiver_configs = NULL;
static guint sender_receiver_config_num = 0;

UAT_HEX_CB_DEF(sender_receiver_configs, bus_id, sender_receiver_config_t)
UAT_HEX_CB_DEF(sender_receiver_configs, can_id, sender_receiver_config_t)
UAT_CSTRING_CB_DEF(sender_receiver_configs, sender_name, sender_receiver_config_t)
UAT_CSTRING_CB_DEF(sender_receiver_configs, receiver_name, sender_receiver_config_t)

static void *
copy_sender_receiver_config_cb(void *n, const void *o, size_t size _U_) {
    sender_receiver_config_t *new_rec = (sender_receiver_config_t *)n;
    const sender_receiver_config_t *old_rec = (const sender_receiver_config_t *)o;

    new_rec->bus_id = old_rec->bus_id;
    new_rec->can_id = old_rec->can_id;
    new_rec->sender_name = g_strdup(old_rec->sender_name);
    new_rec->receiver_name = g_strdup(old_rec->receiver_name);
    return new_rec;
}

static bool
update_sender_receiver_config(void *r, char **err) {
    sender_receiver_config_t *rec = (sender_receiver_config_t *)r;

    if (rec->bus_id > 0xffff) {
        *err = ws_strdup_printf("We currently only support 16 bit bus identifiers (Bus ID: %i  CAN ID: %i)", rec->bus_id, rec->can_id);
        return FALSE;
    }

    return TRUE;
}

static void
free_sender_receiver_config_cb(void *r) {
    sender_receiver_config_t *rec = (sender_receiver_config_t *)r;

    /* freeing result of g_strdup */
    g_free(rec->sender_name);
    rec->sender_name = NULL;
    g_free(rec->receiver_name);
    rec->receiver_name = NULL;
}

static guint64
sender_receiver_key(guint16 bus_id, guint32 can_id) {
    return ((guint64)bus_id << 32) | can_id;
}

static sender_receiver_config_t *
ht_lookup_sender_receiver_config(guint16 bus_id, guint32 can_id) {
    sender_receiver_config_t *tmp = NULL;
    guint64                   key = 0;

    if (sender_receiver_configs == NULL) {
        return NULL;
    }

    key = sender_receiver_key(bus_id, can_id);
    tmp = (sender_receiver_config_t *)g_hash_table_lookup(data_sender_receiver, &key);

    if (tmp == NULL) {
        key = sender_receiver_key(0, can_id);
        tmp = (sender_receiver_config_t *)g_hash_table_lookup(data_sender_receiver, &key);
    }

    return tmp;
}

static void
sender_receiver_free_key(gpointer key) {
    wmem_free(wmem_epan_scope(), key);
}

static void
post_update_sender_receiver_cb(void) {
    guint    i;
    guint64 *key_id = NULL;

    /* destroy old hash table, if it exist */
    if (data_sender_receiver) {
        g_hash_table_destroy(data_sender_receiver);
        data_sender_receiver = NULL;
    }

    /* create new hash table */
    data_sender_receiver = g_hash_table_new_full(g_int64_hash, g_int64_equal, &sender_receiver_free_key, NULL);

    if (data_sender_receiver == NULL || sender_receiver_configs == NULL || sender_receiver_config_num == 0) {
        return;
    }

    for (i = 0; i < sender_receiver_config_num; i++) {
        key_id = wmem_new(wmem_epan_scope(), guint64);
        *key_id = sender_receiver_key(sender_receiver_configs[i].bus_id, sender_receiver_configs[i].can_id);
        g_hash_table_insert(data_sender_receiver, key_id, &sender_receiver_configs[i]);
    }
}

gboolean
socketcan_set_source_and_destination_columns(packet_info *pinfo, can_info_t *caninfo) {
    sender_receiver_config_t *tmp = ht_lookup_sender_receiver_config(caninfo->bus_id, caninfo->id);

    if (tmp != NULL) {
        /* remove all addresses to support CAN as payload (e.g., TECMP) */
        clear_address(&pinfo->net_src);
        clear_address(&pinfo->dl_src);
        clear_address(&pinfo->src);
        clear_address(&pinfo->net_dst);
        clear_address(&pinfo->dl_dst);
        clear_address(&pinfo->dst);

        col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "%s", tmp->sender_name);
        col_add_fstr(pinfo->cinfo, COL_DEF_DST, "%s", tmp->receiver_name);
        return true;
    }
    return false;
}

gboolean
socketcan_call_subdissectors(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct can_info *can_info, const gboolean use_heuristics_first) {
    dissector_table_t effective_can_id_dissector_table = (can_info->id & CAN_EFF_FLAG) ? can_extended_id_dissector_table : can_id_dissector_table;
    guint32 effective_can_id = (can_info->id & CAN_EFF_FLAG) ? can_info->id & CAN_EFF_MASK : can_info->id & CAN_SFF_MASK;

    if (!dissector_try_uint_new(effective_can_id_dissector_table, effective_can_id, tvb, pinfo, tree, TRUE, can_info)) {
        if (!use_heuristics_first) {
            if (!dissector_try_payload_new(subdissector_table, tvb, pinfo, tree, TRUE, can_info)) {
                if (!dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, tree, &heur_dtbl_entry, can_info)) {
                    return FALSE;
                }
            }
        } else {
            if (!dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, tree, &heur_dtbl_entry, can_info)) {
                if (!dissector_try_payload_new(subdissector_table, tvb, pinfo, tree, FALSE, can_info)) {
                    return FALSE;
                }
            }
        }
    }

    return TRUE;
}

/*
 * Either:
 *
 *    1) a given SocketCAN frame is known to contain a classic CAN
 *       packet based on information outside the SocketCAN header;
 *
 *    2) a given SocketCAN frame is known to contain a CAN FD
 *       packet based on information outside the SocketCAN header;
 *
 *    3) a given SocketCAN frame is known to contain a CAN XL
 *       packet based on information outside the SocketCAN header;
 *
 *    4) we don't know whether the given SocketCAN frame is a
 *       classic CAN packet, a CAN FD packet, or a CAN XL packet,
 *       and will have to check the CANXL_XLF bit in the "Frame Length"
 *       field and the CANFD_FDF bit in the "FD flags" field of the
 *       SocketCAN header to determine that.
 */
typedef enum {
    PACKET_TYPE_CAN,
    PACKET_TYPE_CAN_FD,
    PACKET_TYPE_CAN_XL,
    PACKET_TYPE_UNKNOWN
} can_packet_type_t;

static int
dissect_socketcan_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint encoding, guint xl_encoding, can_packet_type_t can_packet_type) {
    proto_tree     *can_tree;
    proto_item     *ti;
    guint8          frame_type;
    can_info_t      can_info;
    int * const    *can_flags_id;

    static int * const can_std_flags_id[] = {
        &hf_can_infoent_std,
        &hf_can_extflag,
        &hf_can_rtrflag,
        &hf_can_errflag,
        NULL,
    };
    static int * const can_ext_flags_id[] = {
        &hf_can_infoent_ext,
        &hf_can_extflag,
        &hf_can_rtrflag,
        &hf_can_errflag,
        NULL,
    };
    static int * const canfd_std_flags_id[] = {
        &hf_can_infoent_std,
        &hf_can_extflag,
        NULL,
    };
    static int * const canfd_ext_flags_id[] = {
        &hf_can_infoent_ext,
        &hf_can_extflag,
        NULL,
    };
    static int * const canfd_flag_fields[] = {
        &hf_canfd_brsflag,
        &hf_canfd_esiflag,
        NULL,
    };
    static int * const can_err_flags[] = {
        &hf_can_errflag,
        &hf_can_err_tx_timeout,
        &hf_can_err_lostarb,
        &hf_can_err_ctrl,
        &hf_can_err_prot,
        &hf_can_err_trx,
        &hf_can_err_ack,
        &hf_can_err_busoff,
        &hf_can_err_buserror,
        &hf_can_err_restarted,
        &hf_can_err_reserved,
        NULL,
    };
    static int * const canxl_prio_vcid_fields[] = {
        &hf_canxl_priority,
        &hf_canxl_vcid,
        NULL,
    };
    static int * const canxl_flag_fields[] = {
        &hf_canxl_secflag,
        NULL,
    };

    /*
     * If we weren't told the type of this frame, check
     * whether the CANFD_FDF flag is set in the FD flags
     * field of the header; if so, it's a CAN FD frame.
     * otherwise, it's a CAN frame.
     *
     * However, trust the CANFD_FDF flag only if the only
     * bits set in the FD flags field are the known bits,
     * and the two bytes following that field are both
     * zero.  This is because some older LINKTYPE_CAN_SOCKETCAN
     * frames had uninitialized junk in the FD flags field,
     * so we treat a frame with what appears to be uninitialized
     * junk as being CAN rather than CAN FD, under the assumption
     * that the CANFD_FDF bit is set because the field is
     * uninitialized, not because it was explicitly set because
     * it's a CAN FD frame.  At least some newer code that sets
     * that flag also makes sure that the fields in question are
     * initialized, so we assume that if they're not initialized
     * the code is older code that didn't support CAN FD.
     */
    if (can_packet_type == PACKET_TYPE_UNKNOWN) {
        guint8 frame_length;
        guint8 fd_flags;

        /*
         * Check whether the frame has the CANXL_XLF flag set in what
         * is in the location of the frame length field of a CAN classic
         * or CAN FD frame; if so, then it's a CAN XL frame (and that
         * field is the flags field of that frame).
         */
        frame_length = tvb_get_guint8(tvb, CAN_LEN_OFFSET);
        if (frame_length & CANXL_XLF) {
            can_packet_type = PACKET_TYPE_CAN_XL;
        } else {
            /*
             * This is a CAN classic or CAN FD frame.
             * Check whether the flags field has the CANFD_FDF
             * flag set, has no unknown flag bits set, and has
             * no bits set in the two reserved fields.  If so,
             * it's a CAN FD frame; otherwise, it's either a
             * CAN classic frame, or a frame where the CANFD_FDF
             * flag is set but where that might just be because
             * that field contains uninitialized junk rather
             * than because it's a CAN FD frame, so we treat it
             * as a CAN classic frame.
             */
            fd_flags = tvb_get_guint8(tvb, CANFD_FLAG_OFFSET);

            if ((fd_flags & CANFD_FDF) &&
                    ((fd_flags & ~(CANFD_BRS | CANFD_ESI | CANFD_FDF)) == 0) &&
                    tvb_get_guint8(tvb, CANFD_FLAG_OFFSET + 1) == 0 &&
                    tvb_get_guint8(tvb, CANFD_FLAG_OFFSET + 2) == 0) {
                can_packet_type = PACKET_TYPE_CAN_FD;
            } else {
                if (tvb_reported_length(tvb) == 72)
                    can_packet_type = PACKET_TYPE_CAN_FD;
                else
                    can_packet_type = PACKET_TYPE_CAN;
            }
        }
    }

    can_info.bus_id = get_bus_id(pinfo);

    if (can_packet_type == PACKET_TYPE_CAN_XL) {
        can_info.fd = CAN_TYPE_CAN_XL;
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "CANXL");
        col_clear(pinfo->cinfo, COL_INFO);

        can_info.id = 0; /* XXX - is there an "ID" for XL frames? */

        ti = proto_tree_add_item(tree, proto_can, tvb, 0, -1, ENC_NA);
        proto_item_set_hidden(ti);
        ti = proto_tree_add_item(tree, proto_canxl, tvb, 0, -1, ENC_NA);
        can_tree = proto_item_add_subtree(ti, ett_can_xl);

        guint32 proto_vcid;

	/*
	 * The priority/VCID field is big-endian in LINKTYPE_CAN_SOCKETCAN
	 * captures, for historical reasons.  It's host-endian in
	 * Linux cooked captures.  This means we use the non-XL encoding.
	 */
        proto_tree_add_bitmask_list(can_tree, tvb, 0, 4, canxl_prio_vcid_fields, encoding);
        proto_vcid = tvb_get_guint32(tvb, 0, encoding);
        col_add_fstr(pinfo->cinfo, COL_INFO, "Priority: %u (0x%03x), VCID: %u (0x%02X)", proto_vcid & 0x7FF, proto_vcid & 0x7FF, (proto_vcid >> 16) & 0xFF, (proto_vcid >> 16) & 0xFF);
        proto_item_append_text(can_tree, ", Priority: %u (0x%03x), VCID: %u (0x%02X)", proto_vcid & 0x7FF, proto_vcid & 0x7FF, (proto_vcid >> 16) & 0xFF, (proto_vcid >> 16) & 0xFF);
        proto_tree_add_bitmask_list(can_tree, tvb, 4, 1, canxl_flag_fields, xl_encoding);

        socketcan_set_source_and_destination_columns(pinfo, &can_info);

        guint32 sdu_type;

	/*
	 * These fields are, if multi-byte, little-endian in
	 * LINKTYPE_CAN_SOCKETCAN captures, so use xl_encoding.
	 */
        proto_tree_add_item_ret_uint(can_tree, hf_canxl_sdu_type, tvb, 5, 1, ENC_NA, &sdu_type);
        proto_tree_add_item_ret_uint(can_tree, hf_canxl_len, tvb, CANXL_LEN_OFFSET, 2, xl_encoding, &can_info.len);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Length: %u", can_info.len);
        proto_item_append_text(can_tree, ", Length: %u", can_info.len);
        proto_tree_add_item(can_tree, hf_canxl_acceptance_field, tvb, CANXL_LEN_OFFSET+2, 4, xl_encoding);

        tvbuff_t   *next_tvb;

        next_tvb = tvb_new_subset_length(tvb, CANXL_DATA_OFFSET, can_info.len);

        if (!dissector_try_uint_new(canxl_sdu_type_dissector_table, sdu_type, next_tvb, pinfo, tree, TRUE, &can_info)) {
            call_data_dissector(next_tvb, pinfo, tree);
        }

        if (tvb_captured_length_remaining(tvb, CANXL_DATA_OFFSET+can_info.len) > 0) {
            proto_tree_add_item(can_tree, hf_can_padding, tvb, CANXL_DATA_OFFSET+can_info.len, -1, ENC_NA);
        }
    } else {
        if (can_packet_type == PACKET_TYPE_CAN_FD) {
            can_info.fd = CAN_TYPE_CAN_FD;
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "CANFD");
        } else {
            can_info.fd = CAN_TYPE_CAN_CLASSIC;
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "CAN");
        }
        col_clear(pinfo->cinfo, COL_INFO);

        ti = proto_tree_add_item(tree, proto_can, tvb, 0, -1, ENC_NA);
        if (can_packet_type == PACKET_TYPE_CAN_FD) {
            proto_item_set_hidden(ti);
            ti = proto_tree_add_item(tree, proto_canfd, tvb, 0, -1, ENC_NA);
        }
        can_tree = proto_item_add_subtree(ti, (can_packet_type == PACKET_TYPE_CAN_FD) ? ett_can_fd : ett_can);

        /* Get the ID and flags field */
        can_info.id = tvb_get_guint32(tvb, 0, encoding);

        /* Error Message Frames are only encapsulated in Classic CAN frames */
        if (can_packet_type == PACKET_TYPE_CAN && (can_info.id & CAN_ERR_FLAG)) {
            frame_type = LINUX_CAN_ERR;
            can_flags_id  = can_err_flags;
        } else if (can_info.id & CAN_EFF_FLAG) {
            frame_type = LINUX_CAN_EXT;
            can_info.id &= (CAN_EFF_MASK | CAN_FLAG_MASK);
            can_flags_id  = (can_packet_type == PACKET_TYPE_CAN_FD) ? canfd_ext_flags_id : can_ext_flags_id;
        } else {
            frame_type = LINUX_CAN_STD;
            can_info.id &= (CAN_SFF_MASK | CAN_FLAG_MASK);
            can_flags_id  = (can_packet_type == PACKET_TYPE_CAN_FD) ? canfd_std_flags_id : can_std_flags_id;
        }

        socketcan_set_source_and_destination_columns(pinfo, &can_info);

        proto_tree_add_bitmask_list(can_tree, tvb, 0, 4, can_flags_id, encoding);
        if (can_info.id & CAN_EFF_FLAG) {
            col_add_fstr(pinfo->cinfo, COL_INFO, "Ext. ID: %u (0x%08x)", can_info.id & CAN_EFF_MASK, can_info.id & CAN_EFF_MASK);
            proto_item_append_text(can_tree, ", Ext. ID: %u (0x%08x)", can_info.id & CAN_EFF_MASK, can_info.id & CAN_EFF_MASK);
        } else {
            col_add_fstr(pinfo->cinfo, COL_INFO, "ID: %u (0x%03x)", can_info.id & CAN_SFF_MASK, can_info.id & CAN_SFF_MASK);
            proto_item_append_text(can_tree, ", ID: %u (0x%03x)", can_info.id & CAN_SFF_MASK, can_info.id & CAN_SFF_MASK);
        }
        proto_tree_add_item_ret_uint(can_tree, hf_can_len, tvb, CAN_LEN_OFFSET, 1, ENC_NA, &can_info.len);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Length: %u", can_info.len);
        proto_item_append_text(can_tree, ", Length: %u", can_info.len);

        if (frame_type == LINUX_CAN_ERR && can_info.len != CAN_ERR_DLC) {
            proto_tree_add_expert(tree, pinfo, &ei_can_err_dlc_mismatch, tvb, CAN_LEN_OFFSET, 1);
        }

        if (can_packet_type == PACKET_TYPE_CAN_FD) {
            proto_tree_add_bitmask_list(can_tree, tvb, CANFD_FLAG_OFFSET, 1, canfd_flag_fields, ENC_NA);
            proto_tree_add_item(can_tree, hf_can_reserved, tvb, CANFD_FLAG_OFFSET+1, 2, ENC_NA);
        } else {
            proto_tree_add_item(can_tree, hf_can_reserved, tvb, CANFD_FLAG_OFFSET, 3, ENC_NA);
        }

        if (frame_type == LINUX_CAN_ERR) {
            int * const *flag;
            const char *sepa = ": ";

            col_set_str(pinfo->cinfo, COL_INFO, "ERR");

            for (flag = can_err_flags; *flag; flag++) {
                header_field_info *hfi;

                hfi = proto_registrar_get_nth(**flag);
                if (!hfi)
                    continue;

                if ((can_info.id & hfi->bitmask & ~CAN_FLAG_MASK) == 0)
                    continue;

                col_append_sep_str(pinfo->cinfo, COL_INFO, sepa, hfi->name);
                sepa = ", ";
            }

            if (can_info.id & CAN_ERR_LOSTARB) {
                proto_tree_add_item(can_tree, hf_can_err_lostarb_bit_number, tvb, CAN_DATA_OFFSET + 0, 1, ENC_NA);
            }

            if (can_info.id & CAN_ERR_CTRL) {
                static int * const can_err_ctrl_flags[] = {
                    &hf_can_err_ctrl_rx_overflow,
                    &hf_can_err_ctrl_tx_overflow,
                    &hf_can_err_ctrl_rx_warning,
                    &hf_can_err_ctrl_tx_warning,
                    &hf_can_err_ctrl_rx_passive,
                    &hf_can_err_ctrl_tx_passive,
                    &hf_can_err_ctrl_active,
                    NULL,
                };

                proto_tree_add_bitmask_list(can_tree, tvb, CAN_DATA_OFFSET+1, 1, can_err_ctrl_flags, ENC_NA);
           }

           if (can_info.id & CAN_ERR_PROT) {
                static int * const can_err_prot_error_type_flags[] = {
                    &hf_can_err_prot_error_type_bit,
                    &hf_can_err_prot_error_type_form,
                    &hf_can_err_prot_error_type_stuff,
                    &hf_can_err_prot_error_type_bit0,
                    &hf_can_err_prot_error_type_bit1,
                    &hf_can_err_prot_error_type_overload,
                    &hf_can_err_prot_error_type_active,
                    &hf_can_err_prot_error_type_tx,
                    NULL
                };
                proto_tree_add_bitmask_list(can_tree, tvb, CAN_DATA_OFFSET+2, 1, can_err_prot_error_type_flags, ENC_NA);
                proto_tree_add_item(can_tree, hf_can_err_prot_error_location, tvb, CAN_DATA_OFFSET+3, 1, ENC_NA);
            }

            if (can_info.id & CAN_ERR_TRX) {
                proto_tree_add_item(can_tree, hf_can_err_trx_canh, tvb, CAN_DATA_OFFSET+4, 1, ENC_NA);
                proto_tree_add_item(can_tree, hf_can_err_trx_canl, tvb, CAN_DATA_OFFSET+4, 1, ENC_NA);
            }

            proto_tree_add_item(can_tree, hf_can_err_ctrl_specific, tvb, CAN_DATA_OFFSET+5, 3, ENC_NA);
        } else {
            tvbuff_t   *next_tvb;

            if (can_info.id & CAN_RTR_FLAG) {
                col_append_str(pinfo->cinfo, COL_INFO, "(Remote Transmission Request)");
            }

            next_tvb = tvb_new_subset_length(tvb, CAN_DATA_OFFSET, can_info.len);

            if (!socketcan_call_subdissectors(next_tvb, pinfo, tree, &can_info, heuristic_first)) {
                call_data_dissector(next_tvb, pinfo, tree);
           }
        }

        if (tvb_captured_length_remaining(tvb, CAN_DATA_OFFSET+can_info.len) > 0) {
            proto_tree_add_item(can_tree, hf_can_padding, tvb, CAN_DATA_OFFSET+can_info.len, -1, ENC_NA);
        }
    }

    return tvb_captured_length(tvb);
}

static int
dissect_socketcan_bigendian(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    return dissect_socketcan_common(tvb, pinfo, tree,
                                    byte_swap ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN,
                                    ENC_LITTLE_ENDIAN,
                                    PACKET_TYPE_UNKNOWN);
}

static int
dissect_socketcan_classic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    return dissect_socketcan_common(tvb, pinfo, tree,
                                    byte_swap ? ENC_ANTI_HOST_ENDIAN : ENC_HOST_ENDIAN,
                                    ENC_HOST_ENDIAN, /* Not used, as this is CAN classic, not CAN XL */
                                    PACKET_TYPE_CAN);
}

static int
dissect_socketcan_fd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    return dissect_socketcan_common(tvb, pinfo, tree,
                                    byte_swap ? ENC_ANTI_HOST_ENDIAN : ENC_HOST_ENDIAN,
                                    ENC_HOST_ENDIAN, /* Not used, as this is CAN FD, not CAN XL */
                                    PACKET_TYPE_CAN_FD);
}

static int
dissect_socketcan_xl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    return dissect_socketcan_common(tvb, pinfo, tree,
                                    byte_swap ? ENC_ANTI_HOST_ENDIAN : ENC_HOST_ENDIAN,
                                    ENC_HOST_ENDIAN,
                                    PACKET_TYPE_CAN_XL);
}

void
proto_register_socketcan(void) {
    static hf_register_info hf[] = {
        { &hf_can_infoent_ext, {
            "ID", "can.id", FT_UINT32, BASE_DEC_HEX, NULL, CAN_EFF_MASK, NULL, HFILL } },
        { &hf_can_infoent_std, {
            "ID", "can.id", FT_UINT32, BASE_DEC_HEX, NULL, CAN_SFF_MASK, NULL, HFILL } },
        { &hf_can_extflag, {
            "Extended Flag", "can.flags.xtd", FT_BOOLEAN, 32, NULL, CAN_EFF_FLAG, NULL, HFILL } },
        { &hf_can_rtrflag, {
            "Remote Transmission Request Flag", "can.flags.rtr", FT_BOOLEAN, 32, NULL, CAN_RTR_FLAG, NULL, HFILL } },
        { &hf_can_errflag, {
            "Error Message Flag", "can.flags.err", FT_BOOLEAN, 32, NULL, CAN_ERR_FLAG, NULL, HFILL } },
        { &hf_can_len, {
            "Frame-Length", "can.len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_can_reserved, {
            "Reserved", "can.reserved", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_can_padding, {
            "Padding", "can.padding", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_canfd_brsflag, {
            "Bit Rate Setting", "canfd.flags.brs", FT_BOOLEAN, 8, NULL, CANFD_BRS, NULL, HFILL } },
        { &hf_canfd_esiflag, {
            "Error State Indicator", "canfd.flags.esi", FT_BOOLEAN, 8, NULL, CANFD_ESI, NULL, HFILL } },
        { &hf_can_err_tx_timeout, {
            "Transmit timeout", "can.err.tx_timeout", FT_BOOLEAN, 32, NULL, CAN_ERR_TX_TIMEOUT, NULL, HFILL } },
        { &hf_can_err_lostarb, {
            "Lost arbitration", "can.err.lostarb", FT_BOOLEAN, 32, NULL, CAN_ERR_LOSTARB, NULL, HFILL } },
        { &hf_can_err_ctrl, {
            "Controller problems", "can.err.ctrl", FT_BOOLEAN, 32, NULL, CAN_ERR_CTRL, NULL, HFILL } },
        { &hf_can_err_prot, {
            "Protocol violation", "can.err.prot", FT_BOOLEAN, 32, NULL, CAN_ERR_PROT, NULL, HFILL } },
        { &hf_can_err_trx, {
            "Transceiver status", "can.err.trx", FT_BOOLEAN, 32, NULL, CAN_ERR_TRX, NULL, HFILL } },
        { &hf_can_err_ack, {
            "No acknowledgment", "can.err.ack", FT_BOOLEAN, 32, NULL, CAN_ERR_ACK, NULL, HFILL } },
        { &hf_can_err_busoff, {
            "Bus off", "can.err.busoff", FT_BOOLEAN, 32, NULL, CAN_ERR_BUSOFF, NULL, HFILL } },
        { &hf_can_err_buserror, {
            "Bus error", "can.err.buserror", FT_BOOLEAN, 32, NULL, CAN_ERR_BUSERROR, NULL, HFILL } },
        { &hf_can_err_restarted, {
            "Controller restarted", "can.err.restarted", FT_BOOLEAN, 32, NULL, CAN_ERR_RESTARTED, NULL, HFILL } },
        { &hf_can_err_reserved, {
            "Reserved", "can.err.reserved", FT_UINT32, BASE_HEX, NULL, CAN_ERR_RESERVED, NULL, HFILL } },
        { &hf_can_err_lostarb_bit_number, {
            "Lost arbitration in bit number", "can.err.lostarb.bitnum", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_can_err_ctrl_rx_overflow, {
            "RX buffer overflow", "can.err.ctrl.rx_overflow", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_can_err_ctrl_tx_overflow, {
            "TX buffer overflow", "can.err.ctrl.tx_overflow", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
        { &hf_can_err_ctrl_rx_warning, {
            "Reached warning level for RX errors", "can.err.ctrl.rx_warning", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL } },
        { &hf_can_err_ctrl_tx_warning, {
            "Reached warning level for TX errors", "can.err.ctrl.tx_warning", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL } },
        { &hf_can_err_ctrl_rx_passive, {
            "Reached error passive status RX", "can.err.ctrl.rx_passive", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL } },
        { &hf_can_err_ctrl_tx_passive, {
            "Reached error passive status TX", "can.err.ctrl.tx_passive", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL } },
        { &hf_can_err_ctrl_active, {
            "Recovered to error active state", "can.err.ctrl.active", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL } },
        { &hf_can_err_prot_error_type_bit, {
            "Single bit error", "can.err.prot.type.bit", FT_BOOLEAN, 8, NULL, CAN_ERR_PROT_BIT, NULL, HFILL } },
        { &hf_can_err_prot_error_type_form, {
            "Frame format error", "can.err.prot.type.form", FT_BOOLEAN, 8, NULL, CAN_ERR_PROT_FORM, NULL, HFILL } },
        { &hf_can_err_prot_error_type_stuff, {
            "Bit stuffing error", "can.err.prot.type.stuff", FT_BOOLEAN, 8, NULL, CAN_ERR_PROT_STUFF, NULL, HFILL } },
        { &hf_can_err_prot_error_type_bit0, {
            "Unable to send dominant bit", "can.err.prot.type.bit0", FT_BOOLEAN, 8, NULL, CAN_ERR_PROT_BIT0, NULL, HFILL } },
        { &hf_can_err_prot_error_type_bit1, {
            "Unable to send recessive bit", "can.err.prot.type.bit1", FT_BOOLEAN, 8, NULL, CAN_ERR_PROT_BIT1, NULL, HFILL } },
        { &hf_can_err_prot_error_type_overload, {
            "Bus overload", "can.err.prot.type.overload", FT_BOOLEAN, 8, NULL, CAN_ERR_PROT_OVERLOAD, NULL, HFILL } },
        { &hf_can_err_prot_error_type_active, {
            "Active error announcement", "can.err.prot.type.active", FT_BOOLEAN, 8, NULL, CAN_ERR_PROT_ACTIVE, NULL, HFILL } },
        { &hf_can_err_prot_error_type_tx, {
            "Error occurred on transmission", "can.err.prot.type.tx", FT_BOOLEAN, 8, NULL, CAN_ERR_PROT_TX, NULL, HFILL } },
        { &hf_can_err_prot_error_location, {
            "Protocol error location", "can.err.prot.location", FT_UINT8, BASE_DEC, VALS(can_err_prot_error_location_vals), 0, NULL, HFILL } },
        { &hf_can_err_trx_canh, {
            "Transceiver CANH status", "can.err.trx.canh", FT_UINT8, BASE_DEC, VALS(can_err_trx_canh_vals), 0x0F, NULL, HFILL } },
        { &hf_can_err_trx_canl, {
            "Transceiver CANL status", "can.err.trx.canl", FT_UINT8, BASE_DEC, VALS(can_err_trx_canl_vals), 0xF0, NULL, HFILL } },
        { &hf_can_err_ctrl_specific, {
            "Controller specific data", "can.err.ctrl_specific", FT_BYTES, SEP_SPACE, NULL, 0, NULL, HFILL } },
        { &hf_canxl_priority, {
            "Priority", "canxl.priority", FT_UINT32, BASE_DEC, NULL, 0x0000FFFF, NULL, HFILL } },
        { &hf_canxl_vcid, {
            "VCID", "canxl.vcid", FT_UINT32, BASE_DEC, NULL, 0x00FF0000, NULL, HFILL } },
        { &hf_canxl_secflag, {
            "Simple Extended Context", "canxl.flags.sec", FT_BOOLEAN, 8, NULL, CANXL_SEC, NULL, HFILL } },
        { &hf_canxl_sdu_type, {
            "SDU type", "canxl.sdu_type", FT_UINT8, BASE_HEX, VALS(canxl_sdu_type_vals), 0, NULL, HFILL } },
        { &hf_canxl_len, {
            "Frame-Length", "canxl.len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_canxl_acceptance_field, {
            "Acceptance field", "canxl.acceptance_field", FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL } },
    };

    uat_t *can_interface_uat = NULL;
    uat_t *sender_receiver_uat = NULL;

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_can,
        &ett_can_fd,
        &ett_can_xl
    };

    static ei_register_info ei[] = {
        { &ei_can_err_dlc_mismatch, {
            "can.err.dlc_mismatch", PI_MALFORMED, PI_ERROR, "ERROR: DLC mismatch", EXPFILL } }
    };

    module_t *can_module;

    proto_can = proto_register_protocol("Controller Area Network", "CAN", "can");

    /*
     * "can-hostendian" is a legacy name (there never was, in any libpcap
     * release, a SocketCAN LINKTYPE_ value for a host-endian CAN ID
     * and flags field); we need to keep it around in case some candump
     * or Busmaster capture that was saved as a pcap or pcapng file,
     * as those use a linktype of LINKTYPE_WIRESHARK_UPPER_PDU with
     * "can-hostendian" as the dissector name.
     *
     * "can-bigendian" is also a legacy name (fpr CAN XL frames, the
     * fields in the header are in *little-endian* order); we keep it
     * around for the same reason.  It's used for the dissector for
     * LINKTYPE_CAN_SOCKETCAN.
     */
    socketcan_classic_handle = register_dissector("can-hostendian", dissect_socketcan_classic, proto_can);
    socketcan_bigendian_handle = register_dissector("can-bigendian", dissect_socketcan_bigendian, proto_can);

    proto_canfd = proto_register_protocol("Controller Area Network FD", "CANFD", "canfd");
    socketcan_fd_handle = register_dissector("canfd", dissect_socketcan_fd, proto_canfd);

    proto_canxl = proto_register_protocol("Controller Area Network XL", "CANXL", "canxl");
    socketcan_xl_handle = register_dissector("canxl", dissect_socketcan_xl, proto_canxl);

    proto_register_field_array(proto_can, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_register_field_array(expert_register_protocol(proto_can), ei, array_length(ei));

    can_module = prefs_register_protocol(proto_can, NULL);

    prefs_register_obsolete_preference(can_module, "protocol");

    prefs_register_bool_preference(can_module, "byte_swap", "Byte-swap the CAN ID/flags field",
        "Whether the CAN ID/flags field should be byte-swapped in CAN classic and CAN FD packets",
        &byte_swap);

    prefs_register_bool_preference(can_module, "try_heuristic_first", "Try heuristic sub-dissectors first",
        "Try to decode a packet using an heuristic sub-dissector before using a sub-dissector registered to \"decode as\"",
        &heuristic_first);

    can_id_dissector_table = register_dissector_table("can.id", "CAN ID", proto_can, FT_UINT32, BASE_DEC);

    can_extended_id_dissector_table = register_dissector_table("can.extended_id", "CAN Extended ID", proto_can, FT_UINT32, BASE_DEC);

    subdissector_table = register_decode_as_next_proto(proto_can, "can.subdissector", "CAN next level dissector", NULL);

    canxl_sdu_type_dissector_table = register_dissector_table("canxl.sdu_type", "CAN XL SDU type",  proto_canxl, FT_UINT8, BASE_HEX);

    heur_subdissector_list = register_heur_dissector_list("can", proto_can);

    static uat_field_t can_interface_mapping_uat_fields[] = {
        UAT_FLD_HEX(interface_configs,      interface_id,   "Interface ID",   "ID of the Interface with 0xffffffff = any (hex uint32 without leading 0x)"),
        UAT_FLD_CSTRING(interface_configs,  interface_name, "Interface Name", "Name of the Interface, empty = any (string)"),
        UAT_FLD_HEX(interface_configs,      bus_id,         "Bus ID",         "Bus ID of the Interface (hex uint16 without leading 0x)"),
        UAT_END_FIELDS
    };

    can_interface_uat = uat_new("CAN Interface Mapping",
        sizeof(interface_config_t),         /* record size           */
        DATAFILE_CAN_INTERFACE_MAPPING,     /* filename              */
        TRUE,                               /* from profile          */
        (void**)&interface_configs,         /* data_ptr              */
        &interface_config_num,              /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,             /* but not fields        */
        NULL,                               /* help                  */
        copy_interface_config_cb,           /* copy callback         */
        update_interface_config,            /* update callback       */
        free_interface_config_cb,           /* free callback         */
        post_update_can_interfaces_cb,      /* post update callback  */
        NULL,                               /* reset callback        */
        can_interface_mapping_uat_fields    /* UAT field definitions */
    );

    prefs_register_uat_preference(can_module, "_can_interface_mapping", "Interface Mapping",
        "A table to define the mapping between interface and Bus ID.", can_interface_uat);

    static uat_field_t sender_receiver_mapping_uat_fields[] = {
        UAT_FLD_HEX(sender_receiver_configs,     bus_id,        "Bus ID",        "Bus ID of the Interface with 0 meaning any (hex uint16 without leading 0x)."),
        UAT_FLD_HEX(sender_receiver_configs,     can_id,        "CAN ID",        "ID of the CAN Message (hex uint32 without leading 0x)"),
        UAT_FLD_CSTRING(sender_receiver_configs, sender_name,   "Sender Name",   "Name of Sender(s)"),
        UAT_FLD_CSTRING(sender_receiver_configs, receiver_name, "Receiver Name", "Name of Receiver(s)"),
        UAT_END_FIELDS
    };

    sender_receiver_uat = uat_new("Sender Receiver Config",
        sizeof(sender_receiver_config_t),   /* record size           */
        DATAFILE_CAN_SENDER_RECEIVER,       /* filename              */
        TRUE,                               /* from profile          */
        (void**)&sender_receiver_configs,   /* data_ptr              */
        &sender_receiver_config_num,        /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,             /* but not fields        */
        NULL,                               /* help                  */
        copy_sender_receiver_config_cb,     /* copy callback         */
        update_sender_receiver_config,      /* update callback       */
        free_sender_receiver_config_cb,     /* free callback         */
        post_update_sender_receiver_cb,     /* post update callback  */
        NULL,                               /* reset callback        */
        sender_receiver_mapping_uat_fields  /* UAT field definitions */
    );

    prefs_register_uat_preference(can_module, "_sender_receiver_config", "Sender Receiver Config",
        "A table to define the mapping between Bus ID and CAN ID to Sender and Receiver.", sender_receiver_uat);
}

void
proto_reg_handoff_socketcan(void) {
    dissector_add_uint("wtap_encap", WTAP_ENCAP_SOCKETCAN, socketcan_bigendian_handle);

    dissector_add_uint("sll.ltype", LINUX_SLL_P_CAN, socketcan_classic_handle);
    dissector_add_uint("sll.ltype", LINUX_SLL_P_CANFD, socketcan_fd_handle);
    dissector_add_uint("sll.ltype", LINUX_SLL_P_CANXL, socketcan_xl_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
