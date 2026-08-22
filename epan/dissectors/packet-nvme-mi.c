/* packet-nvme-mi.c
 * Routines for NVMe Management Interface (NVMe-MI), over MCTP
 * Copyright 2022, Jeremy Kerr <jk@codeconstruct.com.au>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* NVMe-MI is defined by the NVM Express Management Interface specification:
 * https://nvmexpress.org/specification/nvme-mi-specification/
 *
 * This file handles the common NVMe-MI framing (4-byte header, MIC) and
 * request/response transaction tracking.  Per-type body decoding is split
 * into separate files that each register a dissector handle into the
 * "nvme-mi.type" table keyed by the NMIMT field:
 *
 *   packet-nvme-mi-control.c  NMIMT=0  Control Primitive (§4.2.1)
 *   packet-nvme-mi-mi.c       NMIMT=1  MI Command        (§5)
 *   packet-nvme-mi-admin.c    NMIMT=2  Admin Command     (§6)
 */

#include <config.h>

#include <epan/conversation.h>
#include <epan/crc32-tvb.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/tfs.h>
#include <wsutil/array.h>
#include <wsutil/crc32.h>
#include "packet-mctp.h"
#include "packet-nvme-mi.h"

void proto_register_nvme_mi(void);
void proto_reg_handoff_nvme_mi(void);

static int proto_nvme_mi;

static dissector_handle_t nvme_mi_handle;

/* Preference: compute the CRC-32C over each message and verify the MIC.
 * When disabled, the MIC field is still shown (and payload_len still
 * excludes the 4 MIC bytes -- the IC bit says the MIC is on the wire
 * regardless), but the checksum computation and comparison are skipped. */
static bool nvme_mi_check_mic = true;

/* Common NVMe-MI header fields */
static int hf_nvme_mi_mctp_mt;
static int hf_nvme_mi_mctp_ic;
static int hf_nvme_mi_csi;
static int hf_nvme_mi_type;
static int hf_nvme_mi_ror;
static int hf_nvme_mi_ciap;
static int hf_nvme_mi_meb;
static int hf_nvme_mi_mic;
static int hf_nvme_mi_mic_status;

/* Invalid Parameter Error Response — Parameter Error Location (PEL) */
static int hf_nvme_mi_pel_bit;
static int hf_nvme_mi_pel_byte;

/* Error Response — the status-dependent bytes 3:1 when they carry nothing */
static int hf_nvme_mi_resp_rsvd;

/* More Processing Required Response — More Processing Required Time (MPRT) */
static int hf_nvme_mi_mprt;

/* Request/response cross-reference fields */
static int hf_nvme_mi_response_in;
static int hf_nvme_mi_response_to;
static int hf_nvme_mi_response_time;
static int hf_nvme_mi_response_is_mpr;

static int ett_nvme_mi;
static int ett_nvme_mi_hdr;

static expert_field ei_nvme_mi_mic_truncated;
static expert_field ei_nvme_mi_mic_bad;
static expert_field ei_nvme_mi_mic_unverified;
static expert_field ei_nvme_mi_req_superseded;
static expert_field ei_nvme_mi_reserved_type;

/*
 * NMIMT values the NVMe-MI 2.1 "NVMe-MI Message Fields" figure defines; 3h
 * and 6h-Fh are Reserved.  A
 * Reserved type carries no known message format, so the framing layer must not
 * read an opcode or a status byte out of it.
 */
static bool
nvme_mi_type_is_known(unsigned type)
{
    switch (type) {
    case NVME_MI_TYPE_CONTROL:
    case NVME_MI_TYPE_MI:
    case NVME_MI_TYPE_ADMIN:
    case NVME_MI_TYPE_PCIE:
    case NVME_MI_TYPE_AEM:
        return true;
    default:
        return false;
    }
}

/*
 * Whether a message takes part in the Command Slot lifecycle.  Only Command
 * Messages and Control Primitives do.  An Asynchronous Event Message is not a
 * Request or a Response at all -- the ROR bit does not apply to it and its CSI
 * bit "is not applicable and shall be cleared to '0'" (the "NVMe-MI Message
 * Fields" figure) -- so it must be kept out, exactly as a Reserved type is: an
 * AEM carries ROR=0 and CSI=0, so treating it as a request would open a
 * transaction on Command Slot 0, supersede whatever command is outstanding there,
 * and orphan that command's real response.
 */
static bool
nvme_mi_type_tracks_slot(unsigned type)
{
    switch (type) {
    case NVME_MI_TYPE_CONTROL:
    case NVME_MI_TYPE_MI:
    case NVME_MI_TYPE_ADMIN:
    case NVME_MI_TYPE_PCIE:
        return true;
    default:
        return false;
    }
}

/* Dissector table keyed by the NMIMT field; sub-dissectors register here. */
static dissector_table_t nvme_mi_type_dissector_table;

/* Response Message Status (NVMe-MI 2.1 "Response Message Status Values");
 * shared with the per-type body dissectors via packet-nvme-mi.h. */
const range_string nvme_mi_status_vals[] = {
    { NVME_MI_STATUS_SUCCESS, NVME_MI_STATUS_SUCCESS, "Success" },
    { NVME_MI_STATUS_MORE_PROCESSING_REQUIRED, NVME_MI_STATUS_MORE_PROCESSING_REQUIRED, "More Processing Required" },
    { 0x02, 0x02, "Internal Error" },
    { 0x03, 0x03, "Invalid Command Opcode" },
    { NVME_MI_STATUS_INVALID_PARAMETER, NVME_MI_STATUS_INVALID_PARAMETER, "Invalid Parameter" },
    { 0x05, 0x05, "Invalid Command Size" },
    { 0x06, 0x06, "Invalid Command Input Data Size" },
    { 0x07, 0x07, "Access Denied" },
    { 0x08, 0x08, "Unable to Abort" },
    { 0x20, 0x20, "VPD Updates Exceeded" },
    { 0x21, 0x21, "PCIe Inaccessible" },
    { 0x22, 0x22, "Management Endpoint Buffer Cleared Due to Sanitize" },
    { 0x23, 0x23, "Enclosure Services Failure" },
    { 0x24, 0x24, "Enclosure Services Transfer Failure" },
    { 0x25, 0x25, "Enclosure Failure" },
    { 0x26, 0x26, "Enclosure Services Transfer Refused" },
    { 0x27, 0x27, "Unsupported Enclosure Function" },
    { 0x28, 0x28, "Enclosure Services Unavailable" },
    { 0x29, 0x29, "Enclosure Degraded" },
    { 0x2a, 0x2a, "Sanitize In Progress" },
    { 0xE0, 0xFF, "Vendor Specific" },
    { 0, 0, NULL },
};

static const value_string mi_mctp_type_vals[] = {
    { 4, "NVMe-MI" },
    { 0, NULL },
};

const value_string mi_type_vals[] = {
    { NVME_MI_TYPE_CONTROL, "Control primitive" },
    { NVME_MI_TYPE_MI,      "MI command" },
    { NVME_MI_TYPE_ADMIN,   "NVMe Admin command" },
    { NVME_MI_TYPE_PCIE,    "PCIe command" },
    { NVME_MI_TYPE_AEM,     "Asynchronous Event" },
    { 0, NULL },
};

static const true_false_string tfs_meb = { "data in MEB", "data in message" };

/* CSI is a one-bit Command Slot selector (NVMe-MI 2.1 "NVMe-MI Message
 * Fields"). */
static const true_false_string tfs_csi = { "Command Slot 1", "Command Slot 0" };

/* MPRT is a worst-case time in 100 ms units; FFFFh means >= 6,553.5 s
 * (NVMe-MI 2.1 "More Processing Required Response Fields"). */
static void
nvme_mi_fmt_mprt(char *buf, uint32_t value)
{
    if (value == 0xffff)
        snprintf(buf, ITEM_LABEL_LENGTH, ">= 6553.5 s (0xffff)");
    else
        snprintf(buf, ITEM_LABEL_LENGTH, "%u ms (%u x 100 ms)",
                 value * 100, value);
}

bool
nvme_mi_dissect_resp_status_bytes(tvbuff_t *tvb, proto_tree *tree,
                                  uint8_t status)
{
    switch (status) {
    case NVME_MI_STATUS_SUCCESS:
        return true;
    case NVME_MI_STATUS_INVALID_PARAMETER:
        /* Parameter Error Location (NVMe-MI 2.1 "Invalid Parameter Error
         * Response Fields"). */
        proto_tree_add_item(tree, hf_nvme_mi_pel_bit, tvb, 1, 1, ENC_NA);
        proto_tree_add_item(tree, hf_nvme_mi_pel_byte, tvb, 2, 2,
                            ENC_LITTLE_ENDIAN);
        break;
    case NVME_MI_STATUS_MORE_PROCESSING_REQUIRED:
        /* Byte 1 is reserved; MPRT occupies bytes 3:2 (the "More Processing
         * Required Response Fields" figure). */
        proto_tree_add_item(tree, hf_nvme_mi_mprt, tvb, 2, 2,
                            ENC_LITTLE_ENDIAN);
        break;
    default:
        /* Every other Error Response leaves bytes 3:1 Reserved (the "Generic
         * Error Response" figure). */
        proto_tree_add_item(tree, hf_nvme_mi_resp_rsvd, tvb, 1, 3,
                            ENC_LITTLE_ENDIAN);
        break;
    }
    return false;
}

void
nvme_mi_dissect_truncated(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                          proto_item *it, expert_field *ei, int hf_data, int off)
{
    expert_add_info(pinfo, it, ei);
    if (tvb_reported_length_remaining(tvb, off) > 0)
        proto_tree_add_item(tree, hf_data, tvb, off, -1, ENC_NA);
}

proto_item *
nvme_mi_recover_resp_opcode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                            proto_item *it,
                            const struct nvme_mi_transaction *trans,
                            uint8_t nmimt, int hf_opcode,
                            expert_field *ei_orphan, unsigned *opcode)
{
    proto_item *gi;

    if (!trans || !trans->req_parsed || trans->nmimt != nmimt) {
        *opcode = 0;
        expert_add_info(pinfo, it, ei_orphan);
        return NULL;
    }

    *opcode = trans->opcode;
    gi = proto_tree_add_uint(tree, hf_opcode, tvb, 0, 0, trans->opcode);
    proto_item_set_generated(gi);
    return gi;
}

/*
 * Allocate (once) the body dissector's per-transaction context.  "size" is
 * honoured only on the first call; later calls return the existing block
 * whatever size they ask for.  That is safe because a transaction has exactly
 * one NVMe-MI Message Type, and every body dissector reaches its context only
 * after nvme_mi_recover_resp_opcode() has confirmed trans->nmimt matches its
 * own -- so only one struct type is ever stored here.  If that check is ever
 * relaxed, a smaller first allocation would be reinterpreted as a larger
 * struct; add a size check here before doing so.
 */
void *
nvme_mi_trans_body_ctx(struct nvme_mi_transaction *trans, size_t size)
{
    if (!trans->body_ctx)
        trans->body_ctx = wmem_alloc0(wmem_file_scope(), size);
    return trans->body_ctx;
}

/*
 * True when an MCTP endpoint address is the null (unassigned) EID 0.  During
 * MCTP EID assignment the host itself is the null EID, and the peer device EID
 * is not yet stable across a request/response pair (the request targets the
 * null destination while the response carries the device's real EID), so the
 * device address cannot be part of the conversation key in that phase.
 */
static bool
nvme_mi_addr_is_null_eid(const address *addr)
{
    return addr->type == AT_MCTP && addr->len == 1 &&
           *(const uint8_t *)addr->data == 0;
}


/* Per-slot in-flight transaction (NULL when the slot is idle); only written
 * when !pinfo->fd->visited. */
struct nvme_mi_conv_info {
    struct nvme_mi_transaction *command_slots[2];
    /*
     * Control Primitives are processed out-of-band from the command slots:
     * Pause/Abort/Get State/Replay exist precisely to be issued while a
     * command message is outstanding in the targeted slot, so a Control
     * Primitive request must not displace the in-flight command transaction.
     * They get their own per-slot request/response pairing (the CSI bit in
     * the message header selects which slot the primitive targets).
     */
    struct nvme_mi_transaction *cp_slots[2];
};

/* Per-frame annotation; points into the shared transaction. */
struct nvme_mi_frame_info {
    struct nvme_mi_transaction *trans;
    bool                        is_interim_mpr;
    /* This request found the slot still occupied by an unanswered request,
     * whose transaction it supersedes. */
    bool                        superseded_unanswered;
};

static int
dissect_nvme_mi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                void *data _U_)
{
    proto_tree *nvme_mi_tree, *nvme_mi_hdr_tree;
    struct nvme_mi_conv_info *mi_conv;
    unsigned len, payload_len, type;
    bool resp, mic_enabled;
    proto_item *ti, *it2;
    conversation_t *conv;
    tvbuff_t *sub_tvb;
    uint32_t mic = 0;
    bool mic_computed = false;
    bool csi;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NVMe-MI");
    col_clear(pinfo->cinfo, COL_INFO);

    len = tvb_reported_length(tvb);
    if (len < 4) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Bogus length %u, minimum %u",
                     len, 4);
        return tvb_captured_length(tvb);
    }

    ti = proto_tree_add_item(tree, proto_nvme_mi, tvb, 0, -1, ENC_NA);
    nvme_mi_tree = proto_item_add_subtree(ti, ett_nvme_mi);

    proto_item *hdr_it =
        proto_tree_add_item(nvme_mi_tree, proto_nvme_mi, tvb, 0, 4, ENC_NA);
    proto_item_set_text(hdr_it, "NVMe-MI header");
    nvme_mi_hdr_tree = proto_item_add_subtree(hdr_it, ett_nvme_mi_hdr);

    proto_tree_add_item(nvme_mi_hdr_tree, hf_nvme_mi_mctp_mt,
                        tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_item *ic_it =
        proto_tree_add_item_ret_boolean(nvme_mi_hdr_tree, hf_nvme_mi_mctp_ic,
                                        tvb, 0, 4, ENC_LITTLE_ENDIAN,
                                        &mic_enabled);
    proto_tree_add_item_ret_boolean(nvme_mi_hdr_tree, hf_nvme_mi_csi,
                                    tvb, 0, 4, ENC_LITTLE_ENDIAN, &csi);
    proto_item *type_it =
        proto_tree_add_item_ret_uint(nvme_mi_hdr_tree, hf_nvme_mi_type,
                                     tvb, 0, 4, ENC_LITTLE_ENDIAN, &type);
    proto_tree_add_item_ret_boolean(nvme_mi_hdr_tree, hf_nvme_mi_ror,
                                    tvb, 0, 4, ENC_LITTLE_ENDIAN, &resp);
    proto_tree_add_item(nvme_mi_hdr_tree, hf_nvme_mi_ciap,
                        tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(nvme_mi_hdr_tree, hf_nvme_mi_meb,
                        tvb, 0, 4, ENC_LITTLE_ENDIAN);

    payload_len = len - 4;
    if (mic_enabled) {
        if (payload_len < 4) {
            /*
             * The IC bit claims a trailing 4-byte MIC, but the frame is too
             * short to contain one.  Flag the inconsistency and keep the
             * trailing bytes as payload (rather than underflowing
             * payload_len, which would corrupt the sub-tvb's reported
             * length); only MIC verification is skipped.
             */
            expert_add_info(pinfo, ic_it, &ei_nvme_mi_mic_truncated);
            mic_enabled = false;
        } else {
            /*
             * crc32c_calculate() byte-swaps both its seed and its result, so
             * undo that swap to get the CRC-32C value as the MIC field
             * actually carries it (little-endian on the wire, NVMe
             * convention).  Computing the true value rather than its
             * byte-reverse keeps the displayed and filterable
             * "nvme-mi.mic" matching what the endpoint computed.
             */
            /*
             * The MIC covers the whole message ahead of it, and that span
             * comes from the *reported* length, so on a snaplen-sliced frame
             * the bytes to hash are not all present.  Guard the read: an
             * exception here would be thrown before the command slot
             * lifecycle below has run, leaving pinfo->fd->visited set for a
             * frame that never touched slot state -- a later response then
             * links to the wrong request, with a wrong Response Time and no
             * expert info anywhere.  When the CRC cannot be computed, claim
             * no verdict (see the PROTO_CHECKSUM_NO_FLAGS path below).
             */
            if (nvme_mi_check_mic &&
                tvb_bytes_exist(tvb, 0, payload_len)) {
                mic = CRC32C_SWAP(~crc32c_tvb_offset_calculate(tvb, 0,
                                        payload_len, 0xffffffff));
                mic_computed = true;
            }
            payload_len -= 4;
        }
    }

    /* The ROR bit does not apply to an Asynchronous Event Message, so it is
     * neither a request nor a response (NVMe-MI 2.1 "NVMe-MI Message
     * Fields"). */
    if (type == NVME_MI_TYPE_AEM)
        col_add_fstr(pinfo->cinfo, COL_INFO, "NVMe-MI %s",
                     val_to_str_const(type, mi_type_vals, "Reserved type"));
    else
        col_add_fstr(pinfo->cinfo, COL_INFO, "NVMe-MI %s %s",
                     val_to_str_const(type, mi_type_vals, "Reserved type"),
                     tfs_get_string(resp, &tfs_response_request));

    if (!nvme_mi_type_is_known(type))
        expert_add_info(pinfo, type_it, &ei_nvme_mi_reserved_type);

    struct nvme_mi_frame_info *fi = p_get_proto_data(wmem_file_scope(), pinfo,
                                                     proto_nvme_mi, 0);

    /*
     * Identify the transaction this frame belongs to and resolve the slot
     * lifecycle.  An MPR response leaves the slot occupied so the next
     * response links to the same transaction.  Message types that own no
     * Command Slot -- an Asynchronous Event Message, or a Reserved type -- are
     * left out of the lifecycle entirely (see nvme_mi_type_tracks_slot()).
     */
    if (!pinfo->fd->visited && nvme_mi_type_tracks_slot(type)) {
        /*
         * The Response Message Status byte sits at payload offset 0 for
         * every command-message response type (NVMe-MI 2.1 "Response
         * Message Status Values"; Control Primitives have their own
         * out-of-band lifecycle and no MPR concept).  Peek it here in the
         * framing layer so the slot lifecycle below never depends on a body
         * dissector running to completion: a disabled body protocol or an
         * exception thrown on a truncated payload must not leak a pending
         * slot and mislink later responses.
         *
         * On a sliced capture the status byte may be missing even though
         * the reported payload carries one; the response is then treated
         * like an interim one (the slot stays open) so that an MPR whose
         * status was cut off cannot close the slot and silently mislink the
         * real final response.
         */
        bool is_mpr = false;
        bool status_known = true;
        if (resp && type != NVME_MI_TYPE_CONTROL && payload_len >= 1) {
            if (tvb_bytes_exist(tvb, 4, 1))
                is_mpr = tvb_get_uint8(tvb, 4) ==
                         NVME_MI_STATUS_MORE_PROCESSING_REQUIRED;
            else
                status_known = false;
        }

        /*
         * NVMe-MI conversation key: physical address pair + MCTP EID pair +
         * MCTP message tag.  All three are needed; each covers a case the
         * others cannot.
         *
         * The tag alone is not a key.  An MCTP tag is unique only per endpoint
         * pair, so concurrent transactions to different peers routinely share a
         * tag value and would cross-match.
         *
         * The EID pair alone is not a key either, because it is not stable
         * across MCTP EID assignment.  Before assignment the host is the null
         * EID 0 and the device answers from its real EID, so the (src, dst)
         * pair differs between a request and its own response:
         *
         *   request:  src=0,       dst=0, srcport=tag|0x08 (TO=1)
         *   response: src=EID_dev, dst=0, srcport=tag      (TO=0)
         *
         * Keying on that (as find_or_create_conversation() would, on all four
         * of src/dst/sport/dport) puts the two frames in different
         * conversations: the command-slot state is never shared, so every
         * response looks like an orphan and every new request finds the slot
         * still occupied by the previous one.
         *
         * The physical address pair alone is not a key either.  MCTP bridging
         * puts *several* Management Endpoints behind one physical address --
         * OCP Datacenter NVMe SSD 2.7 NVMe-MI-29 requires exactly that, so a
         * Management Controller can manage more than one endpoint on a 2-Wire
         * port -- and those endpoints are distinguished only by EID.  Keying on
         * the address pair alone merges them into one conversation, so a
         * command outstanding on Command Slot 0 of one endpoint is superseded
         * by a command to a *different* endpoint that happens to reuse the tag,
         * and the responses cross-match.
         *
         * So: use the physical addresses when the transport supplies them
         * (packet-mctp-smbus.c publishes the SMBus 7-bit slave addresses in
         * pinfo->net_src/dst; for PCIe VDM they are absent), the EIDs when the
         * tag owner actually has one, and always the tag.  "The tag owner has
         * an EID" is the symmetric test for EID-assignment being complete: the
         * host is the null EID in *both* directions of the exchange while it is
         * still unassigned (request src = 0, response dst = 0), so both frames
         * of a pre-assignment exchange agree to leave the EIDs out of the key
         * and match on the physical addresses instead.
         */
        {
            bool src_owns_tag = (pinfo->srcport & 0x08) != 0;
            uint32_t tag      = src_owns_tag ? pinfo->srcport : pinfo->destport;
            bool has_phys     = (pinfo->net_src.type != AT_NONE &&
                                 pinfo->net_src.len  == sizeof(uint8_t));

            const address *owner_eid  = src_owns_tag ? &pinfo->src : &pinfo->dst;
            const address *device_eid = src_owns_tag ? &pinfo->dst : &pinfo->src;
            bool eids_usable = !nvme_mi_addr_is_null_eid(owner_eid);

            /* At most: 2 addresses + 2 EIDs + tag + type terminator. */
            conversation_element_t *key =
                wmem_alloc_array(pinfo->pool, conversation_element_t, 6);
            unsigned n = 0;

            if (has_phys) {
                key[n].type = CE_ADDRESS;
                copy_address_shallow(&key[n].addr_val,
                        src_owns_tag ? &pinfo->net_src : &pinfo->net_dst);
                n++;
                key[n].type = CE_ADDRESS;
                copy_address_shallow(&key[n].addr_val,
                        src_owns_tag ? &pinfo->net_dst : &pinfo->net_src);
                n++;
            }

            if (eids_usable) {
                key[n].type = CE_ADDRESS;
                copy_address_shallow(&key[n].addr_val, owner_eid);
                n++;
                key[n].type = CE_ADDRESS;
                copy_address_shallow(&key[n].addr_val, device_eid);
                n++;
            } else if (!has_phys) {
                /* Pre-assignment on a transport with no physical addresses:
                 * the tag owner (the null EID) and the tag are all there is. */
                key[n].type = CE_ADDRESS;
                copy_address_shallow(&key[n].addr_val, owner_eid);
                n++;
            }

            key[n].type     = CE_UINT;
            key[n].uint_val = tag;
            n++;
            key[n].type                  = CE_CONVERSATION_TYPE;
            key[n].conversation_type_val = CONVERSATION_NVME_MI;

            conv = find_conversation_full(pinfo->num, key);
            if (!conv)
                conv = conversation_new_full(pinfo->num, key);
        }
        mi_conv = conversation_get_proto_data(conv, proto_nvme_mi);
        if (!mi_conv) {
            mi_conv = wmem_new0(wmem_file_scope(), struct nvme_mi_conv_info);
            conversation_add_proto_data(conv, proto_nvme_mi, mi_conv);
        }

        struct nvme_mi_transaction **slot = (type == NVME_MI_TYPE_CONTROL)
                                                ? &mi_conv->cp_slots[csi]
                                                : &mi_conv->command_slots[csi];

        if (resp) {
            if (*slot) {
                fi = wmem_new0(wmem_file_scope(), struct nvme_mi_frame_info);
                fi->trans = *slot;
                fi->is_interim_mpr = is_mpr;
                p_add_proto_data(wmem_file_scope(), pinfo, proto_nvme_mi,
                                 0, fi);
                if (!is_mpr && status_known) {
                    fi->trans->resp_frame = pinfo->num;
                    *slot = NULL;
                }
            }
        } else {
            struct nvme_mi_transaction *trans =
                wmem_new0(wmem_file_scope(), struct nvme_mi_transaction);
            trans->req_frame = pinfo->num;
            trans->req_time  = pinfo->fd->abs_ts;
            trans->nmimt     = (uint8_t)type;

            /*
             * The opcode byte sits at payload offset 0 for an Admin or MI
             * Command Message request.  Record it here in the always-run
             * framing layer so response->request opcode recovery survives a
             * disabled or truncated body dissector; the per-opcode request
             * context that drives the structured field decode is still
             * recorded separately by the body in trans->body_ctx.
             *
             * Control Primitives are excluded (as in the MPR peek above): they
             * have a stricter minimum length before opcode/tag are trustworthy
             * (the body's >= 4-byte guard) and their own slot lifecycle, so the
             * Control body records trans->opcode/req_parsed itself.
             */
            if (type != NVME_MI_TYPE_CONTROL &&
                payload_len >= 1 && tvb_bytes_exist(tvb, 4, 1)) {
                trans->opcode     = tvb_get_uint8(tvb, 4);
                trans->req_parsed = true;
            }

            fi = wmem_new0(wmem_file_scope(), struct nvme_mi_frame_info);
            fi->trans = trans;
            fi->superseded_unanswered = (*slot != NULL);
            p_add_proto_data(wmem_file_scope(), pinfo, proto_nvme_mi, 0, fi);

            *slot = trans;
        }
    }

    /* Cross-references that do not depend on the body.  fi->trans is shared,
     * so resp_frame written on the response pass is visible here when
     * re-dissecting the request. */
    if (fi && fi->trans) {
        if (resp) {
            if (fi->trans->req_frame) {
                nstime_t ns;
                nstime_delta(&ns, &pinfo->fd->abs_ts, &fi->trans->req_time);

                it2 = proto_tree_add_uint(nvme_mi_tree, hf_nvme_mi_response_to,
                                          tvb, 0, 0, fi->trans->req_frame);
                proto_item_set_generated(it2);
                it2 = proto_tree_add_time(nvme_mi_tree, hf_nvme_mi_response_time,
                                          tvb, 0, 0, &ns);
                proto_item_set_generated(it2);
            }
            if (fi->is_interim_mpr) {
                it2 = proto_tree_add_boolean(nvme_mi_tree,
                                             hf_nvme_mi_response_is_mpr,
                                             tvb, 0, 0, true);
                proto_item_set_generated(it2);
            }
        } else {
            if (fi->superseded_unanswered)
                expert_add_info(pinfo, ti, &ei_nvme_mi_req_superseded);
            if (fi->trans->resp_frame) {
                it2 = proto_tree_add_uint(nvme_mi_tree, hf_nvme_mi_response_in,
                                          tvb, 0, 0, fi->trans->resp_frame);
                proto_item_set_generated(it2);
            }
        }
    }

    sub_tvb = tvb_new_subset_length(tvb, 4, payload_len);

    struct nvme_mi_dissect_ctx ctx = {
        .resp  = resp,
        .trans = fi ? fi->trans : NULL,
    };
    /*
     * A body dissector handed an empty payload legitimately returns 0, which
     * is indistinguishable from "no dissector registered for this type" —
     * only fall back to the data dissector when there are actual payload
     * bytes left to show.
     */
    if (!dissector_try_uint_with_data(nvme_mi_type_dissector_table, type,
                                      sub_tvb, pinfo, nvme_mi_tree, false,
                                      &ctx) && payload_len > 0)
        call_data_dissector(sub_tvb, pinfo, nvme_mi_tree);

    /* The MIC is little-endian on the wire (NVMe convention).  A sliced
     * capture may cut off the MIC itself, or only the bytes it covers; report
     * the first as "missing" and the second as unverified rather than
     * asserting a verdict the capture cannot support. */
    if (mic_enabled) {
        unsigned mic_flags;

        if (!tvb_bytes_exist(tvb, payload_len + 4, 4))
            mic_flags = PROTO_CHECKSUM_NOT_PRESENT;
        else if (mic_computed)
            mic_flags = PROTO_CHECKSUM_VERIFY;
        else
            mic_flags = PROTO_CHECKSUM_NO_FLAGS;

        proto_tree_add_checksum(nvme_mi_tree, tvb, payload_len + 4,
                                hf_nvme_mi_mic, hf_nvme_mi_mic_status,
                                &ei_nvme_mi_mic_bad, pinfo, mic,
                                ENC_LITTLE_ENDIAN, mic_flags);

        if (nvme_mi_check_mic && mic_flags != PROTO_CHECKSUM_VERIFY)
            expert_add_info(pinfo, ic_it, &ei_nvme_mi_mic_unverified);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_nvme_mi(void)
{
    /* *INDENT-OFF* */
    static hf_register_info hf[] = {
        /* Common NVMe-MI header (4 bytes, NVMe-MI 2.1 "NVMe-MI Message
         * Fields") */
        { &hf_nvme_mi_mctp_mt,
          { "MCTP message type", "nvme-mi.mctp-mt",
            FT_UINT32, BASE_HEX, VALS(mi_mctp_type_vals), 0x7f,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mctp_ic,
          { "MCTP IC", "nvme-mi.mctp-ic",
            FT_BOOLEAN, 32, NULL, 0x00000080,
            NULL, HFILL },
        },
        { &hf_nvme_mi_csi,
          { "CSI", "nvme-mi.csi",
            FT_BOOLEAN, 32, TFS(&tfs_csi), 0x00000100,
            "Command Slot Identifier", HFILL },
        },
        { &hf_nvme_mi_type,
          { "Type", "nvme-mi.type",
            FT_UINT32, BASE_HEX, VALS(mi_type_vals), 0x00007800,
            NULL, HFILL },
        },
        { &hf_nvme_mi_ror,
          { "ROR", "nvme-mi.ror",
            FT_BOOLEAN, 32, TFS(&tfs_response_request), 0x00008000,
            NULL, HFILL },
        },
        { &hf_nvme_mi_ciap,
          { "CIAP", "nvme-mi.ciap",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00020000,
            "Command Initiated Auto Pause: pause the Management Endpoint when"
            " this Command Message enters the Process state", HFILL },
        },
        { &hf_nvme_mi_meb,
          { "MEB", "nvme-mi.meb",
            FT_BOOLEAN, 32, TFS(&tfs_meb), 0x00010000,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mic,
          { "Message Integrity Check", "nvme-mi.mic",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mic_status,
          { "Message Integrity Check Status", "nvme-mi.mic.status",
            FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0,
            NULL, HFILL },
        },

        /* Invalid Parameter Error Response (status 04h) — Parameter Error
         * Location over payload bytes 3:1; shared by the command message
         * types via nvme_mi_dissect_invalid_param_resp(). */
        { &hf_nvme_mi_pel_bit,
          { "Parameter Error Bit (PEL)", "nvme-mi.pel.bit",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            "Least-significant bit of the parameter in error", HFILL },
        },
        { &hf_nvme_mi_pel_byte,
          { "Parameter Error Byte (PEL)", "nvme-mi.pel.byte",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Offset of the least-significant byte of the parameter in"
            " error, relative to the start of the message", HFILL },
        },

        /* More Processing Required Response — MPRT over payload bytes 3:2;
         * shared by the command message types via
         * nvme_mi_dissect_mpr_resp(). */
        { &hf_nvme_mi_mprt,
          { "More Processing Required Time (MPRT)", "nvme-mi.mprt",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(nvme_mi_fmt_mprt), 0,
            "Worst-case additional processing time before the final"
            " Response Message (NVMe-MI 2.1 'More Processing Required"
            " Response Fields')", HFILL },
        },
        { &hf_nvme_mi_resp_rsvd,
          { "Reserved", "nvme-mi.resp_reserved",
            FT_UINT24, BASE_HEX, NULL, 0,
            "Reserved in an Error Response that carries no Parameter Error"
            " Location or More Processing Required Time (NVMe-MI 2.1"
            " 'Generic Error Response')", HFILL },
        },

        /* Request/response cross-reference (generated fields) */
        { &hf_nvme_mi_response_in,
          { "Response In", "nvme-mi.response_in",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
            "The response to this NVMe-MI request is in this frame", HFILL }
        },
        { &hf_nvme_mi_response_to,
          { "Request In", "nvme-mi.response_to",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
            "This is a response to the NVMe-MI request in this frame", HFILL }
        },
        { &hf_nvme_mi_response_time,
          { "Response Time", "nvme-mi.response_time",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "The time between the request and the response", HFILL }
        },
        { &hf_nvme_mi_response_is_mpr,
          { "More Processing Required", "nvme-mi.response_is_mpr",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "This is an interim response; the endpoint will send a final"
            " response when processing is complete", HFILL }
        },
    };
    /* *INDENT-ON* */

    static int *ett[] = {
        &ett_nvme_mi,
        &ett_nvme_mi_hdr,
    };

    static ei_register_info ei[] = {
        { &ei_nvme_mi_mic_truncated,
          { "nvme-mi.mic_truncated", PI_MALFORMED, PI_WARN,
            "IC bit is set but the message is too short to contain a MIC;"
            " trailing bytes treated as payload", EXPFILL }
        },
        { &ei_nvme_mi_mic_bad,
          { "nvme-mi.mic_bad", PI_CHECKSUM, PI_WARN,
            "Message Integrity Check does not match the computed CRC-32C",
            EXPFILL }
        },
        { &ei_nvme_mi_mic_unverified,
          { "nvme-mi.mic_unverified", PI_CHECKSUM, PI_NOTE,
            "Message Integrity Check not verified: the frame is sliced, so"
            " the bytes the MIC covers are not all present in the capture",
            EXPFILL }
        },
        { &ei_nvme_mi_req_superseded,
          { "nvme-mi.req_superseded", PI_SEQUENCE, PI_NOTE,
            "The previous request on this command slot was still unanswered;"
            " its transaction is superseded by this request", EXPFILL }
        },
        { &ei_nvme_mi_reserved_type,
          { "nvme-mi.reserved_type", PI_PROTOCOL, PI_WARN,
            "NVMe-MI Message Type is Reserved (NVMe-MI 2.1 'NVMe-MI"
            " Message Fields'); the"
            " message body cannot be decoded and the message takes no part in"
            " command slot tracking", EXPFILL },
        },
    };

    expert_module_t *expert_nvme_mi;

    proto_nvme_mi = proto_register_protocol("NVMe-MI", "NVMe-MI", "nvme-mi");
    proto_register_field_array(proto_nvme_mi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_nvme_mi = expert_register_protocol(proto_nvme_mi);
    expert_register_field_array(expert_nvme_mi, ei, array_length(ei));

    nvme_mi_type_dissector_table = register_dissector_table("nvme-mi.type",
            "NVMe-MI Message Type", proto_nvme_mi, FT_UINT8, BASE_HEX);

    module_t *nvme_mi_module = prefs_register_protocol(proto_nvme_mi, NULL);
    prefs_register_bool_preference(nvme_mi_module, "check_mic",
            "Validate the Message Integrity Check",
            "Whether to compute the CRC-32C over each NVMe-MI message and"
            " verify it against the Message Integrity Check (MIC)",
            &nvme_mi_check_mic);

    nvme_mi_handle = register_dissector_with_description("nvme-mi",
            "NVMe-MI over MCTP", dissect_nvme_mi, proto_nvme_mi);
}

void
proto_reg_handoff_nvme_mi(void)
{
    dissector_add_uint("mctp.type", MCTP_TYPE_NVME, nvme_mi_handle);
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
