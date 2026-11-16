/* packet-nvme.h
 * data structures for NVMe Dissection
 * Copyright 2016
 * Code by Parav Pandit
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef _PACKET_NVME_H_
#define _PACKET_NVME_H_

#define NVME_CMD_SIZE 64
#define NVME_CQE_SIZE 16

#define NVME_FABRIC_OPC 0x7F
#define NVME_FCTYPE_PROP_SET  0x0
#define NVME_FCTYPE_CONNECT   0x1
#define NVME_FCTYPE_PROP_GET  0x4
#define NVME_FCTYPE_AUTH_SEND 0x5
#define NVME_FCTYPE_AUTH_RECV 0x6
#define NVME_FCTYPE_DISCONNECT 0x8

/* NVMe Admin opcodes, shared with NVMe-MI (MI 2.1 Figure 134). */
#define NVME_AQ_OPC_DELETE_SQ              0x00
#define NVME_AQ_OPC_CREATE_SQ              0x01
#define NVME_AQ_OPC_GET_LOG_PAGE           0x02
#define NVME_AQ_OPC_DELETE_CQ              0x04
#define NVME_AQ_OPC_CREATE_CQ              0x05
#define NVME_AQ_OPC_IDENTIFY               0x06
#define NVME_AQ_OPC_ABORT                  0x08
#define NVME_AQ_OPC_SET_FEATURES           0x09
#define NVME_AQ_OPC_GET_FEATURES           0x0a
#define NVME_AQ_OPC_ASYNC_EVE_REQ          0x0c
#define NVME_AQ_OPC_NS_MGMT                0x0d
#define NVME_AQ_OPC_FW_COMMIT              0x10
#define NVME_AQ_OPC_FW_IMG_DOWNLOAD        0x11
#define NVME_AQ_OPC_SELF_TEST              0x14
#define NVME_AQ_OPC_NS_ATTACH              0x15
#define NVME_AQ_OPC_KEEP_ALIVE             0x18
#define NVME_AQ_OPC_DIRECTIVE_SEND         0x19
#define NVME_AQ_OPC_DIRECTIVE_RECV         0x1a
#define NVME_AQ_OPC_VIRT_MGMT              0x1c
#define NVME_AQ_OPC_MI_SEND                0x1d
#define NVME_AQ_OPC_MI_RECV                0x1e
#define NVME_AQ_OPC_CAP_MGMT               0x20
#define NVME_AQ_OPC_DISC_INFO_MGMT         0x21
#define NVME_AQ_OPC_FABRIC_ZONING_RECV     0x22
#define NVME_AQ_OPC_LOCKDOWN               0x24
#define NVME_AQ_OPC_FABRIC_ZONING_LOOKUP   0x25
#define NVME_AQ_OPC_CLEAR_EXP_NVM_CFG      0x28
#define NVME_AQ_OPC_FABRIC_ZONING_SEND     0x29
#define NVME_AQ_OPC_CREATE_EXP_NVM_SUBSYS  0x2a
#define NVME_AQ_OPC_MANAGE_EXP_NVM_SUBSYS  0x2d
#define NVME_AQ_OPC_MANAGE_EXP_NS          0x31
#define NVME_AQ_OPC_MANAGE_EXP_PORT        0x35
#define NVME_AQ_OPC_CROSS_CTRL_RESET       0x38
#define NVME_AQ_OPC_SEND_DISC_LOG_PAGE     0x39
#define NVME_AQ_OPC_TRACK_SEND             0x3d
#define NVME_AQ_OPC_TRACK_RECV             0x3e
#define NVME_AQ_OPC_MIGRATION_SEND         0x41
#define NVME_AQ_OPC_MIGRATION_RECV         0x42
#define NVME_AQ_OPC_CTRL_DATA_QUEUE        0x45
#define NVME_AQ_OPC_DBBUF_CONFIG           0x7c
#define NVME_AQ_OPC_FORMAT_NVM             0x80
#define NVME_AQ_OPC_SECURITY_SEND          0x81
#define NVME_AQ_OPC_SECURITY_RECV          0x82
#define NVME_AQ_OPC_SANITIZE               0x84
#define NVME_AQ_OPC_LOAD_PROGRAM           0x85
#define NVME_AQ_OPC_GET_LBA_STATUS         0x86
#define NVME_AQ_OPC_PROG_ACTIVATION_MGMT   0x88
#define NVME_AQ_OPC_MEM_RANGE_SET_MGMT     0x89
#define NVME_AQ_OPC_SANITIZE_NS            0x8c

#define NVME_IDENTIFY_CNS_IDENTIFY_NS      0x0
#define NVME_IDENTIFY_CNS_IDENTIFY_CTRL    0x1
#define NVME_IDENTIFY_CNS_IDENTIFY_NSLIST  0x2
#define NVME_IDENTIFY_CNS_NSID_DESC_LIST   0x3
#define NVME_IDENTIFY_CNS_NVM_SET_LIST     0x4
#define NVME_IDENTIFY_CNS_CS_IND_NS        0x8
#define NVME_IDENTIFY_CNS_NS_ALLOC_LIST    0x10
#define NVME_IDENTIFY_CNS_NS_ALLOC         0x11
#define NVME_IDENTIFY_CNS_CTRL_LIST_NS     0x12
#define NVME_IDENTIFY_CNS_CTRL_LIST        0x13
#define NVME_IDENTIFY_CNS_PRI_CTRL_CAP     0x14
#define NVME_IDENTIFY_CNS_SEC_CTRL_LIST    0x15
#define NVME_IDENTIFY_CNS_NS_GRAN_LIST     0x16
#define NVME_IDENTIFY_CNS_UUID_LIST        0x17


/* Provenance of data bytes: gates retaining version and log page walk state,
 * not rendering. */
enum nvme_data_provenance {
    NVME_DATA_PROV_NONE = 0, /* not vouched response data: retain nothing */
    NVME_DATA_PROV_RESPONSE, /* response data at its true logical offset */
};

/* How the caller knows the block's logical offset. */
enum nvme_data_window {
    NVME_DATA_WINDOW_UNKNOWN = 0, /* a guess: render, but retain nothing */
    NVME_DATA_WINDOW_TRACKED, /* running transfer offset, recorded per frame */
    NVME_DATA_WINDOW_EXPLICIT, /* from the transport header, in 'offset' */
};

/* Transaction half; Admin data travels one way per opcode. */
enum nvme_data_direction {
    NVME_DATA_DIR_HOST_TO_CONTROLLER, /* request, write, in-capsule data */
    NVME_DATA_DIR_CONTROLLER_TO_HOST, /* response and read data */
};

/* Where the block belongs.  The direction is passed separately. */
struct nvme_data_origin {
    enum nvme_data_provenance prov;
    enum nvme_data_window     window;
    uint32_t                  offset; /* NVME_DATA_WINDOW_EXPLICIT only */
    bool                      level0_prefix; /* Receive may contain only an initial prefix. */
};

/* Common origins: no claim at all, or response data at a tracked offset. */
#define NVME_DATA_ORIGIN_NONE ((struct nvme_data_origin){ \
    .prov = NVME_DATA_PROV_NONE, .window = NVME_DATA_WINDOW_UNKNOWN })
#define NVME_DATA_ORIGIN_TRACKED ((struct nvme_data_origin){ \
    .prov = NVME_DATA_PROV_RESPONSE, .window = NVME_DATA_WINDOW_TRACKED })

struct nvme_q_ctx {
    wmem_tree_t *pending_cmds;
    wmem_tree_t *done_cmds;
    wmem_tree_t *data_requests;
    wmem_tree_t *data_responses;
    wmem_tree_t *data_offsets;
    uint16_t    qid;
};

bool nvme_admin_opcode_is_reserved(uint8_t opcode);

enum nvme_feat_xfer {
    NVME_FEAT_XFER_UNKNOWN,  /* reserved, vendor specific or dword-dependent */
    NVME_FEAT_XFER_NONE,     /* no data buffer (Base 2.4 Figure 466) */
    NVME_FEAT_XFER_DATA,     /* data buffer; *size when fixed, else 0 */
};

/* Whether Set (get=false) or Get Features with these dwords uses a data
 * buffer, and its size in bytes when the structure is fixed (0 = not known). */
enum nvme_feat_xfer nvme_feature_transfer(uint8_t fid, bool get, uint8_t sel,
                                          uint32_t cdw11, uint32_t cdw13,
                                          uint32_t *size);

/* True when tree holds a decoded item: a node with children or one that is
 * not the generic NVMe Data wrapper. */
bool nvme_data_tree_has_fields(proto_tree *tree);

#define NVME_CMD_MAX_TRS (16)

struct nvme_cmd_ctx {
    uint32_t cmd_pkt_num;  /* pkt number of the cmd */
    uint32_t cqe_pkt_num;  /* pkt number of the cqe */

    uint32_t data_req_pkt_num;
    uint32_t data_tr_pkt_num[NVME_CMD_MAX_TRS];
    uint32_t first_tr_psn;

    nstime_t cmd_start_time;
    nstime_t cmd_end_time;
    uint32_t tr_bytes;   /* bytes transferred so far */
    bool fabric;     /* indicate whether cmd fabric type or not */

    union {
        struct {
            uint8_t cns;
            uint8_t csi;
        } cmd_identify;
        struct {
            uint64_t off;
            unsigned records;
            bool records_valid; /* 'records' was read from the page (NAGD may legally be 0). */
            unsigned tr_rcrd_id;
            unsigned tr_off;
            unsigned tr_sub_entries;
            /* Page offset at which the last walked window ended; 0 if none
             * did or the walk lost its framing. */
            uint32_t tr_next_off;
            /* NUMDU:NUMDL, 0's based; tells a whole transfer from an MI window. */
            uint32_t numd;
            /* LSI (CDW11 31:16): the only subject of Figures 222 and 224. */
            uint16_t lsi;
            uint8_t lid;
            uint8_t csi; /* CDW14 31:24; names CSI-specific LIDs. */
            uint8_t tr_type;
            bool ot; /* Offset Type (CDW14 bit 23): 'off' is an index, not a byte offset. */
            /* A Discovery read with LSP EXTDLPE set (Base 2.3 Figure 309): its
             * records may be Extended entries, so each may be TEL bytes long. */
            bool extdlpe;
            uint8_t lsp; /* CDW10 bits 14:08 */
            /* Persistent Event Log reporting-context identity (an NVMe-MI
             * endpoint), or NULL: event framing is then not carried across
             * commands. */
            const void *scope;
            /* Set per data block: the bytes are vouched response data. */
            bool retain;
        } get_logpage;
        struct {
            uint8_t fid;
            uint32_t cdw11;
            uint32_t cdw13;
            uint8_t response_count;
            bool response_count_valid;
            /* Get Features Select (CDW10 bits 10:08); 011b makes Dword 0 the
             * supported capabilities (NVMe Base 2.3 Figure 199). */
            uint8_t sel;
        } set_features;
        struct {
            /* Dword 11: Security Send Transfer Length or Receive Allocation
             * Length; 0 when the request was not seen. */
            uint32_t xfer_len;
            const void *scope; /* Stable transport/endpoint identity, never a command-slot key. */
            uint16_t controller;
            /* MI requests retain both integrity and the Security transfer
             * contract here; responses may narrow, never replace, validity. */
            bool state_valid;
            /* Security Send/Receive CDW10 selectors, for data dispatch. */
            uint16_t spsp;   /* SP Specific (SPSP1:SPSP0); the ComID for TCG */
            uint8_t  secp;   /* Security Protocol */
        } security;
        struct {
            union {
                struct {
                    uint32_t offset;
                    uint8_t attr;   /* ATTRIB.PRS, Base 2.3 Figure 585 */
                } prop_get;
                struct {
                    uint16_t qid;
                } cnct;
            };
            uint8_t fctype; /* fabric cmd type */
        } fabric_cmd;
        struct {
            /* NS Management SEL, Capacity Management OPER or Virtualization
             * Management ACT (CDW10 03:00): selects the CQE Dword 0 layout. */
            uint8_t sel;
        } admin_mgmt;
    } cmd_ctx;
    uint8_t opcode;
};

extern int hf_nvmeof_cmd_pkt;
extern int hf_nvmeof_data_req;

const char *get_nvmeof_cmd_string(uint8_t fctype);

void
nvme_publish_qid(proto_tree *tree, int field_index, uint16_t qid);

void
nvme_publish_cmd_latency(proto_tree *tree, struct nvme_cmd_ctx *cmd_ctx,
                         int field_index);
void
nvme_publish_to_cmd_link(proto_tree *tree, tvbuff_t *tvb,
                             int hf_index, struct nvme_cmd_ctx *cmd_ctx);
void
nvme_publish_to_cqe_link(proto_tree *tree, tvbuff_t *tvb,
                             int hf_index, struct nvme_cmd_ctx *cmd_ctx);
void
nvme_publish_to_data_req_link(proto_tree *tree, tvbuff_t *tvb,
                             int hf_index, struct nvme_cmd_ctx *cmd_ctx);
void
nvme_publish_to_data_resp_link(proto_tree *tree, tvbuff_t *tvb,
                             int hf_index, struct nvme_cmd_ctx *cmd_ctx);
void
nvme_publish_link(proto_tree *tree, tvbuff_t *tvb, int hf_index,
                             uint32_t pkt_no, bool zero_ok);

void nvme_update_cmd_end_info(packet_info *pinfo, struct nvme_cmd_ctx *cmd_ctx);

void
nvme_add_cmd_to_pending_list(packet_info *pinfo, struct nvme_q_ctx *q_ctx,
                             struct nvme_cmd_ctx *cmd_ctx,
                             void *ctx, uint16_t cmd_id);
void* nvme_lookup_cmd_in_pending_list(struct nvme_q_ctx *q_ctx, uint16_t cmd_id);

struct keyed_data_req
{
    uint64_t addr;
    uint32_t key;
    uint32_t size;
};

void
dissect_nvmeof_fabric_cmd(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *nvme_tree,
                                struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd, unsigned off, bool link_data_req);
void
dissect_nvmeof_cmd_data(tvbuff_t *data_tvb, packet_info *pinfo, proto_tree *data_tree,
                                 unsigned pkt_off, struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd, unsigned len);
void
dissect_nvmeof_fabric_cqe(tvbuff_t *nvme_tvb, packet_info *pinfo,
                        proto_tree *nvme_tree,
                        struct nvme_cmd_ctx *cmd_ctx, unsigned off);

void
nvme_add_data_request(struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd_ctx,
                                struct keyed_data_req *req);

struct nvme_cmd_ctx*
nvme_lookup_data_request(struct nvme_q_ctx *q_ctx, struct keyed_data_req *req);

void
nvme_add_data_tr_pkt(struct nvme_q_ctx *q_ctx,
                       struct nvme_cmd_ctx *cmd_ctx, uint32_t rkey, uint32_t frame_num);
struct nvme_cmd_ctx*
nvme_lookup_data_tr_pkt(struct nvme_q_ctx *q_ctx,
                          uint32_t rkey, uint32_t frame_num);

void
nvme_add_data_tr_off(struct nvme_q_ctx *q_ctx, uint32_t off, uint32_t frame_num);

uint32_t
nvme_lookup_data_tr_off(struct nvme_q_ctx *q_ctx, uint32_t frame_num);

void
nvme_add_cmd_cqe_to_done_list(struct nvme_q_ctx *q_ctx,
                              struct nvme_cmd_ctx *cmd_ctx, uint16_t cmd_id);
void*
nvme_lookup_cmd_in_done_list(packet_info *pinfo, struct nvme_q_ctx *q_ctx,
                             uint16_t cmd_id, bool is_cqe);

void dissect_nvme_cmd_sgl(tvbuff_t *cmd_tvb, proto_tree *cmd_tree, int field_index,
                 struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd_ctx, unsigned cmd_off, bool visited);

void
dissect_nvme_cmd(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *root_tree,
                 struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd_ctx);

void nvme_update_transfer_request(packet_info *pinfo, struct nvme_cmd_ctx *cmd_ctx, struct nvme_q_ctx *q_ctx);

void
dissect_nvme_data_response(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *root_tree,
                 struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd_ctx, unsigned len, bool is_inline,
                 enum nvme_data_direction dir, struct nvme_data_origin origin);

void
dissect_nvme_cqe(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *root_tree,
                 struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd_ctx);

/**
 * Returns string representation of opcode according
 * to opcode and queue id
 */
const char *
nvme_get_opcode_string(uint8_t opcode, uint16_t qid);

/* Admin opcode naming with an explicit I/O Command Set Identifier. */
const char *
nvme_get_admin_opcode_string(uint8_t opcode, uint8_t csi);

/* CSTS.SHST shutdown-status names; shared with the NVMe-MI CHDS decode. */
extern const value_string shst_table[];

/* Decode Admin SQE CDW10-CDW15 (SQE offset 40) for cmd_ctx->opcode,
 * filling cmd_ctx; shared with NVMe-MI. */
void
nvme_dissect_admin_sqe_cdws(tvbuff_t *sqe_tvb, packet_info *pinfo,
                            proto_tree *tree, struct nvme_cmd_ctx *cmd_ctx);

/* Decode Admin CQE Dword 0 at dw0_off for cmd_ctx->opcode; shared with
 * NVMe-MI. */
void
nvme_dissect_admin_cqe_dw0(tvbuff_t *nvme_tvb, int dw0_off, proto_tree *cqe_tree,
                           uint16_t status, struct nvme_cmd_ctx *cmd_ctx);

/* Decode Admin CQE Dword 1 fields at dw1_off for cmd_ctx->opcode, where
 * the command defines them; shared with NVMe-MI. */
void
nvme_dissect_admin_cqe_dw1(tvbuff_t *nvme_tvb, int dw1_off, proto_tree *cqe_tree,
                           uint16_t status, struct nvme_cmd_ctx *cmd_ctx);

/* CQE Status Field word alone, for transports without the full CQE layout
 * (Base 2.3 Fig 100); nvmeof selects the fabrics rendering. */
void
nvme_dissect_cqe_status(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *cqe_tree,
                        unsigned status_off, bool nvmeof);

/* As nvme_dissect_cqe_status() for an Admin command completion: a Command
 * Specific Status Code is also checked against the command that the
 * NVM Express Base 2.4 Figure 104 lists it for. */
void
nvme_dissect_admin_cqe_status(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *cqe_tree,
                              unsigned status_off, uint8_t opcode);

/* The 'data' of the "nvme.security.secp" table.  Only a first window
 * (offset 0) is dispatched, a short Receive one included; xfer_len tells a
 * short transfer from a bad length.  Sub-dissectors must reject NULL data. */
struct nvme_security_info {
    bool     send;   /* true = Security Send payload (host to controller) */
    uint8_t  secp;   /* Security Protocol */
    uint16_t spsp;   /* SP Specific (SPSP1:SPSP0); the ComID for TCG */
    uint32_t xfer_len; /* Dword 11 (Send: TL, Receive: AL); 0 if unknown */
    const void *scope;
    uint16_t controller;
    bool state_valid; /* Complete, trustworthy transport data may advance streams. */
    /* Receive only: the window may legally end before AL (Level 0 prefix). */
    bool level0_prefix;
};

/* The security info a Security Send/Receive command recorded. */
static inline struct nvme_security_info
nvme_security_info_of(const struct nvme_cmd_ctx *cmd_ctx, bool send)
{
    return (struct nvme_security_info){
        .send = send,
        .secp = cmd_ctx->cmd_ctx.security.secp,
        .spsp = cmd_ctx->cmd_ctx.security.spsp,
        .xfer_len = cmd_ctx->cmd_ctx.security.xfer_len,
        .scope = cmd_ctx->cmd_ctx.security.scope,
        .controller = cmd_ctx->cmd_ctx.security.controller,
        .state_valid = cmd_ctx->cmd_ctx.security.state_valid,
    };
}

/**
 * Decode the data payload of a data-returning Admin command into cmd_tree.
 * 'off' is the dword-aligned logical offset of nvme_tvb's first byte and
 * NVME_DATA_PROV_RESPONSE asserts it; 'len' bytes are present.  Returns
 * false, for a raw rendering, when the opcode carries no data in 'dir'.
 */
bool
nvme_dissect_admin_data_resp(tvbuff_t *nvme_tvb, packet_info *pinfo,
                             proto_tree *cmd_tree, struct nvme_cmd_ctx *cmd_ctx,
                             unsigned off, unsigned len,
                             struct nvme_data_origin origin,
                             enum nvme_data_direction dir);

/* Tells if the command whose SQE starts at off implies an Admin queue, for
 * guessing the queue type when the Connect was not captured. */
bool
nvme_cmd_implies_admin_queue(tvbuff_t *tvb, unsigned off);

/* Base 2.3 Fig 138, also used by MI 2.1 DTYP 02h. Returns the number of
 * bytes occupied by the count and complete selected identifiers. */
unsigned nvme_dissect_controller_list(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, unsigned off, unsigned len, int hf_count, int hf_id);

#endif

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
