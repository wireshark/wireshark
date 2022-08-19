/* packet-nbt.c
 * Routines for NetBIOS-over-TCP packet disassembly
 * Guy Harris <guy@alum.mit.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/show_exception.h>
#include <epan/to_str.h>

#include "packet-dns.h"
#include "packet-netbios.h"
#include "packet-tcp.h"

void proto_register_nbt(void);
void proto_reg_handoff_nbt(void);

static dissector_handle_t nbns_handle, nbdgm_handle, nbss_handle;

static int proto_nbns = -1;
static int hf_nbns_flags = -1;
static int hf_nbns_flags_response = -1;
static int hf_nbns_flags_opcode = -1;
static int hf_nbns_flags_authoritative = -1;
static int hf_nbns_flags_truncated = -1;
static int hf_nbns_flags_recdesired = -1;
static int hf_nbns_flags_recavail = -1;
static int hf_nbns_flags_broadcast = -1;
static int hf_nbns_flags_rcode = -1;
static int hf_nbns_transaction_id = -1;
static int hf_nbns_count_questions = -1;
static int hf_nbns_count_answers = -1;
static int hf_nbns_count_auth_rr = -1;
static int hf_nbns_count_add_rr = -1;
static int hf_nbns_name_flags = -1;
static int hf_nbns_name_flags_group = -1;
static int hf_nbns_name_flags_ont = -1;
static int hf_nbns_name_flags_drg = -1;
static int hf_nbns_name_flags_cnf = -1;
static int hf_nbns_name_flags_act = -1;
static int hf_nbns_name_flags_prm = -1;
static int hf_nbns_nb_flags = -1;
static int hf_nbns_nb_flags_group = -1;
static int hf_nbns_nb_flags_ont = -1;
static int hf_nbns_name = -1;
static int hf_nbns_type = -1;
static int hf_nbns_class = -1;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_nbns_num_alignment_errors = -1;
static int hf_nbns_data = -1;
static int hf_nbns_unit_id = -1;
static int hf_nbns_num_command_blocks = -1;
static int hf_nbns_num_retransmits = -1;
static int hf_nbns_period_of_statistics = -1;
static int hf_nbns_addr = -1;
static int hf_nbns_test_result = -1;
static int hf_nbns_num_pending_sessions = -1;
static int hf_nbns_num_no_resource_conditions = -1;
static int hf_nbns_session_data_packet_size = -1;
static int hf_nbns_version_number = -1;
static int hf_nbns_max_num_pending_sessions = -1;
static int hf_nbns_num_collisions = -1;
static int hf_nbns_num_good_sends = -1;
static int hf_nbns_num_send_aborts = -1;
static int hf_nbns_number_of_names = -1;
static int hf_nbns_num_crcs = -1;
static int hf_nbns_num_good_receives = -1;
static int hf_nbns_max_total_sessions_possible = -1;
static int hf_nbns_jumpers = -1;
static int hf_nbns_netbios_name = -1;
static int hf_nbns_ttl = -1;
static int hf_nbns_data_length = -1;

static gint ett_nbns = -1;
static gint ett_nbns_qd = -1;
static gint ett_nbns_flags = -1;
static gint ett_nbns_nb_flags = -1;
static gint ett_nbns_name_flags = -1;
static gint ett_nbns_rr = -1;
static gint ett_nbns_qry = -1;
static gint ett_nbns_ans = -1;

static expert_field ei_nbns_incomplete_entry = EI_INIT;

static int proto_nbdgm = -1;
static int hf_nbdgm_type = -1;
static int hf_nbdgm_flags = -1;
static int hf_nbdgm_fragment = -1;
static int hf_nbdgm_first = -1;
static int hf_nbdgm_node_type = -1;
static int hf_nbdgm_datagram_id = -1;
static int hf_nbdgm_src_ip = -1;
static int hf_nbdgm_src_port = -1;
static int hf_nbdgm_datagram_length = -1;
static int hf_nbdgm_packet_offset = -1;
static int hf_nbdgm_error_code = -1;
static int hf_nbdgm_source_name = -1;
static int hf_nbdgm_destination_name = -1;

static gint ett_nbdgm = -1;
static gint ett_nbdgm_flags = -1;

static int proto_nbss = -1;
static int hf_nbss_type = -1;
static int hf_nbss_flags = -1;
static int hf_nbss_flags_e = -1;
static int hf_nbss_length = -1;
static int hf_nbss_cifs_length = -1;
static int hf_nbss_error_code = -1;
static int hf_nbss_retarget_ip_address = -1;
static int hf_nbss_retarget_port = -1;
static int hf_nbss_continuation_data = -1;
static int hf_nbss_called_name = -1;
static int hf_nbss_calling_name = -1;

static gint ett_nbss = -1;
static gint ett_nbss_flags = -1;

/* desegmentation of NBSS over TCP */
static gboolean nbss_desegment = TRUE;

/* See RFC 1001 and 1002 for information on the first three, and see

   http://www.cifs.com/specs/draft-leach-cifs-v1-spec-01.txt

   Appendix B, and various messages on the CIFS mailing list such as

   http://discuss.microsoft.com/SCRIPTS/WA-MSD.EXE?A2=ind9811A&L=cifs&P=R386

   for information on the fourth. */
#define UDP_PORT_NBNS   137
#define UDP_PORT_NBDGM  138
#define TCP_PORT_NBSS   139
#define TCP_PORT_CIFS   445
#define TCP_NBSS_PORT_RANGE  "139,445"

/* Packet structure taken from RFC 1002. See also RFC 1001.
 * Opcode, flags, and rcode treated as "flags", similarly to DNS,
 * to make it easier to lift the dissection code from "packet-dns.c". */

/* Offsets of fields in the NBNS header. */
#define NBNS_ID         0
#define NBNS_FLAGS      2
#define NBNS_QUEST      4
#define NBNS_ANS        6
#define NBNS_AUTH       8
#define NBNS_ADD        10

/* Length of NBNS header. */
#define NBNS_HDRLEN     12

/* type values  */
#define T_NB            32              /* NetBIOS name service RR */
#define T_NBSTAT        33              /* NetBIOS node status RR */

/* Bit fields in the flags */
#define F_RESPONSE      (1<<15)         /* packet is response */
#define F_OPCODE        (0xF<<11)       /* query opcode */
#define OPCODE_SHIFT    11
#define F_AUTHORITATIVE (1<<10)         /* response is authoritative */
#define F_TRUNCATED     (1<<9)          /* response is truncated */
#define F_RECDESIRED    (1<<8)          /* recursion desired */
#define F_RECAVAIL      (1<<7)          /* recursion available */
#define F_BROADCAST     (1<<4)          /* broadcast/multicast packet */
#define F_RCODE         (0xF<<0)        /* reply code */

static const true_false_string tfs_flags_response = {
    "Message is a response",
    "Message is a query"
};

static const true_false_string tfs_flags_authoritative = {
    "Server is an authority for domain",
    "Server is not an authority for domain"
};

static const true_false_string tfs_flags_truncated = {
    "Message is truncated",
    "Message is not truncated"
};

static const true_false_string tfs_flags_recdesired = {
    "Do query recursively",
    "Don't do query recursively"
};

static const true_false_string tfs_flags_recavail = {
    "Server can do recursive queries",
    "Server can't do recursive queries"
};

static const true_false_string tfs_flags_broadcast = {
    "Broadcast packet",
    "Not a broadcast packet"
};

static const true_false_string tfs_nbss_flags_e = {
    "Add 65536 to length",
    "Add 0 to length"
};

/* Opcodes */
#define OPCODE_QUERY          0         /* standard query */
#define OPCODE_REGISTRATION   5         /* registration */
#define OPCODE_RELEASE        6         /* release name */
#define OPCODE_WACK           7         /* wait for acknowledgement */
#define OPCODE_REFRESH        8         /* refresh registration */
#define OPCODE_REFRESHALT     9         /* refresh registration (alternate opcode) */
#define OPCODE_MHREGISTRATION 15        /* multi-homed registration */

static const value_string opcode_vals[] = {
    { OPCODE_QUERY,          "Name query"                 },
    { OPCODE_REGISTRATION,   "Registration"               },
    { OPCODE_RELEASE,        "Release"                    },
    { OPCODE_WACK,           "Wait for acknowledgment"    },
    { OPCODE_REFRESH,        "Refresh"                    },
    { OPCODE_REFRESHALT,     "Refresh (alternate opcode)" },
    { OPCODE_MHREGISTRATION, "Multi-homed registration"   },
    { 0,                     NULL                         }
};

/* Reply codes */
#define RCODE_NOERROR   0
#define RCODE_FMTERROR  1
#define RCODE_SERVFAIL  2
#define RCODE_NAMEERROR 3
#define RCODE_NOTIMPL   4
#define RCODE_REFUSED   5
#define RCODE_ACTIVE    6
#define RCODE_CONFLICT  7

static const value_string rcode_vals[] = {
    { RCODE_NOERROR,   "No error"                        },
    { RCODE_FMTERROR,  "Request was invalidly formatted" },
    { RCODE_SERVFAIL,  "Server failure"                  },
    { RCODE_NAMEERROR, "Requested name does not exist"   },
    { RCODE_NOTIMPL,   "Request is not implemented"      },
    { RCODE_REFUSED,   "Request was refused"             },
    { RCODE_ACTIVE,    "Name is owned by another node"   },
    { RCODE_CONFLICT,  "Name is in conflict"             },
    { 0,               NULL                              }
};

/* Values for the "NB_FLAGS" field of RR data.  From RFC 1001 and 1002,
 * except for NB_FLAGS_ONT_H_NODE, which was discovered by looking at
 * packet traces. */
#define NB_FLAGS_ONT            (3<<(15-2))     /* bits for node type */
#define NB_FLAGS_ONT_B_NODE     (0<<(15-2))     /* B-mode node */
#define NB_FLAGS_ONT_P_NODE     (1<<(15-2))     /* P-mode node */
#define NB_FLAGS_ONT_M_NODE     (2<<(15-2))     /* M-mode node */
#define NB_FLAGS_ONT_H_NODE     (3<<(15-2))     /* H-mode node */

#define NB_FLAGS_G              (1<<(15-0))     /* group name */

/* Values for the "NAME_FLAGS" field of a NODE_NAME entry in T_NBSTAT
 * RR data.  From RFC 1001 and 1002; as I remember, the "NAME_FLAGS"
 * field doesn't include any special values for H-mode nodes, even
 * though one can register them (if so, perhaps that was done to
 * avoid surprising clients that don't know about H-mode nodes). */
#define NAME_FLAGS_PRM          (1<<(15-6))     /* name is permanent node name */

#define NAME_FLAGS_ACT          (1<<(15-5))     /* name is active */

#define NAME_FLAGS_CNF          (1<<(15-4))     /* name is in conflict */

#define NAME_FLAGS_DRG          (1<<(15-3))     /* name is being deregistered */

#define NAME_FLAGS_ONT          (3<<(15-2))     /* bits for node type */
#define NAME_FLAGS_ONT_B_NODE   (0<<(15-2))     /* B-mode node */
#define NAME_FLAGS_ONT_P_NODE   (1<<(15-2))     /* P-mode node */
#define NAME_FLAGS_ONT_M_NODE   (2<<(15-2))     /* M-mode node */

#define NAME_FLAGS_G            (1<<(15-0))     /* group name */

static const value_string name_flags_ont_vals[] = {
    { NAME_FLAGS_ONT_B_NODE, "B-node" },
    { NAME_FLAGS_ONT_P_NODE, "P-node" },
    { NAME_FLAGS_ONT_M_NODE, "M-node" },
    { 0,                     NULL     }
};

static const value_string nb_flags_ont_vals[] = {
    { NB_FLAGS_ONT_B_NODE, "B-node" },
    { NB_FLAGS_ONT_P_NODE, "P-node" },
    { NB_FLAGS_ONT_M_NODE, "M-node" },
    { NB_FLAGS_ONT_H_NODE, "H-node" },
    { 0,                   NULL     }
};

static const value_string nb_type_name_vals[] = {
    { T_NB,     "NB" },
    { T_NBSTAT, "NBSTAT" },
    { 0,        NULL     }
};

#define NBNAME_BUF_LEN 128

static void
add_rr_to_tree(proto_tree *rr_tree, tvbuff_t *tvb, int offset,
               const char *name, int namelen,
               int type, int class_val,
               guint ttl, gushort data_len)
{
    proto_tree_add_string(rr_tree, hf_nbns_name, tvb, offset+1, namelen-1, name);
    offset += namelen;
    proto_tree_add_uint(rr_tree, hf_nbns_type, tvb, offset, 2, type);
    offset += 2;
    proto_tree_add_uint(rr_tree, hf_nbns_class, tvb, offset, 2, class_val);
    offset += 2;
    proto_tree_add_uint_format_value(rr_tree, hf_nbns_ttl, tvb, offset, 4, ttl, "%s",
                        signed_time_secs_to_str(wmem_packet_scope(), ttl));
    offset += 4;
    proto_tree_add_uint(rr_tree, hf_nbns_data_length, tvb, offset, 2, data_len);
}

static int
get_nbns_name(tvbuff_t *tvb, int offset, int nbns_data_offset,
              char *name_ret, int name_ret_len, int *name_type_ret)
{
    int           name_len;
    const gchar  *name;
    const gchar  *nbname;
    char         *nbname_buf;
    const gchar  *pname;
    char          cname, cnbname;
    int           name_type;
    char         *pname_ret;
    size_t        idx = 0;
    guint         used_bytes;

    nbname_buf = (char *)wmem_alloc(wmem_packet_scope(), NBNAME_BUF_LEN);
    nbname = nbname_buf;
    used_bytes = get_dns_name(tvb, offset, 0, nbns_data_offset, &name, &name_len);

    /* OK, now undo the first-level encoding. */
    pname = &name[0];
    pname_ret = name_ret;

    for (;;) {
        /* Every two characters of the first level-encoded name
         * turn into one character in the decoded name. */
        cname = *pname;
        if (cname == '\0')
            break;              /* no more characters */
        if (cname == '.')
            break;              /* scope ID follows */
        if (cname < 'A' || cname > 'Z') {
            /* Not legal. */
            nbname = "Illegal NetBIOS name (1st character not between A and Z in first-level encoding)";
            goto bad;
        }
        cname -= 'A';
        cnbname = cname << 4;
        pname++;

        cname = *pname;
        if (cname == '\0' || cname == '.') {
            /* No more characters in the name - but we're in
             * the middle of a pair.  Not legal. */
            nbname = "Illegal NetBIOS name (odd number of bytes)";
            goto bad;
        }
        if (cname < 'A' || cname > 'Z') {
            /* Not legal. */
            nbname = "Illegal NetBIOS name (2nd character not between A and Z in first-level encoding)";
            goto bad;
        }
        cname -= 'A';
        cnbname |= cname;
        pname++;

        /* Do we have room to store the character? */
        if (idx < NETBIOS_NAME_LEN) {
            /* Yes - store the character. */
            nbname_buf[idx++] = cnbname;
        }
    }

    /* NetBIOS names are supposed to be exactly 16 bytes long. */
    if (idx != NETBIOS_NAME_LEN) {
        /* It's not. */
        snprintf(nbname_buf, NBNAME_BUF_LEN, "Illegal NetBIOS name (%lu bytes long)",
                   (unsigned long)idx);
        goto bad;
    }

    /* This one is; make its name printable. */
    name_type = process_netbios_name(nbname, name_ret, name_ret_len);
    pname_ret += MIN(strlen(name_ret), (size_t) name_ret_len);
    pname_ret += MIN(name_ret_len-(pname_ret-name_ret),
                     snprintf(pname_ret, name_ret_len-(gulong)(pname_ret-name_ret), "<%02x>", name_type));
    if (cname == '.') {
        /* We have a scope ID, starting at "pname"; append that to
         * the decoded host name. */
        snprintf(pname_ret, name_ret_len-(gulong)(pname_ret-name_ret), "%s", pname);
    }
    if (name_type_ret != NULL)
        *name_type_ret = name_type;
    return used_bytes;

bad:
    if (name_type_ret != NULL)
        *name_type_ret = -1;
    /* This is only valid because nbname is always assigned an error string
     * before jumping to bad: Otherwise nbname wouldn't be \0 terminated */
    snprintf(pname_ret, name_ret_len-(gulong)(pname_ret-name_ret), "%s", nbname);
    return used_bytes;
}


static int
get_nbns_name_type_class(tvbuff_t *tvb, int offset, int nbns_data_offset,
                         char *name_ret, int *name_len_ret, int *name_type_ret,
                         int *type_ret, int *class_ret)
{
    int name_len;
    int type;
    int rr_class;

    name_len = get_nbns_name(tvb, offset, nbns_data_offset, name_ret,
                             *name_len_ret, name_type_ret);
    offset += name_len;

    type = tvb_get_ntohs(tvb, offset);
    offset += 2;

    rr_class = tvb_get_ntohs(tvb, offset);

    *type_ret = type;
    *class_ret = rr_class;
    *name_len_ret = name_len;

    return name_len + 4;
}

static void
add_name_and_type(proto_tree *tree, tvbuff_t *tvb, int offset, int len,
                  int hf_tag, const char *name, int name_type)
{
    if (name_type != -1) {
        proto_tree_add_string_format_value(tree, hf_tag, tvb, offset, len, name, "%s (%s)",
                            name, netbios_name_type_descr(name_type));
    } else {
        proto_tree_add_string(tree, hf_tag, tvb, offset, len, name);
    }
}

#define MAX_NAME_LEN (NETBIOS_NAME_LEN - 1)*4 + MAX_DNAME_LEN + 64

static int
dissect_nbns_query(tvbuff_t *tvb, int offset, int nbns_data_offset,
                   column_info *cinfo, proto_tree *nbns_tree)
{
    int         len;
    char       *name;
    int         name_len;
    int         name_type;
    int         type;
    int         dns_class;
    const char *type_name;
    int         data_offset;
    int         data_start;
    proto_tree *q_tree;

    name = (char *)wmem_alloc(wmem_packet_scope(), MAX_NAME_LEN);
    data_start = data_offset = offset;

    name_len = MAX_NAME_LEN;
    len = get_nbns_name_type_class(tvb, offset, nbns_data_offset, name,
                                   &name_len, &name_type, &type, &dns_class);
    data_offset += len;

    type_name = val_to_str_const(type, nb_type_name_vals, "Unknown");

    if (cinfo != NULL)
        col_append_fstr(cinfo, COL_INFO, " %s %s", type_name, name);

    if (nbns_tree != NULL) {
        q_tree = proto_tree_add_subtree_format(nbns_tree, tvb, offset, len,
                                 ett_nbns_qd, NULL, "%s: type %s, class %s",  name, type_name,
                                 val_to_str_const(dns_class, dns_classes, "Unknown"));

        add_name_and_type(q_tree, tvb, offset, name_len, hf_nbns_name, name,
                          name_type);
        offset += name_len;

        proto_tree_add_uint(q_tree, hf_nbns_type, tvb, offset, 2, type);
        offset += 2;

        proto_tree_add_uint(q_tree, hf_nbns_class, tvb, offset, 2, dns_class);
        /*offset += 2;*/
    }

    return data_offset - data_start;
}

static void
nbns_add_nbns_flags(column_info *cinfo, proto_tree *nbns_tree, tvbuff_t *tvb, int offset, int is_wack)
{
    guint16     flag;
    static int * const req_flags[] = {
        &hf_nbns_flags_response,
        &hf_nbns_flags_opcode,
        &hf_nbns_flags_truncated,
        &hf_nbns_flags_recdesired,
        &hf_nbns_flags_broadcast,
        NULL
    };

    static int * const resp_flags[] = {
        &hf_nbns_flags_response,
        &hf_nbns_flags_opcode,
        &hf_nbns_flags_authoritative,
        &hf_nbns_flags_truncated,
        &hf_nbns_flags_recdesired,
        &hf_nbns_flags_recavail,
        &hf_nbns_flags_broadcast,
        &hf_nbns_flags_rcode,
        NULL
    };

    static int * const resp_wack_flags[] = {
        &hf_nbns_flags_response,
        &hf_nbns_flags_opcode,
        &hf_nbns_flags_authoritative,
        &hf_nbns_flags_truncated,
        &hf_nbns_flags_recdesired,
        &hf_nbns_flags_recavail,
        &hf_nbns_flags_broadcast,
        NULL
    };

    flag = tvb_get_ntohs(tvb, offset);
    if (cinfo) {
        if (flag & F_RESPONSE && !is_wack) {
            if ((flag & F_RCODE))
                col_append_fstr(cinfo, COL_INFO, ", %s",
                                val_to_str_const(flag & F_RCODE, rcode_vals,
                                                 "Unknown error"));
        }
    }

    if (!nbns_tree)
        return;

    if (flag & F_RESPONSE) {
        if (!is_wack) {
            proto_tree_add_bitmask(nbns_tree, tvb, offset, hf_nbns_flags, ett_nbns_flags, resp_flags, ENC_BIG_ENDIAN);
        } else {
            proto_tree_add_bitmask(nbns_tree, tvb, offset, hf_nbns_flags, ett_nbns_flags, resp_wack_flags, ENC_BIG_ENDIAN);
        }
    } else {
        proto_tree_add_bitmask(nbns_tree, tvb, offset, hf_nbns_flags, ett_nbns_flags, req_flags, ENC_BIG_ENDIAN);
    }
}

static void
nbns_add_nb_flags(proto_tree *rr_tree, tvbuff_t *tvb, int offset)
{
    proto_item *tf;
    gushort flag;
    static int * const flags[] = {
        &hf_nbns_nb_flags_group,
        &hf_nbns_nb_flags_ont,
        NULL
    };

    tf = proto_tree_add_bitmask(rr_tree, tvb, offset, hf_nbns_nb_flags, ett_nbns_nb_flags, flags, ENC_BIG_ENDIAN);

    flag = tvb_get_ntohs(tvb, offset);
    proto_item_append_text(tf, " (%s, %s)",
                val_to_str_const(flag & NB_FLAGS_ONT, nb_flags_ont_vals, "Unknown"),
                (flag & NB_FLAGS_G) ? "group" : "unique");
}

static void
nbns_add_name_flags(proto_tree *rr_tree, tvbuff_t *tvb, int offset)
{
    static int * const flags[] = {
        &hf_nbns_name_flags_group,
        &hf_nbns_name_flags_ont,
        &hf_nbns_name_flags_drg,
        &hf_nbns_name_flags_cnf,
        &hf_nbns_name_flags_act,
        &hf_nbns_name_flags_prm,
        NULL
    };

    proto_tree_add_bitmask(rr_tree, tvb, offset, hf_nbns_name_flags, ett_nbns_name_flags, flags, ENC_BIG_ENDIAN);
}

static int
dissect_nbns_answer(tvbuff_t *tvb, packet_info *pinfo, int offset, int nbns_data_offset,
                    column_info *cinfo, proto_tree *nbns_tree, int opcode)
{
    int         len;
    char       *name;
    int         name_len;
    int         name_type;
    int         type;
    int         dns_class;
    const char *class_name;
    const char *type_name;
    int         cur_offset;
    guint       ttl;
    gushort     data_len;
    proto_tree *rr_tree = NULL;
    char       *name_str;
    guint       num_names;
    char       *nbname;

    cur_offset = offset;

    name     = (char *)wmem_alloc(wmem_packet_scope(), MAX_NAME_LEN);
    name_str = (char *)wmem_alloc(wmem_packet_scope(), MAX_NAME_LEN);
    nbname   = (char *)wmem_alloc(wmem_packet_scope(), 16+4+1); /* 4 for [<last char>] */

    name_len = MAX_NAME_LEN;
    len      = get_nbns_name_type_class(tvb, offset, nbns_data_offset, name,
                                        &name_len, &name_type, &type, &dns_class);
    cur_offset  += len;

    type_name  = val_to_str_const(type, nb_type_name_vals, "Unknown");
    class_name = val_to_str_const(dns_class, dns_classes, "Unknown");

    ttl = tvb_get_ntohl(tvb, cur_offset);
    cur_offset  += 4;

    data_len = tvb_get_ntohs(tvb, cur_offset);
    cur_offset  += 2;

    /* XXX: This code should be simplified */
    switch (type) {
    case T_NB:          /* "NB" record */
        if (cinfo != NULL) {
            if (opcode != OPCODE_WACK) {
                col_append_fstr(cinfo, COL_INFO, " %s %s",
                                type_name,
                                tvb_ip_to_str(pinfo->pool, tvb, cur_offset+2));
            }
        }

        if (nbns_tree) {
            rr_tree = proto_tree_add_subtree_format(nbns_tree, tvb, offset,
                                      (cur_offset - offset) + data_len,
                                      ett_nbns_rr, NULL, "%s: type %s, class %s",
                                      name, type_name, class_name);
            (void) g_strlcat(name, " (", MAX_NAME_LEN);
            (void) g_strlcat(name, netbios_name_type_descr(name_type), MAX_NAME_LEN);
            (void) g_strlcat(name, ")", MAX_NAME_LEN);
            add_rr_to_tree(rr_tree, tvb, offset, name,
                                 name_len, type, dns_class, ttl, data_len);
        }
        while (data_len > 0) {
            if (opcode == OPCODE_WACK) {
                /* WACK response.  This doesn't contain the
                 * same type of RR data as other T_NB
                 * responses.  */
                if (data_len < 2) {
                    proto_tree_add_expert(rr_tree, pinfo, &ei_nbns_incomplete_entry, tvb, cur_offset, data_len);
                    break;
                }
                nbns_add_nbns_flags(cinfo, rr_tree, tvb, cur_offset, 1);
                cur_offset += 2;
                data_len   -= 2;
            } else {
                if (data_len < 2) {
                    proto_tree_add_expert(rr_tree, pinfo, &ei_nbns_incomplete_entry, tvb, cur_offset, data_len);
                    break;
                }
                nbns_add_nb_flags(rr_tree, tvb, cur_offset);
                cur_offset += 2;
                data_len   -= 2;

                if (data_len < 4) {
                    proto_tree_add_expert(rr_tree, pinfo, &ei_nbns_incomplete_entry, tvb, cur_offset, data_len);
                    break;
                }
                proto_tree_add_item(rr_tree, hf_nbns_addr, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
                cur_offset += 4;
                data_len   -= 4;
            }
        }
        break;

    case T_NBSTAT:      /* "NBSTAT" record */
        if (cinfo != NULL)
            col_append_fstr(cinfo, COL_INFO, " %s", type_name);

        if (nbns_tree) {
            rr_tree = proto_tree_add_subtree_format(nbns_tree, tvb, offset,
                                      (cur_offset - offset) + data_len,
                                      ett_nbns_rr, NULL, "%s: type %s, class %s",
                                      name, type_name, class_name);
            add_rr_to_tree(rr_tree, tvb, offset, name,
                                     name_len, type, dns_class, ttl, data_len);
        }

        if (data_len < 1) {
            proto_tree_add_expert(rr_tree, pinfo, &ei_nbns_incomplete_entry, tvb, cur_offset, data_len);
            break;
        }

        num_names = tvb_get_guint8(tvb, cur_offset);
        proto_tree_add_item(rr_tree, hf_nbns_number_of_names, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
        cur_offset += 1;

        while (num_names != 0) {
            if (data_len < NETBIOS_NAME_LEN) {
                proto_tree_add_expert(rr_tree, pinfo, &ei_nbns_incomplete_entry, tvb, cur_offset, data_len);
                goto out;
            }
            if (rr_tree) {
                tvb_memcpy(tvb, (guint8 *)nbname, cur_offset,
                           NETBIOS_NAME_LEN);
                name_type = process_netbios_name(nbname,
                                                 name_str, name_len);
                proto_tree_add_string_format_value(rr_tree, hf_nbns_netbios_name, tvb, cur_offset,
                                    NETBIOS_NAME_LEN, name_str, "%s<%02x> (%s)",
                                    name_str, name_type,
                                    netbios_name_type_descr(name_type));
            }
            cur_offset += NETBIOS_NAME_LEN;
            data_len   -= NETBIOS_NAME_LEN;

            if (data_len < 2) {
                proto_tree_add_expert(rr_tree, pinfo, &ei_nbns_incomplete_entry, tvb, cur_offset, data_len);
                goto out;
            }
            if (rr_tree) {
                nbns_add_name_flags(rr_tree, tvb, cur_offset);
            }
            cur_offset += 2;
            data_len   -= 2;

            num_names--;
        }

        if (data_len < 6) {
            proto_tree_add_expert(rr_tree, pinfo, &ei_nbns_incomplete_entry, tvb, cur_offset, data_len);
            break;
        }

        proto_tree_add_item(rr_tree, hf_nbns_unit_id, tvb, cur_offset, 6, ENC_NA);
        cur_offset += 6;
        data_len   -= 6;

        if (data_len < 1) {
            proto_tree_add_expert(rr_tree, pinfo, &ei_nbns_incomplete_entry, tvb, cur_offset, data_len);
            break;
        }

        proto_tree_add_item(rr_tree, hf_nbns_jumpers, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
        cur_offset += 1;
        data_len   -= 1;

        if (data_len < 1) {
            proto_tree_add_expert(rr_tree, pinfo, &ei_nbns_incomplete_entry, tvb, cur_offset, data_len);
            break;
        }

        proto_tree_add_item(rr_tree, hf_nbns_test_result, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
        cur_offset += 1;
        data_len   -= 1;

        if (data_len < 2) {
            proto_tree_add_expert(rr_tree, pinfo, &ei_nbns_incomplete_entry, tvb, cur_offset, data_len);
            break;
        }

        proto_tree_add_item(rr_tree, hf_nbns_version_number, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
        cur_offset += 2;
        data_len   -= 2;

        if (data_len < 2) {
            proto_tree_add_expert(rr_tree, pinfo, &ei_nbns_incomplete_entry, tvb, cur_offset, data_len);
            break;
        }

        proto_tree_add_item(rr_tree, hf_nbns_period_of_statistics, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
        cur_offset += 2;
        data_len   -= 2;

        if (data_len < 2) {
           proto_tree_add_expert(rr_tree, pinfo, &ei_nbns_incomplete_entry, tvb, cur_offset, data_len);
            break;
        }

        proto_tree_add_item(rr_tree, hf_nbns_num_crcs, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
        cur_offset += 2;
        data_len   -= 2;

        if (data_len < 2) {
            proto_tree_add_expert(rr_tree, pinfo, &ei_nbns_incomplete_entry, tvb, cur_offset, data_len);
            break;
        }

        proto_tree_add_item(rr_tree, hf_nbns_num_alignment_errors, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
        cur_offset += 2;
        data_len   -= 2;

        if (data_len < 2) {
            proto_tree_add_expert(rr_tree, pinfo, &ei_nbns_incomplete_entry, tvb, cur_offset, data_len);
            break;
        }

        proto_tree_add_item(rr_tree, hf_nbns_num_collisions, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
        cur_offset += 2;
        data_len   -= 2;

        if (data_len < 2) {
            proto_tree_add_expert(rr_tree, pinfo, &ei_nbns_incomplete_entry, tvb, cur_offset, data_len);
            break;
        }

        proto_tree_add_item(rr_tree, hf_nbns_num_send_aborts, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
        cur_offset += 2;
        data_len   -= 2;

        if (data_len < 4) {
            proto_tree_add_expert(rr_tree, pinfo, &ei_nbns_incomplete_entry, tvb, cur_offset, data_len);
            break;
        }

        proto_tree_add_item(rr_tree, hf_nbns_num_good_sends, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
        cur_offset += 4;
        data_len   -= 4;

        if (data_len < 4) {
            proto_tree_add_expert(rr_tree, pinfo, &ei_nbns_incomplete_entry, tvb, cur_offset, data_len);
            break;
        }

        proto_tree_add_item(rr_tree, hf_nbns_num_good_receives, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
        cur_offset += 4;
        data_len   -= 4;

        if (data_len < 2) {
            proto_tree_add_expert(rr_tree, pinfo, &ei_nbns_incomplete_entry, tvb, cur_offset, data_len);
            break;
        }

        proto_tree_add_item(rr_tree, hf_nbns_num_retransmits, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
        cur_offset += 2;
        data_len   -= 2;

        if (data_len < 2) {
            proto_tree_add_expert(rr_tree, pinfo, &ei_nbns_incomplete_entry, tvb, cur_offset, data_len);
            break;
        }

        proto_tree_add_item(rr_tree, hf_nbns_num_no_resource_conditions, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
        cur_offset += 2;
        data_len   -= 2;

        if (data_len < 2) {
            proto_tree_add_expert(rr_tree, pinfo, &ei_nbns_incomplete_entry, tvb, cur_offset, data_len);
            break;
        }

        proto_tree_add_item(rr_tree, hf_nbns_num_command_blocks, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
        cur_offset += 2;
        data_len   -= 2;

        if (data_len < 2) {
            proto_tree_add_expert(rr_tree, pinfo, &ei_nbns_incomplete_entry, tvb, cur_offset, data_len);
            break;
        }

        proto_tree_add_item(rr_tree, hf_nbns_num_pending_sessions, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
        cur_offset += 2;
        data_len   -= 2;

        if (data_len < 2) {
            proto_tree_add_expert(rr_tree, pinfo, &ei_nbns_incomplete_entry, tvb, cur_offset, data_len);
            break;
        }

        proto_tree_add_item(rr_tree, hf_nbns_max_num_pending_sessions, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
        cur_offset += 2;
        data_len   -= 2;

        if (data_len < 2) {
            proto_tree_add_expert(rr_tree, pinfo, &ei_nbns_incomplete_entry, tvb, cur_offset, data_len);
            break;
        }

        proto_tree_add_item(rr_tree, hf_nbns_max_total_sessions_possible, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
        cur_offset += 2;
        data_len   -= 2;

        if (data_len < 2) {
            proto_tree_add_expert(rr_tree, pinfo, &ei_nbns_incomplete_entry, tvb, cur_offset, data_len);
            break;
        }

        proto_tree_add_item(rr_tree, hf_nbns_session_data_packet_size, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
        cur_offset += 2;
        /*data_len -= 2;*/
    out:
        break;

    default:
        if (cinfo != NULL)
            col_append_fstr(cinfo, COL_INFO, " %s", type_name);

        if (nbns_tree) {
            rr_tree = proto_tree_add_subtree_format(nbns_tree, tvb, offset,
                                      (cur_offset - offset) + data_len,
                                      ett_nbns_rr, NULL, "%s: type %s, class %s",
                                      name, type_name, class_name);
            add_rr_to_tree(rr_tree, tvb, offset, name,
                                     name_len, type, dns_class, ttl, data_len);
            proto_tree_add_item(rr_tree, hf_nbns_data, tvb, cur_offset, data_len, ENC_NA);
        }
        cur_offset += data_len;
        break;
    }

    return cur_offset - offset;
}

static int
dissect_query_records(tvbuff_t *tvb, int cur_off, int nbns_data_offset,
                      int count, column_info *cinfo, proto_tree *nbns_tree)
{
    int         start_off, add_off;
    proto_tree *qatree;
    proto_item *ti;

    start_off = cur_off;
    qatree = proto_tree_add_subtree(nbns_tree, tvb, start_off, -1, ett_nbns_qry, &ti, "Queries");

    while (count-- > 0) {
        add_off = dissect_nbns_query(tvb, cur_off, nbns_data_offset,
                                     cinfo, qatree);
        cur_off += add_off;
    }

    proto_item_set_len(ti, cur_off - start_off);

    return cur_off - start_off;
}

static int
dissect_answer_records(tvbuff_t *tvb, packet_info *pinfo, int cur_off, int nbns_data_offset,
                       int count, column_info *cinfo, proto_tree *nbns_tree,
                       int opcode, const char *name)
{
    int         start_off, add_off;
    proto_tree *qatree;
    proto_item *ti;

    start_off = cur_off;
    qatree = proto_tree_add_subtree(nbns_tree, tvb, start_off, -1, ett_nbns_ans, &ti, name);

    while (count-- > 0) {
        add_off = dissect_nbns_answer(tvb, pinfo, cur_off, nbns_data_offset,
                                      cinfo, qatree, opcode);
        cur_off += add_off;
    }

    proto_item_set_len(ti, cur_off - start_off);
    return cur_off - start_off;
}

static int
dissect_nbns(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int          offset    = 0;
    int          nbns_data_offset;
    proto_tree  *nbns_tree = NULL;
    proto_item  *ti;
    guint32      id, flags, opcode, quest, ans, auth, add;
    int          cur_off;

    nbns_data_offset = offset;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NBNS");
    col_clear(pinfo->cinfo, COL_INFO);

    /* To do: check for runts, errs, etc. */
    id     = tvb_get_ntohs(tvb, offset + NBNS_ID);
    flags  = tvb_get_ntohs(tvb, offset + NBNS_FLAGS);
    opcode = (guint16) ((flags & F_OPCODE) >> OPCODE_SHIFT);

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s%s",
                    val_to_str(opcode, opcode_vals, "Unknown operation (%u)"),
                    (flags & F_RESPONSE) ? " response" : "");

    ti = proto_tree_add_item(tree, proto_nbns, tvb, offset, -1, ENC_NA);
    nbns_tree = proto_item_add_subtree(ti, ett_nbns);

    proto_tree_add_uint(nbns_tree, hf_nbns_transaction_id, tvb,
                        offset + NBNS_ID, 2, id);

    nbns_add_nbns_flags(pinfo->cinfo, nbns_tree, tvb, offset + NBNS_FLAGS, 0);

    proto_tree_add_item_ret_uint(nbns_tree, hf_nbns_count_questions, tvb,
                            offset + NBNS_QUEST, 2, ENC_BIG_ENDIAN, &quest);
    proto_tree_add_item_ret_uint(nbns_tree, hf_nbns_count_answers, tvb,
                            offset + NBNS_ANS, 2, ENC_BIG_ENDIAN, &ans);
    proto_tree_add_item_ret_uint(nbns_tree, hf_nbns_count_auth_rr, tvb,
                            offset + NBNS_AUTH, 2, ENC_BIG_ENDIAN, &auth);
    proto_tree_add_item_ret_uint(nbns_tree, hf_nbns_count_add_rr, tvb,
                            offset + NBNS_ADD, 2, ENC_BIG_ENDIAN, &add);

    cur_off = offset + NBNS_HDRLEN;

    if (quest > 0) {
        /* If this is a response, don't add information about the
           queries to the summary, just add information about the
           answers. */
        cur_off += dissect_query_records(tvb, cur_off,
                                         nbns_data_offset, quest,
                                         (!(flags & F_RESPONSE) ? pinfo->cinfo : NULL), nbns_tree);
    }

    if (ans > 0) {
        /* If this is a request, don't add information about the
           answers to the summary, just add information about the
           queries. */
        cur_off += dissect_answer_records(tvb, pinfo, cur_off,
                                          nbns_data_offset, ans,
                                          ((flags & F_RESPONSE) ? pinfo->cinfo : NULL), nbns_tree,
                                          opcode, "Answers");
    }

    /* Don't add information about the authoritative name
       servers, or the additional records, to the summary. */
    if (auth > 0)
        cur_off += dissect_answer_records(tvb, pinfo, cur_off,
                                          nbns_data_offset,
                                          auth, NULL, nbns_tree, opcode,
                                          "Authoritative nameservers");

    if (add > 0)
        /*cur_off += */dissect_answer_records(tvb, pinfo, cur_off,
                                              nbns_data_offset,
                                              add, NULL, nbns_tree, opcode,
                                              "Additional records");

    return tvb_captured_length(tvb);
}

static heur_dissector_list_t netbios_heur_subdissector_list;

static void
dissect_netbios_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    heur_dtbl_entry_t *hdtbl_entry;

    /*
     * Try the heuristic dissectors for NetBIOS; if none of them
     * accept the packet, dissect it as data.
     */
    if (!dissector_try_heuristic(netbios_heur_subdissector_list,
                                 tvb, pinfo, tree, &hdtbl_entry, NULL))
        call_data_dissector(tvb, pinfo, tree);
}

/*
 * NBDS message types.
 */
#define NBDS_DIRECT_UNIQUE      0x10
#define NBDS_DIRECT_GROUP       0x11
#define NBDS_BROADCAST          0x12
#define NBDS_ERROR              0x13
#define NBDS_QUERY_REQUEST      0x14
#define NBDS_POS_QUERY_RESPONSE 0x15
#define NBDS_NEG_QUERY_RESPONSE 0x16

static const value_string nbds_msgtype_vals[] = {
    { NBDS_DIRECT_UNIQUE,      "Direct_unique datagram" },
    { NBDS_DIRECT_GROUP,       "Direct_group datagram" },
    { NBDS_BROADCAST,          "Broadcast datagram" },
    { NBDS_ERROR,              "Datagram error" },
    { NBDS_QUERY_REQUEST,      "Datagram query request" },
    { NBDS_POS_QUERY_RESPONSE, "Datagram positive query response" },
    { NBDS_NEG_QUERY_RESPONSE, "Datagram negative query response" },
    { 0,                       NULL }
};

static const value_string node_type_vals[] = {
    { 0, "B node" },
    { 1, "P node" },
    { 2, "M node" },
    { 3, "NBDD" },
    { 0, NULL }
};

static const value_string nbds_error_codes[] = {
    { 0x82, "Destination name not present" },
    { 0x83, "Invalid source name format" },
    { 0x84, "Invalid destination name format" },
    { 0x00, NULL }
};

static int
dissect_nbdgm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int                  offset     = 0;
    proto_tree          *nbdgm_tree;
    proto_item          *ti;
    tvbuff_t            *next_tvb;
    guint32              msg_type;

    char *name;
    int name_type;
    int len;

    static int * const flags[] = {
        &hf_nbdgm_fragment,
        &hf_nbdgm_first,
        &hf_nbdgm_node_type,
        NULL
    };

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NBDS");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_nbdgm, tvb, offset, -1, ENC_NA);
    nbdgm_tree = proto_item_add_subtree(ti, ett_nbdgm);

    proto_tree_add_item_ret_uint(nbdgm_tree, hf_nbdgm_type, tvb,
                            offset, 1, ENC_NA, &msg_type);

    col_add_str(pinfo->cinfo, COL_INFO,
                val_to_str(msg_type, nbds_msgtype_vals,
                           "Unknown message type (0x%02X)"));

    proto_tree_add_bitmask(nbdgm_tree, tvb, offset+1, hf_nbdgm_flags, ett_nbdgm_flags, flags, ENC_BIG_ENDIAN);

    proto_tree_add_item(nbdgm_tree, hf_nbdgm_datagram_id, tvb, offset+2, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(nbdgm_tree, hf_nbdgm_src_ip, tvb, offset+4, 4, ENC_BIG_ENDIAN);

    proto_tree_add_item(nbdgm_tree, hf_nbdgm_src_port, tvb, offset+8, 2, ENC_BIG_ENDIAN);

    offset += 10;

    switch (msg_type) {

    case NBDS_DIRECT_UNIQUE:
    case NBDS_DIRECT_GROUP:
    case NBDS_BROADCAST:
        proto_tree_add_item(nbdgm_tree, hf_nbdgm_datagram_length,
                                            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(nbdgm_tree, hf_nbdgm_packet_offset,
                                            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        name = (char *)wmem_alloc(wmem_packet_scope(), MAX_NAME_LEN);

        /* Source name */
        len = get_nbns_name(tvb, offset, offset, name, MAX_NAME_LEN, &name_type);

        add_name_and_type(nbdgm_tree, tvb, offset, len, hf_nbdgm_source_name, name, name_type);
        offset += len;

        /* Destination name */
        len = get_nbns_name(tvb, offset, offset, name, MAX_NAME_LEN, &name_type);

        add_name_and_type(nbdgm_tree, tvb, offset, len, hf_nbdgm_destination_name, name, name_type);
        offset += len;

        /*
         * Here we can pass the packet off to the next protocol.
         * Set the length of our top-level tree item to include
         * only our stuff.
         *
         * XXX - take the datagram length into account, including
         * doing datagram reassembly?
         */
        proto_item_set_len(ti, offset);
        next_tvb = tvb_new_subset_remaining(tvb, offset);
        dissect_netbios_payload(next_tvb, pinfo, tree);
        break;

    case NBDS_ERROR:
        proto_tree_add_item(nbdgm_tree, hf_nbdgm_error_code, tvb, offset,
                                1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_item_set_len(ti, offset);
        break;

    case NBDS_QUERY_REQUEST:
    case NBDS_POS_QUERY_RESPONSE:
    case NBDS_NEG_QUERY_RESPONSE:
        name = (char *)wmem_alloc(wmem_packet_scope(), MAX_NAME_LEN);

        /* Destination name */
        len = get_nbns_name(tvb, offset, offset, name, MAX_NAME_LEN, &name_type);

        add_name_and_type(nbdgm_tree, tvb, offset, len,
                              hf_nbdgm_destination_name, name, name_type);
        offset += len;
        proto_item_set_len(ti, offset);
        break;
    }
    return tvb_captured_length(tvb);
}

/*
 * NetBIOS Session Service message types (RFC 1002).
 */
#define SESSION_MESSAGE                 0x00
#define SESSION_REQUEST                 0x81
#define POSITIVE_SESSION_RESPONSE       0x82
#define NEGATIVE_SESSION_RESPONSE       0x83
#define RETARGET_SESSION_RESPONSE       0x84
#define SESSION_KEEP_ALIVE              0x85

static const value_string message_types[] = {
    { SESSION_MESSAGE,           "Session message" },
    { SESSION_REQUEST,           "Session request" },
    { POSITIVE_SESSION_RESPONSE, "Positive session response" },
    { NEGATIVE_SESSION_RESPONSE, "Negative session response" },
    { RETARGET_SESSION_RESPONSE, "Retarget session response" },
    { SESSION_KEEP_ALIVE,        "Session keep-alive" },
    { 0x0,                       NULL }
};

/*
 * NetBIOS Session Service flags.
 */
#define NBSS_FLAGS_E                    0x1

static const value_string nbss_error_codes[] = {
    { 0x80, "Not listening on called name" },
    { 0x81, "Not listening for calling name" },
    { 0x82, "Called name not present" },
    { 0x83, "Called name present, but insufficient resources" },
    { 0x8F, "Unspecified error" },
    { 0x0,  NULL }
};

/*
 * Dissect a single NBSS packet (there may be more than one in a given
 * TCP segment).
 *
 * [ Hmmm, in my experience, I have never seen more than one NBSS in a
 * single segment, since they mostly contain SMBs which are essentially
 * a request response type protocol (RJS). ]
 *
 * [ However, under heavy load with many requests multiplexed on one
 * session it is not unusual to see multiple requests in one TCP
 * segment. Unfortunately, in this case a single session message is
 * frequently split over multiple segments, which frustrates decoding
 * (MMM). ]
 */
static void
dissect_nbss_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    int is_cifs)
{
    int          offset = 0;
    proto_tree   *nbss_tree = NULL;
    proto_item   *ti        = NULL;
    guint8        msg_type;
    guint8        flags;
    guint32       length;
    int           len;
    char         *name;
    int           name_type;
    guint8        error_code;
    tvbuff_t     *next_tvb;
    const char   *saved_proto;
    static int * const nbss_flags[] = {
        &hf_nbss_flags_e,
        NULL
    };

    name = (char *)wmem_alloc(wmem_packet_scope(), MAX_NAME_LEN);

    msg_type = tvb_get_guint8(tvb, offset);

    ti = proto_tree_add_item(tree, proto_nbss, tvb, offset, -1, ENC_NA);
    nbss_tree = proto_item_add_subtree(ti, ett_nbss);

    proto_tree_add_item(nbss_tree, hf_nbss_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;

    if (is_cifs) {
        proto_tree_add_item(nbss_tree, hf_nbss_cifs_length, tvb, offset, 3, ENC_BIG_ENDIAN);
        offset += 3;
    } else {
        flags = tvb_get_guint8(tvb, offset);
        proto_tree_add_bitmask(nbss_tree, tvb, offset, hf_nbss_flags, ett_nbss_flags, nbss_flags, ENC_BIG_ENDIAN);

        length = tvb_get_ntohs(tvb, offset + 1);
        if (flags & NBSS_FLAGS_E)
            length += 0x10000;
        proto_tree_add_uint(nbss_tree, hf_nbss_length, tvb, offset, 3, length);

        offset += 3;
    }

    switch (msg_type) {

    case SESSION_REQUEST:
        len = get_nbns_name(tvb, offset, offset, name, MAX_NAME_LEN, &name_type);
        if (tree)
            add_name_and_type(nbss_tree, tvb, offset, len,
                              hf_nbss_called_name, name, name_type);
        offset += len;

        col_append_fstr(pinfo->cinfo, COL_INFO, ", to %s ", name);

        len = get_nbns_name(tvb, offset, offset, name, MAX_NAME_LEN, &name_type);

        if (tree)
            add_name_and_type(nbss_tree, tvb, offset, len,
                              hf_nbss_calling_name, name, name_type);

        col_append_fstr(pinfo->cinfo, COL_INFO, "from %s", name);

        break;

    case NEGATIVE_SESSION_RESPONSE:
        error_code = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(nbss_tree, hf_nbss_error_code, tvb, offset, 1,
                                error_code);

        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
                        val_to_str(error_code, nbss_error_codes, "Unknown (%x)"));

        break;

    case RETARGET_SESSION_RESPONSE:
        proto_tree_add_item(nbss_tree, hf_nbss_retarget_ip_address,
                                tvb, offset, 4, ENC_BIG_ENDIAN);

        offset += 4;

        proto_tree_add_item(nbss_tree, hf_nbss_retarget_port,
                                tvb, offset, 2, ENC_BIG_ENDIAN);

        break;

    case SESSION_MESSAGE:
        /*
         * Here we can pass the message off to the next protocol.
         * Set the length of our top-level tree item to include
         * only our stuff.
         */
        next_tvb = tvb_new_subset_remaining(tvb, offset);

        /*
         * Dissect the message.
         *
         * If it gets an error that means there's no point in
         * dissecting any more PDUs, rethrow the exception in
         * question.
         *
         * If it gets any other error, report it and continue, as that
         * means that PDU got an error, but that doesn't mean we should
         * stop dissecting PDUs within this frame or chunk of reassembled
         * data.
         */
        saved_proto = pinfo->current_proto;
        TRY {
            dissect_netbios_payload(next_tvb, pinfo, tree);
        }
        CATCH_NONFATAL_ERRORS {
            show_exception(tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
            pinfo->current_proto = saved_proto;
        }
        ENDTRY;
        break;

    }
}

static int
dissect_continuation_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree     *nbss_tree;
    proto_item     *ti;

    /*
     * It looks like a continuation.
     */
    col_set_str(pinfo->cinfo, COL_INFO, "NBSS Continuation Message");

    if (tree) {
        ti = proto_tree_add_item(tree, proto_nbss, tvb, 0, -1, ENC_NA);
        nbss_tree = proto_item_add_subtree(ti, ett_nbss);
        proto_tree_add_item(nbss_tree, hf_nbss_continuation_data, tvb, 0, -1, ENC_NA);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_nbss(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    struct tcpinfo *tcpinfo;
    int             offset  = 0;
    guint           length_remaining;
    guint           plen;
    int             max_data;
    guint8          msg_type;
    guint8          flags;
    guint32         length;
    gboolean        is_cifs;
    tvbuff_t       *next_tvb;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    tcpinfo = (struct tcpinfo *)data;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NBSS");
    col_clear(pinfo->cinfo, COL_INFO);

    max_data = tvb_captured_length(tvb);

    msg_type = tvb_get_guint8(tvb, offset);

    if (pinfo->match_uint == TCP_PORT_CIFS) {
        /*
         * Windows 2000 CIFS clients can dispense completely
         * with the NETBIOS encapsulation and directly use CIFS
         * over TCP. As would be expected, the framing is
         * identical, except that the length is 24 bits instead
         * of 17. The only message types used are
         * SESSION_MESSAGE and SESSION_KEEP_ALIVE.
         */
        is_cifs = TRUE;
    } else {
        is_cifs = FALSE;
    }

    /*
     * This might be a continuation of an earlier message.
     * (Yes, that might be true even if we're doing TCP reassembly,
     * as the first TCP segment in the capture might start in the
     * middle of an NBNS message.)
     */

    /*
     * If this isn't reassembled data, check to see whether it
     * looks like a continuation of a message.
     * (If it is reassembled data, it shouldn't be a continuation,
     * as reassembly should've gathered the continuations together
     * into a message.)
     */
    if (!tcpinfo->is_reassembled) {
        if (max_data < 4) {
            /*
             * Not enough data for an NBSS header; assume
             * it's a continuation of a message.
             *
             * XXX - if there's not enough data, we should
             * attempt to reassemble the data, if the first byte
             * is a valid message type.
             */
            return dissect_continuation_packet(tvb, pinfo, tree);
        }

        /*
         * The largest size in for non-SMB NBSS traffic is
         * 17 bits (0x1FFFF).
         *
         * The SMB1 unix extensions and the SMB2 multi credit
         * feature allow more than 17 bits (0x1FFFF), they allow
         * 24 bits (0xFFFFFF).
         *
         * So if it is a SESSION_MESSAGE and SMB1 or SMB2
         * mark it as is_cifs.
         */
        if (tvb_captured_length_remaining(tvb, offset) >= 8
            && tvb_get_guint8(tvb,offset+0) == SESSION_MESSAGE
            && tvb_get_guint8(tvb,offset+5) == 'S'
            && tvb_get_guint8(tvb,offset+6) == 'M'
            && tvb_get_guint8(tvb,offset+7) == 'B') {
            is_cifs = TRUE;
        } else {
            is_cifs = FALSE;
        }

        /*
         * We have enough data for an NBSS header.
         * Get the flags and length of the message,
         * and see if they're sane.
         */
        if (is_cifs) {
            flags = 0;
            length = tvb_get_ntoh24(tvb, offset + 1);
        } else {
            flags  = tvb_get_guint8(tvb, offset + 1);
            length = tvb_get_ntohs(tvb, offset + 2);
            if (flags & NBSS_FLAGS_E)
                length += 0x10000;
        }
        if ((flags & (~NBSS_FLAGS_E)) != 0) {
            /*
             * A bogus flag was set; assume it's a continuation.
             */
            return dissect_continuation_packet(tvb, pinfo, tree);
        }

        switch (msg_type) {

        case SESSION_MESSAGE:
            /*
             * This is variable-length.
             * All we know is that it shouldn't be zero.
             * (XXX - can we get zero-length messages?
             * Not with SMB, but perhaps other NetBIOS-based
             * protocols have them.)
             */
            if (length == 0)
                return dissect_continuation_packet(tvb, pinfo, tree);

            break;

        case SESSION_REQUEST:
            /*
             * This is variable-length.
             * The names are DNS-encoded 32-byte values;
             * we need at least 2 bytes (one for each name;
             * actually, we should have more for the first
             * name, as there's no name preceding it so
             * there should be no compression), and we
             * shouldn't have more than 128 bytes (actually,
             * we shouldn't have that many).
             *
             * XXX - actually, Mac OS X 10.1 (yes, that's
             * redundant, but that's what Apple calls it,
             * not Mac OS X.1) puts names longer than 16
             * characters into session request messages,
             * so we can have more than 32 bytes of
             * name value, so we can have more than 128
             * bytes of data.
             */
            if (length < 2 || length > 256)
                return dissect_continuation_packet(tvb, pinfo, tree);
            break;

        case POSITIVE_SESSION_RESPONSE:
            /*
             * This has no data, so the length must be zero.
             */
            if (length != 0)
                return dissect_continuation_packet(tvb, pinfo, tree);
            break;

        case NEGATIVE_SESSION_RESPONSE:
            /*
             * This has 1 byte of data.
             */
            if (length != 1)
                return dissect_continuation_packet(tvb, pinfo, tree);
            break;

        case RETARGET_SESSION_RESPONSE:
            /*
             * This has 6 bytes of data.
             */
            if (length != 6)
                return dissect_continuation_packet(tvb, pinfo, tree);
            break;

        case SESSION_KEEP_ALIVE:
            /*
             * This has no data, so the length must be zero.
             */
            if (length != 0)
                return dissect_continuation_packet(tvb, pinfo, tree);
            break;

        default:
            /*
             * Unknown message type; assume it's a continuation.
             */
            return dissect_continuation_packet(tvb, pinfo, tree);
        }
    }

    col_add_str(pinfo->cinfo, COL_INFO,
                val_to_str(msg_type, message_types, "Unknown (%02x)"));

    while ((length_remaining = tvb_reported_length_remaining(tvb, offset)) > 0) {
        /*
         * Can we do reassembly?
         */
        if (nbss_desegment && pinfo->can_desegment) {
            /*
             * Yes - is the NBSS header split across segment boundaries?
             */
            if (length_remaining < 4) {
                /*
                 * Yes.  Tell the TCP dissector where the data for this message
                 * starts in the data it handed us and that we need "some more
                 * data."  Don't tell it exactly how many bytes we need because
                 * if/when we ask for even more (after the header) that will
                 * break reassembly.
                 */
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                return tvb_captured_length(tvb);
            }
        }

        /*
         * Get the length of the NBSS message.
         */
        if (is_cifs) {
            length = tvb_get_ntoh24(tvb, offset + 1);
        } else {
            flags  = tvb_get_guint8(tvb, offset + 1);
            length = tvb_get_ntohs(tvb, offset + 2);
            if (flags & NBSS_FLAGS_E)
                length += 65536;
        }
        plen = length + 4; /* Include length of NBSS header */

        /* give a hint to TCP where the next PDU starts
         * so that it can attempt to find it in case it starts
         * somewhere in the middle of a segment.
         */
        if(!pinfo->fd->visited){
            /* 'Only' SMB is transported ontop of this  so make sure
             * there is an SMB header there ...
             */
            if( ((int)plen>tvb_reported_length_remaining(tvb, offset))
                &&(tvb_captured_length_remaining(tvb, offset) >= 8)
                &&(tvb_get_guint8(tvb,offset+5) == 'S')
                &&(tvb_get_guint8(tvb,offset+6) == 'M')
                &&(tvb_get_guint8(tvb,offset+7) == 'B') ){
                pinfo->want_pdu_tracking = 2;
                pinfo->bytes_until_next_pdu = (length+4)-tvb_reported_length_remaining(tvb, offset);
            }
        }

        /*
         * Can we do reassembly?
         */
        if (nbss_desegment && pinfo->can_desegment) {
            /*
             * Yes - is the NBSS message split across segment boundaries?
             */
            if (length_remaining < plen) {
                /*
                 * Yes.  Tell the TCP dissector where the data for this message
                 * starts in the data it handed us, and how many more bytes we
                 * need, and return.
                 */
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = plen - length_remaining;
                return tvb_captured_length(tvb);
            }
        }

        /*
         * Construct a tvbuff containing the amount of the payload we have
         * available.  Make its reported length the amount of data in the PDU.
         */
        next_tvb = tvb_new_subset_length(tvb, offset, plen);

        dissect_nbss_packet(next_tvb, pinfo, tree, is_cifs);

        offset += plen;
    }

    return tvb_captured_length(tvb);
}

void
proto_register_nbt(void)
{

    static hf_register_info hf_nbns[] = {
        { &hf_nbns_flags,
          { "Flags",            "nbns.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_nbns_flags_response,
          { "Response",         "nbns.flags.response",
            FT_BOOLEAN, 16, TFS(&tfs_flags_response), F_RESPONSE,
            "Is the message a response?", HFILL }},
        { &hf_nbns_flags_opcode,
          { "Opcode",           "nbns.flags.opcode",
            FT_UINT16, BASE_DEC, VALS(opcode_vals), F_OPCODE,
            "Operation code", HFILL }},
        { &hf_nbns_flags_authoritative,
          { "Authoritative",    "nbns.flags.authoritative",
            FT_BOOLEAN, 16, TFS(&tfs_flags_authoritative), F_AUTHORITATIVE,
            "Is the server is an authority for the domain?", HFILL }},
        { &hf_nbns_flags_truncated,
          { "Truncated",        "nbns.flags.truncated",
            FT_BOOLEAN, 16, TFS(&tfs_flags_truncated), F_TRUNCATED,
            "Is the message truncated?", HFILL }},
        { &hf_nbns_flags_recdesired,
          { "Recursion desired",        "nbns.flags.recdesired",
            FT_BOOLEAN, 16, TFS(&tfs_flags_recdesired), F_RECDESIRED,
            "Do query recursively?", HFILL }},
        { &hf_nbns_flags_recavail,
          { "Recursion available",      "nbns.flags.recavail",
            FT_BOOLEAN, 16, TFS(&tfs_flags_recavail), F_RECAVAIL,
            "Can the server do recursive queries?", HFILL }},
        { &hf_nbns_flags_broadcast,
          { "Broadcast",                "nbns.flags.broadcast",
            FT_BOOLEAN, 16, TFS(&tfs_flags_broadcast), F_BROADCAST,
            "Is this a broadcast packet?", HFILL }},
        { &hf_nbns_flags_rcode,
          { "Reply code",               "nbns.flags.rcode",
            FT_UINT16, BASE_DEC, VALS(rcode_vals), F_RCODE,
            NULL, HFILL }},
        { &hf_nbns_transaction_id,
          { "Transaction ID",           "nbns.id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "Identification of transaction", HFILL }},
        { &hf_nbns_count_questions,
          { "Questions",                "nbns.count.queries",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Number of queries in packet", HFILL }},
        { &hf_nbns_count_answers,
          { "Answer RRs",               "nbns.count.answers",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Number of answers in packet", HFILL }},
        { &hf_nbns_count_auth_rr,
          { "Authority RRs",            "nbns.count.auth_rr",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Number of authoritative records in packet", HFILL }},
        { &hf_nbns_count_add_rr,
          { "Additional RRs",           "nbns.count.add_rr",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Number of additional records in packet", HFILL }},
        { &hf_nbns_name_flags,
          { "Name flags",       "nbns.name_flags",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_nbns_name_flags_group,
          { "Name type",        "nbns.name_flags.group",
            FT_BOOLEAN, 16, TFS(&tfs_group_unique_name), NAME_FLAGS_G,
            NULL, HFILL }},
        { &hf_nbns_name_flags_ont,
          { "ONT",              "nbns.name_flags.ont",
            FT_UINT16, BASE_DEC, VALS(name_flags_ont_vals), NAME_FLAGS_ONT,
            NULL, HFILL }},
        { &hf_nbns_name_flags_drg,
          { "Name is being deregistered",       "nbns.name_flags.drg",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), NAME_FLAGS_DRG,
            NULL, HFILL }},
        { &hf_nbns_name_flags_cnf,
          { "Name is in conflict",              "nbns.name_flags.cnf",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), NAME_FLAGS_CNF,
            NULL, HFILL }},
        { &hf_nbns_name_flags_act,
          { "Name is active",           "nbns.name_flags.act",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), NAME_FLAGS_ACT,
            NULL, HFILL }},
        { &hf_nbns_name_flags_prm,
          { "Permanent node name",              "nbns.name_flags.prm",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), NAME_FLAGS_PRM,
            NULL, HFILL }},
        { &hf_nbns_nb_flags,
          { "Name flags",       "nbns.nb_flags",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_nbns_nb_flags_group,
          { "Name type",        "nbns.nb_flags.group",
            FT_BOOLEAN, 16, TFS(&tfs_group_unique_name), NB_FLAGS_G,
            NULL, HFILL }},
        { &hf_nbns_nb_flags_ont,
          { "ONT",              "nbns.nb_flags.ont",
            FT_UINT16, BASE_DEC, VALS(nb_flags_ont_vals), NB_FLAGS_ONT,
            NULL, HFILL }},
        { &hf_nbns_type,
          { "Type",              "nbns.type",
            FT_UINT16, BASE_DEC, VALS(nb_type_name_vals), 0x0,
            NULL, HFILL }},
        { &hf_nbns_class,
          { "Class",              "nbns.class",
            FT_UINT16, BASE_DEC, VALS(dns_classes), 0x0,
            NULL, HFILL }},
        { &hf_nbns_name,
          { "Name",            "nbns.name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_nbns_addr, { "Addr", "nbns.addr", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_nbns_number_of_names, { "Number of names", "nbns.number_of_names", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_nbns_unit_id, { "Unit ID", "nbns.unit_id", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_nbns_jumpers, { "Jumpers", "nbns.jumpers", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_nbns_test_result, { "Test result", "nbns.test_result", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_nbns_version_number, { "Version number", "nbns.version_number", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_nbns_period_of_statistics, { "Period of statistics", "nbns.period_of_statistics", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_nbns_num_crcs, { "Number of CRCs", "nbns.num_crcs", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_nbns_num_alignment_errors, { "Number of alignment errors", "nbns.num_alignment_errors", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_nbns_num_collisions, { "Number of collisions", "nbns.num_collisions", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_nbns_num_send_aborts, { "Number of send aborts", "nbns.num_send_aborts", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_nbns_num_good_sends, { "Number of good sends", "nbns.num_good_sends", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_nbns_num_good_receives, { "Number of good receives", "nbns.num_good_receives", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_nbns_num_retransmits, { "Number of retransmits", "nbns.numretransmits", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_nbns_num_no_resource_conditions, { "Number of no resource conditions", "nbns.num_no_resource_conditions", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_nbns_num_command_blocks, { "Number of command blocks", "nbns.numcommand_blocks", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_nbns_num_pending_sessions, { "Number of pending sessions", "nbns.numpending_sessions", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_nbns_max_num_pending_sessions, { "Max number of pending sessions", "nbns.max_num_pending_sessions", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_nbns_max_total_sessions_possible, { "Max total sessions possible", "nbns.max_total_sessions_possible", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_nbns_session_data_packet_size, { "Session data packet size", "nbns.session_data_packet_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_nbns_data, { "Data", "nbns.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_nbns_netbios_name, { "Name", "nbns.netbios_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_nbns_ttl, { "Time to live", "nbns.ttl", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_nbns_data_length, { "Data length", "nbns.data_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    };

    static hf_register_info hf_nbdgm[] = {
        { &hf_nbdgm_type,
          { "Message Type",             "nbdgm.type",
            FT_UINT8, BASE_DEC, VALS(nbds_msgtype_vals), 0x0,
            "NBDGM message type", HFILL }},
        { &hf_nbdgm_flags,
          { "Flags",             "nbdgm.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_nbdgm_fragment,
          { "More fragments follow",    "nbdgm.next",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            "TRUE if more fragments follow", HFILL }},
        { &hf_nbdgm_first,
          { "This is first fragment",   "nbdgm.first",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            "TRUE if first fragment", HFILL }},
        { &hf_nbdgm_node_type,
          { "Node Type",                "nbdgm.node_type",
            FT_UINT8, BASE_DEC, VALS(node_type_vals), 0x0C,
            NULL, HFILL }},
        { &hf_nbdgm_datagram_id,
          { "Datagram ID",              "nbdgm.dgram_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "Datagram identifier", HFILL }},
        { &hf_nbdgm_src_ip,
          { "Source IP",                "nbdgm.src.ip",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            "Source IPv4 address", HFILL }},
        { &hf_nbdgm_src_port,
          { "Source Port",              "nbdgm.src.port",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_nbdgm_datagram_length,
          { "Datagram length",          "nbdgm.dgram_len",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,
            NULL, HFILL }},
        { &hf_nbdgm_packet_offset,
          { "Packet offset",            "nbdgm.pkt_offset",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,
            NULL, HFILL }},
        { &hf_nbdgm_error_code,
          { "Error code",               "nbdgm.error_code",
            FT_UINT8, BASE_HEX, VALS(nbds_error_codes), 0x0,
            NULL, HFILL }},
        { &hf_nbdgm_source_name,
          { "Source name",            "nbdgm.source_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_nbdgm_destination_name,
          { "Destination name",            "nbdgm.destination_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
    };

    static hf_register_info hf_nbss[] = {
        { &hf_nbss_type,
          { "Message Type",             "nbss.type",
            FT_UINT8, BASE_HEX, VALS(message_types), 0x0,
            "NBSS message type", HFILL }},
        { &hf_nbss_flags,
          { "Flags",            "nbss.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "NBSS message flags", HFILL }},
        { &hf_nbss_flags_e,
          { "Extend",           "nbss.flags.e",
            FT_BOOLEAN, 8, TFS(&tfs_nbss_flags_e), NBSS_FLAGS_E,
            NULL, HFILL }},
        { &hf_nbss_length,
          { "Length",           "nbss.length",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            "Length of trailer (payload) following this field in bytes", HFILL }},
        { &hf_nbss_cifs_length,
          { "Length",           "nbss.length",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            "Length trailer (payload) following this field in bytes", HFILL }},
        { &hf_nbss_error_code,
          { "Error code",       "nbss.error_code",
            FT_UINT8, BASE_HEX, VALS(nbss_error_codes), 0x0,
            NULL, HFILL }},
        { &hf_nbss_retarget_ip_address,
          { "Retarget IP address",      "nbss.retarget_ip_address",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_nbss_retarget_port,
          { "Retarget port",    "nbss.retarget_port",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_nbss_continuation_data,
          { "Continuation data", "nbss.continuation_data",
             FT_BYTES, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
        { &hf_nbss_called_name,
          { "Called name", "nbss.called_name",
             FT_STRING, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
        { &hf_nbss_calling_name,
          { "Calling name", "nbss.calling_name",
             FT_STRING, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
    };
    static gint *ett[] = {
        &ett_nbns,
        &ett_nbns_qd,
        &ett_nbns_flags,
        &ett_nbns_nb_flags,
        &ett_nbns_name_flags,
        &ett_nbns_rr,
        &ett_nbns_qry,
        &ett_nbns_ans,
        &ett_nbdgm,
        &ett_nbdgm_flags,
        &ett_nbss,
        &ett_nbss_flags,
    };

    static ei_register_info ei[] = {
        { &ei_nbns_incomplete_entry, { "nbns.incomplete_entry", PI_MALFORMED, PI_ERROR, "incomplete entry", EXPFILL }},
    };

    module_t *nbss_module;
    expert_module_t* expert_nbns;

    proto_nbns = proto_register_protocol("NetBIOS Name Service", "NBNS", "nbns");
    nbns_handle = register_dissector("nbns", dissect_nbns, proto_nbns);
    proto_register_field_array(proto_nbns, hf_nbns, array_length(hf_nbns));
    expert_nbns = expert_register_protocol(proto_nbns);
    expert_register_field_array(expert_nbns, ei, array_length(ei));

    proto_nbdgm = proto_register_protocol("NetBIOS Datagram Service",
                                          "NBDS", "nbdgm");
    nbdgm_handle = register_dissector("nbds", dissect_nbdgm, proto_nbdgm);
    proto_register_field_array(proto_nbdgm, hf_nbdgm, array_length(hf_nbdgm));

    proto_nbss = proto_register_protocol("NetBIOS Session Service",
                                         "NBSS", "nbss");
    nbss_handle  = register_dissector("nbss", dissect_nbss, proto_nbss);
    proto_register_field_array(proto_nbss, hf_nbss, array_length(hf_nbss));

    proto_register_subtree_array(ett, array_length(ett));

    nbss_module = prefs_register_protocol(proto_nbss, NULL);
    prefs_register_bool_preference(nbss_module, "desegment_nbss_commands",
                                   "Reassemble NBSS packets spanning multiple TCP segments",
                                   "Whether the NBSS dissector should reassemble packets spanning multiple TCP segments."
                                   " To use this option, you must also enable"
                                   " \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                   &nbss_desegment);
}

void
proto_reg_handoff_nbt(void)
{
    dissector_add_uint_with_preference("udp.port", UDP_PORT_NBNS, nbns_handle);
    dissector_add_uint_with_preference("udp.port", UDP_PORT_NBDGM, nbdgm_handle);
    dissector_add_uint_range_with_preference("tcp.port", TCP_NBSS_PORT_RANGE, nbss_handle);

    netbios_heur_subdissector_list = find_heur_dissector_list("netbios");

    dissector_add_string("quic.proto", "smb", nbss_handle);
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
