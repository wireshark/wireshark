/* packet-fcels.c
 * Routines for FC Extended Link Services
 * Copyright 2001, Dinesh G Dutt <ddutt@cisco.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/*
 * TODO Still (Complete compliance with FC-MI):
 * - Decode RNID, RLIR
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/conversation.h>
#include <epan/etypes.h>
#include <epan/expert.h>
#include "packet-scsi.h"
#include "packet-fc.h"
#include "packet-fcels.h"

#define FC_ELS_RPLY 0
#define FC_ELS_REQ  1

/* Initialize the protocol and registered fields */
static int proto_fcels                  = -1;
static int hf_fcels_opcode              = -1;
static int hf_fcels_rjtcode             = -1;
static int hf_fcels_rjtdetcode          = -1;
static int hf_fcels_vnduniq             = -1;
static int hf_fcels_b2b                 = -1;
static int hf_fcels_cmnfeatures         = -1;
static int hf_fcels_bbscnum             = -1;
static int hf_fcels_rcvsize             = -1;
static int hf_fcels_maxconseq           = -1;
static int hf_fcels_reloffset           = -1;
static int hf_fcels_edtov               = -1;
static int hf_fcels_npname              = -1;
static int hf_fcels_fnname              = -1;
static int hf_fcels_cls1param           = -1;
static int hf_fcels_cls2param           = -1;
static int hf_fcels_cls3param           = -1;
static int hf_fcels_cls4param           = -1;
static int hf_fcels_vendorvers          = -1;
static int hf_fcels_svcavail            = -1;
static int hf_fcels_clsflags            = -1;
static int hf_fcels_clsrcvsize          = -1;
static int hf_fcels_conseq              = -1;
static int hf_fcels_e2e                 = -1;
static int hf_fcels_openseq             = -1;
static int hf_fcels_nportid             = -1;
static int hf_fcels_oxid                = -1;
static int hf_fcels_rxid                = -1;
static int hf_fcels_recovqual           = -1;
static int hf_fcels_fabricaddr          = -1;
static int hf_fcels_fabricpname         = -1;
static int hf_fcels_failedrcvr          = -1;
static int hf_fcels_flacompliance       = -1;
static int hf_fcels_loopstate           = -1;
static int hf_fcels_publicloop_bmap     = -1;
static int hf_fcels_pvtloop_bmap        = -1;
static int hf_fcels_alpa_map            = -1;
static int hf_fcels_scrregn             = -1;
static int hf_fcels_farp_matchcodept    = -1;
static int hf_fcels_farp_respaction     = -1;
static int hf_fcels_resportid           = -1;
static int hf_fcels_respname            = -1;
static int hf_fcels_respnname           = -1;
static int hf_fcels_reqipaddr           = -1;
static int hf_fcels_respipaddr          = -1;
static int hf_fcels_hardaddr            = -1;
static int hf_fcels_rps_flag            = -1;
static int hf_fcels_rps_portnum         = -1;
static int hf_fcels_rps_portstatus      = -1;
static int hf_fcels_rnft_fc4type        = -1;
static int hf_fcels_rscn_evqual         = -1;
static int hf_fcels_rscn_addrfmt        = -1;
static int hf_fcels_rscn_domain         = -1;
static int hf_fcels_rscn_area           = -1;
static int hf_fcels_rscn_port           = -1;
static int hf_fcels_rec_fc4             = -1;
static int hf_fcels_estat               = -1;
static int hf_fcels_estat_resp          = -1;
static int hf_fcels_estat_seq_init      = -1;
static int hf_fcels_estat_compl         = -1;
static int hf_fcels_nodeidfmt           = -1;
static int hf_fcels_spidlen             = -1;
static int hf_fcels_vendoruniq          = -1;
static int hf_fcels_vendorsp            = -1;
static int hf_fcels_asstype             = -1;
static int hf_fcels_physport            = -1;
static int hf_fcels_attnodes            = -1;
static int hf_fcels_nodemgmt            = -1;
static int hf_fcels_ipvers              = -1;
static int hf_fcels_tcpport             = -1;
static int hf_fcels_ip                  = -1;
static int hf_fcels_cbind_liveness      = -1;
static int hf_fcels_cbind_addr_mode     = -1;
static int hf_fcels_cbind_ifcp_version  = -1;
static int hf_fcels_cbind_userinfo      = -1;
static int hf_fcels_cbind_snpname       = -1;
static int hf_fcels_cbind_dnpname       = -1;
static int hf_fcels_cbind_status        = -1;
static int hf_fcels_chandle             = -1;
static int hf_fcels_unbind_status       = -1;
static int hf_fcels_cmn_cios            = -1;
static int hf_fcels_cmn_rro             = -1;
static int hf_fcels_cmn_vvv             = -1;
static int hf_fcels_cmn_b2b             = -1;
static int hf_fcels_cmn_e_d_tov         = -1;
static int hf_fcels_cmn_simplex         = -1;
static int hf_fcels_cmn_multicast       = -1;
static int hf_fcels_cmn_broadcast       = -1;
static int hf_fcels_cmn_security        = -1;
static int hf_fcels_cmn_clk             = -1;
static int hf_fcels_cmn_dhd             = -1;
static int hf_fcels_cmn_seqcnt          = -1;
static int hf_fcels_cmn_payload         = -1;
static int hf_fcels_cls_cns             = -1;
static int hf_fcels_cls_sdr             = -1;
static int hf_fcels_cls_prio            = -1;
static int hf_fcels_cls_nzctl           = -1;
static int hf_fcels_initctl             = -1;
static int hf_fcels_initctl_initial_pa  = -1;
static int hf_fcels_initctl_ack0        = -1;
static int hf_fcels_initctl_ackgaa      = -1;
static int hf_fcels_initctl_sync        = -1;
static int hf_fcels_rcptctl             = -1;
static int hf_fcels_rcptctl_ack0        = -1;
static int hf_fcels_rcptctl_interlock   = -1;
static int hf_fcels_rcptctl_policy      = -1;
static int hf_fcels_rcptctl_category    = -1;
static int hf_fcels_rcptctl_sync        = -1;
static int hf_fcels_fcpflags            = -1;
static int hf_fcels_fcpflags_trireq     = -1;
static int hf_fcels_fcpflags_trirep     = -1;
static int hf_fcels_fcpflags_retry      = -1;
static int hf_fcels_fcpflags_ccomp      = -1;
static int hf_fcels_fcpflags_datao      = -1;
static int hf_fcels_fcpflags_initiator  = -1;
static int hf_fcels_fcpflags_target     = -1;
static int hf_fcels_fcpflags_rdxr       = -1;
static int hf_fcels_fcpflags_wrxr       = -1;
static int hf_fcels_prliloflags         = -1;
static int hf_fcels_tprloflags_opav     = -1;
static int hf_fcels_tprloflags_rpav     = -1;
static int hf_fcels_tprloflags_npv      = -1;
static int hf_fcels_tprloflags_gprlo    = -1;
static int hf_fcels_speedflags          = -1;
static int hf_fcels_speedflags_1gb      = -1;
static int hf_fcels_speedflags_2gb      = -1;
static int hf_fcels_speedflags_4gb      = -1;
static int hf_fcels_speedflags_10gb     = -1;
static int hf_fcels_prliloflags_opav    = -1;
static int hf_fcels_prliloflags_ipe     = -1;
static int hf_fcels_prliloflags_eip     = -1;

static gint ett_fcels                   = -1;
static gint ett_fcels_lsrjt             = -1;
static gint ett_fcels_acc               = -1;
static gint ett_fcels_logi              = -1;
static gint ett_fcels_logi_cmnsvc       = -1;
static gint ett_fcels_logi_clssvc       = -1;
static gint ett_fcels_logo              = -1;
static gint ett_fcels_abtx              = -1;
static gint ett_fcels_rsi               = -1;
static gint ett_fcels_rrq               = -1;
static gint ett_fcels_rec               = -1;
static gint ett_fcels_prli              = -1;
static gint ett_fcels_prli_svcpg        = -1;
static gint ett_fcels_adisc             = -1;
static gint ett_fcels_farp              = -1;
static gint ett_fcels_rps               = -1;
static gint ett_fcels_rpl               = -1;
static gint ett_fcels_rplpb             = -1;
static gint ett_fcels_fan               = -1;
static gint ett_fcels_rscn              = -1;
static gint ett_fcels_rscn_rec          = -1;
static gint ett_fcels_estat             = -1;
static gint ett_fcels_scr               = -1;
static gint ett_fcels_rnft              = -1;
static gint ett_fcels_rnft_fc4          = -1;
static gint ett_fcels_lsts              = -1;
static gint ett_fcels_rnid              = -1;
static gint ett_fcels_rlir              = -1;
static gint ett_fcels_lirr              = -1;
static gint ett_fcels_srl               = -1;
static gint ett_fcels_rpsc              = -1;
static gint ett_fcels_cbind             = -1;
static gint ett_fcels_cmnfeatures       = -1;
static gint ett_fcels_clsflags          = -1;
static gint ett_fcels_initctl           = -1;
static gint ett_fcels_rcptctl           = -1;
static gint ett_fcels_fcpflags          = -1;
static gint ett_fcels_prliloflags       = -1;
static gint ett_fcels_speedflags        = -1;

static const int *hf_fcels_estat_fields[] = {
    &hf_fcels_estat_resp,
    &hf_fcels_estat_seq_init,
    &hf_fcels_estat_compl,
    NULL
};

static const true_false_string tfs_fcels_estat_resp = {
        "Responding to Exchange",
        "Originator of Exchange"
};

static const true_false_string tfs_fcels_estat_seq_init = {
        "Seq Initiative held by REC responder",
        "Seq Initiative not held by REC responder"
};

static const true_false_string tfs_fcels_estat_compl = {
        "Exchange Complete",
        "Exchange Incomplete"
};

#define FC_ESB_ST_RESP      (1 << 31)   /* responder to exchange */
#define FC_ESB_ST_SEQ_INIT  (1 << 30)   /* holds sequence initiative */
#define FC_ESB_ST_COMPLETE  (1 << 29)   /* exchange is complete */

static const value_string fc_prli_fc4_val[] = {
    {FC_TYPE_SCSI    , "FCP"},
    {FC_TYPE_IP      , "IP/FC"},
    {FC_TYPE_LLCSNAP , "LLC_SNAP"},
    {FC_TYPE_ELS     , "Ext Link Svc"},
    {FC_TYPE_FCCT    , "FC_CT"},
    {FC_TYPE_SWILS   , "SW_ILS"},
    {FC_TYPE_AL      , "AL"},
    {FC_TYPE_SNMP    , "SNMP"},
    {FC_TYPE_CMNSVC  , "Common to all FC-4 Types"},
    {0, NULL},
};

static const value_string cbind_addr_mode_vals[] = {
    {0, "Address Translation mode"},
    {1, "Address Transparent Mode"},
    {0, NULL},
};

static const value_string cbind_status_vals[] = {
    {0, "Success"},
    {16, "Failed - Unspecified Reason"},
    {18, "Failed - Connection ID invalid"},
    {0, NULL},
};

static const value_string unbind_status_vals[] = {
    {0, "Success"},
    {16, "Failed - Unspecified Reason"},
    {17, "Failed - No such device"},
    {18, "Failed - iFCP session already exists"},
    {19, "Failed - Lack of resources"},
    {20, "Failed - Incompatible address translation mode"},
    {21, "Failed - Incorrect protocol version"},
    {22, "Failed - Gateway not synchronized"},
    {0, NULL},
};

typedef struct _fcels_conv_key {
    guint32 conv_idx;
} fcels_conv_key_t;

typedef struct _fcels_conv_data {
    guint32 opcode;
} fcels_conv_data_t;

static GHashTable *fcels_req_hash = NULL;

static dissector_handle_t data_handle, fcsp_handle;

/*
 * Hash Functions
 */
static gint
fcels_equal(gconstpointer v, gconstpointer w)
{
  const fcels_conv_key_t *v1 = v;
  const fcels_conv_key_t *v2 = w;

  return (v1->conv_idx == v2->conv_idx);
}

static guint
fcels_hash (gconstpointer v)
{
    const fcels_conv_key_t *key = v;
    guint val;

    val = key->conv_idx;

    return val;
}

/*
 * Protocol initialization
 */
static void
fcels_init_protocol(void)
{
    if (fcels_req_hash)
        g_hash_table_destroy(fcels_req_hash);

    fcels_req_hash = g_hash_table_new(fcels_hash, fcels_equal);
}


static const true_false_string tfs_fc_fcels_cmn_cios = {
    "Cont. Incr. Offset Supported",
    "Cont. incr. offset NOT supported"
};
static const true_false_string tfs_fc_fcels_cmn_rro = {
    "RRO Supported",
    "Rro NOT supported"
};
static const true_false_string tfs_fc_fcels_cmn_vvv = {
    "Valid Vendor Version",
    "Vendor version NOT valid"
};
static const true_false_string tfs_fc_fcels_cmn_b2b = {
    "Alt B2B Credit Mgmt",
    "Normal B2B Credit Mgmt"
};
static const true_false_string tfs_fc_fcels_cmn_e_d_tov = {
    "E_D_TOV Resolution in ns",
    "E_D_TOV Resolution in ms"
};
static const true_false_string tfs_fc_fcels_cmn_simplex = {
    "Simplex Dedicated Conn Supported",
    "Simplex dedicated conn NOT supported"
};
static const true_false_string tfs_fc_fcels_cmn_multicast = {
    "Multicast supported",
    "Multicast NOT supported"
};
static const true_false_string tfs_fc_fcels_cmn_broadcast = {
    "Broadcast Supported",
    "Broadcast NOT supported"
};
static const true_false_string tfs_fc_fcels_cmn_security = {
    "SECURITY Bit is SET",
    "Security bit is NOT set"
};
static const true_false_string tfs_fc_fcels_cmn_clk = {
    "Clk Sync Prim Capable",
    "NOT clk sync prim capable"
};
static const true_false_string tfs_fc_fcels_cmn_dhd = {
    "DHD Capable",
    "NOT dhd capable"
};
static const true_false_string tfs_fc_fcels_cmn_seqcnt = {
    "Cont. Incr SEQCNT rules",
    "Normal SEQCNT rules"
};
static const true_false_string tfs_fc_fcels_cmn_payload = {
    "Payload Len=256 bytes",
    "Payload Len=116 bytes"
};

static void
dissect_cmnsvc (proto_tree *parent_tree, tvbuff_t *tvb, int offset, guint16 flags, guint8 opcode)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;

    if(parent_tree){
        item=proto_tree_add_uint(parent_tree, hf_fcels_cmnfeatures,
                                 tvb, offset, 2, flags);
        tree=proto_item_add_subtree(item, ett_fcels_cmnfeatures);
    }

    proto_tree_add_boolean(tree, hf_fcels_cmn_cios, tvb, offset, 2, flags);
    if (flags&0x8000){
        proto_item_append_text(item, "  Cont. Incr. Offset Supported");
    }
    flags&=(~( 0x8000 ));

    proto_tree_add_boolean(tree, hf_fcels_cmn_rro, tvb, offset, 2, flags);
    if (flags&0x4000){
        proto_item_append_text(item, "  RRO Supported");
    }
    flags&=(~( 0x4000 ));

    proto_tree_add_boolean(tree, hf_fcels_cmn_vvv, tvb, offset, 2, flags);
    if (flags&0x2000){
        proto_item_append_text(item, "  Valid Vendor Version");
    }
    flags&=(~( 0x2000 ));

    proto_tree_add_boolean(tree, hf_fcels_cmn_b2b, tvb, offset, 2, flags);
    if (flags&0x0800){
        proto_item_append_text(item, "  Alt B2B Credit Mgmt");
    } else {
        proto_item_append_text(item, "  Normal B2B Credit Mgmt");
    }
    flags&=(~( 0x0800 ));

    if ((opcode == FC_ELS_PLOGI) || (opcode == FC_ELS_PDISC)) {
        proto_tree_add_boolean(tree, hf_fcels_cmn_e_d_tov, tvb, offset, 2, flags);
        if (flags&0x0400){
            proto_item_append_text(item, "  E_D_TOV Resolution in ns");
        } else {
            proto_item_append_text(item, "  E_D_TOV Resolution in ms");
        }
        flags&=(~( 0x0400 ));

        proto_tree_add_boolean(tree, hf_fcels_cmn_simplex, tvb, offset, 2, flags);
        if (flags&0x0040){
            proto_item_append_text(item, "  Simplex Dedicated Conn Supported");
        }
        flags&=(~( 0x0040 ));
    }

    proto_tree_add_boolean(tree, hf_fcels_cmn_multicast, tvb, offset, 2, flags);
    if (flags&0x0200){
        proto_item_append_text(item, "  Multicast Supported");
    }
    flags&=(~( 0x0200 ));

    proto_tree_add_boolean(tree, hf_fcels_cmn_broadcast, tvb, offset, 2, flags);
    if (flags&0x0100){
        proto_item_append_text(item, "  Broadcast Supported");
    }
    flags&=(~( 0x0100 ));

    proto_tree_add_boolean(tree, hf_fcels_cmn_security, tvb, offset, 2, flags);
    if (flags&0x0020){
        proto_item_append_text(item, "  Security Bit");
    }
    flags&=(~( 0x0020 ));

    proto_tree_add_boolean(tree, hf_fcels_cmn_clk, tvb, offset, 2, flags);
    if (flags&0x0010){
        proto_item_append_text(item, "  Clk Sync Prim Capable");
    }
    flags&=(~( 0x0010 ));

    proto_tree_add_boolean(tree, hf_fcels_cmn_dhd, tvb, offset, 2, flags);
    if (flags&0x0004){
        proto_item_append_text(item, "  DHD Capable");
    }
    flags&=(~( 0x0004 ));

    if ((opcode == FC_ELS_PLOGI) || (opcode == FC_ELS_PDISC)) {
        proto_tree_add_boolean(tree, hf_fcels_cmn_seqcnt, tvb, offset, 2, flags);
        if (flags&0x0002){
            proto_item_append_text(item, "  Cont. Incr SEQCNT rules");
        } else {
            proto_item_append_text(item, "  Normal SEQCNT rules");
        }
        flags&=(~( 0x0002 ));
    }

    proto_tree_add_boolean(tree, hf_fcels_cmn_payload, tvb, offset, 2, flags);
    if (flags&0x0001){
        proto_item_append_text(item, "  Payload Len=256 bytes");
    } else {
        proto_item_append_text(item, "  Payload Len=116 bytes");
    }
    flags&=(~( 0x0001 ));
}


static const true_false_string tfs_fc_fcels_cls_cns = {
    "Class IS Supported",
    "Class NOT supported"
};
static const true_false_string tfs_fc_fcels_cls_sdr = {
    "Seq Delivery Requested",
    "Out of Order Delivery Requested"
};
static const true_false_string tfs_fc_fcels_cls_prio = {
    "Priority/preemption Supported",
    "Priority/preemption NOT supported"
};
static const true_false_string tfs_fc_fcels_cls_nzctl = {
    "Non-zero CS_CTL Tolerated",
    "Non-zero CS_CTL Maybe Tolerated"
};

/* The next 3 routines decode only Class 2 & Class 3 relevant bits */
static void
dissect_clssvc_flags (proto_tree *parent_tree, tvbuff_t *tvb, int offset, guint16 flags, guint8 opcode)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;

    if(parent_tree){
        item=proto_tree_add_uint(parent_tree, hf_fcels_clsflags,
                                 tvb, offset, 2, flags);
        tree=proto_item_add_subtree(item, ett_fcels_clsflags);
    }

    proto_tree_add_boolean(tree, hf_fcels_cls_cns, tvb, offset, 2, flags);
    if (!(flags&0x8000)){
        proto_item_append_text(item, "  Class Not Supported");
        return;
    }
    flags&=(~( 0x8000 ));

    if ((opcode == FC_ELS_FLOGI) || (opcode == FC_ELS_FDISC)) {
        proto_tree_add_boolean(tree, hf_fcels_cls_sdr, tvb, offset, 2, flags);
        if (flags&0x0800){
            proto_item_append_text(item, "  Seq Delivery Requested");
        } else {
            proto_item_append_text(item, "  Out of Order Delivery Requested");
        }
        flags&=(~( 0x0800 ));
    }

    proto_tree_add_boolean(tree, hf_fcels_cls_prio, tvb, offset, 2, flags);
    if (flags&0x0080){
        proto_item_append_text(item, "  Priority/preemption Supported");
    }
    flags&=(~( 0x0080 ));

    if ((opcode == FC_ELS_PLOGI) || (opcode == FC_ELS_PDISC)) {
        proto_tree_add_boolean(tree, hf_fcels_cls_nzctl, tvb, offset, 2, flags);
        if (flags & 0x0040) {
            proto_item_append_text(item, "  Non-zero CS_CTL Tolerated");
        } else {
            proto_item_append_text(item, "  Non-zero CS_CTL Maybe Tolerated");
        }
        flags&=(~( 0x0040 ));
    }
}


static const true_false_string tfs_fc_fcels_fcpflags_trireq = {
    "Task Retry Ident REQUESTED",
    "Task retry ident NOT requested"
};
static const true_false_string tfs_fc_fcels_fcpflags_trirep = {
    "Task Retry Ident ACCEPTED",
    "Task retry ident NOT accepted"
};
static const true_false_string tfs_fc_fcels_fcpflags_retry = {
    "Retry Possible",
    "Retry NOT possible"
};
static const true_false_string tfs_fc_fcels_fcpflags_ccomp = {
    "Confirmed Comp",
    "Comp NOT confirmed"
};
static const true_false_string tfs_fc_fcels_fcpflags_datao = {
    "Data Overlay",
    "NO data overlay"
};
static const true_false_string tfs_fc_fcels_fcpflags_initiator = {
    "Initiator",
    "NOT an initiator"
};
static const true_false_string tfs_fc_fcels_fcpflags_target = {
    "Target",
    "NOT a target"
};
static const true_false_string tfs_fc_fcels_fcpflags_rdxr = {
    "Rd Xfer_Rdy Dis",
    "NO rd xfer_rdy dis"
};
static const true_false_string tfs_fc_fcels_fcpflags_wrxr = {
    "Wr Xfer_Rdy Dis",
    "NO wr xfer_rdy dis"
};

static void
dissect_fcp_flags (proto_tree *parent_tree, tvbuff_t *tvb, int offset, guint32 flags, guint8 isreq)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;

    if(parent_tree){
        item=proto_tree_add_uint(parent_tree, hf_fcels_fcpflags,
                                 tvb, offset, 4, flags);
        tree=proto_item_add_subtree(item, ett_fcels_fcpflags);
    }

    if (isreq) {
        proto_tree_add_boolean(tree, hf_fcels_fcpflags_trireq, tvb, offset, 4, flags);
        if (flags&0x2000){
            proto_item_append_text(item, "  Task Retry Ident Req");
        }
    } else {
        proto_tree_add_boolean(tree, hf_fcels_fcpflags_trirep, tvb, offset, 4, flags);
        if (flags&0x2000){
            proto_item_append_text(item, "  Task Retry Ident Acc");
        }
    }
    flags&=(~( 0x2000 ));

    proto_tree_add_boolean(tree, hf_fcels_fcpflags_retry, tvb, offset, 4, flags);
    if (flags&0x1000){
        proto_item_append_text(item, "  Retry Possible");
    }
    flags&=(~( 0x1000 ));

    proto_tree_add_boolean(tree, hf_fcels_fcpflags_ccomp, tvb, offset, 4, flags);
    if (flags&0x0080){
        proto_item_append_text(item, "  Confirmed Comp");
    }
    flags&=(~( 0x0080 ));

    proto_tree_add_boolean(tree, hf_fcels_fcpflags_datao, tvb, offset, 4, flags);
    if (flags&0x0040){
        proto_item_append_text(item, "  Data Overlay");
    }
    flags&=(~( 0x0040 ));

    proto_tree_add_boolean(tree, hf_fcels_fcpflags_initiator, tvb, offset, 4, flags);
    if (flags&0x0020){
        proto_item_append_text(item, "  Initiator");
    }
    flags&=(~( 0x0020 ));

    proto_tree_add_boolean(tree, hf_fcels_fcpflags_target, tvb, offset, 4, flags);
    if (flags&0x0010){
        proto_item_append_text(item, "  Target");
    }
    flags&=(~( 0x0010 ));

    proto_tree_add_boolean(tree, hf_fcels_fcpflags_rdxr, tvb, offset, 4, flags);
    if (flags&0x0002){
        proto_item_append_text(item, "  Rd Xfer_Rdy Dis");
    }
    flags&=(~( 0x0002 ));

    proto_tree_add_boolean(tree, hf_fcels_fcpflags_wrxr, tvb, offset, 4, flags);
    if (flags&0x0001){
        proto_item_append_text(item, "  Wr Xfer_Rdy Dis");
    }
    flags&=(~( 0x0001 ));
}


static const true_false_string tfs_fc_fcels_speedflags_1gb = {
    "1Gbit/second supported",
    "1Gbit/second NOT supported"
};
static const true_false_string tfs_fc_fcels_speedflags_2gb = {
    "2Gbit/second supported",
    "2Gbit/second NOT supported"
};
static const true_false_string tfs_fc_fcels_speedflags_4gb = {
    "4Gbit/second supported",
    "4Gbit/second NOT supported"
};
static const true_false_string tfs_fc_fcels_speedflags_10gb = {
    "10Gbit/second supported",
    "10Gbit/second NOT supported"
};

static void
dissect_speed_flags (proto_tree *parent_tree, tvbuff_t *tvb, int offset, guint32 flags, int port)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;

    if(parent_tree){
        item=proto_tree_add_uint_format(parent_tree, hf_fcels_speedflags,
                                        tvb, offset, 2, flags,
                                        "Port Speed Capabilities (Port %u): 0x%04x",
                                        port, flags);
        tree=proto_item_add_subtree(item, ett_fcels_speedflags);
    }

    proto_tree_add_boolean(tree, hf_fcels_speedflags_1gb, tvb, offset, 2, flags);
    if (flags&0x8000){
        proto_item_append_text(item, "  1Gb");
    }
    flags&=(~( 0x8000 ));

    proto_tree_add_boolean(tree, hf_fcels_speedflags_2gb, tvb, offset, 2, flags);
    if (flags&0x4000){
        proto_item_append_text(item, "  2Gb");
    }
    flags&=(~( 0x4000 ));

    proto_tree_add_boolean(tree, hf_fcels_speedflags_4gb, tvb, offset, 2, flags);
    if (flags&0x2000){
        proto_item_append_text(item, "  4Gb");
    }
    flags&=(~( 0x2000 ));

    proto_tree_add_boolean(tree, hf_fcels_speedflags_10gb, tvb, offset, 2, flags);
    if (flags&0x1000){
        proto_item_append_text(item, "  10Gb");
    }
    flags&=(~( 0x1000 ));
}

static const true_false_string tfs_fc_fcels_tprloflags_opav = {
    "3rd Party Orig PA Valid",
    "3rd party orig pa is NOT valid"
};
static const true_false_string tfs_fc_fcels_tprloflags_rpav = {
    "Resp PA Valid",
    "Resp pa is NOT valid"
};
static const true_false_string tfs_fc_fcels_tprloflags_npv = {
    "3rd Party N_Port Valid",
    "3rd party n_port is NOT valid"
};
static const true_false_string tfs_fc_fcels_tprloflags_gprlo = {
    "Global PRLO",
    "NO global prlo"
};
static const true_false_string tfs_fc_fcels_prliloflags_opav = {
    "Orig PA Valid",
    "Orig pa is NOT valid"
};
static const true_false_string tfs_fc_fcels_prliloflags_ipe = {
    "Image Pair Estd",
    "Image pair NOT estd"
};
static const true_false_string tfs_fc_fcels_prliloflags_eip = {
    "Est Image Pair & Exchg Svc Param",
    "Exchange Svc Param Only"
};

static void
dissect_prlilo_flags (proto_tree *parent_tree, tvbuff_t *tvb, int offset, int flags, guint8 opcode)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;

    if(parent_tree){
        item=proto_tree_add_uint(parent_tree, hf_fcels_prliloflags,
                                 tvb, offset, 1, flags);
        tree=proto_item_add_subtree(item, ett_fcels_prliloflags);
    }

    if (opcode == FC_ELS_TPRLO) {
        proto_tree_add_boolean(tree, hf_fcels_tprloflags_opav, tvb, offset, 1, flags);
        if (flags&0x80){
            proto_item_append_text(item, "  3rd Party Orig PA Valid");
        }
        flags&=(~( 0x80 ));

        proto_tree_add_boolean(tree, hf_fcels_tprloflags_rpav, tvb, offset, 1, flags);
        if (flags&0x40){
            proto_item_append_text(item, "  Resp PA Valid");
        }
        flags&=(~( 0x40 ));

        proto_tree_add_boolean(tree, hf_fcels_tprloflags_npv, tvb, offset, 1, flags);
        if (flags&0x20){
            proto_item_append_text(item, "  3rd Party N_Port Valid");
        }
        flags&=(~( 0x20 ));

        proto_tree_add_boolean(tree, hf_fcels_tprloflags_gprlo, tvb, offset, 1, flags);
        if (flags&0x10){
            proto_item_append_text(item, "  Global PRLO");
        }
        flags&=(~( 0x10 ));
    } else { /* opcode != TPRLO */
        proto_tree_add_boolean(tree, hf_fcels_prliloflags_opav, tvb, offset, 1, flags);
        if (flags&0x80){
            proto_item_append_text(item, "  Orig PA Valid");
        }
        flags&=(~( 0x80 ));

        proto_tree_add_boolean(tree, hf_fcels_tprloflags_rpav, tvb, offset, 1, flags);
        if (flags&0x40){
            proto_item_append_text(item, "  Resp PA Valid");
        }
        flags&=(~( 0x40 ));

        if (opcode == FC_ELS_PRLI) {
            proto_tree_add_boolean(tree, hf_fcels_prliloflags_ipe, tvb, offset, 1, flags);
            if (flags&0x20){
                proto_item_append_text(item, "  Image Pair Estd");
            } else {
                proto_item_append_text(item, "  Image Pair NOT Estd");
            }
            flags&=(~( 0x20 ));
        } else {
            proto_tree_add_boolean(tree, hf_fcels_prliloflags_eip, tvb, offset, 1, flags);
            if (flags&0x20){
                proto_item_append_text(item, "  Est Image Pair & Exchg Svc Param");
            } else {
                proto_item_append_text(item, "  Exchange Svc Param Only");
            }
            flags&=(~( 0x20 ));
        }
    }
}

static const value_string initial_pa_vals[] = {
    { 0, "Initial P_A Not Supported" },
    { 1, "Initial P_A Supported" },
    { 3, "Initial P_A Required & Supported" },
    { 0, NULL }
};
static const true_false_string tfs_fc_fcels_initctl_ack0 = {
    "ACK0 Capable",
    "NOT Ack0 capable"
};
static const true_false_string tfs_fc_fcels_initctl_ackgaa = {
    "ACK Generation Assistance Avail",
    "NO ack generation assistance"
};
static const true_false_string tfs_fc_fcels_initctl_sync = {
    "Clock Sync ELS Supported",
    "NO clock sync els support"
};

static void
dissect_initctl_flags (proto_tree *parent_tree, tvbuff_t *tvb, int offset, guint16 flags, guint8 opcode)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;

    if(parent_tree){
        item=proto_tree_add_uint(parent_tree, hf_fcels_initctl,
                                 tvb, offset, 2, flags);
        tree=proto_item_add_subtree(item, ett_fcels_initctl);
    }

    if ((opcode == FC_ELS_PLOGI) || (opcode == FC_ELS_PDISC)) {
        proto_tree_add_uint(tree, hf_fcels_initctl_initial_pa,
                            tvb, offset, 2, flags);
        proto_item_append_text(item, "  %s",
                               val_to_str((flags&0x3000)>>12, initial_pa_vals,
                                          "0x%02x")
            );
        flags&=(~( 0x3000 ));

        proto_tree_add_boolean(tree, hf_fcels_initctl_ack0, tvb, offset, 2, flags);
        if (flags&0x0800){
            proto_item_append_text(item, "  ACK0 Capable");
        }
        flags&=(~( 0x0800 ));

        proto_tree_add_boolean(tree, hf_fcels_initctl_ackgaa, tvb, offset, 2, flags);
        if (flags&0x0200){
            proto_item_append_text(item, "  ACK Generation Assistance Avail");
        }
        flags&=(~( 0x0200 ));

    }


    proto_tree_add_boolean(tree, hf_fcels_initctl_sync, tvb, offset, 2, flags);
    if (flags&0x0010){
        proto_item_append_text(item, "  Clock Sync ELS Supported");
    }
    flags&=(~( 0x0010 ));
}


static const true_false_string tfs_fc_fcels_rcptctl_ack0 = {
    "ACK0 Supported",
    "Ack0 NOT supported"
};
static const true_false_string tfs_fc_fcels_rcptctl_interlock = {
    "X_ID Interlock Reqd",
    "X_id interlock NOT reqd"
};
static const value_string rcptctl_policy_vals[] = {
    { 0, "Error Policy: Discard Policy only" },
    { 1, "Error Policy: Reserved" },
    { 2, "Error Policy: Both discard and process policies supported" },
    { 3, "Error Policy: Reserved" },
    { 0, NULL }
};
static const value_string rcptctl_category_vals[] = {
    { 0, "1 Category/Seq" },
    { 1, "2 Categories/Seq" },
    { 3, "More than 2 Categories/Seq" },
    { 0, NULL }
};
static const true_false_string tfs_fc_fcels_rcptctl_sync = {
    "Clock Sync ELS Supported",
    "NO clock sync els support"
};

static void
dissect_rcptctl_flags (proto_tree *parent_tree, tvbuff_t *tvb, int offset, guint16 flags, guint8 opcode)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;

    if(parent_tree){
        item=proto_tree_add_uint(parent_tree, hf_fcels_rcptctl,
                                 tvb, offset, 2, flags);
        tree=proto_item_add_subtree(item, ett_fcels_rcptctl);
    }

    if ((opcode == FC_ELS_PLOGI) || (opcode == FC_ELS_PDISC)) {
        proto_tree_add_boolean(tree, hf_fcels_rcptctl_ack0, tvb, offset, 2, flags);
        if (flags&0x8000){
            proto_item_append_text(item, "  ACK0 Supported");
        } else {
            proto_item_append_text(item, "  ACK0 NOT Supported");
        }
        flags&=(~( 0x8000 ));

        proto_tree_add_boolean(tree, hf_fcels_rcptctl_interlock, tvb, offset, 2, flags);
        if (flags&0x2000){
            proto_item_append_text(item, "  X_ID Interlock Reqd");
        }
        flags&=(~( 0x2000 ));

        proto_tree_add_uint(tree, hf_fcels_rcptctl_policy,
                            tvb, offset, 2, flags);
        proto_item_append_text(item, "  %s",
                               val_to_str((flags&0x1800)>>11, rcptctl_policy_vals,
                                          "0x%02x")
            );
        flags&=(~( 0x1800 ));

        proto_tree_add_uint(tree, hf_fcels_rcptctl_category,
                            tvb, offset, 2, flags);
        proto_item_append_text(item, "  %s",
                               val_to_str((flags&0x0030)>>4, rcptctl_category_vals,
                                          "0x%02x")
            );
        flags&=(~( 0x0030 ));
    }

    proto_tree_add_boolean(tree, hf_fcels_rcptctl_sync, tvb, offset, 2, flags);
    if (flags&0x0008){
        proto_item_append_text(item, "  Clock Sync ELS Supported");
    }
    flags&=(~( 0x0008 ));
}

/* Maximum length of possible string from, construct_*_string
 * 296 bytes, FIX possible buffer overflow */
#define FCELS_LOGI_MAXSTRINGLEN 512

static void
dissect_fcels_logi (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    proto_item *ti, guint8 opcode)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    int offset = 0,
        svcvld = 0,
        class;
    proto_tree *logi_tree, *cmnsvc_tree;
    proto_item *subti;
    guint16 flag;

    if (tree) {
        logi_tree = proto_item_add_subtree (ti, ett_fcels_logi);
        proto_tree_add_item (logi_tree, hf_fcels_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);

        subti = proto_tree_add_text (logi_tree, tvb, offset+4, 16,
                                     "Common Svc Parameters");
        cmnsvc_tree = proto_item_add_subtree (subti, ett_fcels_logi_cmnsvc);
        proto_tree_add_item (cmnsvc_tree, hf_fcels_b2b, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        flag = tvb_get_ntohs (tvb, offset+8);

        if (flag & 0x0001) {
            svcvld = 1;
        }

        dissect_cmnsvc (cmnsvc_tree, tvb, offset+8, flag, opcode);

        proto_tree_add_item (cmnsvc_tree, hf_fcels_bbscnum, tvb, offset+10, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (cmnsvc_tree, hf_fcels_rcvsize, tvb, offset+10, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (cmnsvc_tree, hf_fcels_maxconseq, tvb, offset+12, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (cmnsvc_tree, hf_fcels_reloffset, tvb, offset+14, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (cmnsvc_tree, hf_fcels_edtov, tvb, offset+16, 4, ENC_BIG_ENDIAN);
        proto_tree_add_string (cmnsvc_tree, hf_fcels_npname, tvb, offset+20, 8,
                               tvb_fcwwn_to_str (tvb, offset+20));
        proto_tree_add_string (cmnsvc_tree, hf_fcels_fnname, tvb, offset+28, 8,
                               tvb_fcwwn_to_str (tvb, offset+28));

        /* Add subtree for class paramters */
        offset = 36;
        for (class = 1; class < 5; class++) {
            subti = proto_tree_add_text (logi_tree, tvb, offset, 16,
                                         "Class %d Svc Parameters", class);
            cmnsvc_tree = proto_item_add_subtree (subti, ett_fcels_logi_cmnsvc);

            flag = tvb_get_ntohs (tvb, offset);
            dissect_clssvc_flags (cmnsvc_tree, tvb, offset, flag, opcode);
            if (flag & 0x8000) {
                flag = tvb_get_ntohs (tvb, offset+2);
                dissect_initctl_flags (cmnsvc_tree, tvb, offset+2, flag, opcode);

                flag = tvb_get_ntohs (tvb, offset+4);
                dissect_rcptctl_flags (cmnsvc_tree, tvb, offset+4, flag, opcode);

                proto_tree_add_item (cmnsvc_tree, hf_fcels_clsrcvsize, tvb,
                                     offset+6, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item (cmnsvc_tree, hf_fcels_conseq, tvb,
                                     offset+8, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item (cmnsvc_tree, hf_fcels_e2e, tvb,
                                     offset+10, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item (cmnsvc_tree, hf_fcels_openseq, tvb,
                                     offset+12, 2, ENC_BIG_ENDIAN);
            }
            offset += 16;
        }
        proto_tree_add_item (logi_tree, hf_fcels_vendorvers, tvb, offset, 16, ENC_NA);
        if (svcvld) {
            proto_tree_add_item (logi_tree, hf_fcels_svcavail, tvb, offset+32, 8, ENC_NA);
        }
    }
}

static void
dissect_fcels_plogi (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                     guint8 isreq _U_, proto_item *ti)
{
    dissect_fcels_logi (tvb, pinfo, tree, ti, FC_ELS_PLOGI);
}

static void
dissect_fcels_flogi (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                     guint8 isreq _U_, proto_item *ti)
{
    dissect_fcels_logi (tvb, pinfo, tree, ti, FC_ELS_FLOGI);
}

static void
dissect_fcels_logout (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                      guint8 isreq, proto_item *ti)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    int offset = 5;             /* bypass opcode+rsvd field */
    proto_tree *logo_tree;

    if (tree) {
        logo_tree = proto_item_add_subtree (ti, ett_fcels_logo);

        proto_tree_add_item (logo_tree, hf_fcels_opcode, tvb, offset-5, 1, ENC_BIG_ENDIAN);

        if (!isreq) {
            /* Accept has no payload */
            return;
        }

        proto_tree_add_string (logo_tree, hf_fcels_nportid, tvb, offset, 3,
                               tvb_fc_to_str (tvb, offset));
        proto_tree_add_string (logo_tree, hf_fcels_npname, tvb, offset+3, 6,
                               tvb_fcwwn_to_str (tvb, offset+3));
    }
}

static void
dissect_fcels_abtx (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint8 isreq, proto_item *ti)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    int offset = 0;
    proto_tree *abtx_tree;

    if (tree) {
        abtx_tree = proto_item_add_subtree (ti, ett_fcels_abtx);

        proto_tree_add_item (abtx_tree, hf_fcels_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);

        if (!isreq) {
            return;
        }

        proto_tree_add_text (abtx_tree, tvb, offset+4, 1,
                             "Recovery Qualifier Status: 0x%x",
                             tvb_get_guint8 (tvb, offset+4));
        proto_tree_add_string (abtx_tree, hf_fcels_nportid, tvb, offset+5, 3,
                               tvb_fc_to_str (tvb, offset+5));
        proto_tree_add_item (abtx_tree, hf_fcels_oxid, tvb, offset+8, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (abtx_tree, hf_fcels_rxid, tvb, offset+10, 2, ENC_BIG_ENDIAN);
    }
}

static void
dissect_fcels_rsi (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                   guint8 isreq, proto_item *ti)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    int offset = 4;
    proto_tree *rsi_tree;

    if (tree) {
        rsi_tree = proto_item_add_subtree (ti, ett_fcels_rsi);

        proto_tree_add_item (rsi_tree, hf_fcels_opcode, tvb, offset-4, 1, ENC_BIG_ENDIAN);
        if (!isreq)
            return;

        proto_tree_add_item (rsi_tree, hf_fcels_recovqual, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_string (rsi_tree, hf_fcels_nportid, tvb, offset+1, 3,
                               tvb_fc_to_str (tvb, offset+1));
        proto_tree_add_item (rsi_tree, hf_fcels_rxid, tvb, offset+4, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (rsi_tree, hf_fcels_oxid, tvb, offset+6, 2, ENC_BIG_ENDIAN);
    }
}

static void
dissect_fcels_rrq (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                   guint8 isreq, proto_item *ti)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    int offset = 0;
    proto_tree *rrq_tree;

    if (tree) {
        rrq_tree = proto_item_add_subtree (ti, ett_fcels_rrq);

        proto_tree_add_item (rrq_tree, hf_fcels_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
        if (!isreq)
            return;

        proto_tree_add_string (rrq_tree, hf_fcels_nportid, tvb, offset+5, 3,
                               tvb_fc_to_str (tvb, offset+5));
        proto_tree_add_item (rrq_tree, hf_fcels_oxid, tvb, offset+8, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (rrq_tree, hf_fcels_rxid, tvb, offset+10, 2, ENC_BIG_ENDIAN);
    }
}

static void
dissect_fcels_rec (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                   guint8 isreq, proto_item *ti)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    int offset = 0;
    proto_tree *rec_tree;

    if (tree) {
        rec_tree = proto_item_add_subtree (ti, ett_fcels_rec);

        proto_tree_add_item (rec_tree, hf_fcels_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);

        if (isreq) {
            proto_tree_add_string (rec_tree, hf_fcels_nportid, tvb,
                                   offset+5, 3,
                                   tvb_fc_to_str (tvb, offset+5));
            proto_tree_add_item (rec_tree, hf_fcels_oxid, tvb,
                                 offset+8, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item (rec_tree, hf_fcels_rxid, tvb,
                                 offset+10, 2, ENC_BIG_ENDIAN);
        } else {
            proto_tree_add_item (rec_tree, hf_fcels_oxid, tvb,
                                 offset+4, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item (rec_tree, hf_fcels_rxid, tvb,
                                 offset+6, 2, ENC_BIG_ENDIAN);
            proto_tree_add_string (rec_tree, hf_fcels_nportid, tvb,
                                   offset+9, 3,
                                   tvb_fc_to_str (tvb, offset+9));
            proto_tree_add_string (rec_tree, hf_fcels_resportid, tvb,
                                   offset+13, 3,
                                   tvb_fc_to_str (tvb, offset+13));
            proto_tree_add_item (rec_tree, hf_fcels_rec_fc4, tvb,
                                 offset+16, 4, ENC_BIG_ENDIAN);
            proto_tree_add_bitmask (rec_tree, tvb, offset+20, hf_fcels_estat,
                                    ett_fcels_estat, hf_fcels_estat_fields,
                                    ENC_BIG_ENDIAN);
        }
    }
}

static void
dissect_fcels_pdisc (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                     guint8 isreq _U_, proto_item *ti)
{
    dissect_fcels_logi (tvb, pinfo, tree, ti, FC_ELS_PDISC);
}

static void
dissect_fcels_fdisc (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                     guint8 isreq _U_, proto_item *ti)
{
    dissect_fcels_logi (tvb, pinfo, tree, ti, FC_ELS_FDISC);
}

static void
dissect_fcels_adisc (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint8 isreq _U_, proto_item *ti)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    int offset = 5;
    proto_tree *adisc_tree;

    if (tree) {
        adisc_tree = proto_item_add_subtree (ti, ett_fcels_adisc);

        proto_tree_add_item (adisc_tree, hf_fcels_opcode, tvb, offset-5, 1, ENC_BIG_ENDIAN);

        proto_tree_add_string (adisc_tree, hf_fcels_hardaddr, tvb, offset, 3,
                               tvb_fc_to_str (tvb, offset));
        proto_tree_add_string (adisc_tree, hf_fcels_npname, tvb, offset+3, 8,
                               tvb_fcwwn_to_str (tvb, offset+3));
        proto_tree_add_string (adisc_tree, hf_fcels_fnname, tvb, offset+11, 8,
                               tvb_fcwwn_to_str (tvb, offset+11));
        proto_tree_add_string (adisc_tree, hf_fcels_nportid, tvb, offset+20, 3,
                               tvb_fc_to_str (tvb, offset+20));
    }

}

static void
dissect_fcels_farp (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    proto_item *ti)
{
    int offset = 4;
    proto_tree *farp_tree;

    if (tree) {
        farp_tree = proto_item_add_subtree (ti, ett_fcels_farp);

        proto_tree_add_item (farp_tree, hf_fcels_opcode, tvb, offset-4, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item (farp_tree, hf_fcels_farp_matchcodept,
                             tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_string (farp_tree, hf_fcels_nportid, tvb, offset+1,
                               3, tvb_fc_to_str (tvb, offset+1));
        proto_tree_add_item (farp_tree, hf_fcels_farp_respaction, tvb,
                             offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_string (farp_tree, hf_fcels_resportid, tvb, offset+5,
                               3, tvb_fc_to_str (tvb, offset+5));
        proto_tree_add_string (farp_tree, hf_fcels_npname, tvb, offset+8,
                               8, tvb_fcwwn_to_str (tvb, offset+8));
        proto_tree_add_string (farp_tree, hf_fcels_fnname, tvb, offset+16,
                               8, tvb_fcwwn_to_str (tvb, offset+16));
        proto_tree_add_string (farp_tree, hf_fcels_respname, tvb, offset+24,
                               8, tvb_fcwwn_to_str (tvb, offset+24));
        proto_tree_add_string (farp_tree, hf_fcels_respnname, tvb, offset+32,
                               8, tvb_fcwwn_to_str (tvb, offset+32));
        proto_tree_add_item (farp_tree, hf_fcels_reqipaddr, tvb, offset+40,
                             16, ENC_NA);
        proto_tree_add_item (farp_tree, hf_fcels_respipaddr, tvb, offset+56,
                             16, ENC_NA);
    }
}

static void
dissect_fcels_farp_req (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint8 isreq _U_, proto_item *ti)
{
    dissect_fcels_farp (tvb, pinfo, tree, ti);
}

static void
dissect_fcels_farp_rply (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                         guint8 isreq _U_, proto_item *ti)
{
    dissect_fcels_farp (tvb, pinfo, tree, ti);
}

static void
dissect_fcels_rps (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                   guint8 isreq, proto_item *ti)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    int offset = 3;
    guint8 flag;
    proto_tree *rps_tree;

    flag = tvb_get_guint8 (tvb, offset);

    if (tree) {
        rps_tree = proto_item_add_subtree (ti, ett_fcels_rps);

        if (isreq) {
            proto_tree_add_item (rps_tree, hf_fcels_rps_flag, tvb, offset, 1, ENC_BIG_ENDIAN);

            proto_tree_add_item (rps_tree, hf_fcels_opcode, tvb, offset-3, 1, ENC_BIG_ENDIAN);

            if (flag & 0x2) {
                proto_tree_add_string (rps_tree, hf_fcels_npname, tvb, offset+1,
                                       8, tvb_fcwwn_to_str (tvb, offset+1));
            }
            else if (flag & 0x1) {
                proto_tree_add_item (rps_tree, hf_fcels_rps_portnum, tvb,
                                     offset+5, 3, ENC_BIG_ENDIAN);
            }
        }
        else {
            proto_tree_add_item (rps_tree, hf_fcels_rps_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rps_tree, hf_fcels_rps_portstatus, tvb,
                                 offset+3, 2, ENC_BIG_ENDIAN);
            /* Next 6 fields are from Link Error Status Block (LESB) */
            proto_tree_add_text (rps_tree, tvb, offset+5, 4,
                                 "Link Failure Count: %u",
                                 tvb_get_ntohl (tvb, offset+5));
            proto_tree_add_text (rps_tree, tvb, offset+9, 4,
                                 "Loss of Sync Count: %u",
                                 tvb_get_ntohl (tvb, offset+9));
            proto_tree_add_text (rps_tree, tvb, offset+13, 4,
                                 "Loss of Signal Count: %u",
                                 tvb_get_ntohl (tvb, offset+13));
            proto_tree_add_text (rps_tree, tvb, offset+17, 4,
                                 "Primitive Seq Protocol Err: %u",
                                 tvb_get_ntohl (tvb, offset+17));
            proto_tree_add_text (rps_tree, tvb, offset+21, 4,
                                 "Invalid Xmission Word: %u",
                                 tvb_get_ntohl (tvb, offset+21));
            proto_tree_add_text (rps_tree, tvb, offset+25, 4,
                                 "Invalid CRC Count: %u",
                                 tvb_get_ntohl (tvb, offset+25));
            if (flag & 0x01) {
                /* Next 6 fields are from L_Port Extension field */
                proto_tree_add_text (rps_tree, tvb, offset+31, 2,
                                     "L_Port Status: 0x%x",
                                     tvb_get_ntohs (tvb, offset+31));
                proto_tree_add_text (rps_tree, tvb, offset+36, 1,
                                     "LIP AL_PS: 0x%x",
                                     tvb_get_guint8 (tvb, offset+36));
                proto_tree_add_text (rps_tree, tvb, offset+37, 4,
                                     "LIP F7 Initiated Count: %u",
                                     tvb_get_ntohl (tvb, offset+37));
                proto_tree_add_text (rps_tree, tvb, offset+41, 4,
                                     "LIP F7 Received Count: %u",
                                     tvb_get_ntohl (tvb, offset+41));
                proto_tree_add_text (rps_tree, tvb, offset+45, 4,
                                     "LIP F8 Initiated Count: %u",
                                     tvb_get_ntohl (tvb, offset+45));
                proto_tree_add_text (rps_tree, tvb, offset+49, 4,
                                     "LIP F8 Received Count: %u",
                                     tvb_get_ntohl (tvb, offset+49));
                proto_tree_add_text (rps_tree, tvb, offset+53, 4,
                                     "LIP Reset Initiated Count: %u",
                                     tvb_get_ntohl (tvb, offset+53));
                proto_tree_add_text (rps_tree, tvb, offset+57, 4,
                                     "LIP Reset Received Count: %u",
                                     tvb_get_ntohl (tvb, offset+57));
            }
        }
    }
}

static void
dissect_fcels_rpl (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                   guint8 isreq, proto_item *ti)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    int offset = 0;
    proto_tree *rpl_tree, *pb_tree;
    proto_item *subti;
    int loop;

    if (tree) {
        rpl_tree = proto_item_add_subtree (ti, ett_fcels_rpl);

        proto_tree_add_item (rpl_tree, hf_fcels_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);

        if (isreq) {
            proto_tree_add_text (rpl_tree, tvb, offset+6, 2,
                                 "Max Size: %u",
                                 tvb_get_ntohs (tvb, offset+6));
            proto_tree_add_text (rpl_tree, tvb, offset+9, 3,
                                 "Index: %u",
                                 tvb_get_ntoh24 (tvb, offset+9));
        }
        else {
            /* Reply consists of a header and a number of port blocks */
            proto_tree_add_text (rpl_tree, tvb, offset+2, 2,
                                 "Payload Length: %u",
                                 tvb_get_ntohs (tvb, offset+2));
            proto_tree_add_text (rpl_tree, tvb, offset+5, 3,
                                 "List Length: %u",
                                 tvb_get_ntoh24 (tvb, offset+5));
            proto_tree_add_text (rpl_tree, tvb, offset+9, 3,
                                 "Index of I Port Block: %u",
                                 tvb_get_ntoh24 (tvb, offset+9));
            offset = 12;
            /* The following loop is for dissecting the port blocks */
            for (loop = tvb_get_ntoh24 (tvb, 5); loop > 0; loop--) {
                subti = proto_tree_add_text (rpl_tree, tvb, offset+12, 16,
                                             "Port Block %u", loop);
                pb_tree = proto_item_add_subtree (subti, ett_fcels_rplpb);

                proto_tree_add_text (pb_tree, tvb, offset, 4,
                                     "Physical Port #: %u",
                                     tvb_get_ntohl (tvb, offset));
                proto_tree_add_text (pb_tree, tvb, offset+5, 3,
                                     "Port Identifier: %s",
                                     tvb_fc_to_str (tvb, offset+5));
                proto_tree_add_text (pb_tree, tvb, offset+8, 8,
                                     "Port Name: %s",
                                     tvb_fcwwn_to_str (tvb, offset+8));
                offset += 16;
            }
        }
    }
}

static void
dissect_fcels_fan (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                   guint8 isreq _U_, proto_item *ti)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    int offset = 5;
    proto_tree *fan_tree;

    if (tree) {
        fan_tree = proto_item_add_subtree (ti, ett_fcels_fan);

        proto_tree_add_item (fan_tree, hf_fcels_opcode, tvb, offset-5, 1, ENC_BIG_ENDIAN);

        proto_tree_add_string (fan_tree, hf_fcels_fabricaddr, tvb, offset, 3,
                               tvb_fc_to_str (tvb, offset));
        proto_tree_add_string (fan_tree, hf_fcels_fabricpname, tvb, offset+3,
                               8, tvb_fcwwn_to_str (tvb, offset));
        proto_tree_add_string (fan_tree, hf_fcels_fnname, tvb, offset+11, 8,
                               tvb_fcwwn_to_str (tvb, offset+11));
    }
}

static void
dissect_fcels_rscn (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint8 isreq, proto_item *ti)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    int offset = 1;
    proto_tree *rscn_tree, *rectree;
    proto_item *subti;
    int numrec, plen, i;

    if (tree) {
        rscn_tree = proto_item_add_subtree (ti, ett_fcels_rscn);

        proto_tree_add_item (rscn_tree, hf_fcels_opcode, tvb, offset-1, 1, ENC_BIG_ENDIAN);
        if (!isreq)
            return;

        proto_tree_add_text (rscn_tree, tvb, offset, 1,
                             "Page Len: %u", tvb_get_guint8 (tvb, offset));
        plen = tvb_get_ntohs (tvb, offset+1);
        proto_tree_add_text (rscn_tree, tvb, offset+1, 2,
                             "Payload Len: %u", plen);
        numrec = (plen - 4)/4;

        offset = 4;
        for (i = 0; i < numrec; i++) {
            subti = proto_tree_add_text (rscn_tree, tvb, offset, 4,
                                         "Affected N_Port Page %u", i);
            rectree = proto_item_add_subtree (subti, ett_fcels_rscn_rec);

            proto_tree_add_item (rectree, hf_fcels_rscn_evqual, tvb, offset,
                                 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rectree, hf_fcels_rscn_addrfmt, tvb, offset,
                                 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rectree, hf_fcels_rscn_domain, tvb, offset+1,
                                 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rectree, hf_fcels_rscn_area, tvb, offset+2,
                                 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rectree, hf_fcels_rscn_port, tvb, offset+3,
                                 1, ENC_BIG_ENDIAN);
            offset += 4;
        }
    }
}

static void
dissect_fcels_scr (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                   guint8 isreq, proto_item *ti)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    int offset = 7;
    proto_tree *scr_tree;

    if (tree) {
        scr_tree = proto_item_add_subtree (ti, ett_fcels_scr);
        proto_tree_add_item (scr_tree, hf_fcels_opcode, tvb, offset-7, 1, ENC_BIG_ENDIAN);
        if (isreq)
            proto_tree_add_item (scr_tree, hf_fcels_scrregn, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
}

static void
dissect_fcels_rnft (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint8 isreq, proto_item *ti)
{
    int offset = 0;
    guint16 numrec, i;
    proto_tree *rnft_tree, *fc4_tree;
    proto_item *subti;

    if (tree) {
        rnft_tree = proto_item_add_subtree (ti, ett_fcels_rnft);

        proto_tree_add_item (rnft_tree, hf_fcels_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);

        if (isreq) {
            proto_tree_add_text (rnft_tree, tvb, offset+2, 2,
                                 "Max Size: %u", tvb_get_ntohs (tvb, offset+2));
            proto_tree_add_text (rnft_tree, tvb, offset+7, 1,
                                 "Index: %u", tvb_get_guint8 (tvb, offset+7));
        }
        else {
            proto_tree_add_text (rnft_tree, tvb, offset+2, 2,
                                 "Payload Len: %u",
                                 tvb_get_ntohs (tvb, offset+2));
            numrec = tvb_get_guint8 (tvb, offset+5);
            proto_tree_add_text (rnft_tree, tvb, offset+5, 1,
                                 "List Length: %u", numrec);
            proto_tree_add_text (rnft_tree, tvb, offset+7, 1,
                                 "Index of First Rec in List: %u",
                                 tvb_get_guint8 (tvb, offset+7));
            offset = 8;
            for (i = 0; i < numrec; i++) {
                subti = proto_tree_add_text (rnft_tree, tvb, offset, 4,
                                             "FC-4 Entry #%u", i);
                fc4_tree = proto_item_add_subtree (subti, ett_fcels_rnft_fc4);

                proto_tree_add_item (fc4_tree, hf_fcels_rnft_fc4type, tvb,
                                     offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_text (fc4_tree, tvb, offset+1, 3,
                                     "FC-4 Qualifier 0x%x",
                                     tvb_get_ntoh24 (tvb, offset+1));
                offset += 4;
            }
        }
    }
}

static void
dissect_fcels_lsts (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint8 isreq, proto_item *ti)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    int offset = 5;
    proto_tree *lsts_tree;

    if (tree) {
        lsts_tree = proto_item_add_subtree (ti, ett_fcels_lsts);

        proto_tree_add_item (lsts_tree, hf_fcels_opcode, tvb, offset-5, 1, ENC_BIG_ENDIAN);
        if (isreq) {
            /* In case of LSTS, the reply has the meat */
            return;
        }
        proto_tree_add_item (lsts_tree, hf_fcels_failedrcvr, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (lsts_tree, hf_fcels_flacompliance, tvb, offset+1,
                             1, ENC_BIG_ENDIAN);
        proto_tree_add_item (lsts_tree, hf_fcels_loopstate, tvb, offset+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (lsts_tree, hf_fcels_publicloop_bmap, tvb, offset+3,
                             16, ENC_NA);
        proto_tree_add_item (lsts_tree, hf_fcels_pvtloop_bmap, tvb, offset+19,
                             16, ENC_NA);
        proto_tree_add_item (lsts_tree, hf_fcels_alpa_map, tvb, offset+35,
                             128, ENC_NA);
    }
}

/* Maximum length of possible string from, dissect_fcels_prlilo_payload
 * 119 bytes, FIX possible buffer overflow */
#define FCELS_PRLILO_MAXSTRINGLEN 256

static void
dissect_fcels_prlilo_payload (tvbuff_t *tvb, packet_info *pinfo _U_,
                              guint8 isreq, proto_item *ti, guint8 opcode)
{
    int offset = 0;
    guint8 type;
    proto_tree *prli_tree, *svcpg_tree;
    int num_svcpg, payload_len, i, flag;
    proto_item *subti;

    /* We're assuming that we're invoked only if tree is not NULL i.e.
     * we don't do the usual "if (tree)" check here, the caller must.
     */
    prli_tree = proto_item_add_subtree (ti, ett_fcels_prli);

    proto_tree_add_item (prli_tree, hf_fcels_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_text (prli_tree, tvb, offset+1, 1,
                         "Page Length: %u",
                         tvb_get_guint8 (tvb, offset+1));
    payload_len = tvb_get_ntohs (tvb, offset+2);
    proto_tree_add_text (prli_tree, tvb, offset+2, 2,
                         "Payload Length: %u", payload_len);
    num_svcpg = payload_len/16;

    offset = 4;
    for (i = 0; i < num_svcpg; i++) {
        subti = proto_tree_add_text (prli_tree, tvb, offset, 16,
                                     "Service Parameter Page %u", i);
        svcpg_tree = proto_item_add_subtree (subti, ett_fcels_prli_svcpg);

        type = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (svcpg_tree, tvb, offset, 1,
                             "TYPE: %s",
                             val_to_str (type,
                                         fc_prli_fc4_val, "0x%x"));
        proto_tree_add_text (svcpg_tree, tvb, offset+1, 1,
                             "TYPE Code Extension: %u",
                             tvb_get_guint8 (tvb, offset+1));

        flag = tvb_get_guint8 (tvb, offset+2);
        dissect_prlilo_flags (svcpg_tree, tvb, offset+2, flag, opcode);

        if (!isreq && (opcode != FC_ELS_TPRLO)) {
            /* This is valid only for ACC */
            proto_tree_add_text (svcpg_tree, tvb, offset+2, 1,
                                 "Response Code: 0x%x",
                                 (tvb_get_guint8 (tvb, offset+2) & 0x0F));
        }
        if (opcode != FC_ELS_TPRLO) {
            proto_tree_add_text (svcpg_tree, tvb, offset+4, 4,
                                 "Originator PA: 0x%x",
                                 tvb_get_ntohl (tvb, offset+4));
        }
        else {
            proto_tree_add_text (svcpg_tree, tvb, offset+4, 4,
                                 "3rd Party Originator PA: 0x%x",
                                 tvb_get_ntohl (tvb, offset+4));
        }
        proto_tree_add_text (svcpg_tree, tvb, offset+8, 4,
                             "Responder PA: 0x%x",
                             tvb_get_ntohl (tvb, offset+8));

        if (type == FC_TYPE_SCSI) {
            flag = tvb_get_ntohs (tvb, offset+14);
            dissect_fcp_flags (svcpg_tree, tvb, offset+12, flag, isreq);
        }
        else if ((opcode == FC_ELS_PRLI) && !isreq) {
            proto_tree_add_text (svcpg_tree, tvb, offset+12, 4,
                                 "Service Parameter Response: 0x%x",
                                 tvb_get_ntohl (tvb, offset+12));
        }
        else if (opcode == FC_ELS_TPRLO) {
            proto_tree_add_text (svcpg_tree, tvb, offset+13, 3,
                                 "3rd Party N_Port Id: %s",
                                 tvb_fc_to_str (tvb, offset+13));
        }
    }
}

static void
dissect_fcels_prli (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    guint8 isreq, proto_item *ti)
{
    if (tree) {
        dissect_fcels_prlilo_payload (tvb, pinfo, isreq, ti, FC_ELS_PRLI);
    }
}

static void
dissect_fcels_prlo (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    guint8 isreq, proto_item *ti)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    if (tree) {
        dissect_fcels_prlilo_payload (tvb, pinfo, isreq, ti, FC_ELS_PRLO);
    }
}

static void
dissect_fcels_tprlo (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                     guint8 isreq, proto_item *ti)
{
    /* Set up structures needed to add the protocol subtree and manage it */

    if (tree) {
        dissect_fcels_prlilo_payload (tvb, pinfo, isreq, ti, FC_ELS_TPRLO);
    }
}

static void
dissect_fcels_lirr (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint8 isreq _U_, proto_item *ti)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    int offset = 4;
    proto_tree *lirr_tree;
    guint8 lirr_fmt;

    if (tree) {
        lirr_tree = proto_item_add_subtree (ti, ett_fcels_lirr);

        proto_tree_add_item (lirr_tree, hf_fcels_opcode, tvb, offset-4, 1, ENC_BIG_ENDIAN);

        proto_tree_add_text (lirr_tree, tvb, offset, 1,
                             "Regn. Function: %s",
                             val_to_str (tvb_get_guint8 (tvb, offset),
                                         fc_els_lirr_regfunc_val,
                                         "Reserved (0x%x)"));
        lirr_fmt = tvb_get_guint8 (tvb, offset+1);
        if (!lirr_fmt) {
            /* This scheme is resorted to because the value 0 has a string in
             * the value_string that is not what we want displayed here.
             */
            proto_tree_add_text (lirr_tree, tvb, offset, 1,
                                 "Regn. Format: Common Format");
        }
        else {
            proto_tree_add_text (lirr_tree, tvb, offset, 1,
                                 "Regn. Format: %s",
                                 val_to_str (lirr_fmt, fc_fc4_val, "0x%x"));
        }
    }
}

static void
dissect_fcels_srl (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                   guint8 isreq, proto_item *ti)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    int offset = 4,
        flag = 0;
    proto_tree *srl_tree;

    if (tree) {
        srl_tree = proto_item_add_subtree (ti, ett_fcels_srl);

        proto_tree_add_item (srl_tree, hf_fcels_opcode, tvb, offset-4, 1, ENC_BIG_ENDIAN);
        if (!isreq)
            return;

        flag = tvb_get_guint8 (tvb, offset);
        if (flag & 0x1) {
            proto_tree_add_text (srl_tree, tvb, offset, 1,
                                 "Flag: Scan only specified FL Port");
        }
        else {
            proto_tree_add_text (srl_tree, tvb, offset, 1,
                                 "Flag: Scan all loops in domain");
        }
        proto_tree_add_text (srl_tree, tvb, offset+1, 3,
                             "FL_Port Addr: %s",
                             tvb_fc_to_str (tvb, offset+1));
    }
}

static void
dissect_fcels_rpsc (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint8 isreq, proto_item *ti)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    int offset = 2;
    int num_entries, i, cap;
    proto_tree *rpsc_tree;

    if (tree) {
        rpsc_tree = proto_item_add_subtree (ti, ett_fcels_rpsc);

        proto_tree_add_item (rpsc_tree, hf_fcels_opcode, tvb, offset-2, 1, ENC_BIG_ENDIAN);
        if (isreq)
            return;

        num_entries = tvb_get_ntohs (tvb, offset);
        proto_tree_add_text (rpsc_tree, tvb, offset, 2,
                             "Number of Entries: %u", num_entries);
        offset = 4;
        for (i = 0; i < num_entries; i++) {
            cap = tvb_get_ntohs (tvb, offset);
            dissect_speed_flags (rpsc_tree, tvb, offset, cap, i);

            cap = tvb_get_ntohs (tvb, offset+2);
            proto_tree_add_text (rpsc_tree, tvb, offset+2, 2,
                                 "Port Oper Speed: %s",
                                 val_to_str (cap, fc_els_portspeed_val,
                                             "0x%x"));
        }
    }
}


static void
dissect_fcels_cbind (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    proto_item *ti)
{
    int offset = 0;
    proto_tree *cbind_tree=NULL;

    if (tree) {
        cbind_tree = proto_item_add_subtree (ti, ett_fcels_cbind);

        proto_tree_add_item (cbind_tree, hf_fcels_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    col_set_str(pinfo->cinfo, COL_INFO, "CBIND ");

    proto_tree_add_item (cbind_tree, hf_fcels_cbind_liveness, tvb, offset+4, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item (cbind_tree, hf_fcels_cbind_addr_mode, tvb, offset+6, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item (cbind_tree, hf_fcels_cbind_ifcp_version, tvb, offset+7, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item (cbind_tree, hf_fcels_cbind_userinfo, tvb, offset+8, 4, ENC_BIG_ENDIAN);

    proto_tree_add_string (cbind_tree, hf_fcels_cbind_snpname, tvb, offset+12, 8,
                           tvb_fcwwn_to_str (tvb, offset+12));
    proto_tree_add_string (cbind_tree, hf_fcels_cbind_dnpname, tvb, offset+20, 8,
                           tvb_fcwwn_to_str (tvb, offset+20));

    switch(tvb_reported_length(tvb)){
    case 32: /* 28 byte Request + 4 bytes FC CRC */
        col_append_str (pinfo->cinfo, COL_INFO, "Request");
        break;
    case 40: /* 36 byte Response + 4 bytes FC CRC */
        col_append_str (pinfo->cinfo, COL_INFO, "Response");
        proto_tree_add_item (cbind_tree, hf_fcels_cbind_status, tvb, offset+30, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (cbind_tree, hf_fcels_chandle, tvb, offset+34, 2, ENC_BIG_ENDIAN);
        break;
    }

}

static void
dissect_fcels_unbind (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    proto_item *ti)
{
    int offset = 0;
    proto_tree *cbind_tree=NULL;

    if (tree) {
        cbind_tree = proto_item_add_subtree (ti, ett_fcels_cbind);

        proto_tree_add_item (cbind_tree, hf_fcels_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    col_set_str(pinfo->cinfo, COL_INFO, "UNBIND ");

    proto_tree_add_item (cbind_tree, hf_fcels_cbind_userinfo, tvb, offset+4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item (cbind_tree, hf_fcels_chandle, tvb, offset+10, 2, ENC_BIG_ENDIAN);


    switch(tvb_reported_length(tvb)){
    case 24: /* 20 byte Request + 4 bytes FC CRC */
        col_append_str (pinfo->cinfo, COL_INFO, "Request");
        break;
    case 28: /* 24 byte Response + 4 bytes FC CRC */
        col_append_str (pinfo->cinfo, COL_INFO, "Response");
        proto_tree_add_item (cbind_tree, hf_fcels_unbind_status, tvb, offset+22, 2, ENC_BIG_ENDIAN);
        break;
    }

}

static void
dissect_fcels_rnid (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                    guint8 isreq, proto_item *ti)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    int offset = 0;
    int clen;
    proto_tree *rnid_tree;

    if (tree) {
        rnid_tree = proto_item_add_subtree (ti, ett_fcels_rnid);

        proto_tree_add_item (rnid_tree, hf_fcels_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
        if (isreq) {
            proto_tree_add_item (rnid_tree, hf_fcels_nodeidfmt, tvb, offset+4,
                                 1, ENC_BIG_ENDIAN);
        }
        else {
            /* We only decode responses to nodeid fmt DF */
            proto_tree_add_item (rnid_tree, hf_fcels_nodeidfmt, tvb, offset+4,
                                 1, ENC_BIG_ENDIAN);
            clen = tvb_get_guint8 (tvb, offset+5);
            proto_tree_add_text (rnid_tree, tvb, offset+5, 1,
                                 "Common Identification Data Length: %u", clen);
            proto_tree_add_item (rnid_tree, hf_fcels_spidlen, tvb, offset+7,
                                 1, ENC_BIG_ENDIAN);
            if (clen) {
                proto_tree_add_string (rnid_tree, hf_fcels_npname, tvb,
                                       offset+8, 8,
                                       tvb_fcwwn_to_str (tvb, offset+8));
                proto_tree_add_string (rnid_tree, hf_fcels_fnname, tvb,
                                       offset+16, 8,
                                       tvb_fcwwn_to_str (tvb, offset+16));
            }
            if (tvb_get_guint8 (tvb, offset+4) == 0xDF) {
                /* Decode the Specific Node ID Format as this is known */
                proto_tree_add_item (rnid_tree, hf_fcels_vendoruniq, tvb,
                                     offset+24, 16, ENC_NA);
                proto_tree_add_item (rnid_tree, hf_fcels_asstype, tvb,
                                     offset+40, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item (rnid_tree, hf_fcels_physport, tvb,
                                     offset+44, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item (rnid_tree, hf_fcels_attnodes, tvb,
                                     offset+48, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item (rnid_tree, hf_fcels_nodemgmt, tvb,
                                     offset+52, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (rnid_tree, hf_fcels_ipvers, tvb,
                                     offset+53, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (rnid_tree, hf_fcels_tcpport, tvb,
                                     offset+54, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item (rnid_tree, hf_fcels_ip, tvb, offset+56,
                                     16, ENC_NA);
                proto_tree_add_item (rnid_tree, hf_fcels_vendorsp, tvb,
                                     offset+74, 2, ENC_BIG_ENDIAN);
            }
        }
    }
}

static void
dissect_fcels_rlir (tvbuff_t *tvb _U_, packet_info *pinfo _U_,
                    proto_tree *tree, guint8 isreq _U_,
                    proto_item *ti _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */

    if (tree) {
    }
}

static void
dissect_fcels_lsrjt (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint8 isreq _U_, proto_item *ti)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    int offset = 5;
    proto_tree *lsrjt_tree;

    if (tree) {
        lsrjt_tree = proto_item_add_subtree (ti, ett_fcels_lsrjt);

        proto_tree_add_item (lsrjt_tree, hf_fcels_opcode, tvb, offset-5, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item (lsrjt_tree, hf_fcels_rjtcode, tvb, offset++, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (lsrjt_tree, hf_fcels_rjtdetcode, tvb, offset++, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (lsrjt_tree, hf_fcels_vnduniq, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
}

static void
dissect_fcels (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti = NULL;
    proto_tree *acc_tree;
    guint8 isreq = FC_ELS_REQ;
    int offset = 0;
    guint8 opcode,
           failed_opcode = 0;
    conversation_t *conversation;
    fcels_conv_data_t *cdata;
    fcels_conv_key_t ckey, *req_key;
    guint options;
    address dstaddr;
    guint8 addrdata[3];

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FC ELS");

    /* decoding of this is done by each individual opcode handler */
    opcode = tvb_get_guint8 (tvb, 0);

    if (tree) {
        ti = proto_tree_add_protocol_format (tree, proto_fcels, tvb, 0,
                                             tvb_length (tvb), "FC ELS");
    }

    /* Register conversation in case this is not a response */
    if ((opcode != FC_ELS_LSRJT) && (opcode != FC_ELS_ACC)) {
        if (opcode == FC_ELS_FLOGI) {
            const guint8 *srcfc;

            /* Check that the source address is, in fact, an FC address */
            if (pinfo->src.type != AT_FC) {
                expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_WARN,
                                       "Unknown source address type: %u",
                                       pinfo->src.type);
                return;
            }

            srcfc = pinfo->src.data;
            if (srcfc[2]) {
                /* If it is a loop port, we'll need to remember the ALPA */
                options = NO_PORT2;
            }
            else {
                options = NO_PORT2 | NO_ADDR2;
            }
        }
        else {
            options = NO_PORT2;
        }
        conversation = find_conversation (pinfo->fd->num, &pinfo->dst, &pinfo->src,
                                          pinfo->ptype, pinfo->oxid,
                                          pinfo->rxid, options);

        if (!conversation) {
            conversation = conversation_new (pinfo->fd->num, &pinfo->dst, &pinfo->src,
                                             pinfo->ptype, pinfo->oxid,
                                             pinfo->rxid, options);
        }

        ckey.conv_idx = conversation->index;

        cdata = (fcels_conv_data_t *)g_hash_table_lookup (fcels_req_hash,
                                                          &ckey);
        if (cdata) {
            /* Since we never free the memory used by an exchange, this maybe a
             * case of another request using the same exchange as a previous
             * req.
             */
            cdata->opcode = opcode;
        }
        else {
            req_key = se_alloc (sizeof(fcels_conv_key_t));
            req_key->conv_idx = conversation->index;

            cdata = se_alloc (sizeof(fcels_conv_data_t));
            cdata->opcode = opcode;

            g_hash_table_insert (fcels_req_hash, req_key, cdata);
        }
    }
    else {
        isreq = FC_ELS_RPLY;

        options = NO_PORT2;
        conversation = find_conversation (pinfo->fd->num, &pinfo->dst, &pinfo->src,
                                          pinfo->ptype, pinfo->oxid,
                                          pinfo->rxid, options);
        if (!conversation) {
            /* FLOGI has two ways to save state: without the src and using just
             * the port (ALPA) part of the address. Try both.
             */
            const guint8 *dstfc;

            /* Check that the source address is, in fact, an FC address */
            if (pinfo->dst.type != AT_FC) {
                expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_WARN,
                                       "Unknown destination address type: %u",
                                       pinfo->dst.type);
                return;
            }

            dstfc = pinfo->dst.data;

            addrdata[0] = addrdata[1] = 0;
            addrdata[2] = dstfc[2];
            SET_ADDRESS (&dstaddr, AT_FC, 3, addrdata);
            conversation = find_conversation (pinfo->fd->num, &dstaddr, &pinfo->src,
                                              pinfo->ptype, pinfo->oxid,
                                              pinfo->rxid, options);
        }

        if (!conversation) {
            /* Finally check for FLOGI with both NO_PORT2 and NO_ADDR2 set */
            options = NO_ADDR2 | NO_PORT2;
            conversation = find_conversation (pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                              pinfo->ptype, pinfo->oxid,
                                              pinfo->rxid, options);
            if (!conversation) {
                if (tree && (opcode == FC_ELS_ACC)) {
                    /* No record of what this accept is for. Can't decode */
                    acc_tree = proto_item_add_subtree (ti, ett_fcels_acc);
                    proto_tree_add_text (acc_tree, tvb, offset, tvb_length (tvb),
                                         "No record of Exchange. Unable to decode ACC");
                    return;
                }
                failed_opcode = 0;
            }
        }

        if (conversation) {
            ckey.conv_idx = conversation->index;

            cdata = (fcels_conv_data_t *)g_hash_table_lookup (fcels_req_hash, &ckey);

            if (cdata != NULL) {
                if ((options & NO_ADDR2) && (cdata->opcode != FC_ELS_FLOGI)) {
                    /* only FLOGI can have this special check */
                    if (tree && (opcode == FC_ELS_ACC)) {
                        /* No record of what this accept is for. Can't decode */
                        acc_tree = proto_item_add_subtree (ti,
                                                           ett_fcels_acc);
                        proto_tree_add_text (acc_tree, tvb, offset,
                                             tvb_length (tvb),
                                             "No record of Exchg. Unable to decode ACC");
                        return;
                    }
                }
                if (opcode == FC_ELS_ACC)
                    opcode = cdata->opcode;
                else
                    failed_opcode = cdata->opcode;
            }

            if (tree) {
                if ((cdata == NULL) && (opcode != FC_ELS_LSRJT)) {
                    /* No record of what this accept is for. Can't decode */
                    acc_tree = proto_item_add_subtree (ti, ett_fcels_acc);
                    proto_tree_add_text (acc_tree, tvb, offset, tvb_length (tvb),
                                         "No record of ELS Req. Unable to decode ACC");
                    return;
                }
            }
        }
    }

    if (check_col (pinfo->cinfo, COL_INFO)) {
        if (isreq == FC_ELS_REQ) {
            col_add_str (pinfo->cinfo, COL_INFO,
                         val_to_str (opcode, fc_els_proto_val, "0x%x"));
        }
        else if (opcode == FC_ELS_LSRJT) {
            col_add_fstr (pinfo->cinfo, COL_INFO, "LS_RJT (%s)",
                          val_to_str (failed_opcode, fc_els_proto_val, "0x%x"));
        }
        else {
            col_add_fstr (pinfo->cinfo, COL_INFO, "ACC (%s)",
                          val_to_str (opcode, fc_els_proto_val, "0x%x"));
        }
    }

    switch (opcode) {
    case FC_ELS_LSRJT:
        dissect_fcels_lsrjt (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_PLOGI:
        dissect_fcels_plogi (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_FLOGI:
        dissect_fcels_flogi (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_LOGOUT:
        dissect_fcels_logout (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_ABTX:
        dissect_fcels_abtx (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_RSI:
        dissect_fcels_rsi (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_RRQ:
        dissect_fcels_rrq (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_REC:
        dissect_fcels_rec (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_PRLI:
        dissect_fcels_prli (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_PRLO:
        dissect_fcels_prlo (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_TPRLO:
        dissect_fcels_tprlo (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_PDISC:
        dissect_fcels_pdisc (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_FDISC:
        dissect_fcels_fdisc (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_ADISC:
        dissect_fcels_adisc (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_FARP_REQ:
        dissect_fcels_farp_req (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_FARP_RPLY:
        dissect_fcels_farp_rply (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_RPS:
        dissect_fcels_rps (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_RPL:
        dissect_fcels_rpl (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_FAN:
        dissect_fcels_fan (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_RSCN:
        dissect_fcels_rscn (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_SCR:
        dissect_fcels_scr (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_RNFT:
        dissect_fcels_rnft (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_LSTS:
        dissect_fcels_lsts (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_RNID:
        dissect_fcels_rnid (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_RLIR:
        dissect_fcels_rlir (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_LIRR:
        dissect_fcels_lirr (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_SRL:
        dissect_fcels_srl (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_RPSC:
        dissect_fcels_rpsc (tvb, pinfo, tree, isreq, ti);
        break;
    case FC_ELS_AUTH:
        if (isreq && fcsp_handle)
            call_dissector (fcsp_handle, tvb, pinfo, tree);
        break;
    case FC_ELS_CBIND:
        dissect_fcels_cbind (tvb, pinfo, tree, ti);
        break;
    case FC_ELS_UNBIND:
        dissect_fcels_unbind (tvb, pinfo, tree, ti);
        break;
    default:
        /* proto_tree_add_text ( */
        call_dissector (data_handle, tvb, pinfo, tree);
        break;
    }
}

void
proto_register_fcels (void)
{
    static hf_register_info hf[] = {
        { &hf_fcels_opcode,
          {"Cmd Code", "fcels.opcode", FT_UINT8, BASE_HEX,
           VALS (fc_els_proto_val), 0x0, NULL, HFILL}},
        { &hf_fcels_rjtcode,
          {"Reason Code", "fcels.rjt.reason", FT_UINT8, BASE_HEX,
           VALS (fc_els_rjt_val), 0x0, NULL, HFILL}},
        { &hf_fcels_rjtdetcode,
          {"Reason Explanation", "fcels.rjt.detail", FT_UINT8, BASE_HEX,
           VALS (fc_els_rjt_det_val), 0x0, NULL, HFILL}},
        { &hf_fcels_vnduniq,
          {"Vendor Unique", "fcels.rjt.vnduniq", FT_UINT8, BASE_HEX, NULL,
           0x0, NULL, HFILL}},
        { &hf_fcels_b2b,
          {"B2B Credit", "fcels.logi.b2b", FT_UINT8, BASE_DEC, NULL, 0x0, NULL,
           HFILL}},
        { &hf_fcels_cmnfeatures,
          {"Common Svc Parameters", "fcels.logi.cmnfeatures", FT_UINT16, BASE_HEX, NULL,
           0x0, NULL, HFILL}},
        { &hf_fcels_bbscnum,
          {"BB_SC Number", "fcels.logi.bbscnum", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL,
           HFILL}},
        { &hf_fcels_rcvsize,
          {"Receive Size", "fcels.logi.rcvsize", FT_UINT16, BASE_DEC, NULL, 0x0FFF, NULL,
           HFILL}},
        { &hf_fcels_maxconseq,
          {"Max Concurrent Seq", "fcels.logi.maxconseq", FT_UINT16, BASE_DEC, NULL,
           0x0, NULL, HFILL}},
        { &hf_fcels_reloffset,
          {"Relative Offset By Info Cat", "fcels.logi.reloff", FT_UINT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcels_edtov,
          {"E_D_TOV", "fcels.edtov", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        { &hf_fcels_npname,
          {"N_Port Port_Name", "fcels.npname", FT_STRING, BASE_NONE, NULL, 0x0,
           NULL, HFILL}},
        { &hf_fcels_fnname,
          {"Fabric/Node Name", "fcels.fnname", FT_STRING, BASE_NONE, NULL, 0x0,
           NULL, HFILL}},
        { &hf_fcels_cls1param,
          {"Class 1 Svc Param", "fcels.logi.cls1param", FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}},
        { &hf_fcels_cls2param,
          {"Class 2 Svc Param", "fcels.logi.cls2param", FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}},
        { &hf_fcels_cls3param,
          {"Class 3 Svc Param", "fcels.logi.cls3param", FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}},
        { &hf_fcels_cls4param,
          {"Class 4 Svc Param", "fcels.logi.cls4param", FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}},
        { &hf_fcels_vendorvers,
          {"Vendor Version", "fcels.logi.vendvers", FT_BYTES, BASE_NONE, NULL, 0x0, NULL,
           HFILL}},
        { &hf_fcels_svcavail,
          {"Services Availability", "fcels.logi.svcavail", FT_BYTES, BASE_NONE, NULL,
           0x0, NULL, HFILL}},
        { &hf_fcels_clsflags,
          {"Service Options", "fcels.logi.clsflags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL,
           HFILL}},
        { &hf_fcels_clsrcvsize,
          {"Class Recv Size", "fcels.logi.clsrcvsize", FT_UINT16, BASE_DEC, NULL,
           0x0, NULL, HFILL}},
        { &hf_fcels_conseq,
          {"Total Concurrent Seq", "fcels.logi.totconseq", FT_UINT8, BASE_DEC, NULL,
           0x0, NULL, HFILL}},
        { &hf_fcels_e2e,
          {"End2End Credit", "fcels.logi.e2e", FT_UINT16, BASE_DEC, NULL, 0x0, NULL,
           HFILL}},
        { &hf_fcels_openseq,
          {"Open Seq Per Exchg", "fcels.logi.openseq", FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}},
        { &hf_fcels_nportid,
          {"Originator S_ID", "fcels.portid", FT_STRING, BASE_NONE, NULL, 0x0,
           NULL, HFILL}},
        { &hf_fcels_oxid,
          {"OXID", "fcels.oxid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        { &hf_fcels_rxid,
          {"RXID", "fcels.rxid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        { &hf_fcels_recovqual,
          {"Recovery Qualifier", "fcels.rcovqual", FT_UINT8, BASE_HEX, NULL,
           0x0, NULL, HFILL}},
        { &hf_fcels_fabricaddr,
          {"Fabric Address", "fcels.faddr", FT_STRING, BASE_NONE, NULL, 0x0, NULL,
           HFILL}},
        { &hf_fcels_fabricpname,
          {"Fabric Port Name", "fcels.fpname", FT_STRING, BASE_NONE, NULL, 0x0,
           NULL, HFILL}},
        { &hf_fcels_failedrcvr,
          {"Failed Receiver AL_PA", "fcels.faildrcvr", FT_UINT8, BASE_HEX, NULL,
           0x0, NULL, HFILL}},
        { &hf_fcels_flacompliance,
          {"FC-FLA Compliance", "fcels.flacompliance", FT_UINT8, BASE_HEX,
           VALS (fc_els_flacompliance_val), 0x0, NULL, HFILL}},
        { &hf_fcels_loopstate,
          {"Loop State", "fcels.loopstate", FT_UINT8, BASE_HEX,
           VALS (fc_els_loopstate_val), 0x0, NULL, HFILL}},
        { &hf_fcels_publicloop_bmap,
          {"Public Loop Device Bitmap", "fcels.pubdev_bmap", FT_BYTES, BASE_NONE,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcels_pvtloop_bmap,
          {"Private Loop Device Bitmap", "fcels.pvtdev_bmap", FT_BYTES,
           BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_fcels_alpa_map,
          {"AL_PA Map", "fcels.alpa", FT_BYTES, BASE_NONE, NULL, 0x0, NULL,
           HFILL}},
        { &hf_fcels_scrregn,
          {"Registration Function", "fcels.scr.regn", FT_UINT8, BASE_HEX,
           VALS (fc_els_scr_reg_val), 0x0, NULL, HFILL}},
        { &hf_fcels_farp_matchcodept,
          {"Match Address Code Points", "fcels.matchcp", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcels_farp_respaction,
          {"Responder Action", "fcels.respaction", FT_UINT8, BASE_HEX,
           VALS (fc_els_farp_respaction_val), 0x0, NULL, HFILL}},
        { &hf_fcels_resportid,
          {"Responding Port ID", "fcels.resportid", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcels_respname,
          {"Responding Port Name", "fcels.respname", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcels_respnname,
          {"Responding Node Name", "fcels.respnname", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcels_reqipaddr,
          {"Requesting IP Address", "fcels.reqipaddr", FT_IPv6, BASE_NONE,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcels_respipaddr,
          {"Responding IP Address", "fcels.respipaddr", FT_IPv6, BASE_NONE,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcels_hardaddr,
          {"Hard Address of Originator", "fcels.hrdaddr", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcels_rps_flag,
          {"Flag", "fcels.flag", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        { &hf_fcels_rps_portnum,
          {"Physical Port Number", "fcels.portnum", FT_UINT32, BASE_HEX, NULL,
           0x0, NULL, HFILL}},
        { &hf_fcels_rps_portstatus,
          {"Port Status", "fcels.portstatus", FT_UINT16, BASE_HEX,
           VALS(fc_els_portstatus_val), 0x0, NULL, HFILL}},
        { &hf_fcels_rnft_fc4type,
          {"FC-4 Type", "fcels.rnft.fc4type", FT_UINT8, BASE_HEX,
           VALS (fc_fc4_val), 0x0, NULL, HFILL}},
        { &hf_fcels_rscn_evqual,
          {"Event Qualifier", "fcels.rscn.evqual", FT_UINT8, BASE_HEX,
           VALS (fc_els_rscn_evqual_val), 0x3C, NULL, HFILL}},
        { &hf_fcels_rscn_addrfmt,
          {"Address Format", "fcels.rscn.addrfmt", FT_UINT8, BASE_HEX,
           VALS (fc_els_rscn_addrfmt_val), 0x03, NULL, HFILL}},
        { &hf_fcels_rscn_domain,
          {"Affected Domain", "fcels.rscn.domain", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcels_rscn_area,
          {"Affected Area", "fcels.rscn.area", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcels_rscn_port,
          {"Affected Port", "fcels.rscn.port", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcels_rec_fc4,
          {"FC4 value", "fcels.rec.fc4value", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcels_estat,
          {"Exchange Status", "fcels.estat", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcels_estat_resp,
          {"Sequence Responder", "fcels.estat.resp", FT_BOOLEAN, 32,
           TFS(&tfs_fcels_estat_resp),
           FC_ESB_ST_RESP, "Seq responder?", HFILL}},
        { &hf_fcels_estat_seq_init,
          {"Sequence Initiative", "fcels.estat.seq_init", FT_BOOLEAN, 32,
           TFS(&tfs_fcels_estat_seq_init),
           FC_ESB_ST_SEQ_INIT, "Responder has Sequence Initiative?", HFILL}},
        { &hf_fcels_estat_compl,
          {"Exchange Complete", "fcels.estat.complete", FT_BOOLEAN, 32,
           TFS(&tfs_fcels_estat_compl),
           FC_ESB_ST_COMPLETE, "Exchange complete?", HFILL}},
        { &hf_fcels_nodeidfmt,
          {"Node Identification Format", "fcels.rnid.nodeidfmt", FT_UINT8,
           BASE_HEX, VALS (fc_els_nodeid_val), 0x0, NULL, HFILL}},
        { &hf_fcels_spidlen,
          {"Specific Id Length", "fcels.rnid.spidlen", FT_UINT8, BASE_DEC, NULL,
           0x0, NULL, HFILL}},
        { &hf_fcels_vendoruniq,
          {"Vendor Unique", "fcels.rnid.vendoruniq", FT_BYTES, BASE_NONE, NULL,
           0x0, NULL, HFILL}},
        { &hf_fcels_vendorsp,
          {"Vendor Specific", "fcels.rnid.vendorsp", FT_UINT16, BASE_HEX, NULL,
           0x0, NULL, HFILL}},
        { &hf_fcels_asstype,
          {"Associated Type", "fcels.rnid.asstype", FT_UINT32, BASE_HEX,
           VALS (fc_els_rnid_asstype_val), 0x0, NULL, HFILL}},
        { &hf_fcels_physport,
          {"Physical Port Number", "fcels.rnid.physport", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcels_attnodes,
          {"Number of Attached Nodes", "fcels.rnid.attnodes", FT_UINT32,
           BASE_HEX, NULL, 0x0, NULL, HFILL}},
        { &hf_fcels_nodemgmt,
          {"Node Management", "fcels.rnid.nodemgmt", FT_UINT8, BASE_HEX,
           VALS (fc_els_rnid_mgmt_val), 0x0, NULL, HFILL}},
        { &hf_fcels_ipvers,
          {"IP Version", "fcels.rnid.ipvers", FT_UINT8, BASE_HEX,
           VALS (fc_els_rnid_ipvers_val), 0x0, NULL, HFILL}},
        { &hf_fcels_tcpport,
          {"TCP/UDP Port Number", "fcels.rnid.tcpport", FT_UINT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcels_ip,
          {"IP Address", "fcels.rnid.ip", FT_IPv6, BASE_NONE, NULL, 0x0, NULL,
           HFILL}},
        { &hf_fcels_cbind_liveness,
          {"Liveness Test Interval", "fcels.cbind.liveness", FT_UINT16, BASE_DEC,
           NULL, 0x0, "Liveness Test Interval in seconds", HFILL}},
        { &hf_fcels_cbind_addr_mode,
          {"Addressing Mode", "fcels.cbind.addr_mode", FT_UINT8, BASE_HEX,
           VALS(cbind_addr_mode_vals), 0x0, NULL, HFILL}},
        { &hf_fcels_cbind_ifcp_version,
          {"iFCP version", "fcels.cbind.ifcp_version", FT_UINT8, BASE_DEC,
           NULL, 0x0, "Version of iFCP protocol", HFILL}},
        { &hf_fcels_cbind_userinfo,
          {"UserInfo", "fcels.cbind.userinfo", FT_UINT32, BASE_HEX,
           NULL, 0x0, "Userinfo token", HFILL}},
        { &hf_fcels_cbind_snpname,
          {"Source N_Port Port_Name", "fcels.cbind.snpname", FT_STRING, BASE_NONE, NULL, 0x0,
           NULL, HFILL}},
        { &hf_fcels_cbind_dnpname,
          {"Destination N_Port Port_Name", "fcels.cbind.dnpname", FT_STRING, BASE_NONE, NULL, 0x0,
           NULL, HFILL}},
        { &hf_fcels_cbind_status,
          {"Status", "fcels.cbind.status", FT_UINT16, BASE_DEC,
           VALS(cbind_status_vals), 0x0, "Cbind status", HFILL}},
        { &hf_fcels_chandle,
          {"Connection Handle", "fcels.cbind.handle", FT_UINT16, BASE_HEX,
           NULL, 0x0, "Cbind/Unbind connection handle", HFILL}},
        { &hf_fcels_unbind_status,
          {"Status", "fcels.unbind.status", FT_UINT16, BASE_DEC,
           VALS(unbind_status_vals), 0x0, "Unbind status", HFILL}},
        { &hf_fcels_cmn_cios,
          {"Cont. Incr. Offset Supported", "fcels.cmn.cios", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_cmn_cios), 0x8000, NULL, HFILL}},
        { &hf_fcels_cmn_rro,
          {"RRO Supported", "fcels.cmn.rro", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_cmn_rro), 0x4000, NULL, HFILL}},
        { &hf_fcels_cmn_vvv,
          {"Valid Vendor Version", "fcels.cmn.vvv", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_cmn_vvv), 0x2000, NULL, HFILL}},
        { &hf_fcels_cmn_b2b,
          {"B2B Credit Mgmt", "fcels.cmn.bbb", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_cmn_b2b), 0x0800, NULL, HFILL}},
        { &hf_fcels_cmn_e_d_tov,
          {"E_D_TOV", "fcels.cmn.e_d_tov", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_cmn_e_d_tov), 0x0400, NULL, HFILL}},
        { &hf_fcels_cmn_simplex,
          {"Simplex", "fcels.cmn.simplex", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_cmn_simplex), 0x0040, NULL, HFILL}},
        { &hf_fcels_cmn_multicast,
          {"Multicast", "fcels.cmn.multicast", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_cmn_multicast), 0x0200, NULL, HFILL}},
        { &hf_fcels_cmn_broadcast,
          {"Broadcast", "fcels.cmn.broadcast", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_cmn_broadcast), 0x0100, NULL, HFILL}},
        { &hf_fcels_cmn_security,
          {"Security", "fcels.cmn.security", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_cmn_security), 0x0020, NULL, HFILL}},
        { &hf_fcels_cmn_clk,
          {"Clk Sync", "fcels.cmn.clk", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_cmn_clk), 0x0010, NULL, HFILL}},
        { &hf_fcels_cmn_dhd,
          {"DHD Capable", "fcels.cmn.dhd", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_cmn_dhd), 0x0004, NULL, HFILL}},
        { &hf_fcels_cmn_seqcnt,
          {"SEQCNT", "fcels.cmn.seqcnt", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_cmn_seqcnt), 0x0002, NULL, HFILL}},
        { &hf_fcels_cmn_payload,
          {"Payload Len", "fcels.cmn.payload", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_cmn_payload), 0x0001, NULL, HFILL}},
        { &hf_fcels_cls_cns,
          {"Class Supported", "fcels.cls.cns", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_cls_cns), 0x8000, NULL, HFILL}},
        { &hf_fcels_cls_sdr,
          {"Delivery Mode", "fcels.cls.sdr", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_cls_sdr), 0x0800, NULL, HFILL}},
        { &hf_fcels_cls_prio,
          {"Priority", "fcels.cls.prio", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_cls_prio), 0x0080, NULL, HFILL}},
        { &hf_fcels_cls_nzctl,
          {"Non-zero CS_CTL", "fcels.cls.nzctl", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_cls_nzctl), 0x0040, NULL, HFILL}},
        { &hf_fcels_initctl,
          {"Initiator Ctl", "fcels.logi.initctl", FT_UINT16, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcels_initctl_initial_pa,
          {"Initial P_A", "fcels.logi.initctl.initial_pa", FT_UINT16, BASE_HEX,
           VALS(initial_pa_vals), 0x3000, NULL, HFILL}},
        { &hf_fcels_initctl_ack0,
          {"ACK0 Capable", "fcels.logi.initctl.ack0", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_initctl_ack0), 0x0800, NULL, HFILL}},
        { &hf_fcels_initctl_ackgaa,
          {"ACK GAA", "fcels.logi.initctl.ackgaa", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_initctl_ackgaa), 0x0200, NULL, HFILL}},
        { &hf_fcels_initctl_sync,
          {"Clock Sync", "fcels.logi.initctl.sync", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_initctl_sync), 0x0010, NULL, HFILL}},
        { &hf_fcels_rcptctl,
          {"Recipient Ctl", "fcels.logi.rcptctl", FT_UINT16, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcels_rcptctl_ack0,
          {"ACK0", "fcels.logi.rcptctl.ack", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_rcptctl_ack0), 0x8000, NULL, HFILL}},
        { &hf_fcels_rcptctl_interlock,
          {"X_ID Interlock", "fcels.logi.rcptctl.interlock", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_rcptctl_interlock), 0x2000, NULL, HFILL}},
        { &hf_fcels_rcptctl_policy,
          {"Policy", "fcels.logi.rcptctl.policy", FT_UINT16, BASE_HEX,
           VALS(rcptctl_policy_vals), 0x1800, NULL, HFILL}},
        { &hf_fcels_rcptctl_category,
          {"Category", "fcels.logi.rcptctl.category", FT_UINT16, BASE_HEX,
           VALS(rcptctl_category_vals), 0x0030, NULL, HFILL}},
        { &hf_fcels_rcptctl_sync,
          {"Clock Sync", "fcels.logi.rcptctl.sync", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_rcptctl_sync), 0x0008, NULL, HFILL}},
        { &hf_fcels_fcpflags,
          {"FCP Flags", "fcels.fcpflags", FT_UINT32, BASE_HEX, NULL, 0x0, NULL,
           HFILL}},
        { &hf_fcels_fcpflags_trireq,
          {"Task Retry Ident", "fcels.fcpflags.trireq", FT_BOOLEAN, 32,
           TFS(&tfs_fc_fcels_fcpflags_trireq), 1 << 9, NULL, HFILL}},
        { &hf_fcels_fcpflags_trirep,
          {"Task Retry Ident", "fcels.fcpflags.trirep", FT_BOOLEAN, 32,
           TFS(&tfs_fc_fcels_fcpflags_trirep), 1 << 9, NULL, HFILL}},
        { &hf_fcels_fcpflags_retry,
          {"Retry", "fcels.fcpflags.retry", FT_BOOLEAN, 32,
           TFS(&tfs_fc_fcels_fcpflags_retry), 1 << 8, NULL, HFILL}},
        { &hf_fcels_fcpflags_ccomp,
          {"Comp", "fcels.fcpflags.ccomp", FT_BOOLEAN, 32,
           TFS(&tfs_fc_fcels_fcpflags_ccomp), 0x0080, NULL, HFILL}},
        { &hf_fcels_fcpflags_datao,
          {"Data Overlay", "fcels.fcpflags.datao", FT_BOOLEAN, 32,
           TFS(&tfs_fc_fcels_fcpflags_datao), 0x0040, NULL, HFILL}},
        { &hf_fcels_fcpflags_initiator,
          {"Initiator", "fcels.fcpflags.initiator", FT_BOOLEAN, 32,
           TFS(&tfs_fc_fcels_fcpflags_initiator), 0x0020, NULL, HFILL}},
        { &hf_fcels_fcpflags_target,
          {"Target", "fcels.fcpflags.target", FT_BOOLEAN, 32,
           TFS(&tfs_fc_fcels_fcpflags_target), 0x0010, NULL, HFILL}},
        { &hf_fcels_fcpflags_rdxr,
          {"Rd Xfer_Rdy Dis", "fcels.fcpflags.rdxr", FT_BOOLEAN, 32,
           TFS(&tfs_fc_fcels_fcpflags_rdxr), 0x0002, NULL, HFILL}},
        { &hf_fcels_fcpflags_wrxr,
          {"Wr Xfer_Rdy Dis", "fcels.fcpflags.wrxr", FT_BOOLEAN, 32,
           TFS(&tfs_fc_fcels_fcpflags_wrxr), 0x0001, NULL, HFILL}},
        { &hf_fcels_prliloflags,
          {"PRLILO Flags", "fcels.prliloflags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
           HFILL}},
        { &hf_fcels_tprloflags_opav,
          {"3rd Party Orig PA Valid", "fcels.tprloflags.opav", FT_BOOLEAN, 8,
           TFS(&tfs_fc_fcels_tprloflags_opav), 0x80, NULL, HFILL}},
        { &hf_fcels_tprloflags_rpav,
          {"Resp PA Valid", "fcels.tprloflags.rpav", FT_BOOLEAN, 8,
           TFS(&tfs_fc_fcels_tprloflags_rpav), 0x40, NULL, HFILL}},
        { &hf_fcels_tprloflags_npv,
          {"3rd Party N_Port Valid", "fcels.tprloflags.npv", FT_BOOLEAN, 8,
           TFS(&tfs_fc_fcels_tprloflags_npv), 0x20, NULL, HFILL}},
        { &hf_fcels_tprloflags_gprlo,
          {"Global PRLO", "fcels.tprloflags.gprlo", FT_BOOLEAN, 8,
           TFS(&tfs_fc_fcels_tprloflags_gprlo), 0x10, NULL, HFILL}},
        { &hf_fcels_speedflags,
          {"Port Speed Capabilities", "fcels.speedflags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL,
           HFILL}},
        { &hf_fcels_speedflags_1gb,
          {"1Gb Support", "fcels.speedflags.1gb", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_speedflags_1gb), 0x8000, NULL, HFILL}},
        { &hf_fcels_speedflags_2gb,
          {"2Gb Support", "fcels.speedflags.2gb", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_speedflags_2gb), 0x4000, NULL, HFILL}},
        { &hf_fcels_speedflags_4gb,
          {"4Gb Support", "fcels.speedflags.4gb", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_speedflags_4gb), 0x2000, NULL, HFILL}},
        { &hf_fcels_speedflags_10gb,
          {"10Gb Support", "fcels.speedflags.10gb", FT_BOOLEAN, 16,
           TFS(&tfs_fc_fcels_speedflags_10gb), 0x1000, NULL, HFILL}},
        { &hf_fcels_prliloflags_opav,
          {"Orig PA Valid", "fcels.prliloflags.opav", FT_BOOLEAN, 8,
           TFS(&tfs_fc_fcels_prliloflags_opav), 0x80, NULL, HFILL}},
        { &hf_fcels_prliloflags_ipe,
          {"Image Pair Estd", "fcels.prliloflags.ipe", FT_BOOLEAN, 8,
           TFS(&tfs_fc_fcels_prliloflags_ipe), 0x20, NULL, HFILL}},
        { &hf_fcels_prliloflags_eip,
          {"Est Image Pair", "fcels.prliloflags.eip", FT_BOOLEAN, 8,
           TFS(&tfs_fc_fcels_prliloflags_eip), 0x20, NULL, HFILL}},
    };

    static gint *ett[] = {
        &ett_fcels,
        &ett_fcels_lsrjt,
        &ett_fcels_acc,
        &ett_fcels_logi,
        &ett_fcels_logi_cmnsvc,
        &ett_fcels_logi_clssvc,
        &ett_fcels_logo,
        &ett_fcels_abtx,
        &ett_fcels_rsi,
        &ett_fcels_rrq,
        &ett_fcels_rec,
        &ett_fcels_prli,
        &ett_fcels_prli_svcpg,
        &ett_fcels_adisc,
        &ett_fcels_farp,
        &ett_fcels_rps,
        &ett_fcels_rpl,
        &ett_fcels_rplpb,
        &ett_fcels_fan,
        &ett_fcels_rscn,
        &ett_fcels_rscn_rec,
        &ett_fcels_estat,
        &ett_fcels_scr,
        &ett_fcels_rnft,
        &ett_fcels_rnft_fc4,
        &ett_fcels_lsts,
        &ett_fcels_rnid,
        &ett_fcels_rlir,
        &ett_fcels_lirr,
        &ett_fcels_srl,
        &ett_fcels_rpsc,
        &ett_fcels_cbind,
        &ett_fcels_cmnfeatures,
        &ett_fcels_clsflags,
        &ett_fcels_initctl,
        &ett_fcels_rcptctl,
        &ett_fcels_fcpflags,
        &ett_fcels_prliloflags,
        &ett_fcels_speedflags,
    };

    proto_fcels = proto_register_protocol("FC Extended Link Svc", "FC ELS", "fcels");

    proto_register_field_array(proto_fcels, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_init_routine (&fcels_init_protocol);
}

void
proto_reg_handoff_fcels (void)
{
    dissector_handle_t els_handle;

    els_handle = create_dissector_handle (dissect_fcels, proto_fcels);
    dissector_add_uint("fc.ftype", FC_FTYPE_ELS, els_handle);

    data_handle = find_dissector ("data");
    fcsp_handle = find_dissector ("fcsp");
}
