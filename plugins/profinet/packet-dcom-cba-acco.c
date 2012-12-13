/* packet-dcom-cba-acco.c
 * Routines for DCOM CBA
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/emem.h>
#include <epan/addr_resolv.h>
#include <epan/dissectors/packet-dcerpc.h>
#include <epan/dissectors/packet-dcom.h>
#include "packet-dcom-cba-acco.h"

static int hf_cba_acco_opnum = -1;

static int hf_cba_acco_ping_factor = -1;

static int hf_cba_acco_count = -1;

static int hf_cba_acco_item = -1;
static int hf_cba_acco_data = -1;
static int hf_cba_acco_qc = -1;
static int hf_cba_acco_time_stamp = -1;

static int hf_cba_acco_conn_qos_type = -1;
static int hf_cba_acco_conn_qos_value = -1;
static int hf_cba_acco_conn_state = -1;
static int hf_cba_acco_conn_cons_id = -1;
static int hf_cba_acco_conn_version = -1;
static int hf_cba_acco_conn_prov_id = -1;
static int hf_cba_acco_conn_provider = -1;
static int hf_cba_acco_conn_consumer = -1;
static int hf_cba_acco_conn_provider_item = -1;
static int hf_cba_acco_conn_consumer_item = -1;
static int hf_cba_acco_conn_substitute = -1;
static int hf_cba_acco_conn_epsilon = -1;
static int hf_cba_acco_conn_persist = -1;

static int hf_cba_acco_cb_length = -1;
static int hf_cba_acco_cb_conn_data = -1;
static int hf_cba_acco_cb_version = -1;
static int hf_cba_acco_cb_flags = -1;
static int hf_cba_acco_cb_count = -1;
static int hf_cba_acco_cb_item = -1;
static int hf_cba_acco_cb_item_hole = -1;
static int hf_cba_acco_cb_item_length = -1;
static int hf_cba_acco_cb_item_data = -1;

static int hf_cba_connect_in = -1;
static int hf_cba_disconnect_in = -1;
static int hf_cba_connectcr_in = -1;
static int hf_cba_disconnectcr_in = -1;
static int hf_cba_disconnectme_in = -1;
static int hf_cba_data_first_in = -1;
static int hf_cba_data_last_in = -1;

static int hf_cba_acco_server_pICBAAccoCallback = -1;

static int hf_cba_acco_server_first_connect = -1;

static int hf_cba_acco_serversrt_prov_mac = -1;
static int hf_cba_acco_serversrt_cons_mac = -1;

static int hf_cba_acco_serversrt_cr_id = -1;
static int hf_cba_acco_serversrt_cr_length = -1;
static int hf_cba_acco_serversrt_cr_flags = -1;
static int hf_cba_acco_serversrt_cr_flags_timestamped = -1;
static int hf_cba_acco_serversrt_cr_flags_reconfigure = -1;
static int hf_cba_acco_serversrt_record_length = -1;
static int hf_cba_acco_serversrt_action = -1;
static int hf_cba_acco_serversrt_last_connect = -1;

static int hf_cba_getprovconnout = -1;

static int hf_cba_type_desc_len = -1;

static int hf_cba_connectincr = -1;
static int hf_cba_connectoutcr = -1;
static int hf_cba_connectin = -1;
static int hf_cba_connectout = -1;
static int hf_cba_getconnectionout = -1;
static int hf_cba_readitemout = -1;
static int hf_cba_writeitemin = -1;
static int hf_cba_addconnectionin = -1;
static int hf_cba_addconnectionout = -1;
static int hf_cba_getidout = -1;

static int hf_cba_getconsconnout = -1;
static int hf_cba_diagconsconnout = -1;
static int hf_cba_acco_conn_error_state = -1;

static int hf_cba_acco_info_max = -1;
static int hf_cba_acco_info_curr = -1;

static int hf_cba_acco_cdb_cookie = -1;

static int hf_cba_acco_rtauto = -1;

static int hf_cba_acco_prov_crid = -1;

static int hf_cba_acco_diag_req = -1;
static int hf_cba_acco_diag_in_length = -1;
static int hf_cba_acco_diag_out_length = -1;
static int hf_cba_acco_diag_data = -1;
static int hf_cba_acco_dcom_call = -1;
static int hf_cba_acco_srt_call = -1;

gint ett_cba_connectincr = -1;
gint ett_cba_connectoutcr = -1;
gint ett_cba_connectin = -1;
gint ett_cba_connectout = -1;
gint ett_cba_getprovconnout = -1;
gint ett_cba_addconnectionin = -1;
gint ett_cba_addconnectionout = -1;
gint ett_cba_getidout = -1;
gint ett_cba_getconnectionout = -1;
gint ett_cba_readitemout = -1;
gint ett_cba_writeitemin = -1;
gint ett_cba_acco_serversrt_cr_flags = -1;
gint ett_cba_frame_info = -1;
gint ett_cba_conn_info = -1;

static int proto_ICBAAccoMgt = -1;
static gint ett_ICBAAccoMgt = -1;
static e_uuid_t uuid_ICBAAccoMgt = { 0xcba00041, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBAAccoMgt = 0;

static int proto_ICBAAccoMgt2 = -1;
static e_uuid_t uuid_ICBAAccoMgt2 = { 0xcba00046, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBAAccoMgt2 = 0;

static int proto_ICBAAccoCallback = -1;
static gint ett_ICBAAccoCallback = -1;
static gint ett_ICBAAccoCallback_Buffer = -1;
static gint ett_ICBAAccoCallback_Item = -1;
static e_uuid_t uuid_ICBAAccoCallback = { 0xcba00042, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBAAccoCallback = 0;

static int proto_ICBAAccoCallback2 = -1;
static e_uuid_t uuid_ICBAAccoCallback2 = { 0xcba00047, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBAAccoCallback2 = 0;

static int proto_ICBAAccoServer = -1;
static gint ett_ICBAAccoServer = -1;
static e_uuid_t uuid_ICBAAccoServer = { 0xcba00043, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBAAccoServer = 0;

static int proto_ICBAAccoServer2 = -1;
static e_uuid_t uuid_ICBAAccoServer2 = { 0xcba00048, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBAAccoServer2 = 0;

static int      proto_ICBAAccoServerSRT = -1;
static gint     ett_ICBAAccoServerSRT   = -1;
static e_uuid_t uuid_ICBAAccoServerSRT  = { 0xcba00045, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBAAccoServerSRT   = 0;

static int      proto_ICBAAccoSync = -1;
static gint     ett_ICBAAccoSync   = -1;
static e_uuid_t uuid_ICBAAccoSync  = { 0xcba00044, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBAAccoSync   = 0;



static const value_string cba_acco_qc_vals[] = {
    { 0x1c, "BadOutOfService" },
    { 0x44, "UncertainLastUsableValue" },
    { 0x48, "UncertainSubstituteSet" },
    { 0x50, "UncertainSensorNotAccurate" },
    { 0x80, "GoodNonCascOk" },
    { 0, NULL }
};


static const value_string cba_qos_type_vals[] = {
    { 0x00, "Acyclic" },
    { 0x01, "Acyclic seconds" },        /* obsolete */
    { 0x02, "Acyclic status" },
    { 0x03, "Acyclic HMI" },
    { 0x20, "Constant" },
    { 0x30, "Cyclic Real-Time" },
    { 0, NULL }
};


static const value_string cba_persist_vals[] = {
    { 0x00, "Volatile" },
    { 0x01, "PendingPersistent" },
    { 0x02, "Persistent" },
    { 0, NULL }
};


static const value_string cba_acco_conn_state_vals[] = {
    { 0x00, "Passive" },
    { 0x01, "Active" },
    { 0, NULL }
};

static const value_string cba_acco_serversrt_action_vals[] = {
    { 0x00, "Activate" },
    { 0x01, "Deactivate" },
    { 0x02, "Remove" },
    { 0, NULL }
};

static const value_string cba_acco_serversrt_last_connect_vals[] = {
    { 0x00, "CR not complete" },
    { 0x01, "CR complete" },
    { 0, NULL }
};

static const value_string cba_acco_diag_req_vals[] = {
    { 0x0000, "Function directory" },
    { 0x1000, "DevCat statistic" },
    { 0x2000, "Reset statistic" },
    { 0x3000, "Consumer Comm. Events" },
    { 0x4000, "Provider Comm. Events" },
    { 0, NULL }
};

static const true_false_string cba_acco_call_flags = {
    "Consumer calls Provider (TRUE)",
    "Provider calls Consumer (FALSE)"
};

static const value_string cba_qos_type_short_vals[] = {
    { 0x00, "DCOM" },
    { 0x01, "DCOM(sec)" },      /* obsolete */
    { 0x02, "Status" },
    { 0x03, "HMI" },
    { 0x20, "Const" },
    { 0x30, "SRT" },
    { 0, NULL }
};


typedef struct cba_frame_s {
    cba_ldev_t   *consparent;
    cba_ldev_t   *provparent;
    GList        *conns;
    guint         packet_connect;
    guint         packet_disconnect;
    guint         packet_disconnectme;
    guint         packet_first;
    guint         packet_last;

    guint16       length;
    const guint8  consmac[6];
    guint16       conscrid;
    guint32       provcrid;
    guint32       conncrret;
    guint16       qostype;
    guint16       qosvalue;
    guint16       offset;
} cba_frame_t;

typedef struct cba_connection_s {
    cba_ldev_t   *consparentacco;
    cba_ldev_t   *provparentacco;
    cba_frame_t  *parentframe;
    guint         packet_connect;
    guint         packet_disconnect;
    guint         packet_disconnectme;
    guint         packet_first;
    guint         packet_last;

    guint16       length;
    guint32       consid;
    guint32       provid;
    const gchar  *provitem;
    guint32       connret;
    guint16       typedesclen;
    guint16      *typedesc;
    guint16       qostype;
    guint16       qosvalue;
    guint16       frame_offset;
} cba_connection_t;


typedef struct server_frame_call_s {
    guint         frame_count;
    cba_frame_t **frames;
} server_frame_call_t;


typedef struct server_connect_call_s {
    guint         conn_count;
    cba_frame_t  *frame;
    cba_connection_t **conns;
} server_connect_call_t;

typedef struct server_disconnectme_call_s {
    cba_ldev_t   *cons;
    cba_ldev_t   *prov;
} server_disconnectme_call_t;


GList *cba_pdevs;

/* as we are a plugin, we cannot get this from libwireshark! */
const true_false_string acco_flags_set_truth = { "Set", "Not set" };

#if 0
static void
cba_connection_dump(cba_connection_t *conn, const char *role)
{
    if (conn->qostype != 0x30) {
        g_warning("   %s#%5u: CID:0x%8x PID:0x%8x PItem:\"%s\" Type:%s QoS:%s/%u Ret:%s Data#%5u-#%5u",
            role,
            conn->packet_connect,
            conn->consid, conn->provid, conn->provitem,
            conn->typedesclen != 0 ? val_to_str(conn->typedesc[0], dcom_variant_type_vals, "Unknown (0x%08x)") : "-",
            val_to_str(conn->qostype, cba_qos_type_short_vals, "0x%x"), conn->qosvalue,
            conn->connret==0xffffffff ? "[pending]" : val_to_str(conn->connret, dcom_hresult_vals, "Unknown (0x%08x)"),
            conn->packet_first, conn->packet_last);
    } else {
        g_warning("   %s#%5u: CID:0x%8x PID:0x%8x PItem:\"%s\" Type:%s QoS:%s/%u Ret:%s Off:%u",
            role,
            conn->packet_connect,
            conn->consid, conn->provid, conn->provitem,
            conn->typedesclen != 0 ? val_to_str(conn->typedesc[0], dcom_variant_type_vals, "Unknown (0x%08x)") : "-",
            val_to_str(conn->qostype, cba_qos_type_short_vals, "0x%x"), conn->qosvalue,
            conn->connret==0xffffffff ? "[pending]" : val_to_str(conn->connret, dcom_hresult_vals, "Unknown (0x%08x)"),
            conn->frame_offset);
    }
}


static void
cba_object_dump(void)
{
    GList       *pdevs;
    GList       *ldevs;
    GList       *frames;
    GList       *conns;
    cba_pdev_t  *pdev;
    cba_ldev_t  *ldev;
    cba_frame_t *frame;


    for(pdevs = cba_pdevs; pdevs != NULL; pdevs = g_list_next(pdevs)) {
        pdev = pdevs->data;
        g_warning("PDev #%5u: %s IFs:%u", pdev->first_packet, ip_to_str(pdev->ip),
            pdev->object ? g_list_length(pdev->object->interfaces) : 0);

        for(ldevs = pdev->ldevs; ldevs != NULL; ldevs = g_list_next(ldevs)) {
            ldev = ldevs->data;
            g_warning(" LDev#%5u: \"%s\" LDevIFs:%u AccoIFs:%u", ldev->first_packet, ldev->name,
                ldev->ldev_object ? g_list_length(ldev->ldev_object->interfaces) : 0,
                ldev->acco_object ? g_list_length(ldev->acco_object->interfaces) : 0);
            for(frames = ldev->consframes; frames != NULL; frames = g_list_next(frames)) {
                frame = frames->data;
                g_warning("  ConsFrame#%5u: CCRID:0x%x PCRID:0x%x Len:%u Ret:%s Data#%5u-#%5u",
                    frame->packet_connect, frame->conscrid, frame->provcrid, frame->length,
                    frame->conncrret==0xffffffff ? "[pending]" : val_to_str(frame->conncrret, dcom_hresult_vals, "Unknown (0x%08x)"),
                    frame->packet_first, frame->packet_last);
                for(conns = frame->conns; conns != NULL; conns = g_list_next(conns)) {
                    cba_connection_dump(conns->data, "ConsConn");
                }
            }
            for(frames = ldev->provframes; frames != NULL; frames = g_list_next(frames)) {
                frame = frames->data;
                g_warning("  ProvFrame#%5u: CCRID:0x%x PCRID:0x%x Len:%u Ret:%s Data#%5u-#%5u",
                    frame->packet_connect, frame->conscrid, frame->provcrid, frame->length,
                    frame->conncrret==0xffffffff ? "[pending]" : val_to_str(frame->conncrret, dcom_hresult_vals, "Unknown (0x%08x)"),
                    frame->packet_first, frame->packet_last);
                for(conns = frame->conns; conns != NULL; conns = g_list_next(conns)) {
                    cba_connection_dump(conns->data, "ProvConn");
                }
            }
            for(conns = ldev->consconns; conns != NULL; conns = g_list_next(conns)) {
                cba_connection_dump(conns->data, "ConsConn");
            }
            for(conns = ldev->provconns; conns != NULL; conns = g_list_next(conns)) {
                cba_connection_dump(conns->data, "ProvConn");
            }
        }
    }
}
#endif


cba_pdev_t *
cba_pdev_find(packet_info *pinfo, const guint8 *ip, e_uuid_t *ipid)
{
    cba_pdev_t       *pdev;
    dcom_interface_t *interf;


    interf = dcom_interface_find(pinfo, ip, ipid);
    if (interf != NULL) {
        pdev = interf->parent->private_data;
        if (pdev == NULL) {
            expert_add_info_format(pinfo, NULL, PI_UNDECODED, PI_NOTE, "pdev_find: no pdev for IP:%s IPID:%s",
                ip_to_str(ip), guids_resolve_uuid_to_str(ipid));
        }
    } else {
        expert_add_info_format(pinfo, NULL, PI_UNDECODED, PI_NOTE, "pdev_find: unknown interface of IP:%s IPID:%s",
            ip_to_str(ip), guids_resolve_uuid_to_str(ipid));
        pdev = NULL;
    }

    return pdev;
}


cba_pdev_t *
cba_pdev_add(packet_info *pinfo, const guint8 *ip)
{
    GList      *cba_iter;
    cba_pdev_t *pdev;


    /* find pdev */
    for(cba_iter = cba_pdevs; cba_iter != NULL; cba_iter = g_list_next(cba_iter)) {
        pdev = cba_iter->data;
        if (memcmp(pdev->ip, ip, 4) == 0) {
            return pdev;
        }
    }

    /* not found, create a new */
    pdev = se_alloc(sizeof(cba_pdev_t));
    memcpy( (void *) (pdev->ip), ip, 4);
    pdev->first_packet = pinfo->fd->num;
    pdev->ldevs        = NULL;
    pdev->object       = NULL;
    cba_pdevs = g_list_append(cba_pdevs, pdev);

    return pdev;
}


void
cba_pdev_link(packet_info *pinfo _U_, cba_pdev_t *pdev, dcom_interface_t *pdev_interf)
{

    /* "crosslink" pdev interface and it's object */
    pdev->object = pdev_interf->parent;
    pdev_interf->private_data = pdev;
    if (pdev_interf->parent) {
        pdev_interf->parent->private_data = pdev;
    }
}


void
cba_ldev_link(packet_info *pinfo _U_, cba_ldev_t *ldev, dcom_interface_t *ldev_interf)
{

    /* "crosslink" interface and it's object */
    ldev->ldev_object = ldev_interf->parent;
    ldev_interf->private_data = ldev;
    if (ldev_interf->parent) {
        ldev_interf->parent->private_data = ldev;
    }
}


void
cba_ldev_link_acco(packet_info *pinfo _U_, cba_ldev_t *ldev, dcom_interface_t *acco_interf)
{

    /* "crosslink" interface and it's object */
    ldev->acco_object = acco_interf->parent;
    acco_interf->private_data = ldev;
    if (acco_interf->parent) {
        acco_interf->parent->private_data = ldev;
    }
}


cba_ldev_t *
cba_ldev_add(packet_info *pinfo, cba_pdev_t *pdev, const char *name)
{
    GList      *cba_iter;
    cba_ldev_t *ldev;


    /* find ldev */
    for(cba_iter = pdev->ldevs; cba_iter != NULL; cba_iter = g_list_next(cba_iter)) {
        ldev = cba_iter->data;
        if (strcmp(ldev->name, name) == 0) {
            return ldev;
        }
    }

    /* not found, create a new */
    ldev = se_alloc(sizeof(cba_ldev_t));
    ldev->name         = se_strdup(name);
    ldev->first_packet = pinfo->fd->num;
    ldev->ldev_object  = NULL;
    ldev->acco_object  = NULL;
    ldev->parent       = pdev;

    ldev->provframes   = NULL;
    ldev->consframes   = NULL;
    ldev->provconns    = NULL;
    ldev->consconns    = NULL;

    pdev->ldevs = g_list_append(pdev->ldevs, ldev);

    return ldev;
}


cba_ldev_t *
cba_ldev_find(packet_info *pinfo, const guint8 *ip, e_uuid_t *ipid) {
    /*dcerpc_info *info = (dcerpc_info *)pinfo->private_data;*/
    dcom_interface_t *interf;
    cba_ldev_t       *ldev;


    interf = dcom_interface_find(pinfo, ip, ipid);
    if (interf != NULL) {
        ldev = interf->private_data;

        if (ldev == NULL) {
            ldev = interf->parent->private_data;
        }
        if (ldev == NULL) {
            expert_add_info_format(pinfo, NULL, PI_UNDECODED, PI_NOTE, "Unknown LDev of %s",
                ip_to_str(ip));
        }
    } else {
        expert_add_info_format(pinfo, NULL, PI_UNDECODED, PI_NOTE, "Unknown IPID of %s",
            ip_to_str(ip));
        ldev = NULL;
    }

    return ldev;
}


static cba_ldev_t *
cba_acco_add(packet_info *pinfo, const char *acco)
{
    char       *ip_str;
    char       *delim;
    guint32     ip;
    cba_pdev_t *pdev;
    cba_ldev_t *ldev;


    ip_str = g_strdup(acco);
    delim  = strchr(ip_str, '!');
    if (delim ==  NULL) {
        g_free(ip_str);
        return NULL;
    }
    *delim = 0;

    if (!get_host_ipaddr(ip_str, &ip)) {
        g_free(ip_str);
        return NULL;
    }

    pdev = cba_pdev_add(pinfo, (guint8 *) &ip);
    delim++;

    ldev = cba_ldev_add(pinfo, pdev, delim);

    g_free(ip_str);

    return ldev;
}


static gboolean
cba_packet_in_range(packet_info *pinfo, guint packet_connect, guint packet_disconnect, guint packet_disconnectme)
{

    if (packet_connect == 0) {
        g_warning("cba_packet_in_range#%u: packet_connect not set?", pinfo->fd->num);
    }

    if (packet_connect == 0 || pinfo->fd->num < packet_connect) {
        return FALSE;
    }
    if (packet_disconnect != 0 && pinfo->fd->num > packet_disconnect) {
        return FALSE;
    }
    if (packet_disconnectme != 0 && pinfo->fd->num > packet_disconnectme) {
        return FALSE;
    }

    return TRUE;
}


static void
cba_frame_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, cba_frame_t *frame)
{
    if (tree) {
        proto_item *item;
        proto_item *sub_item;
        proto_tree *sub_tree;

        sub_item = proto_tree_add_text(tree, tvb, 0, 0,
            "Cons:\"%s\" CCRID:0x%x Prov:\"%s\" PCRID:0x%x QoS:%s/%ums Len:%u",
            frame->consparent ? frame->consparent->name : "", frame->conscrid,
            frame->provparent ? frame->provparent->name : "", frame->provcrid,
            val_to_str(frame->qostype, cba_qos_type_short_vals, "%u"),
            frame->qosvalue, frame->length);
        sub_tree = proto_item_add_subtree(sub_item, ett_cba_frame_info);
        PROTO_ITEM_SET_GENERATED(sub_item);

        item = proto_tree_add_uint(sub_tree, hf_cba_acco_conn_qos_type,       tvb, 0, 0, frame->qostype);
        PROTO_ITEM_SET_GENERATED(item);
        item = proto_tree_add_uint(sub_tree, hf_cba_acco_conn_qos_value,      tvb, 0, 0, frame->qosvalue);
        PROTO_ITEM_SET_GENERATED(item);
        item = proto_tree_add_uint(sub_tree, hf_cba_acco_serversrt_cr_id,     tvb, 0, 0, frame->conscrid);
        PROTO_ITEM_SET_GENERATED(item);
        item = proto_tree_add_uint(sub_tree, hf_cba_acco_prov_crid,           tvb, 0, 0, frame->provcrid);
        PROTO_ITEM_SET_GENERATED(item);
        item = proto_tree_add_uint(sub_tree, hf_cba_acco_serversrt_cr_length, tvb, 0, 0, frame->length);
        PROTO_ITEM_SET_GENERATED(item);

        if (frame->consparent != NULL) {
            item = proto_tree_add_string(sub_tree, hf_cba_acco_conn_consumer, tvb, 0, 0, frame->consparent->name);
            PROTO_ITEM_SET_GENERATED(item);
        }
        if (frame->provparent != NULL) {
            item = proto_tree_add_string(sub_tree, hf_cba_acco_conn_provider, tvb, 0, 0, frame->provparent->name);
            PROTO_ITEM_SET_GENERATED(item);
        }

        item = proto_tree_add_uint(sub_tree, hf_cba_connectcr_in,
                    tvb, 0, 0, frame->packet_connect);
        PROTO_ITEM_SET_GENERATED(item);
        item = proto_tree_add_uint(sub_tree, hf_cba_data_first_in,
                    tvb, 0, 0, frame->packet_first);
        PROTO_ITEM_SET_GENERATED(item);
        item = proto_tree_add_uint(sub_tree, hf_cba_data_last_in,
                    tvb, 0, 0, frame->packet_last);
        PROTO_ITEM_SET_GENERATED(item);
        item = proto_tree_add_uint(sub_tree, hf_cba_disconnectcr_in,
                    tvb, 0, 0, frame->packet_disconnect);
        PROTO_ITEM_SET_GENERATED(item);
        item = proto_tree_add_uint(sub_tree, hf_cba_disconnectme_in,
                    tvb, 0, 0, frame->packet_disconnectme);
        PROTO_ITEM_SET_GENERATED(item);
    }
}


static cba_frame_t *
cba_frame_connect(packet_info *pinfo, cba_ldev_t *cons_ldev, cba_ldev_t *prov_ldev,
              guint16 qostype, guint16 qosvalue, const guint8 *consmac, guint16 conscrid, guint16 length)
{
    GList       *cba_iter;
    cba_frame_t *frame;

    /* find frame */
    for(cba_iter = cons_ldev->consframes; cba_iter != NULL; cba_iter = g_list_next(cba_iter)) {
        frame = cba_iter->data;
        if ( frame->conscrid == conscrid &&
            memcmp(frame->consmac, consmac, 6) == 0 &&
            cba_packet_in_range(pinfo, frame->packet_connect, frame->packet_disconnect, frame->packet_disconnectme)) {
            return frame;
        }
    }

    frame = se_alloc(sizeof(cba_frame_t));

    frame->consparent          = cons_ldev;
    frame->provparent          = prov_ldev;

    frame->packet_connect      = pinfo->fd->num;
    frame->packet_disconnect   = 0;
    frame->packet_disconnectme = 0;
    frame->packet_first        = 0;
    frame->packet_last         = 0;

    frame->length              = length;
    memcpy( (guint8 *) (frame->consmac), consmac, sizeof(frame->consmac));
    frame->conscrid            = conscrid;
    frame->qostype             = qostype;
    frame->qosvalue            = qosvalue;

    frame->offset              = 4;
    frame->conns               = NULL;

    frame->provcrid            = 0;
    frame->conncrret           = -1;

    cons_ldev->consframes = g_list_append(cons_ldev->consframes, frame);
    prov_ldev->provframes = g_list_append(prov_ldev->provframes, frame);

    return frame;
}


static void
cba_frame_disconnect(packet_info *pinfo, cba_frame_t *frame)
{

    if (frame->packet_disconnect == 0) {
        frame->packet_disconnect = pinfo->fd->num;
    }

    if (frame->packet_disconnect != pinfo->fd->num) {
        g_warning("cba_frame_disconnect#%u: frame already disconnected in #%u",
            pinfo->fd->num, frame->packet_disconnect);
    }
}


static void
cba_frame_disconnectme(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, cba_ldev_t *cons_ldev, cba_ldev_t *prov_ldev)
{
    GList       *frames;
    cba_frame_t *frame;


    for(frames = cons_ldev->consframes; frames != NULL; frames = g_list_next(frames)) {
        frame = frames->data;

        if ( frame->provparent == prov_ldev &&
            cba_packet_in_range(pinfo, frame->packet_connect, frame->packet_disconnect, frame->packet_disconnectme)) {

            cba_frame_info(tvb, pinfo, tree, frame);

            if (frame->packet_disconnectme == 0) {
                frame->packet_disconnectme = pinfo->fd->num;
            }

            if (frame->packet_disconnectme != pinfo->fd->num) {
                g_warning("cba_frame_disconnectme#%u: frame already disconnectme'd in #%u",
                    pinfo->fd->num, frame->packet_disconnectme);
            }
        }
    }
}


static cba_frame_t *
cba_frame_find_by_cons(packet_info *pinfo, const guint8 *consmac, guint16 conscrid)
{
    GList       *pdevs;
    GList       *ldevs;
    GList       *frames;
    cba_pdev_t  *pdev;
    cba_ldev_t  *ldev;
    cba_frame_t *frame;


    /* find pdev */
    for(pdevs = cba_pdevs; pdevs != NULL; pdevs = g_list_next(pdevs)) {
        pdev = pdevs->data;

        /* find ldev */
        for(ldevs = pdev->ldevs; ldevs != NULL; ldevs = g_list_next(ldevs)) {
            ldev = ldevs->data;

            /* find frame */
            for(frames = ldev->consframes; frames != NULL; frames = g_list_next(frames)) {
                frame = frames->data;

                if ( frame->conscrid == conscrid &&
                    memcmp(frame->consmac, consmac, 6) == 0 &&
                    cba_packet_in_range(pinfo, frame->packet_connect, frame->packet_disconnect, frame->packet_disconnectme)) {
                    return frame;
                }
            }
        }
    }

    return NULL;
}


static cba_frame_t *
cba_frame_find_by_provcrid(packet_info *pinfo, cba_ldev_t *prov_ldev, guint32 provcrid)
{
    GList       *frames;
    cba_frame_t *frame;


    if (prov_ldev == NULL) {
        return NULL;
    }

    for(frames = prov_ldev->provframes; frames != NULL; frames = g_list_next(frames)) {
        frame = frames->data;

        if ( frame->provcrid == provcrid &&
            cba_packet_in_range(pinfo, frame->packet_connect, frame->packet_disconnect, frame->packet_disconnectme)) {
            return frame;
        }
    }

    expert_add_info_format(pinfo, NULL, PI_UNDECODED, PI_NOTE,
        "Unknown provider frame ProvCRID");

    return NULL;
}


static void
cba_frame_incoming_data(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree _U_, cba_frame_t *frame)
{
    if (frame->packet_first == 0) {
        frame->packet_first = pinfo->fd->num;
    }

    if ( pinfo->fd->num > frame->packet_last &&
        cba_packet_in_range(pinfo, frame->packet_connect, frame->packet_disconnect, frame->packet_disconnectme)) {
        frame->packet_last = pinfo->fd->num;
    }
}


static void
cba_connection_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, cba_connection_t *conn)
{
    if (tree) {
        proto_item *item;
        proto_item *sub_item;
        proto_tree *sub_tree;

        if (conn->qostype != 0x30) {
            sub_item = proto_tree_add_text(tree, tvb, 0, 0, "ProvItem:\"%s\" PID:0x%x CID:0x%x QoS:%s/%ums",
                conn->provitem, conn->provid, conn->consid,
                val_to_str(conn->qostype, cba_qos_type_short_vals, "%u"), conn->qosvalue);
        } else {
            sub_item = proto_tree_add_text(tree, tvb, 0, 0, "ProvItem:\"%s\" PID:0x%x CID:0x%x Len:%u",
                conn->provitem, conn->provid, conn->consid, conn->length);
        }
        sub_tree = proto_item_add_subtree(sub_item, ett_cba_conn_info);
        PROTO_ITEM_SET_GENERATED(sub_item);

        item = proto_tree_add_string(sub_tree, hf_cba_acco_conn_provider_item,    tvb, 0, 0 /* len */, conn->provitem);
        PROTO_ITEM_SET_GENERATED(item);
        item = proto_tree_add_uint(sub_tree, hf_cba_acco_conn_prov_id,            tvb, 0, 0 /* len */, conn->provid);
        PROTO_ITEM_SET_GENERATED(item);
        item = proto_tree_add_uint(sub_tree, hf_cba_acco_conn_cons_id,            tvb, 0, 0 /* len */, conn->consid);
        PROTO_ITEM_SET_GENERATED(item);
        item = proto_tree_add_uint(sub_tree, hf_cba_acco_serversrt_record_length, tvb, 0, 0 /* len */, conn->length);
        PROTO_ITEM_SET_GENERATED(item);

        if (conn->qostype != 0x30) {
            item = proto_tree_add_uint(sub_tree, hf_cba_acco_conn_qos_type,
                        tvb, 0, 0, conn->qostype);
            PROTO_ITEM_SET_GENERATED(item);
            item = proto_tree_add_uint(sub_tree, hf_cba_acco_conn_qos_value,
                        tvb, 0, 0, conn->qosvalue);
            PROTO_ITEM_SET_GENERATED(item);
            item = proto_tree_add_uint(sub_tree, hf_cba_connect_in,
                        tvb, 0, 0, conn->packet_connect);
            PROTO_ITEM_SET_GENERATED(item);
            item = proto_tree_add_uint(sub_tree, hf_cba_data_first_in,
                        tvb, 0, 0, conn->packet_first);
            PROTO_ITEM_SET_GENERATED(item);
            item = proto_tree_add_uint(sub_tree, hf_cba_data_last_in,
                        tvb, 0, 0, conn->packet_last);
            PROTO_ITEM_SET_GENERATED(item);
            item = proto_tree_add_uint(sub_tree, hf_cba_disconnect_in,
                        tvb, 0, 0, conn->packet_disconnect);
            PROTO_ITEM_SET_GENERATED(item);
            item = proto_tree_add_uint(sub_tree, hf_cba_disconnectme_in,
                        tvb, 0, 0, conn->packet_disconnectme);
            PROTO_ITEM_SET_GENERATED(item);
        }
    }
}


static cba_connection_t *
cba_connection_connect(packet_info *pinfo, cba_ldev_t *cons_ldev, cba_ldev_t *prov_ldev, cba_frame_t *cons_frame,
                   guint16 qostype, guint16 qosvalue, const char *provitem, guint32 consid, guint16 length,
                   guint16 *typedesc, guint16 typedesclen)
{
    GList *cba_iter;
    cba_connection_t *conn;


    /* find connection */
    if (cons_frame != NULL) {
        /* SRT: search in frame */
        for(cba_iter = cons_frame->conns; cba_iter != NULL; cba_iter = g_list_next(cba_iter)) {
            conn = cba_iter->data;
            if (conn->consid == consid) {
                return conn;
            }
        }
    } else {
        /* DCOM: search in ldev */
        for(cba_iter = cons_ldev->consconns; cba_iter != NULL; cba_iter = g_list_next(cba_iter)) {
            conn = cba_iter->data;
            if ( conn->consid == consid &&
                cba_packet_in_range(pinfo, conn->packet_connect, conn->packet_disconnect, conn->packet_disconnectme)) {
                return conn;
            }
        }
    }

    conn = se_alloc(sizeof(cba_connection_t));

    conn->consparentacco      = cons_ldev;
    conn->provparentacco      = prov_ldev;
    conn->parentframe         = cons_frame;

    conn->packet_connect      = pinfo->fd->num;
    conn->packet_disconnect   = 0;
    conn->packet_disconnectme = 0;
    conn->packet_first        = 0;
    conn->packet_last         = 0;

    conn->consid              = consid;
    conn->provitem            = se_strdup(provitem);
    conn->typedesclen         = typedesclen;
    conn->typedesc            = typedesc;
    conn->qostype             = qostype;
    conn->qosvalue            = qosvalue;
    conn->length              = length;

    conn->provid              = 0;
    conn->connret             = -1;

    if (cons_frame != NULL) {
        conn->frame_offset   = cons_frame->offset;
        conn->length         = length;
        cons_frame->offset  += length;
        cons_frame->conns    = g_list_append(cons_frame->conns, conn);
    } else {
        conn->frame_offset   = 0;
        cons_ldev->consconns = g_list_append(cons_ldev->consconns, conn);
        prov_ldev->provconns = g_list_append(prov_ldev->provconns, conn);
    }

    return conn;
}


static void
cba_connection_disconnect(packet_info *pinfo, cba_connection_t *conn)
{
    /* XXX - detect multiple disconnects? */
    if (conn->packet_disconnect == 0) {
        conn->packet_disconnect = pinfo->fd->num;
    }

    if (conn->packet_disconnect != pinfo->fd->num) {
        g_warning("connection_disconnect#%u: already disconnected",
                  conn->packet_disconnect);
    }
}


static void
cba_connection_disconnectme(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, cba_ldev_t *cons_ldev, cba_ldev_t *prov_ldev)
{
    GList *conns;
    cba_connection_t *conn;


    for(conns = cons_ldev->consconns; conns != NULL; conns = g_list_next(conns)) {
        conn = conns->data;

        if ( conn->provparentacco == prov_ldev &&
            cba_packet_in_range(pinfo, conn->packet_connect, conn->packet_disconnect, conn->packet_disconnectme)) {

            cba_connection_info(tvb, pinfo, tree, conn);

            if (conn->packet_disconnectme == 0) {
                conn->packet_disconnectme = pinfo->fd->num;
            }

            if (conn->packet_disconnectme != pinfo->fd->num) {
                g_warning("connection_disconnectme#%u: already disconnectme'd",
                          conn->packet_disconnectme);
            }
        }
    }
}


static cba_connection_t *
cba_connection_find_by_provid(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree _U_, cba_ldev_t *prov_ldev, guint32 provid)
{
    GList *cba_iter;
    cba_connection_t *conn;


    for(cba_iter = prov_ldev->provconns; cba_iter != NULL; cba_iter = g_list_next(cba_iter)) {
        conn = cba_iter->data;
        if ( conn->provid == provid &&
            cba_packet_in_range(pinfo, conn->packet_connect, conn->packet_disconnect, conn->packet_disconnectme)) {
            return conn;
        }
    }
    return NULL;
}


static void
cba_connection_incoming_data(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree _U_, cba_connection_t *conn)
{
    if (conn->packet_first == 0) {
        conn->packet_first = pinfo->fd->num;
    }

    if ( pinfo->fd->num > conn->packet_last &&
        cba_packet_in_range(pinfo, conn->packet_connect, conn->packet_disconnect, conn->packet_disconnectme)) {
        conn->packet_last = pinfo->fd->num;
    }
}


/* dissect a response containing an array of hresults (e.g: ICBAAccoMgt::RemoveConnections) */
static int
dissect_HResultArray_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32HResult;
    guint32 u32Pointer;
    guint32 u32ArraySize = 0;
    guint32 u32Idx;
    guint32 u32Tmp;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                            &u32Pointer);

    if (u32Pointer) {
        offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                            &u32ArraySize);

        u32Idx = 1;
        u32Tmp = u32ArraySize;
        while (u32Tmp--) {
            offset = dissect_dcom_indexed_HRESULT(tvb, offset, pinfo, tree, drep,
                            &u32HResult, u32Idx);
            u32Idx++;
        }
    }

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                            &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, ": Cnt=%u -> %s",
        u32ArraySize,
        val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_ICBAAccoServer_SetActivation_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32HResult;
    guint32 u32Pointer;
    guint32 u32ArraySize = 0;
    guint32 u32Idx;
    guint32 u32Tmp;
    proto_item *item;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    item = proto_tree_add_boolean (tree, hf_cba_acco_dcom_call, tvb, offset, 0, FALSE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 1;

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                        &u32Pointer);

    if (u32Pointer) {
        offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                            &u32ArraySize);

        u32Idx = 1;
        u32Tmp = u32ArraySize;
        while (u32Tmp--) {
            offset = dissect_dcom_indexed_HRESULT(tvb, offset, pinfo, tree, drep,
                                &u32HResult, u32Idx);
            u32Idx++;
        }
    }

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                        &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, ": Cnt=%u -> %s",
        u32ArraySize,
        val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_ICBAAccoServerSRT_Disconnect_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32HResult;
    guint32 u32Pointer;
    guint32 u32ArraySize = 0;
    guint32 u32Idx;
    guint32 u32Tmp;
    proto_item *item;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    item = proto_tree_add_boolean (tree, hf_cba_acco_srt_call, tvb, offset, 0, FALSE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 3;

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                        &u32Pointer);

    if (u32Pointer) {
        offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                            &u32ArraySize);

        u32Idx = 1;
        u32Tmp = u32ArraySize;
        while (u32Tmp--) {
            offset = dissect_dcom_indexed_HRESULT(tvb, offset, pinfo, tree, drep,
                                &u32HResult, u32Idx);
            u32Idx++;
        }
    }

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                        &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, ": Cnt=%u -> %s",
        u32ArraySize,
        val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_ICBAAccoServerSRT_SetActivation_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32HResult;
    guint32 u32Pointer;
    guint32 u32ArraySize = 0;
    guint32 u32Idx;
    guint32 u32Tmp;
    proto_item *item;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    item = proto_tree_add_boolean (tree, hf_cba_acco_srt_call, tvb, offset, 0, FALSE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 3;

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                        &u32Pointer);

    if (u32Pointer) {
        offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                            &u32ArraySize);

        u32Idx = 1;
        u32Tmp = u32ArraySize;
        while (u32Tmp--) {
            offset = dissect_dcom_indexed_HRESULT(tvb, offset, pinfo, tree, drep,
                                &u32HResult, u32Idx);
            u32Idx++;
        }
    }

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                        &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, ": Cnt=%u -> %s",
        u32ArraySize,
        val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_ICBAAccoServer_Connect_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16QoSType;
    guint16 u16QoSValue;
    guint8  u8State;
    guint32 u32Count;
    guint32 u32ArraySize;

    guint32 u32VariableOffset;
    guint32 u32SubStart;
    guint32 u32Pointer;
    guint16 u16VarType;
    guint32 u32ConsID;
    gchar   szItem[1000]  = { 0 };
    guint32 u32MaxItemLen = sizeof(szItem);
    gchar   szCons[1000]  = { 0 };
    guint32 u32MaxConsLen = sizeof(szCons);
    guint32 u32Idx;

    proto_item       *item;
    dcerpc_info      *info = (dcerpc_info *)pinfo->private_data;
    dcom_interface_t *cons_interf;
    cba_ldev_t       *cons_ldev;
    cba_ldev_t       *prov_ldev;
    cba_connection_t *conn;
    server_connect_call_t *call;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    /* get corresponding provider ldev */
    prov_ldev = cba_ldev_find(pinfo, pinfo->net_dst.data, &info->call_data->object_uuid);

    item = proto_tree_add_boolean (tree, hf_cba_acco_dcom_call, tvb, offset, 0, TRUE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 2;

    offset = dissect_dcom_LPWSTR(tvb, offset, pinfo, tree, drep,
                       hf_cba_acco_conn_consumer, szCons, u32MaxConsLen);

    /* find the consumer ldev by it's name */
    cons_ldev = cba_acco_add(pinfo, szCons);

    offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_conn_qos_type, &u16QoSType);
    offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_conn_qos_value, &u16QoSValue);
    offset = dissect_dcom_BYTE(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_conn_state, &u8State);

    offset = dissect_dcom_PMInterfacePointer(tvb, offset, pinfo, tree, drep, 0, &cons_interf);
    if (cons_interf == NULL) {
        expert_add_info_format(pinfo, NULL, PI_UNDECODED, PI_NOTE,
            "Server_Connect: consumer interface invalid");
    }

    /* "crosslink" consumer interface and it's object */
    if (cons_interf != NULL && cons_ldev != NULL) {
        cba_ldev_link_acco(pinfo, cons_ldev, cons_interf);
    }

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_count, &u32Count);

    offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                        &u32ArraySize);

    /* link connections infos to the call */
    if (prov_ldev != NULL && cons_ldev != NULL) {
        call = se_alloc(sizeof(server_connect_call_t) + u32ArraySize * sizeof(cba_connection_t *));
        call->conn_count = 0;
        call->frame      = NULL;
        call->conns      = (cba_connection_t **) (call+1);
        info->call_data->private_data = call;
    } else{
        call = NULL;
    }

    u32VariableOffset = offset + u32ArraySize*16;

    /* array of CONNECTINs */
    u32Idx = 1;
    while (u32ArraySize--) {
        proto_item *sub_item;
        proto_tree *sub_tree;

        sub_item    = proto_tree_add_item(tree, hf_cba_connectin, tvb, offset, 0, ENC_NA);
        sub_tree    = proto_item_add_subtree(sub_item, ett_cba_connectin);
        u32SubStart = offset;

        /* ProviderItem */
        offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                            &u32Pointer);
        if (u32Pointer) {
            u32VariableOffset = dissect_dcom_LPWSTR(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                            hf_cba_acco_conn_provider_item, szItem, u32MaxItemLen);
        }

        /* DataType */
        offset = dissect_dcom_VARTYPE(tvb, offset, pinfo, sub_tree, drep,
                            &u16VarType);

        /* Epsilon */
        offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                            &u32Pointer);
        if (u32Pointer) {
            u32VariableOffset = dissect_dcom_VARIANT(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                            hf_cba_acco_conn_epsilon);
        }
        /* ConsumerID */
        offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, drep,
                            hf_cba_acco_conn_cons_id, &u32ConsID);

        /* add to object database */
        if (prov_ldev != NULL && cons_ldev != NULL) {
            conn = cba_connection_connect(pinfo, cons_ldev, prov_ldev, /*cons_frame*/ NULL,
                u16QoSType, u16QoSValue, szItem, u32ConsID, 0,
                /* XXX - VarType must be translated to new type description if it includes an array (0x2000) */
                se_memdup(&u16VarType, 2), 1);

            cba_connection_info(tvb, pinfo, sub_tree, conn);
        } else {
            conn = NULL;
        }

        /* add to current call */
        if (call != NULL) {
            call->conn_count++;
            call->conns[u32Idx-1] = conn;
        }

        /* update subtree header */
        proto_item_append_text(sub_item, "[%u]: ConsID=0x%x, ProvItem=\"%s\", VarType=%s",
            u32Idx, u32ConsID, szItem,
            val_to_str(u16VarType, dcom_variant_type_vals, "Unknown (0x%04x)") );
        proto_item_set_len(sub_item, offset - u32SubStart);

        u32Idx++;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, ": Consumer=\"%s\" Cnt=%u", szCons, u32Count);

    return u32VariableOffset;
}

static int
dissect_ICBAAccoServer2_Connect2_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16QoSType;
    guint16 u16QoSValue;
    guint8  u8State;
    guint32 u32Count;
    guint32 u32ArraySize;

    guint32 u32VariableOffset;
    guint32 u32SubStart;
    guint32 u32Pointer;
    guint16 u16VarType;
    guint32 u32ConsID;
    gchar   szItem[1000]  = { 0 };
    guint32 u32MaxItemLen = sizeof(szItem);
    gchar   szCons[1000]  = { 0 };
    guint32 u32MaxConsLen = sizeof(szCons);
    guint32 u32Idx;
    guint16 u16TypeDescLen;
    guint32 u32ArraySize2;
    guint32 u32Idx2;
    guint16 u16VarType2   = -1;

    proto_item       *item;
    dcerpc_info      *info        = (dcerpc_info *)pinfo->private_data;
    dcom_interface_t *cons_interf;
    cba_ldev_t       *prov_ldev;
    cba_ldev_t       *cons_ldev;
    cba_connection_t *conn;
    guint16           typedesclen = 0;
    guint16          *typedesc    = NULL;
    server_connect_call_t *call   = NULL;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    /* get corresponding provider ldev */
    prov_ldev = cba_ldev_find(pinfo, pinfo->net_dst.data, &info->call_data->object_uuid);

    item = proto_tree_add_boolean (tree, hf_cba_acco_dcom_call, tvb, offset, 0, TRUE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 2;

    offset = dissect_dcom_LPWSTR(tvb, offset, pinfo, tree, drep,
                       hf_cba_acco_conn_consumer, szCons, u32MaxConsLen);

    /* find the consumer ldev by it's name */
    cons_ldev = cba_acco_add(pinfo, szCons);

    offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_conn_qos_type, &u16QoSType);
    offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_conn_qos_value, &u16QoSValue);
    offset = dissect_dcom_BYTE(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_conn_state, &u8State);

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep, &u32Pointer);

    if (u32Pointer) {
        offset = dissect_dcom_MInterfacePointer(tvb, offset, pinfo, tree, drep, 0, &cons_interf);
        if (cons_interf == NULL) {
            expert_add_info_format(pinfo, NULL, PI_UNDECODED, PI_NOTE,
                "Server2_Connect2: consumer interface invalid");
        }
    } else {
        /* GetConnectionData do it this way */
        cons_interf = NULL;
    }

    /* "crosslink" consumer interface and it's object */
    if (cons_interf != NULL && cons_ldev != NULL) {
        cba_ldev_link_acco(pinfo, cons_ldev, cons_interf);
    }

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_count, &u32Count);

    offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                        &u32ArraySize);

    /* link connection infos to the call */
    if (prov_ldev != NULL && cons_ldev != NULL) {
        call = se_alloc(sizeof(server_connect_call_t) + u32ArraySize * sizeof(cba_connection_t *));
        call->conn_count = 0;
        call->frame      = NULL;
        call->conns      = (cba_connection_t **) (call+1);
        info->call_data->private_data = call;
    } else{
        call = NULL;
    }

    u32VariableOffset = offset + u32ArraySize*20;

    /* array of CONNECTINs */
    u32Idx = 1;
    while (u32ArraySize--) {
        proto_item       *sub_item;
        proto_tree       *sub_tree;

        sub_item = proto_tree_add_item(tree, hf_cba_connectin, tvb, offset, 0, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_cba_connectin);
        u32SubStart = offset;

        /* ProviderItem */
        offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                            &u32Pointer);
        if (u32Pointer) {
            u32VariableOffset = dissect_dcom_LPWSTR(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                            hf_cba_acco_conn_provider_item, szItem, u32MaxItemLen);
        }

        /* TypeDescLen */
        offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, drep,
                            hf_cba_type_desc_len, &u16TypeDescLen);

        offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                            &u32Pointer);
        /* pTypeDesc */
        if (u32Pointer) {
            u32VariableOffset = dissect_dcom_dcerpc_array_size(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                                &u32ArraySize2);

            /* limit the allocation to a reasonable size */
            if (u32ArraySize2 < 1000) {
                typedesc = se_alloc0(u32ArraySize2 * 2);
                typedesclen = u32ArraySize2;
            } else {
                typedesc = NULL;
                typedesclen = 0;
            }

            /* extended type description will build an array here */
            u32Idx2 = 1;
            while (u32ArraySize2--) {
                /* ToBeDone: some of the type description values are counts */
                u32VariableOffset = dissect_dcom_VARTYPE(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                                &u16VarType);

                if (typedesc != NULL && u32Idx2 <= typedesclen) {
                    typedesc[u32Idx2-1] = u16VarType;
                }

                /* remember first VarType only */
                if (u32Idx2 == 1) {
                    u16VarType2 = u16VarType;
                }
                u32Idx2++;
            }
        }

        /* Epsilon */
        offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                            &u32Pointer);
        if (u32Pointer) {
            u32VariableOffset = dissect_dcom_VARIANT(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                            hf_cba_acco_conn_epsilon);
        }
        /* ConsumerID */
        offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, drep,
                            hf_cba_acco_conn_cons_id, &u32ConsID);

        /* add to object database */
        if (prov_ldev != NULL && cons_ldev != NULL) {
            conn = cba_connection_connect(pinfo, cons_ldev, prov_ldev, /*cons_frame*/ NULL,
                u16QoSType, u16QoSValue, szItem, u32ConsID, 0,
                typedesc, typedesclen);

            cba_connection_info(tvb, pinfo, sub_tree, conn);
        } else {
            conn = NULL;
        }

        /* add to current call */
        if (call != NULL) {
            call->conn_count++;
            call->conns[u32Idx-1] = conn;
        }

        /* update subtree header */
        proto_item_append_text(sub_item, "[%u]: ConsID=0x%x, ProvItem=\"%s\", TypeDesc=%s",
            u32Idx, u32ConsID, szItem,
            val_to_str(u16VarType2, dcom_variant_type_vals, "Unknown (0x%04x)") );
        proto_item_set_len(sub_item, offset - u32SubStart);

        u32Idx++;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, ": Consumer=\"%s\" Cnt=%u", szCons, u32Count);


    return u32VariableOffset;
}


static int
dissect_ICBAAccoServer_Connect_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint8  u8FirstConnect;
    guint32 u32Pointer;
    guint32 u32ArraySize = 0;
    guint32 u32HResult;
    guint32 u32Idx       = 1;
    guint32 u32ProvID;
    guint32 u32SubStart;

    proto_item  *item;
    dcerpc_info *info         = (dcerpc_info *)pinfo->private_data;
    cba_connection_t *conn;
    server_connect_call_t *call = info->call_data->private_data;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    if (call == NULL) {
        expert_add_info_format(pinfo, NULL, PI_UNDECODED, PI_NOTE,
            "No request info, response data ignored");
    }

    item = proto_tree_add_boolean (tree, hf_cba_acco_dcom_call, tvb, offset, 0, FALSE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 1;

    offset = dissect_dcom_BOOLEAN(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_server_first_connect, &u8FirstConnect);

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                        &u32Pointer);

    if (u32Pointer) {
        offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                            &u32ArraySize);

        /* array of CONNECTOUTs */
        while(u32ArraySize--) {
            proto_item *sub_item;
            proto_tree *sub_tree;

            sub_item = proto_tree_add_item(tree, hf_cba_connectout, tvb, offset, 8, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_cba_connectout);
            u32SubStart = offset;

            offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_prov_id, &u32ProvID);

            offset = dissect_dcom_indexed_HRESULT(tvb, offset, pinfo, sub_tree, drep,
                                &u32HResult, u32Idx);

            /* put response data into the connection */
            if (call && u32Idx <= call->conn_count) {
                conn = call->conns[u32Idx-1];
                conn->provid  = u32ProvID;
                conn->connret = u32HResult;

                cba_connection_info(tvb, pinfo, sub_tree, conn);
            }

            proto_item_append_text(sub_item, "[%u]: ProvID=0x%x %s",
                u32Idx, u32ProvID,
                val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );
            proto_item_set_len(sub_item, offset - u32SubStart);

            u32Idx++;
        }
    }

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                        &u32HResult);

    /* this might be a global HRESULT */
    while(call && u32Idx <= call->conn_count) {
        conn = call->conns[u32Idx-1];
        conn->provid  = 0;
        conn->connret = u32HResult;
        u32Idx++;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s Cnt=%u -> %s",
        (u8FirstConnect) ? "First" : "NotFirst",
        u32Idx-1,
        val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_ICBAAccoServer_Disconnect_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32Count;
    guint32 u32ArraySize;
    guint32 u32Idx;
    guint32 u32ProvID;

    proto_item  *item;
    dcerpc_info *info = (dcerpc_info *)pinfo->private_data;
    cba_ldev_t  *prov_ldev;
    cba_connection_t *conn;
    server_connect_call_t *call;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    item = proto_tree_add_boolean (tree, hf_cba_acco_dcom_call, tvb, offset, 0, TRUE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 2;

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_count, &u32Count);

    offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                        &u32ArraySize);

    prov_ldev = cba_ldev_find(pinfo, pinfo->net_dst.data, &info->call_data->object_uuid);

    /* link connection infos to the call */
    if (prov_ldev != NULL) {
        call = se_alloc(sizeof(server_connect_call_t) + u32ArraySize * sizeof(cba_connection_t *));
        call->conn_count = 0;
        call->frame      = NULL;
        call->conns      = (cba_connection_t **) (call+1);
        info->call_data->private_data = call;
    } else{
        call = NULL;
    }

    u32Idx = 1;
    while (u32ArraySize--) {
        offset = dissect_dcom_indexed_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_conn_prov_id, &u32ProvID, u32Idx);

        /* add to current call */
        if (call != NULL) {
            conn = cba_connection_find_by_provid(tvb, pinfo, tree, prov_ldev, u32ProvID);
            call->conn_count++;
            call->conns[u32Idx-1] = conn;
        }

        u32Idx++;
    }

    /* update column info now */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": Cnt=%u", u32Count);


    return offset;
}


static int
dissect_ICBAAccoServer_Disconnect_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32HResult;
    guint32 u32Pointer;
    guint32 u32ArraySize = 0;
    guint32 u32Idx;
    guint32 u32Tmp;

    proto_item  *item;
    dcerpc_info *info = (dcerpc_info *)pinfo->private_data;
    cba_connection_t *conn;
    server_connect_call_t *call = info->call_data->private_data;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    if (call == NULL) {
        expert_add_info_format(pinfo, NULL, PI_UNDECODED, PI_NOTE,
            "No request info, response data ignored");
    }

    item = proto_tree_add_boolean (tree, hf_cba_acco_dcom_call, tvb, offset, 0, FALSE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 1;

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                        &u32Pointer);

    if (u32Pointer) {
        offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                            &u32ArraySize);

        u32Idx = 1;
        u32Tmp = u32ArraySize;
        while (u32Tmp--) {
            offset = dissect_dcom_indexed_HRESULT(tvb, offset, pinfo, tree, drep,
                                &u32HResult, u32Idx);

            /* mark this connection as disconnected */
            if (call && u32Idx <= call->conn_count) {
                conn = call->conns[u32Idx-1];
                if (conn != NULL) {
                    cba_connection_disconnect(pinfo, conn);
                }
            }

            u32Idx++;
        }
    }

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                        &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, ": Cnt=%u -> %s",
        u32ArraySize,
        val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_ICBAAccoServerSRT_Disconnect_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32Count;
    guint32 u32ArraySize;
    guint32 u32Idx;
    guint32 u32ProvID;
    proto_item *item;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    item = proto_tree_add_boolean (tree, hf_cba_acco_srt_call, tvb, offset, 0, TRUE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 4;

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_count, &u32Count);

    offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                        &u32ArraySize);

    u32Idx = 1;
    while (u32ArraySize--) {
        offset = dissect_dcom_indexed_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_conn_prov_id, &u32ProvID, u32Idx);
        u32Idx++;
    }

    /* update column info now */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": Cnt=%u", u32Count);

    return offset;
}


static int
dissect_ICBAAccoServer_DisconnectMe_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    gchar        szStr[1000];
    guint32      u32MaxStr = sizeof(szStr);
    proto_item  *item;
    dcerpc_info *info      = (dcerpc_info *)pinfo->private_data;
    cba_ldev_t  *prov_ldev;
    cba_ldev_t  *cons_ldev;
    server_disconnectme_call_t *call;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    /* get corresponding provider ldev */
    prov_ldev = cba_ldev_find(pinfo, pinfo->net_dst.data, &info->call_data->object_uuid);

    item = proto_tree_add_boolean (tree, hf_cba_acco_dcom_call, tvb, offset, 0, TRUE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 2;

    offset = dissect_dcom_LPWSTR(tvb, offset, pinfo, tree, drep,
        hf_cba_acco_conn_consumer, szStr, u32MaxStr);

    /* find the consumer ldev by it's name */
    cons_ldev = cba_acco_add(pinfo, szStr);

    if (prov_ldev != NULL && cons_ldev != NULL) {
        call = se_alloc(sizeof(server_disconnectme_call_t));
        call->cons = cons_ldev;
        call->prov = prov_ldev;
        info->call_data->private_data = call;
    }

    /* update column info now */
    col_append_fstr(pinfo->cinfo, COL_INFO, " Consumer=\"%s\"", szStr);

    return offset;
}


static int
dissect_ICBAAccoServer_DisconnectMe_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32      u32HResult;
    proto_item  *item;
    dcerpc_info *info = (dcerpc_info *)pinfo->private_data;
    server_disconnectme_call_t *call;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    item = proto_tree_add_boolean (tree, hf_cba_acco_dcom_call, tvb, offset, 0, FALSE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 1;

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                    &u32HResult);

    call = info->call_data->private_data;
    if (call) {
        cba_connection_disconnectme(tvb, pinfo, tree, call->cons, call->prov);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s",
        val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_ICBAAccoServerSRT_DisconnectMe_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    gchar        szStr[1000];
    guint32      u32MaxStr = sizeof(szStr);
    proto_item  *item;
    dcerpc_info *info      = (dcerpc_info *)pinfo->private_data;
    cba_ldev_t  *prov_ldev;
    cba_ldev_t  *cons_ldev;
    server_disconnectme_call_t *call;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    /* get corresponding provider ldev */
    prov_ldev = cba_ldev_find(pinfo, pinfo->net_dst.data, &info->call_data->object_uuid);

    item = proto_tree_add_boolean (tree, hf_cba_acco_srt_call, tvb, offset, 0, TRUE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 4;

    offset = dissect_dcom_LPWSTR(tvb, offset, pinfo, tree, drep,
        hf_cba_acco_conn_consumer, szStr, u32MaxStr);

    /* find the consumer ldev by it's name */
    cons_ldev = cba_acco_add(pinfo, szStr);

    if (prov_ldev != NULL && cons_ldev != NULL) {
        call = se_alloc(sizeof(server_disconnectme_call_t));
        call->cons = cons_ldev;
        call->prov = prov_ldev;
        info->call_data->private_data = call;
    }

    /* update column info now */
    col_append_fstr(pinfo->cinfo, COL_INFO, " Consumer=\"%s\"", szStr);

    return offset;
}


static int
dissect_ICBAAccoServerSRT_DisconnectMe_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32      u32HResult;
    proto_item  *item;
    dcerpc_info *info = (dcerpc_info *)pinfo->private_data;
    server_disconnectme_call_t *call;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    item = proto_tree_add_boolean (tree, hf_cba_acco_srt_call, tvb, offset, 0, FALSE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 3;

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                    &u32HResult);

    call = info->call_data->private_data;
    if (call) {
        cba_frame_disconnectme(tvb, pinfo, tree, call->cons, call->prov);
    }

  col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s",
    val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_ICBAAccoServer_Ping_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32     u32HResult;
    proto_item *item;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    item = proto_tree_add_boolean (tree, hf_cba_acco_dcom_call, tvb, offset, 0, FALSE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 1;

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                    &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s",
        val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_ICBAAccoServer_SetActivation_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint8      u8State;
    guint32     u32Count;
    guint32     u32ArraySize;
    guint32     u32Idx;
    guint32     u32ProvID;
    proto_item *item;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    item = proto_tree_add_boolean (tree, hf_cba_acco_dcom_call, tvb, offset, 0, TRUE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 2;

    offset = dissect_dcom_BOOLEAN(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_conn_state, &u8State);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_count, &u32Count);

    offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                        &u32ArraySize);

    u32Idx = 1;
    while (u32ArraySize--) {
        offset = dissect_dcom_indexed_DWORD(tvb, offset, pinfo, tree, drep,
                     hf_cba_acco_conn_prov_id, &u32ProvID, u32Idx);
        u32Idx++;
    }

    /* update column info now */

    col_append_fstr(pinfo->cinfo, COL_INFO, ": Cnt=%u", u32Count);

    return offset;
}


static int
dissect_ICBAAccoServerSRT_SetActivation_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint8      u8State;
    guint32     u32Count;
    guint32     u32ArraySize;
    guint32     u32Idx;
    guint32     u32ProvID;
    proto_item *item;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    item = proto_tree_add_boolean (tree, hf_cba_acco_srt_call, tvb, offset, 0, TRUE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 4;

    offset = dissect_dcom_BOOLEAN(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_conn_state, &u8State);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_count, &u32Count);

    offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                        &u32ArraySize);

    u32Idx = 1;
    while (u32ArraySize--) {
        offset = dissect_dcom_indexed_DWORD(tvb, offset, pinfo, tree, drep,
                     hf_cba_acco_conn_prov_id, &u32ProvID, u32Idx);
        u32Idx++;
    }

    /* update column info now */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": Cnt=%u", u32Count);

    return offset;
}


static int
dissect_ICBAAccoServer_Ping_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    gchar       szStr[1000];
    guint32     u32MaxStr = sizeof(szStr);
    proto_item *item;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    item = proto_tree_add_boolean (tree, hf_cba_acco_dcom_call, tvb, offset, 0, TRUE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 2;

    offset = dissect_dcom_LPWSTR(tvb, offset, pinfo, tree, drep,
        hf_cba_acco_conn_consumer, szStr, u32MaxStr);

    /* update column info now */
    col_append_fstr(pinfo->cinfo, COL_INFO, " Consumer=\"%s\"", szStr);

    return offset;
}


static int
dissect_ICBAAccoServerSRT_ConnectCR_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    gchar   szCons[1000]            = { 0 };
    guint32           u32MaxConsLen = sizeof(szCons);
    guint16           u16QoSType;
    guint16           u16QoSValue;
    guint8            u8ConsMac[6];
    guint16           u16CRID       = 0;
    guint16           u16CRLength   = 0;
    guint32           u32Flags;
    guint32           u32Count;
    guint32           u32ArraySize;
    guint32           u32Idx;
    proto_item       *item;
    proto_tree       *flags_tree;
    guint32           u32SubStart;
    dcerpc_info      *info          = (dcerpc_info *)pinfo->private_data;
    dcom_interface_t *cons_interf;
    cba_ldev_t       *prov_ldev;
    cba_ldev_t       *cons_ldev;
    cba_frame_t      *frame;
    server_frame_call_t *call;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    /* get corresponding provider ldev */
    prov_ldev = cba_ldev_find(pinfo, pinfo->net_dst.data, &info->call_data->object_uuid);

    item = proto_tree_add_boolean (tree, hf_cba_acco_srt_call, tvb, offset, 0, TRUE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 4;

    /* szCons */
    offset = dissect_dcom_LPWSTR(tvb, offset, pinfo, tree, drep,
                       hf_cba_acco_conn_consumer, szCons, u32MaxConsLen);

    /* find the consumer ldev by it's name */
    cons_ldev = cba_acco_add(pinfo, szCons);

    offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_conn_qos_type, &u16QoSType);
    offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_conn_qos_value, &u16QoSValue);

    offset = dissect_dcom_PMInterfacePointer(tvb, offset, pinfo, tree, drep, 0, &cons_interf);
    if (cons_interf == NULL) {
        expert_add_info_format(pinfo, NULL, PI_UNDECODED, PI_NOTE,
            "ServerSRT_ConnectCR: consumer interface invalid");
    }

    /* "crosslink" consumer interface and it's object */
    if (cons_interf != NULL && cons_ldev != NULL) {
        cba_ldev_link_acco(pinfo, cons_ldev, cons_interf);
    }

    /* ConsumerMAC (big-endian, 1byte-aligned) */
    tvb_memcpy(tvb, u8ConsMac, offset, 6);

    proto_tree_add_ether(tree, hf_cba_acco_serversrt_cons_mac, tvb,
        offset, 6, u8ConsMac);
    offset += 6;

    /* add flags subtree */
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, NULL /*tree*/, drep,
                        0 /* hfindex */, &u32Flags);
    offset -= 4;
    item = proto_tree_add_uint_format_value(tree, hf_cba_acco_serversrt_cr_flags,
        tvb, offset, 4, u32Flags,
        "0x%02x (%s, %s)", u32Flags,
        (u32Flags & 0x2) ? "Reconfigure" : "not Reconfigure",
        (u32Flags & 0x1) ? "Timestamped" : "not Timestamped");
    flags_tree = proto_item_add_subtree(item, ett_cba_acco_serversrt_cr_flags);
    proto_tree_add_boolean(flags_tree, hf_cba_acco_serversrt_cr_flags_reconfigure, tvb, offset, 4, u32Flags);
    proto_tree_add_boolean(flags_tree, hf_cba_acco_serversrt_cr_flags_timestamped, tvb, offset, 4, u32Flags);
    offset += 4;

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_count, &u32Count);

    offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                        &u32ArraySize);

    /* link frame infos to the call */
    if (prov_ldev != NULL && cons_ldev != NULL && u32ArraySize < 100) {
        call = se_alloc(sizeof(server_frame_call_t) + u32ArraySize * sizeof(cba_frame_t *));
        call->frame_count = 0;
        call->frames = (cba_frame_t **) (call+1);
        info->call_data->private_data = call;
    } else {
        call = NULL;
    }

    u32Idx = 1;
    while (u32ArraySize--) {
        proto_item *sub_item;
        proto_tree *sub_tree;

        /* array of CONNECTINCRs */
        sub_item = proto_tree_add_item(tree, hf_cba_connectincr, tvb, offset, 0, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_cba_connectincr);
        u32SubStart = offset;

        offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, drep,
                            hf_cba_acco_serversrt_cr_id, &u16CRID);

        offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, drep,
                            hf_cba_acco_serversrt_cr_length, &u16CRLength);

        /* add to object database */
        if (prov_ldev != NULL && cons_ldev != NULL) {
            frame = cba_frame_connect(pinfo, cons_ldev, prov_ldev, u16QoSType, u16QoSValue, u8ConsMac, u16CRID, u16CRLength);

            cba_frame_info(tvb, pinfo, sub_tree, frame);
        } else {
            frame = NULL;
        }

        /* add to current call */
        if (call != NULL) {
            call->frame_count++;
            call->frames[u32Idx-1] = frame;
        }

        /* update subtree header */
        proto_item_append_text(sub_item, "[%u]: CRID=0x%x, CRLength=%u",
            u32Idx, u16CRID, u16CRLength);
        proto_item_set_len(sub_item, offset - u32SubStart);

        u32Idx++;
    }


    /* update column info now */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": %sConsCRID=0x%x Len=%u QoS=%u",
           (u32Flags & 0x2) ? "Reco " : "", u16CRID, u16CRLength, u16QoSValue);

    return offset;
}


static int
dissect_ICBAAccoServerSRT_ConnectCR_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint8       u8FirstConnect;
    guint8       u8ProvMac[6];
    guint32      u32ProvCRID = 0;
    guint32      u32HResult;
    guint32      u32ArraySize;
    guint32      u32Idx      = 1;
    guint32      u32Pointer;
    guint32      u32SubStart;
    proto_item  *item;
    cba_frame_t *frame;
    dcerpc_info *info        = (dcerpc_info *)pinfo->private_data;
    server_frame_call_t *call = info->call_data->private_data;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    if (call == NULL) {
        expert_add_info_format(pinfo, NULL, PI_UNDECODED, PI_NOTE,
            "No request info, response data ignored");
    }

    item = proto_tree_add_boolean (tree, hf_cba_acco_srt_call, tvb, offset, 0, FALSE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 3;

    offset = dissect_dcom_BOOLEAN(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_server_first_connect, &u8FirstConnect);

    /* ProviderMAC (big-endian, 1byte-aligned) */
    tvb_memcpy(tvb, u8ProvMac, offset, 6);

    proto_tree_add_ether(tree, hf_cba_acco_serversrt_prov_mac, tvb,
        offset, 6, u8ProvMac);
    offset += 6;


    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                        &u32Pointer);
    if (u32Pointer) {

        offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                            &u32ArraySize);

        while (u32ArraySize--) {
            proto_item *sub_item;
            proto_tree *sub_tree;

            /* array of CONNECTOUTCRs */
            sub_item = proto_tree_add_item(tree, hf_cba_connectoutcr, tvb, offset, 0, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_cba_connectoutcr);
            u32SubStart = offset;

            offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, drep,
                                        hf_cba_acco_prov_crid, &u32ProvCRID);

            offset = dissect_dcom_HRESULT(tvb, offset, pinfo, sub_tree, drep,
                                          &u32HResult);

            /* put response data into the frame */
            if (call && u32Idx <= call->frame_count) {
                frame = call->frames[u32Idx-1];
                frame->provcrid  = u32ProvCRID;
                frame->conncrret = u32HResult;

                cba_frame_info(tvb, pinfo, sub_tree, frame);
            }

            /* update subtree header */
            proto_item_append_text(sub_item, "[%u]: ProvCRID=0x%x, %s",
                                   u32Idx, u32ProvCRID,
                                   val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );
            proto_item_set_len(sub_item, offset - u32SubStart);

            u32Idx++;
        }
    }

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                        &u32HResult);

    /* this might be a global HRESULT */
    while(call && u32Idx <= call->frame_count) {
        frame = call->frames[u32Idx-1];
        frame->provcrid  = 0;
        frame->conncrret = u32HResult;
        u32Idx++;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s PCRID=0x%x -> %s",
        (u8FirstConnect) ? "FirstCR" : "NotFirstCR",
        u32ProvCRID,
        val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_ICBAAccoServerSRT_DisconnectCR_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32      u32Count;
    guint32      u32ArraySize;
    guint32      u32Idx;
    guint32      u32ProvCRID = 0;
    proto_item  *item;
    dcerpc_info *info        = (dcerpc_info *)pinfo->private_data;
    cba_ldev_t  *prov_ldev;
    cba_frame_t *frame;
    server_frame_call_t *call;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    /* get corresponding provider ldev */
    prov_ldev = cba_ldev_find(pinfo, pinfo->net_dst.data, &info->call_data->object_uuid);

    item = proto_tree_add_boolean (tree, hf_cba_acco_srt_call, tvb, offset, 0, TRUE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 4;

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_count, &u32Count);

    offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                        &u32ArraySize);

    /* link frame infos to the call */
    if (prov_ldev != NULL) {
        call = se_alloc(sizeof(server_frame_call_t) + u32ArraySize * sizeof(cba_frame_t *));
        call->frame_count = 0;
        call->frames      = (cba_frame_t **) (call+1);
        info->call_data->private_data = call;
    } else{
        call = NULL;
    }

    u32Idx = 1;
    while (u32ArraySize--) {
        offset = dissect_dcom_indexed_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_prov_crid, &u32ProvCRID, u32Idx);

        /* find frame and add it to current call */
        if (call != NULL) {
            frame = cba_frame_find_by_provcrid(pinfo, prov_ldev, u32ProvCRID);
            call->frame_count++;
            call->frames[u32Idx-1] = frame;
        }

        u32Idx++;
    }

    /* update column info now */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": PCRID=0x%x",
           u32ProvCRID);

    return offset;
}


static int
dissect_ICBAAccoServerSRT_DisconnectCR_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32      u32HResult;
    guint32      u32Pointer;
    guint32      u32ArraySize = 0;
    guint32      u32Idx;
    guint32      u32Tmp;
    cba_frame_t *frame;
    proto_item  *item;
    dcerpc_info *info         = (dcerpc_info *)pinfo->private_data;
    server_frame_call_t *call = info->call_data->private_data;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    item = proto_tree_add_boolean (tree, hf_cba_acco_srt_call, tvb, offset, 0, FALSE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 3;

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                        &u32Pointer);

    if (u32Pointer) {
        offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                            &u32ArraySize);

        u32Idx = 1;
        u32Tmp = u32ArraySize;
        while (u32Tmp--) {
            offset = dissect_dcom_indexed_HRESULT(tvb, offset, pinfo, tree, drep,
                                &u32HResult, u32Idx);
            /* put response data into the frame */
            if (call && u32Idx <= call->frame_count) {
                frame = call->frames[u32Idx-1];
                if (frame != NULL) {
                    cba_frame_disconnect(pinfo, frame);
                }
            }

            u32Idx++;
        }
    }

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                        &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s",
        val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_ICBAAccoServerSRT_Connect_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32ProvCRID;
    guint8  u8State;
    guint8  u8LastConnect;
    guint32 u32Count;
    guint32 u32ArraySize;
    guint32 u32VariableOffset;
    guint32 u32Idx;
    guint32 u32SubStart;
    guint32 u32Pointer;
    gchar   szProvItem[1000]  = { 0 };
    guint32 u32MaxProvItemLen = sizeof(szProvItem);
    guint16 u16TypeDescLen;
    guint32 u32ArraySize2;
    guint32 u32Idx2;
    guint16 u16VarType2 = -1;
    guint16 u16VarType;
    guint32 u32ConsID;
    guint16 u16RecordLength;

    proto_item  *item;
    dcerpc_info *info        = (dcerpc_info *)pinfo->private_data;
    cba_ldev_t  *prov_ldev;
    cba_frame_t *frame       = NULL;
    guint16      typedesclen = 0;
    guint16     *typedesc    = NULL;

    cba_connection_t      *conn;
    server_connect_call_t *call;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    /* get corresponding provider ldev */
    prov_ldev = cba_ldev_find(pinfo, pinfo->net_dst.data, &info->call_data->object_uuid);

    item = proto_tree_add_boolean (tree, hf_cba_acco_srt_call, tvb, offset, 0, TRUE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 4;

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_prov_crid, &u32ProvCRID);

    frame = cba_frame_find_by_provcrid(pinfo, prov_ldev, u32ProvCRID);

    if (frame != NULL) {
        cba_frame_info(tvb, pinfo, tree, frame);
    }

    offset = dissect_dcom_BYTE(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_conn_state, &u8State);

    offset = dissect_dcom_BYTE(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_serversrt_last_connect, &u8LastConnect);


    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_count, &u32Count);

    offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                        &u32ArraySize);

    /* link connections infos to the call */
    if (frame != NULL) {
        call = se_alloc(sizeof(server_connect_call_t) + u32ArraySize * sizeof(cba_connection_t *));
        call->conn_count = 0;
        call->frame = frame;
        call->conns = (cba_connection_t **) (call+1);
        info->call_data->private_data = call;
    } else{
        call = NULL;
    }

    u32VariableOffset = offset + u32ArraySize*20;

    u32Idx = 1;
    while (u32ArraySize--) {
        proto_item *sub_item;
        proto_tree *sub_tree;

        /* array of CONNECTINs */
        sub_item = proto_tree_add_item(tree, hf_cba_connectin, tvb, offset, 0, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_cba_connectin);
        u32SubStart = offset;

        /* ProviderItem */
        offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                            &u32Pointer);
        if (u32Pointer) {
            u32VariableOffset = dissect_dcom_LPWSTR(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                            hf_cba_acco_conn_provider_item, szProvItem, u32MaxProvItemLen);
        }

        /* TypeDescLen */
        offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, drep,
                            hf_cba_type_desc_len, &u16TypeDescLen);

        offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                            &u32Pointer);
        /* pTypeDesc */
        if (u32Pointer) {
            u32VariableOffset = dissect_dcom_dcerpc_array_size(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                                &u32ArraySize2);

            typedesc = se_alloc0(u32ArraySize2 * 2);
            typedesclen = u32ArraySize2;

            /* extended type description will build an array here */
            u32Idx2 = 1;
            while (u32ArraySize2--) {
                /* ToBeDone: some of the type description values are counts */
                u32VariableOffset = dissect_dcom_VARTYPE(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                                &u16VarType);

                if (u32Idx2 <= typedesclen) {
                    typedesc[u32Idx2-1] = u16VarType;
                }

                /* remember first VarType only */
                if (u32Idx2 == 1) {
                    u16VarType2 = u16VarType;
                }
                u32Idx2++;
            }
        }

        /* ConsumerID */
        offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, drep,
                            hf_cba_acco_conn_cons_id, &u32ConsID);

        /* RecordLength */
        offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, drep,
                            hf_cba_acco_serversrt_record_length, &u16RecordLength);

        /* add to object database */
        if (frame != NULL) {
            conn = cba_connection_connect(pinfo, frame->consparent, frame->provparent, frame,
                frame->qostype, frame->qosvalue, szProvItem, u32ConsID, u16RecordLength,
                typedesc, typedesclen);

            cba_connection_info(tvb, pinfo, sub_tree, conn);
        } else {
            conn = NULL;
        }

        /* add to current call */
        if (call != NULL) {
            call->conn_count++;
            call->conns[u32Idx-1] = conn;
        }

        /* update subtree header */
        proto_item_append_text(sub_item, "[%u]: ConsID=0x%x, ProvItem=\"%s\", TypeDesc=%s",
            u32Idx, u32ConsID, szProvItem,
            val_to_str(u16VarType2, dcom_variant_type_vals, "Unknown (0x%04x)") );
        proto_item_set_len(sub_item, offset - u32SubStart);


        u32Idx++;
    }

    /* update column info now */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s Cnt=%u PCRID=0x%x",
        (u8LastConnect) ? "LastOfCR" : "",
        u32Idx-1,
        u32ProvCRID);

    return u32VariableOffset;
}


static int
dissect_ICBAAccoServerSRT_Connect_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32Pointer;
    guint32 u32ArraySize;
    guint32 u32Idx = 1;
    guint32 u32SubStart;
    guint32 u32ProvID;
    guint32 u32HResult;

    proto_item  *item;
    dcerpc_info *info = (dcerpc_info *)pinfo->private_data;

    server_connect_call_t *call = info->call_data->private_data;
    cba_connection_t      *conn;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    if (call == NULL) {
        expert_add_info_format(pinfo, NULL, PI_UNDECODED, PI_NOTE,
            "No request info, response data ignored");
    }

    item = proto_tree_add_boolean (tree, hf_cba_acco_srt_call, tvb, offset, 0, FALSE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 3;

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                        &u32Pointer);

    if (call && call->frame != NULL) {
        cba_frame_info(tvb, pinfo, tree, call->frame);
    }

    if (u32Pointer) {
        offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                            &u32ArraySize);

        /* array of CONNECTOUTs */
        while(u32ArraySize--) {
            proto_item *sub_item;
            proto_tree *sub_tree;

            sub_item = proto_tree_add_item(tree, hf_cba_connectout, tvb, offset, 8, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_cba_connectout);
            u32SubStart = offset;

            offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_prov_id, &u32ProvID);

            offset = dissect_dcom_indexed_HRESULT(tvb, offset, pinfo, sub_tree, drep,
                                &u32HResult, u32Idx);

            /* put response data into the frame */
            if (call && u32Idx <= call->conn_count) {
                conn = call->conns[u32Idx-1];
                conn->provid  = u32ProvID;
                conn->connret = u32HResult;

                cba_connection_info(tvb, pinfo, sub_tree, conn);
            }

            proto_item_append_text(sub_item, "[%u]: ProvID=0x%x %s",
                u32Idx, u32ProvID,
                val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );
            proto_item_set_len(sub_item, offset - u32SubStart);

            u32Idx++;
        }
    }

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                        &u32HResult);

    /* this might be a global HRESULT */
    while(call && u32Idx <= call->conn_count) {
        conn = call->conns[u32Idx-1];
        conn->provid  = 0;
        conn->connret = u32HResult;
        u32Idx++;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, ": Cnt=%u -> %s",
        u32Idx-1,
        val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_Server_GetProvIDs_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32Count;
    guint32 u32Pointer;
    guint32 u32ArraySize;
    guint32 u32Idx;
    guint32 u32ProvID;
    guint32 u32HResult;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_count, &u32Count);

    if (u32Count) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ": Cnt=%u ProvID=", u32Count);
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, ": Cnt=%u", u32Count);
    }

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                        &u32Pointer);
    if (u32Pointer) {
        offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                            &u32ArraySize);

        u32Idx = 1;
        while (u32ArraySize--) {
            offset = dissect_dcom_indexed_DWORD(tvb, offset, pinfo,
                     tree, drep,
                     hf_cba_acco_conn_prov_id, &u32ProvID, u32Idx);

            if (u32Idx == 1) {
                col_append_fstr(pinfo->cinfo, COL_INFO, "0x%x", u32ProvID);
            } else if (u32Idx < 10) {
                col_append_fstr(pinfo->cinfo, COL_INFO, ",0x%x", u32ProvID);
            } else if (u32Idx == 10) {
                col_append_fstr(pinfo->cinfo, COL_INFO, ",...");
            }

            u32Idx++;
        }
    }

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                        &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s",
        val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_Server_GetProvConnections_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32Count;
    guint32 u32ArraySize;
    guint32 u32Idx;
    guint32 u32ProvID;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_count, &u32Count);

    offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                        &u32ArraySize);

    u32Idx = 1;
    while (u32ArraySize--) {
        offset = dissect_dcom_indexed_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_conn_prov_id, &u32ProvID, u32Idx);
        u32Idx++;
    }

    /* update column info now */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": Cnt=%u", u32Count);

    return offset;
}


static int
dissect_Server_GetProvConnections_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32Count;
    guint32 u32TmpCount;
    guint32 u32Pointer;
    guint32 u32VariableOffset;
    guint32 u32Idx;
    guint32 u32SubStart;
    gchar   szCons[1000] = { 0 };
    guint32 u32MaxConsLen = sizeof(szCons);
    gchar   szProvItem[1000] = { 0 };
    guint32 u32MaxProvItemLen = sizeof(szProvItem);
    guint32 u32ConsID;
    guint16 u16QoSType;
    guint16 u16QoSValue;
    guint8  u8State;
    guint32 u32HResult;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                        &u32Pointer);

    u32VariableOffset = offset;

    if (u32Pointer) {
        offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                            hf_cba_acco_count, &u32Count);

        u32VariableOffset = offset + u32Count*28;

        /* array fixed part (including pointers to variable part) */
        u32TmpCount = u32Count;
        u32Idx = 1;
        while (u32TmpCount--) {
            proto_item *sub_item;
            proto_tree *sub_tree;

            sub_item = proto_tree_add_item(tree, hf_cba_getprovconnout, tvb, offset, 0, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_cba_getprovconnout);
            u32SubStart = offset;

            /* wszConsumer */
            offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                                &u32Pointer);
            if (u32Pointer) {
                u32VariableOffset = dissect_dcom_LPWSTR(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                               hf_cba_acco_conn_consumer, szCons, u32MaxConsLen);
            }
            /* wszProviderItem */
            offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                                &u32Pointer);
            if (u32Pointer) {
                u32VariableOffset = dissect_dcom_LPWSTR(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                               hf_cba_acco_conn_provider_item, szProvItem, u32MaxProvItemLen);
            }
            /* dwConsID */
            offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_cons_id, &u32ConsID);

            /* Epsilon */
            offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                                &u32Pointer);
            if (u32Pointer) {
                u32VariableOffset = dissect_dcom_VARIANT(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_epsilon);
            }

            /* QoS Type */
            offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_qos_type, &u16QoSType);
            /* QoS Value */
            offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_qos_value, &u16QoSValue);
            /* State */
            offset = dissect_dcom_BOOLEAN(tvb, offset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_state, &u8State);
            /* PartialResult */
            offset = dissect_dcom_indexed_HRESULT(tvb, offset, pinfo, sub_tree, drep,
                                &u32HResult, u32Idx);

            proto_item_append_text(sub_item, "[%u]: %s",
                u32Idx,
                val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );
            proto_item_set_len(sub_item, offset - u32SubStart);

            u32Idx++;
        }
    }

    u32VariableOffset = dissect_dcom_HRESULT(tvb, u32VariableOffset, pinfo, tree, drep,
                        &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s",
        val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return u32VariableOffset;
}


#define CBA_MRSH_VERSION_DCOM                   0x01
#define CBA_MRSH_VERSION_SRT_WITH_CONSID        0x10
#define CBA_MRSH_VERSION_SRT_WITHOUT_CONSID     0x11


int
dissect_CBA_Connection_Data(tvbuff_t *tvb,
    packet_info *pinfo, proto_tree *tree, cba_ldev_t *cons_ldev, cba_frame_t *frame)
{
    guint8      u8Version;
    guint8      u8Flags;
    guint16     u16CountFix;
    guint16     u16Count;
    guint32     u32ItemIdx;
    guint32     u32HoleIdx;
    proto_item *conn_data_item = NULL;
    proto_tree *conn_data_tree = NULL;
    guint16     u16Len;
    guint32     u32ID;
    guint8      u8QC;
    guint16     u16DataLen;
    guint16     u16HdrLen;
    int         offset         = 0;
    int         offset_hole;
    gboolean    qc_reported    = FALSE;
    int         qc_good        = 0;
    int         qc_uncertain   = 0;
    int         qc_bad         = 0;
    GList      *conns;
    int         item_offset;
    cba_connection_t *conn;


    /*** ALL data in this buffer is NOT aligned and always little endian ordered ***/

    if (tree) {
        conn_data_item = proto_tree_add_item(tree, hf_cba_acco_cb_conn_data, tvb, offset, 0, ENC_NA);
        conn_data_tree = proto_item_add_subtree(conn_data_item, ett_ICBAAccoCallback_Buffer);
    }

    /* add buffer header */
    u8Version = tvb_get_guint8 (tvb, offset);
    if (conn_data_tree) {
        proto_tree_add_item(conn_data_tree, hf_cba_acco_cb_version, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    }
    offset += 1;

    u8Flags = tvb_get_guint8 (tvb, offset);
    if (conn_data_tree) {
        proto_tree_add_item(conn_data_tree, hf_cba_acco_cb_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    }
    offset += 1;

    u16Count = tvb_get_letohs (tvb, offset);
    if (conn_data_tree) {
        proto_tree_add_item(conn_data_tree, hf_cba_acco_cb_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    }
    offset += 2;
    u16CountFix = u16Count;

    /* show meta information */
    if (frame) {
        cba_frame_info(tvb, pinfo, conn_data_tree, frame);
    } else {
        if (cons_ldev && cons_ldev->name) {
            proto_item *item;
            item = proto_tree_add_string(conn_data_tree, hf_cba_acco_conn_consumer, tvb, offset, 0, cons_ldev->name);
            PROTO_ITEM_SET_GENERATED(item);
        }
    }

    /* update column info now */
#if 0
    col_append_fstr(pinfo->cinfo, COL_INFO, " Cnt=%u", u16Count);
#endif

    /* is this an OnDataChanged buffer format (version), we know? */
    if ((u8Version != CBA_MRSH_VERSION_DCOM) &&
        (u8Version != CBA_MRSH_VERSION_SRT_WITH_CONSID) &&
        (u8Version != CBA_MRSH_VERSION_SRT_WITHOUT_CONSID))
    {
        return offset;
    }

    /* Timestamps are currently unused -> flags must be zero */
    if (u8Flags != 0) {
        return offset;
    }

    u32ItemIdx = 1;
    u32HoleIdx = 1;
    while (u16Count--) {
        proto_item *sub_item;
        proto_tree *sub_tree;
        proto_item *item;

        /* find next record header */
        u16Len = tvb_get_letohs (tvb, offset);

        /* trapped inside an empty hole? -> try to find next record header */
        if (u16Len == 0 &&
            (u8Version == CBA_MRSH_VERSION_SRT_WITH_CONSID ||
            u8Version == CBA_MRSH_VERSION_SRT_WITHOUT_CONSID))
        {
            u32HoleIdx++;
            offset_hole = offset;
            /* length smaller or larger than possible -> must be a hole */
            while (u16Len == 0) {
                offset++;
                u16Len = tvb_get_letohs(tvb, offset);
                /* this is a bit tricky here! we know: */
                /* u16Len must be greater than 3 (min. size of header itself) */
                /* u16Len must be a lot smaller than 0x300 (max. size of frame) */
                /* -> if we found a length larger than 0x300, */
                /* this must be actually the high byte, so do one more step */
                if (u16Len > 0x300) {
                    u16Len = 0;
                }
            }
            proto_tree_add_none_format(conn_data_tree, hf_cba_acco_cb_item_hole, tvb,
                offset_hole, offset - offset_hole,
                "Hole(--): -------------, offset=%2u, length=%2u",
                offset_hole, offset - offset_hole);
        }

        /* add callback-item subtree */
        sub_item = proto_tree_add_item(conn_data_tree, hf_cba_acco_cb_item, tvb, offset, 0, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_ICBAAccoCallback_Item);

        item_offset = offset;

        /* add item header fields */
        if (sub_tree) {
            proto_tree_add_item(sub_tree, hf_cba_acco_cb_item_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        }
        offset    += 2;
        u16HdrLen  = 2;

        if (u8Version == CBA_MRSH_VERSION_DCOM ||
            u8Version == CBA_MRSH_VERSION_SRT_WITH_CONSID)
        {
            u32ID = tvb_get_letohl (tvb, offset);
            if (sub_tree) {
                proto_tree_add_item(sub_tree, hf_cba_acco_conn_cons_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            }
            offset    += 4;
            u16HdrLen += 4;
        } else {
            u32ID = 0;
        }

        u8QC = tvb_get_guint8 (tvb, offset);
        item = NULL;
        if (sub_tree) {
            item = proto_tree_add_item(sub_tree, hf_cba_acco_qc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        }
        offset    += 1;
        u16HdrLen += 1;

        if ( u8QC != 0x80 && /* GoodNonCascOk */
            u8QC != 0x1C && /* BadOutOfService (usually permanent, so don't report for every frame) */
            qc_reported == 0) {
            expert_add_info_format(pinfo, item, PI_RESPONSE_CODE, PI_CHAT, "%s QC: %s",
                u8Version == CBA_MRSH_VERSION_DCOM ? "DCOM" : "SRT",
                val_to_str(u8QC, cba_acco_qc_vals, "Unknown (0x%02x)"));
            qc_reported = 0;
        }

        switch(u8QC >> 6) {
        case(00):
            qc_bad++;
            break;
        case(01):
            qc_uncertain++;
            break;
        default:
            qc_good++;
        }

        /* user data length is item length without headers */
        u16DataLen = u16Len - u16HdrLen;

        /* append text to subtree header */
        if (u8Version == CBA_MRSH_VERSION_DCOM ||
            u8Version == CBA_MRSH_VERSION_SRT_WITH_CONSID)
        {
            proto_item_append_text(sub_item,
                "[%2u]: ConsID=0x%08x, offset=%2u, length=%2u (user-length=%2u), QC=%s (0x%02x)",
                u32ItemIdx, u32ID, offset - u16HdrLen, u16Len, u16DataLen,
                val_to_str(u8QC, cba_acco_qc_vals, "Unknown (0x%02x)"), u8QC );
        } else {
            proto_item_append_text(sub_item,
                "[%2u]: ConsID=-, offset=%2u, length=%2u (user-length=%2u), QC=%s (0x%02x)",
                u32ItemIdx, offset - u16HdrLen, u16Len, u16DataLen,
                val_to_str(u8QC, cba_acco_qc_vals, "Unknown (0x%02x)"), u8QC );
        }
        proto_item_set_len(sub_item, u16Len);

        /* hexdump of user data */
        proto_tree_add_item(sub_tree, hf_cba_acco_cb_item_data, tvb, offset, u16DataLen, ENC_NA);
        offset += u16DataLen;

        if (frame != NULL ) {
            /* find offset in SRT */
            /* XXX - expensive! */
            cba_frame_incoming_data(tvb, pinfo, sub_tree, frame);
            for(conns = frame->conns; conns != NULL; conns = g_list_next(conns)) {
                conn = conns->data;
                if (conn->frame_offset == item_offset) {
                    cba_connection_info(tvb, pinfo, sub_tree, conn);
                    break;
                }
            }
        } else {
            /* find consID in ldev */
            /* XXX - expensive! */
            if (cons_ldev != NULL) {
                for(conns = cons_ldev->consconns; conns != NULL; conns = g_list_next(conns)) {
                    conn = conns->data;
                    if (conn->consid == u32ID) {
                        cba_connection_info(tvb, pinfo, sub_tree, conn);
                        cba_connection_incoming_data(tvb, pinfo, sub_tree, conn);
                        break;
                    }
                }
            }
        }

        u32ItemIdx++;
    }

    if (u8Version == 1) {
        proto_item_append_text(conn_data_item,
            ": Version=0x%x (DCOM), Flags=0x%x, Count=%u",
            u8Version, u8Flags, u16CountFix);
    } else {
        proto_item_append_text(conn_data_item,
            ": Version=0x%x (SRT), Flags=0x%x, Count=%u, Items=%u, Holes=%u",
            u8Version, u8Flags, u16CountFix, u32ItemIdx-1, u32HoleIdx-1);
    }
    proto_item_set_len(conn_data_item, offset);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", QC (G:%u,U:%u,B:%u)",
        qc_good, qc_uncertain, qc_bad);

    return offset;
}


static gboolean
dissect_CBA_Connection_Data_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void *data _U_)
{
    guint8       u8Version;
    guint8       u8Flags;
    guint16      u16FrameID;
    cba_frame_t *frame;

    /* the tvb will NOT contain the frame_id here! */
    u16FrameID = GPOINTER_TO_UINT(pinfo->private_data);

    /* frame id must be in valid range (cyclic Real-Time, class=1 or class=2) */
    if (u16FrameID < 0x8000 || u16FrameID >= 0xfb00) {
        return FALSE;
    }

    u8Version = tvb_get_guint8 (tvb, 0);
    u8Flags   = tvb_get_guint8 (tvb, 1);

    /* version and flags must be ok */
    if (u8Version != 0x11 || u8Flags != 0x00) {
        return FALSE;
    }

        col_set_str(pinfo->cinfo, COL_PROTOCOL, "PN-CBA");

    frame = cba_frame_find_by_cons(pinfo, pinfo->dl_dst.data, u16FrameID);

    dissect_CBA_Connection_Data(tvb, pinfo, tree, frame ? frame->consparent : NULL, frame);

    return TRUE;
}


static int
dissect_ICBAAccoCallback_OnDataChanged_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32      u32Length;
    guint32      u32ArraySize;
    tvbuff_t    *next_tvb;
    proto_item  *item;
    dcerpc_info *info = (dcerpc_info *)pinfo->private_data;
    cba_ldev_t  *cons_ldev;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    /* get corresponding provider ldev */
    cons_ldev = cba_ldev_find(pinfo, pinfo->net_dst.data, &info->call_data->object_uuid);

    item = proto_tree_add_boolean (tree, hf_cba_acco_dcom_call, tvb, offset, 0, FALSE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 1;

    /* length */
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_cb_length, &u32Length);

    /* array size */
    offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                        &u32ArraySize);

    /*** the data below is NOT ndr encoded (especially NOT aligned)!!! ***/
    /* dissect PROFINET component data (without header) */
    next_tvb = tvb_new_subset_remaining(tvb, offset);

    offset += dissect_CBA_Connection_Data(next_tvb, pinfo, tree, cons_ldev, NULL /* frame */);

    return offset;
}


static int
dissect_ICBAAccoCallback_OnDataChanged_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32     u32HResult;
    proto_item *item;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    item = proto_tree_add_boolean (tree, hf_cba_acco_dcom_call, tvb, offset, 0, TRUE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 2;

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                    &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s",
        val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_ICBAAccoCallback_Gnip_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    proto_item *item;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    item = proto_tree_add_boolean (tree, hf_cba_acco_srt_call, tvb, offset, 0, FALSE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 3;

    return offset;
}


static int
dissect_ICBAAccoCallback_Gnip_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32     u32HResult;
    proto_item *item;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    item = proto_tree_add_boolean (tree, hf_cba_acco_srt_call, tvb, offset, 0, TRUE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 4;

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                    &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s",
        val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_ICBAAccoServer2_GetConnectionData_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    gchar         szStr[1000];
    guint32       u32MaxStr = sizeof(szStr);
    proto_item   *item;
    cba_ldev_t   *cons_ldev;
    dcerpc_info  *info      = (dcerpc_info *)pinfo->private_data;
    cba_ldev_t  **call;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    item = proto_tree_add_boolean (tree, hf_cba_acco_dcom_call, tvb, offset, 0, TRUE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 2;

    offset = dissect_dcom_LPWSTR(tvb, offset, pinfo, tree, drep,
        hf_cba_acco_conn_consumer, szStr, u32MaxStr);

    cons_ldev = cba_acco_add(pinfo, szStr);

    /* link ldev to the call */
    if (cons_ldev != NULL) {
        call = se_alloc(sizeof(cba_ldev_t *));
        *call = cons_ldev;
        info->call_data->private_data = call;
    }

    /* update column info now */
    col_append_fstr(pinfo->cinfo, COL_INFO, " Consumer=\"%s\"", szStr);

    return offset;
}


static int
dissect_ICBAAccoServer2_GetConnectionData_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32       u32Length;
    guint32       u32ArraySize;
    tvbuff_t     *next_tvb;
    guint32       u32Pointer;
    guint32       u32HResult;
    proto_item   *item;
    dcerpc_info  *info      = (dcerpc_info *)pinfo->private_data;
    cba_ldev_t  **call      = info->call_data->private_data;
    cba_ldev_t   *cons_ldev = (call!=NULL) ? *call : NULL;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    if (cons_ldev == NULL) {
        expert_add_info_format(pinfo, NULL, PI_UNDECODED, PI_NOTE,
            "No request info, response data ignored");
    }

    item = proto_tree_add_boolean (tree, hf_cba_acco_dcom_call, tvb, offset, 0, FALSE);
    PROTO_ITEM_SET_GENERATED(item);
    pinfo->profinet_type = 1;

    /* length */
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_cb_length, &u32Length);

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                        &u32Pointer);
    if (u32Pointer) {
        /* array size */
        offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                            &u32ArraySize);

        /*** the data below is NOT ndr encoded (especially NOT aligned)!!! ***/
        /* dissect PROFINET component data (without header) */
        next_tvb = tvb_new_subset_remaining(tvb, offset);

        offset += dissect_CBA_Connection_Data(next_tvb, pinfo, tree, (call != NULL) ? *call : NULL, NULL /* frame */);

    }

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                        &u32HResult);

    /* update column info now */
    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s",
            val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_ICBAAccoMgt_AddConnections_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    gchar   szConsumer[1000] = { 0 };
    guint32 u32MaxConsLen = sizeof(szConsumer);
    guint16 u16QoSType;
    guint16 u16QoSValue;
    guint8  u8State;
    guint32 u32Count;
    guint32 u32ArraySize;
    guint32 u32Pointer;
    guint16 u16Persistence;
    gchar   szConsItem[1000] = { 0 };
    guint32 u32MaxConsItemLen = sizeof(szConsItem);
    gchar   szProvItem[1000] = { 0 };
    guint32 u32MaxProvItemLen = sizeof(szProvItem);
    guint32 u32VariableOffset;
    guint32 u32SubStart;
    guint32 u32Idx;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_LPWSTR(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_conn_provider, szConsumer, u32MaxConsLen);
    offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_conn_qos_type, &u16QoSType);
    offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_conn_qos_value, &u16QoSValue);
    offset = dissect_dcom_BOOLEAN(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_conn_state, &u8State);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_count, &u32Count);

    offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                        &u32ArraySize);

    u32VariableOffset = offset + u32ArraySize * 20;

    u32Idx = 1;
    while (u32ArraySize--) {
        proto_item *sub_item;
        proto_tree *sub_tree;

        sub_item = proto_tree_add_item(tree, hf_cba_addconnectionin, tvb, offset, 0, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_cba_addconnectionin);
        u32SubStart = offset;

        offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                            &u32Pointer);
        if (u32Pointer) {
            u32VariableOffset = dissect_dcom_LPWSTR(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                            hf_cba_acco_conn_provider_item, szProvItem, u32MaxProvItemLen);
        }
        offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                            &u32Pointer);
        if (u32Pointer) {
            u32VariableOffset = dissect_dcom_LPWSTR(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                            hf_cba_acco_conn_consumer_item, szConsItem, u32MaxConsItemLen);
        }
        offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, drep,
                            hf_cba_acco_conn_persist, &u16Persistence);

        offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                            &u32Pointer);
        if (u32Pointer) {
            u32VariableOffset = dissect_dcom_VARIANT(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                            hf_cba_acco_conn_substitute);
        }
        offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                            &u32Pointer);
        if (u32Pointer) {
            u32VariableOffset = dissect_dcom_VARIANT(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                            hf_cba_acco_conn_epsilon);
        }
        proto_item_append_text(sub_item, "[%u]: ConsItem=\"%s\" ProvItem=\"%s\" %s Pers=%u",
            u32Idx, szConsItem, szProvItem,
            val_to_str(u16Persistence, cba_persist_vals, "Unknown (0x%02x)"), u16Persistence);
        proto_item_set_len(sub_item, offset - u32SubStart);

        u32Idx++;
    }

    /* update column info now */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": Prov=\"%s\" State=%s Cnt=%u",
            szConsumer,
            val_to_str(u8State, cba_acco_conn_state_vals, "Unknown (0x%02x)"),
            u32Count);

    return u32VariableOffset;
}


static int
dissect_ICBAAccoMgt_AddConnections_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32Pointer;
    guint32 u32ArraySize = 0;
    guint32 u32ConsID;
    guint16 u16ConnVersion;
    guint32 u32HResult = 0;
    guint32 u32Count = 0;
    guint32 u32Idx;
    guint32 u32SubStart;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                        &u32Pointer);

    if (u32Pointer) {
        offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                            &u32ArraySize);

        u32Count = u32ArraySize;
        u32Idx = 1;
        while (u32ArraySize--) {
            proto_item *sub_item;
            proto_tree *sub_tree;

            sub_item = proto_tree_add_item(tree, hf_cba_addconnectionout, tvb, offset, 0, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_cba_addconnectionout);
            u32SubStart = offset;

            offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, drep,
                            hf_cba_acco_conn_cons_id, &u32ConsID);

            offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_version, &u16ConnVersion);

            offset = dissect_dcom_indexed_HRESULT(tvb, offset, pinfo, sub_tree, drep,
                                &u32HResult, u32Idx);

            proto_item_append_text(sub_item, "[%u]: ConsID=0x%x Version=%u %s",
                u32Idx, u32ConsID, u16ConnVersion,
                val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );
            proto_item_set_len(sub_item, offset - u32SubStart);

            u32Idx++;
        }

        /* update column info now */
        col_append_fstr(pinfo->cinfo, COL_INFO, ": Cnt=%u", u32Count);
    }

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                        &u32HResult);

    /* update column info now */
    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s",
        val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_ICBAAccoMgt_RemoveConnections_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32Count;
    guint32 u32ArraySize;
    guint32 u32Idx;
    guint32 u32ConsID;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_count, &u32Count);

    offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                        &u32ArraySize);

    u32Idx = 1;
    while (u32ArraySize--) {
        offset = dissect_dcom_indexed_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_conn_cons_id, &u32ConsID, u32Idx);
        u32Idx++;
    }

    /* update column info now */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": Cnt=%u", u32Count);

    return offset;
}


static int
dissect_ICBAAccoMgt_SetActivationState_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint8  u8State;
    guint32 u32Count;
    guint32 u32ArraySize;
    guint32 u32Idx;
    guint32 u32ConsID;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_BOOLEAN(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_conn_state, &u8State);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_count, &u32Count);

    offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                        &u32ArraySize);

    u32Idx = 1;
    while (u32ArraySize--) {
        offset = dissect_dcom_indexed_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_conn_cons_id, &u32ConsID, u32Idx);
        u32Idx++;
    }

    /* update column info now */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": Cnt=%u", u32Count);

    return offset;
}


static int
dissect_ICBAAccoMgt_GetInfo_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32Max;
    guint32 u32CurCnt;
    guint32 u32HResult;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_info_max, &u32Max);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_info_curr, &u32CurCnt);

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                        &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, ": %u/%u -> %s",
        u32CurCnt, u32Max,
        val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_ICBAAccoMgt_GetIDs_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32Count;
    guint32 u32Pointer;
    guint32 u32ArraySize;
    guint32 u32ConsID;
    guint8  u8State;
    guint16 u16Version;
    guint32 u32HResult;
    guint32 u32Idx;
    guint32 u32SubStart;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_count, &u32Count);

    if (u32Count) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ": Cnt=%u ConsID=", u32Count);
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, ": Cnt=%u", u32Count);
    }

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                        &u32Pointer);
    if (u32Pointer) {
        offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                            &u32ArraySize);

        u32Idx = 1;
        while (u32ArraySize--) {
            proto_item *sub_item;
            proto_tree *sub_tree;

            sub_item = proto_tree_add_item(tree, hf_cba_getidout, tvb, offset, 0, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_cba_getidout);
            u32SubStart = offset;

            offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_cons_id, &u32ConsID);
            offset = dissect_dcom_BOOLEAN(tvb, offset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_state, &u8State);
            offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_version, &u16Version);
            offset = dissect_dcom_indexed_HRESULT(tvb, offset, pinfo, sub_tree, drep,
                                &u32HResult, u32Idx);

            proto_item_append_text(sub_item, "[%u]: ConsID=0x%x State=%s Version=%u %s",
                u32Idx, u32ConsID,
                val_to_str(u8State, cba_acco_conn_state_vals, "Unknown (0x%02x)"),
                u16Version,
                val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );
            proto_item_set_len(sub_item, offset - u32SubStart);

            if (u32Idx == 1) {
                col_append_fstr(pinfo->cinfo, COL_INFO, "0x%x", u32ConsID);
            } else if (u32Idx < 10) {
                col_append_fstr(pinfo->cinfo, COL_INFO, ",0x%x", u32ConsID);
            } else if (u32Idx == 10) {
                col_append_fstr(pinfo->cinfo, COL_INFO, ",...");
            }

            u32Idx++;
        }
    }

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                        &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s",
        val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_ICBAAccoMgt2_GetConsIDs_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32Count;
    guint32 u32Pointer;
    guint32 u32ArraySize;
    guint32 u32Idx;
    guint32 u32ConsID;
    guint32 u32HResult;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_count, &u32Count);

    if (u32Count) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ": Cnt=%u ConsID=", u32Count);
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, ": Cnt=%u", u32Count);
    }

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                        &u32Pointer);
    if (u32Pointer) {
        offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                            &u32ArraySize);

        u32Idx = 1;
        while (u32ArraySize--) {
            offset = dissect_dcom_indexed_DWORD(tvb, offset, pinfo,
                     tree, drep,
                     hf_cba_acco_conn_cons_id, &u32ConsID, u32Idx);

            if (u32Idx == 1) {
                col_append_fstr(pinfo->cinfo, COL_INFO, "0x%x", u32ConsID);
            } else if (u32Idx < 10) {
                col_append_fstr(pinfo->cinfo, COL_INFO, ",0x%x", u32ConsID);
            } else if (u32Idx == 10) {
                col_append_fstr(pinfo->cinfo, COL_INFO, ",...");
            }

            u32Idx++;
        }
    }

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                        &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s",
        val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_ICBAAccoMgt2_GetConsConnections_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32Count;
    guint32 u32TmpCount;
    guint32 u32Pointer;
    guint32 u32HResult;

    guint16 u16QoSType;
    guint16 u16QoSValue;
    guint8  u8State;
    guint16 u16Persistence;
    guint32 u32SubStart;
    guint32 u32Idx;
    guint32 u32VariableOffset;
    gchar   szProv[1000] = { 0 };
    guint32 u32MaxProvLen = sizeof(szProv);
    gchar   szProvItem[1000] = { 0 };
    guint32 u32MaxProvItemLen = sizeof(szProvItem);
    gchar   szConsItem[1000] = { 0 };
    guint32 u32MaxConsItemLen = sizeof(szConsItem);


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                        &u32Pointer);

    u32VariableOffset = offset;

    if (u32Pointer) {
        offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                            hf_cba_acco_count, &u32Count);

        u32VariableOffset = offset + u32Count*32;

        /* array fixed part (including pointers to variable part) */
        u32TmpCount = u32Count;
        u32Idx = 1;
        while (u32TmpCount--) {
            proto_item *sub_item;
            proto_tree *sub_tree;

            sub_item    = proto_tree_add_item(tree, hf_cba_getconsconnout, tvb, offset, 0, ENC_NA);
            sub_tree    = proto_item_add_subtree(sub_item, ett_cba_getconnectionout);
            u32SubStart = offset;

            offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                                &u32Pointer);
            if (u32Pointer) {
                u32VariableOffset = dissect_dcom_LPWSTR(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                               hf_cba_acco_conn_provider, szProv, u32MaxProvLen);
            }
            offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                                &u32Pointer);
            if (u32Pointer) {
                u32VariableOffset = dissect_dcom_LPWSTR(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                               hf_cba_acco_conn_provider_item, szProvItem, u32MaxProvItemLen);
            }
            offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                                &u32Pointer);
            if (u32Pointer) {
                u32VariableOffset = dissect_dcom_LPWSTR(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_consumer_item, szConsItem, u32MaxConsItemLen);
            }
            offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                                &u32Pointer);
            if (u32Pointer) {
                u32VariableOffset = dissect_dcom_VARIANT(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_substitute);
            }
            offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                                &u32Pointer);
            if (u32Pointer) {
                u32VariableOffset = dissect_dcom_VARIANT(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_epsilon);
            }

            offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_qos_type, &u16QoSType);
            offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_qos_value, &u16QoSValue);
            offset = dissect_dcom_BOOLEAN(tvb, offset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_state, &u8State);
            offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_persist, &u16Persistence);
            offset = dissect_dcom_indexed_HRESULT(tvb, offset, pinfo, sub_tree, drep,
                                &u32HResult, u32Idx);

            proto_item_append_text(sub_item, "[%u]: %s",
                u32Idx,
                val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );
            proto_item_set_len(sub_item, offset - u32SubStart);

            u32Idx++;
        }
    }

    u32VariableOffset = dissect_dcom_HRESULT(tvb, u32VariableOffset, pinfo, tree, drep,
                        &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s",
        val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return u32VariableOffset;
}


static int
dissect_ICBAAccoMgt2_DiagConsConnections_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32Count;
    guint32 u32TmpCount;
    guint32 u32Pointer;
    guint32 u32HResult;
    guint8  u8State;
    guint16 u16Persistence;
    guint16 u16ConnVersion;
    guint32 u32SubStart;
    guint32 u32Idx;
    guint32 u32VariableOffset;
    guint32 u32ConnErrorState;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                        &u32Pointer);

    u32VariableOffset = offset;

    if (u32Pointer) {
        offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                            hf_cba_acco_count, &u32Count);

        u32VariableOffset = offset + u32Count*16;

        /* array fixed part (including pointers to variable part) */
        u32TmpCount = u32Count;
        u32Idx = 1;
        while (u32TmpCount--) {
            proto_item *sub_item;
            proto_tree *sub_tree;
            proto_item *state_item;

            sub_item    = proto_tree_add_item(tree, hf_cba_diagconsconnout, tvb, offset, 0, ENC_NA);
            sub_tree    = proto_item_add_subtree(sub_item, ett_cba_getconnectionout);
            u32SubStart = offset;

            offset = dissect_dcom_BOOLEAN(tvb, offset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_state, &u8State);
            offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_persist, &u16Persistence);
            offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_version, &u16ConnVersion);
                        /* connection state */
#if 0
            offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_error_state, &u32ConnErrorState);
#endif
            offset = dissect_dcom_HRESULT_item(tvb, offset, pinfo, sub_tree, drep,
                                 &u32ConnErrorState, hf_cba_acco_conn_error_state, &state_item);
            proto_item_set_text(state_item, "ConnErrorState: %s (0x%x)",
                                 val_to_str(u32ConnErrorState, dcom_hresult_vals, "Unknown (0x%08x)"),
                                 u32ConnErrorState);

            offset = dissect_dcom_indexed_HRESULT(tvb, offset, pinfo, sub_tree, drep,
                                 &u32HResult, u32Idx);

            proto_item_append_text(sub_item, "[%u]: %s",
              u32Idx,
              val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );
            proto_item_set_len(sub_item, offset - u32SubStart);

            u32Idx++;
        }
    }

    u32VariableOffset = dissect_dcom_HRESULT(tvb, u32VariableOffset, pinfo, tree, drep,
                        &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s",
        val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return u32VariableOffset;
}


static int
dissect_ICBAAccoMgt_GetConnections_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32ConsID;
    guint32 u32Count;
    guint32 u32ArraySize;
    guint32 u32Idx;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_count, &u32Count);

    offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                        &u32ArraySize);

    u32Idx = 1;
    while (u32ArraySize--){
        offset = dissect_dcom_indexed_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_conn_cons_id, &u32ConsID, u32Idx);
        u32Idx++;
    }

    return offset;
}


static int
dissect_ICBAAccoMgt_GetConnections_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32Count;
    guint32 u32TmpCount;
    guint32 u32Pointer;
    guint32 u32HResult;

    guint16 u16QoSType;
    guint16 u16QoSValue;
    guint8  u8State;
    guint16 u16Persistence;
    guint16 u16ConnVersion;
    guint32 u32SubStart;
    guint32 u32Idx;
    guint32 u32VariableOffset;
    gchar   szProv[1000] = { 0 };
    guint32 u32MaxProvLen = sizeof(szProv);
    gchar   szProvItem[1000] = { 0 };
    guint32 u32MaxProvItemLen = sizeof(szProvItem);
    gchar   szConsItem[1000] = { 0 };
    guint32 u32MaxConsItemLen = sizeof(szConsItem);


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                        &u32Pointer);

    u32VariableOffset = offset;

    if (u32Pointer) {
        offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                            hf_cba_acco_count, &u32Count);

        u32VariableOffset = offset + u32Count*36;

        /* array fixed part (including pointers to variable part) */
        u32TmpCount = u32Count;
        u32Idx = 1;
        while (u32TmpCount--) {
            proto_item *sub_item;
            proto_tree *sub_tree;

            sub_item = proto_tree_add_item(tree, hf_cba_getconnectionout, tvb, offset, 0, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_cba_getconnectionout);
            u32SubStart = offset;

            offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                                &u32Pointer);
            if (u32Pointer) {
                u32VariableOffset = dissect_dcom_LPWSTR(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                               hf_cba_acco_conn_provider, szProv, u32MaxProvLen);
            }
            offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                                &u32Pointer);
            if (u32Pointer) {
                u32VariableOffset = dissect_dcom_LPWSTR(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                               hf_cba_acco_conn_provider_item, szProvItem, u32MaxProvItemLen);
            }
            offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                                &u32Pointer);
            if (u32Pointer) {
                u32VariableOffset = dissect_dcom_LPWSTR(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_consumer_item, szConsItem, u32MaxConsItemLen);
            }
            offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                                &u32Pointer);
            if (u32Pointer) {
                u32VariableOffset = dissect_dcom_VARIANT(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_substitute);
            }
            offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                                &u32Pointer);
            if (u32Pointer) {
                u32VariableOffset = dissect_dcom_VARIANT(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_epsilon);
            }

            offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_qos_type, &u16QoSType);
            offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_qos_value, &u16QoSValue);
            offset = dissect_dcom_BOOLEAN(tvb, offset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_state, &u8State);
            offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_persist, &u16Persistence);
            offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, drep,
                                hf_cba_acco_conn_version, &u16ConnVersion);
            offset = dissect_dcom_indexed_HRESULT(tvb, offset, pinfo, sub_tree, drep,
                                &u32HResult, u32Idx);

            proto_item_append_text(sub_item, "[%u]: %s",
                u32Idx,
                val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );
            proto_item_set_len(sub_item, offset - u32SubStart);

            u32Idx++;
        }
    }

    u32VariableOffset = dissect_dcom_HRESULT(tvb, u32VariableOffset, pinfo, tree, drep,
                        &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s",
        val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return u32VariableOffset;
}


static int
dissect_ICBAAccoMgt_ReviseQoS_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16QoSType;
    guint16 u16QoSValue;
    gchar   szStr[1000];
    guint32 u32MaxStr = sizeof(szStr);


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_LPWSTR(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_rtauto, szStr, u32MaxStr);

    offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_conn_qos_type, &u16QoSType);

    offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_conn_qos_value, &u16QoSValue);

    col_append_fstr(pinfo->cinfo, COL_INFO, ": RTAuto=\"%s\" QoSType=%s QoSValue=%u",
            szStr,
            val_to_str(u16QoSType, cba_qos_type_vals, "Unknown (0x%04x)"),
            u16QoSValue);

    return offset;
}


static int
dissect_ICBAAccoMgt_ReviseQoS_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16QoSValue;
    guint32 u32HResult;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_conn_qos_value, &u16QoSValue);

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                        &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, ": %u -> %s",
      u16QoSValue,
      val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_ICBAAccoMgt_get_PingFactor_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16PF;
    guint32 u32HResult;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_ping_factor, &u16PF);

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                        &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, ": %u -> %s",
      u16PF,
      val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_ICBAAccoMgt_put_PingFactor_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16PF;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_ping_factor, &u16PF);

    col_append_fstr(pinfo->cinfo, COL_INFO, ": %u", u16PF);

    return offset;
}



static int
dissect_ICBAAccoMgt_get_CDBCookie_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32Cookie;
    guint32 u32HResult;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_cdb_cookie, &u32Cookie);

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                        &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, ": CDBCookie=0x%x -> %s",
            u32Cookie,
            val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_ICBAAccoMgt_GetDiagnosis_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32Request;
    guint32 u32InLength;
    guint32 u32ArraySize;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_diag_req, &u32Request);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_diag_in_length, &u32InLength);

    offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                        &u32ArraySize);

    if (u32ArraySize != 0) {
        proto_tree_add_item(tree, hf_cba_acco_diag_data, tvb, offset, u32InLength, ENC_NA);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s: %u bytes",
            val_to_str(u32Request, cba_acco_diag_req_vals, "Unknown request (0x%08x)"),
            u32InLength);

    return offset;
}


static int
dissect_ICBAAccoMgt_GetDiagnosis_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32OutLength;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_diag_out_length, &u32OutLength);

    if (u32OutLength != 0) {
        proto_tree_add_item(tree, hf_cba_acco_diag_data, tvb, offset, u32OutLength, ENC_NA);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, ": %u bytes",
            u32OutLength);

    return offset;
}


static int
dissect_ICBAAccoSync_ReadItems_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32Count;
    gchar   szStr[1000];
    guint32 u32MaxStr = sizeof(szStr);
    guint32 u32Pointer;
    guint32 u32ArraySize;
    guint32 u32VariableOffset;
    guint32 u32Idx;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_count, &u32Count);

    offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                        &u32ArraySize);

    u32VariableOffset = offset + u32ArraySize*4;

    u32Idx = 1;
    while (u32ArraySize--) {
        offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                            &u32Pointer);
        if (u32Pointer) {
            u32VariableOffset = dissect_dcom_indexed_LPWSTR(tvb, u32VariableOffset, pinfo, tree, drep,
                            hf_cba_acco_item, szStr, u32MaxStr, u32Idx);
        }

        u32Idx++;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, ": Cnt=%u", u32Count);

    return u32VariableOffset;
}




static int
dissect_ICBAAccoSync_ReadItems_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32Pointer;
    guint16 u16QC;
    guint32 u32ArraySize = 0;
    guint32 u32HResult;
    guint32 u32Idx;
    guint32 u32SubStart;
    guint32 u32VariableOffset;
    guint32 u32Tmp;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                        &u32Pointer);
    u32VariableOffset = offset;

    if (u32Pointer) {
        offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                            &u32ArraySize);

        u32VariableOffset = offset + u32ArraySize * 20;
        u32Idx = 1;
        u32Tmp = u32ArraySize;
        while(u32Tmp--) {
            proto_item *sub_item;
            proto_tree *sub_tree;

            sub_item = proto_tree_add_item(tree, hf_cba_readitemout, tvb, offset, 0, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_cba_readitemout);
            u32SubStart = offset;

            offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                                &u32Pointer);
            if (u32Pointer) {
                u32VariableOffset = dissect_dcom_VARIANT(tvb, u32VariableOffset, pinfo, sub_tree, drep, hf_cba_acco_data);
            }

            offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, drep,
                                hf_cba_acco_qc, &u16QC);
            offset = dissect_dcom_FILETIME(tvb, offset, pinfo, sub_tree, drep,
                                hf_cba_acco_time_stamp, NULL);

            offset = dissect_dcom_indexed_HRESULT(tvb, offset, pinfo, sub_tree, drep,
                                &u32HResult, u32Idx);

            proto_item_append_text(sub_item, "[%u]: QC=%s (0x%02x) %s",
                u32Idx,
                val_to_str(u16QC, cba_acco_qc_vals, "Unknown"),
                u16QC,
                val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );
            proto_item_set_len(sub_item, offset - u32SubStart);

            u32Idx++;
        }
    }

    u32VariableOffset = dissect_dcom_HRESULT(tvb, u32VariableOffset, pinfo, tree, drep,
                       &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, ": Cnt=%u -> %s",
      u32ArraySize,
      val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return u32VariableOffset;
}


static int
dissect_ICBAAccoSync_WriteItems_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32Count;
    guint32 u32ArraySize;
    gchar   szStr[1000];
    guint32 u32MaxStr = sizeof(szStr);
    guint32 u32Pointer;
    guint32 u32VariableOffset;
    guint32 u32SubStart;
    guint32 u32Idx;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_count, &u32Count);

    offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                        &u32ArraySize);

    u32VariableOffset = offset + u32ArraySize * 8;
    u32Idx = 1;
    while(u32ArraySize--) {
        proto_item *sub_item;
        proto_tree *sub_tree;

        sub_item = proto_tree_add_item(tree, hf_cba_writeitemin, tvb, offset, 0, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_cba_writeitemin);
        u32SubStart = offset;

        offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                            &u32Pointer);
        if (u32Pointer) {
            u32VariableOffset = dissect_dcom_LPWSTR(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                            hf_cba_acco_item, szStr, u32MaxStr);
        }
        offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                            &u32Pointer);
        if (u32Pointer) {
            u32VariableOffset = dissect_dcom_VARIANT(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                            hf_cba_acco_data);
        }

        proto_item_append_text(sub_item, "[%u]: Item=\"%s\"", u32Idx, szStr);
        proto_item_set_len(sub_item, offset - u32SubStart);

        u32Idx++;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, ": Cnt=%u", u32Count);

    return u32VariableOffset;
}



static int
dissect_ICBAAccoSync_WriteItemsQCD_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32Count;
    guint32 u32ArraySize;
    gchar   szStr[1000];
    guint32 u32MaxStr = sizeof(szStr);
    guint32 u32Pointer;
    guint32 u32VariableOffset;
    guint32 u32SubStart;
    guint32 u32Idx;
    guint16 u16QC;

    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                        hf_cba_acco_count, &u32Count);

    offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                        &u32ArraySize);

    u32VariableOffset = offset + u32ArraySize * 20;
    u32Idx = 1;
    while(u32ArraySize--) {
        proto_item *sub_item;
        proto_tree *sub_tree;

        sub_item = proto_tree_add_item(tree, hf_cba_writeitemin, tvb, offset, 0, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_cba_writeitemin);
        u32SubStart = offset;

        offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                            &u32Pointer);
        if (u32Pointer) {
        u32VariableOffset = dissect_dcom_LPWSTR(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                            hf_cba_acco_item, szStr, u32MaxStr);
        }

        offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, drep,
                            &u32Pointer);
        if (u32Pointer) {
        u32VariableOffset = dissect_dcom_VARIANT(tvb, u32VariableOffset, pinfo, sub_tree, drep,
                            hf_cba_acco_data);
        }

        offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, drep,
                            hf_cba_acco_qc, &u16QC);

        offset = dissect_dcom_FILETIME(tvb, offset, pinfo, sub_tree, drep,
                            hf_cba_acco_time_stamp, NULL);

        proto_item_append_text(sub_item, "[%u]: Item=\"%s\" QC=%s (0x%02x)",
            u32Idx, szStr,
            val_to_str(u16QC, cba_acco_qc_vals, "Unknown"), u16QC);

        proto_item_set_len(sub_item, offset - u32SubStart);
        u32Idx++;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, ": Cnt=%u", u32Count);

    return u32VariableOffset;
}


/* sub dissector table of ICBAAccoMgt / ICBAAccoMgt2 interface */
static dcerpc_sub_dissector ICBAAccoMgt_dissectors[] = {
    { 0, "QueryInterface",      NULL, NULL },
    { 1, "AddRef",              NULL, NULL },
    { 2, "Release",             NULL, NULL },

    { 3, "AddConnections",      dissect_ICBAAccoMgt_AddConnections_rqst, dissect_ICBAAccoMgt_AddConnections_resp },
    { 4, "RemoveConnections",   dissect_ICBAAccoMgt_RemoveConnections_rqst, dissect_HResultArray_resp },
    { 5, "ClearConnections",    dissect_dcom_simple_rqst, dissect_dcom_simple_resp },
    { 6, "SetActivationState",  dissect_ICBAAccoMgt_SetActivationState_rqst, dissect_HResultArray_resp },
    { 7, "GetInfo",             dissect_dcom_simple_rqst, dissect_ICBAAccoMgt_GetInfo_resp },
    { 8, "GetIDs",              dissect_dcom_simple_rqst, dissect_ICBAAccoMgt_GetIDs_resp },
    { 9, "GetConnections",      dissect_ICBAAccoMgt_GetConnections_rqst, dissect_ICBAAccoMgt_GetConnections_resp },
    {10, "ReviseQoS",           dissect_ICBAAccoMgt_ReviseQoS_rqst, dissect_ICBAAccoMgt_ReviseQoS_resp },
    {11, "get_PingFactor",      dissect_dcom_simple_rqst, dissect_ICBAAccoMgt_get_PingFactor_resp },
    {12, "put_PingFactor",      dissect_ICBAAccoMgt_put_PingFactor_rqst, dissect_dcom_simple_resp },
    {13, "get_CDBCookie",       dissect_dcom_simple_rqst, dissect_ICBAAccoMgt_get_CDBCookie_resp },
    /* stage 2 */
    {14, "GetConsIDs",          dissect_dcom_simple_rqst, dissect_ICBAAccoMgt2_GetConsIDs_resp },
    {15, "GetConsConnections",  dissect_ICBAAccoMgt_GetConnections_rqst, dissect_ICBAAccoMgt2_GetConsConnections_resp },
    {16, "DiagConsConnections", dissect_ICBAAccoMgt_GetConnections_rqst, dissect_ICBAAccoMgt2_DiagConsConnections_resp },
    {17, "GetProvIDs",          dissect_dcom_simple_rqst, dissect_Server_GetProvIDs_resp },
    {18, "GetProvConnections",  dissect_Server_GetProvConnections_rqst, dissect_Server_GetProvConnections_resp },
    {19, "GetDiagnosis",        dissect_ICBAAccoMgt_GetDiagnosis_rqst, dissect_ICBAAccoMgt_GetDiagnosis_resp },
    { 0, NULL, NULL, NULL },
};


/* sub dissector table of ICBAAccoCallback interface */
static dcerpc_sub_dissector ICBAAccoCallback_dissectors[] = {
    { 0, "QueryInterface", NULL, NULL },
    { 1, "AddRef",         NULL, NULL },
    { 2, "Release",        NULL, NULL },

    { 3, "OnDataChanged",  dissect_ICBAAccoCallback_OnDataChanged_rqst, dissect_ICBAAccoCallback_OnDataChanged_resp },
    /* stage 2 */
    { 4, "Gnip",           dissect_ICBAAccoCallback_Gnip_rqst, dissect_ICBAAccoCallback_Gnip_resp },
    { 0, NULL, NULL, NULL },
};


/* sub dissector table of ICBAAccoServer interface */
static dcerpc_sub_dissector ICBAAccoServer_dissectors[] = {
    { 0, "QueryInterface",    NULL, NULL },
    { 1, "AddRef",            NULL, NULL },
    { 2, "Release",           NULL, NULL },

    { 3, "Connect",           dissect_ICBAAccoServer_Connect_rqst, dissect_ICBAAccoServer_Connect_resp },
    { 4, "Disconnect",        dissect_ICBAAccoServer_Disconnect_rqst, dissect_ICBAAccoServer_Disconnect_resp },
    { 5, "DisconnectMe",      dissect_ICBAAccoServer_DisconnectMe_rqst, dissect_ICBAAccoServer_DisconnectMe_resp },
    { 6, "SetActivation",     dissect_ICBAAccoServer_SetActivation_rqst, dissect_ICBAAccoServer_SetActivation_resp },
    { 7, "Ping",              dissect_ICBAAccoServer_Ping_rqst, dissect_ICBAAccoServer_Ping_resp },
    /* stage 2 */
    { 8, "Connect2",          dissect_ICBAAccoServer2_Connect2_rqst, dissect_ICBAAccoServer_Connect_resp },
    { 9, "GetConnectionData", dissect_ICBAAccoServer2_GetConnectionData_rqst, dissect_ICBAAccoServer2_GetConnectionData_resp },
    { 0, NULL, NULL, NULL },
};


/* sub dissector table of ICBAAccoServerSRT interface (stage 2 only) */
static dcerpc_sub_dissector ICBAAccoServerSRT_dissectors[] = {
    { 0, "QueryInterface", NULL, NULL },
    { 1, "AddRef",         NULL, NULL },
    { 2, "Release",        NULL, NULL },

    { 3, "ConnectCR",      dissect_ICBAAccoServerSRT_ConnectCR_rqst, dissect_ICBAAccoServerSRT_ConnectCR_resp },
    { 4, "DisconnectCR",   dissect_ICBAAccoServerSRT_DisconnectCR_rqst, dissect_ICBAAccoServerSRT_DisconnectCR_resp },
    { 5, "Connect",        dissect_ICBAAccoServerSRT_Connect_rqst, dissect_ICBAAccoServerSRT_Connect_resp },
    { 6, "Disconnect",     dissect_ICBAAccoServerSRT_Disconnect_rqst, dissect_ICBAAccoServerSRT_Disconnect_resp },
    { 7, "DisconnectMe",   dissect_ICBAAccoServerSRT_DisconnectMe_rqst, dissect_ICBAAccoServerSRT_DisconnectMe_resp },
    { 8, "SetActivation",  dissect_ICBAAccoServerSRT_SetActivation_rqst, dissect_ICBAAccoServerSRT_SetActivation_resp },
    { 0, NULL, NULL, NULL },
};


/* sub dissector table of ICBAAccoSync interface */
static dcerpc_sub_dissector ICBAAccoSync_dissectors[] = {
    { 0, "QueryInterface", NULL, NULL },
    { 1, "AddRef",         NULL, NULL },
    { 2, "Release",        NULL, NULL },

    { 3, "ReadItems",      dissect_ICBAAccoSync_ReadItems_rqst, dissect_ICBAAccoSync_ReadItems_resp },
    { 4, "WriteItems",     dissect_ICBAAccoSync_WriteItems_rqst, dissect_HResultArray_resp },
    { 5, "WriteItemsQCD",  dissect_ICBAAccoSync_WriteItemsQCD_rqst, dissect_HResultArray_resp },
    { 0, NULL, NULL, NULL },
};


/* register protocol */
void
proto_register_dcom_cba_acco (void)
{
    static gint *ett3[3];
    static gint *ett4[4];
    static gint *ett5[5];


    static hf_register_info hf_cba_acco_array[] = {
        { &hf_cba_acco_opnum,
          { "Operation", "cba.acco.opnum",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_ping_factor,
          { "PingFactor", "cba.acco.ping_factor",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_count,
          { "Count", "cba.acco.count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_info_max,
          { "Max", "cba.acco.info_max",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_info_curr,
          { "Current", "cba.acco.info_curr",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_rtauto,
          { "RTAuto", "cba.acco.rtauto",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_item,
          { "Item", "cba.acco.item",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_data,
          { "Data", "cba.acco.data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_qc,
          { "QualityCode", "cba.acco.qc",
            FT_UINT8, BASE_HEX, VALS(cba_acco_qc_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_time_stamp,
          { "TimeStamp", "cba.acco.time_stamp",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_readitemout,
          { "ReadItemOut", "cba.acco.readitemout",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_writeitemin,
          { "WriteItemIn", "cba.acco.writeitemin",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_cdb_cookie,
          { "CDBCookie", "cba.acco.cdb_cookie",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
                /* dcom_hresult_vals from packet-dcom.h doesn't work here, as length is unknown! */
        { &hf_cba_acco_conn_error_state,
          { "ConnErrorState", "cba.acco.conn_error_state",
            FT_UINT32, BASE_HEX, NULL /*VALS(dcom_hresult_vals)*/, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_diag_req,
          { "Request", "cba.acco.diag_req",
            FT_UINT32, BASE_HEX, VALS(cba_acco_diag_req_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_diag_in_length,
          { "InLength", "cba.acco.diag_in_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_diag_out_length,
          { "OutLength", "cba.acco.diag_out_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_diag_data,
          { "Data", "cba.acco.diag_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_dcom_call,
          { "DcomRuntime", "cba.acco.dcom",
            FT_BOOLEAN, BASE_NONE, TFS(&cba_acco_call_flags), 0x0,
            "This is a DCOM runtime context", HFILL }
        },
        { &hf_cba_acco_srt_call,
          { "SrtRuntime", "cba.acco.srt",
            FT_BOOLEAN, BASE_NONE, TFS(&cba_acco_call_flags), 0x0,
            "This is an SRT runtime context", HFILL }
        }

    };

    static hf_register_info hf_cba_acco_server[] = {
        { &hf_cba_acco_server_pICBAAccoCallback,
          { "pICBAAccoCallback", "cba.acco.server_pICBAAccoCallback",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_server_first_connect,
          { "FirstConnect", "cba.acco.server_first_connect",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_getprovconnout,
          { "GETPROVCONNOUT", "cba.acco.getprovconnout",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_serversrt_prov_mac,
          { "ProviderMAC", "cba.acco.serversrt_prov_mac",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_serversrt_cons_mac,
          { "ConsumerMAC", "cba.acco.serversrt_cons_mac",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_serversrt_cr_id,
          { "ConsumerCRID", "cba.acco.serversrt_cr_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_serversrt_cr_length,
          { "CRLength", "cba.acco.serversrt_cr_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_serversrt_cr_flags,
          { "Flags", "cba.acco.serversrt_cr_flags",
            FT_UINT32, BASE_HEX, 0, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_serversrt_cr_flags_timestamped,
          { "Timestamped", "cba.acco.serversrt_cr_flags_timestamped",
            FT_BOOLEAN, 32, TFS (&acco_flags_set_truth), 0x1,
            NULL, HFILL }
        },
        { &hf_cba_acco_serversrt_cr_flags_reconfigure,
          { "Reconfigure", "cba.acco.serversrt_cr_flags_reconfigure",
            FT_BOOLEAN, 32, TFS (&acco_flags_set_truth), 0x2,
            NULL, HFILL }
        },
        { &hf_cba_type_desc_len,
          { "TypeDescLen", "cba.acco.type_desc_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_serversrt_record_length,
          { "RecordLength", "cba.acco.serversrt_record_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_serversrt_action,
          { "Action", "cba.acco.serversrt_action",
            FT_UINT32, BASE_DEC, VALS(cba_acco_serversrt_action_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_serversrt_last_connect,
          { "LastConnect", "cba.acco.serversrt_last_connect",
            FT_UINT8, BASE_DEC, VALS(cba_acco_serversrt_last_connect_vals), 0x0,
            NULL, HFILL }
        },
    };

    static hf_register_info hf_cba_connectcr_array[] = {
        { &hf_cba_acco_prov_crid,
          { "ProviderCRID", "cba.acco.prov_crid",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static hf_register_info hf_cba_connect_array[] = {
        { &hf_cba_addconnectionin,
          { "ADDCONNECTIONIN", "cba.acco.addconnectionin",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_addconnectionout,
          { "ADDCONNECTIONOUT", "cba.acco.addconnectionout",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_getidout,
          { "GETIDOUT", "cba.acco.getidout",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_getconnectionout,
          { "GETCONNECTIONOUT", "cba.acco.getconnectionout",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_getconsconnout,
          { "GETCONSCONNOUT", "cba.acco.getconsconnout",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_diagconsconnout,
          { "DIAGCONSCONNOUT", "cba.acco.diagconsconnout",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_connectincr,
          { "CONNECTINCR", "cba.acco.connectincr",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_connectoutcr,
          { "CONNECTOUTCR", "cba.acco.connectoutcr",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_connectin,
          { "CONNECTIN", "cba.acco.connectin",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_connectout,
          { "CONNECTOUT", "cba.acco.connectout",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_conn_prov_id,
          { "ProviderID", "cba.acco.conn_prov_id",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_conn_cons_id,
          { "ConsumerID", "cba.acco.conn_cons_id",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_conn_version,
          { "ConnVersion", "cba.acco.conn_version",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_conn_consumer,
          { "Consumer", "cba.acco.conn_consumer",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_conn_qos_type,
          { "QoSType", "cba.acco.conn_qos_type",
            FT_UINT16, BASE_HEX, VALS(cba_qos_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_conn_qos_value,
          { "QoSValue", "cba.acco.conn_qos_value",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_conn_state,
          { "State", "cba.acco.conn_state",
            FT_UINT8, BASE_HEX, VALS(cba_acco_conn_state_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_conn_provider,
          { "Provider", "cba.acco.conn_provider",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_conn_provider_item,
          { "ProviderItem", "cba.acco.conn_provider_item",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_conn_consumer_item,
          { "ConsumerItem", "cba.acco.conn_consumer_item",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_conn_persist,
          { "Persistence", "cba.acco.conn_persist",
            FT_UINT16, BASE_HEX, VALS(cba_persist_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_conn_epsilon,
          { "Epsilon", "cba.acco.conn_epsilon",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_conn_substitute,
          { "Substitute", "cba.acco.conn_substitute",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static hf_register_info hf_cba_acco_cb[] = {
        { &hf_cba_acco_cb_length,
          { "Length", "cba.acco.cb_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_cb_version,
          { "Version", "cba.acco.cb_version",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_cb_flags,
          { "Flags", "cba.acco.cb_flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_cb_count,
          { "Count", "cba.acco.cb_count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_cb_conn_data,
          { "CBA Connection data", "cba.acco.cb_conn_data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_cb_item,
          { "Item", "cba.acco.cb_item",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_cb_item_hole,
          { "Hole", "cba.acco.cb_item_hole",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_cb_item_length,
          { "Length", "cba.acco.cb_item_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_acco_cb_item_data,
          { "Data(Hex)", "cba.acco.cb_item_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cba_connect_in,
          { "Connect in frame", "cba.connect_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0,
            "This connection Connect was in the packet with this number", HFILL }
        },
        { &hf_cba_disconnect_in,
          { "Disconnect in frame", "cba.disconnect_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0,
            "This connection Disconnect was in the packet with this number", HFILL }
        },
        { &hf_cba_connectcr_in,
          { "ConnectCR in frame", "cba.connect_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0,
            "This frame ConnectCR was in the packet with this number", HFILL }
        },
        { &hf_cba_disconnectcr_in,
          { "DisconnectCR in frame", "cba.disconnect_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0,
            "This frame DisconnectCR was in the packet with this number", HFILL }
        },
        { &hf_cba_disconnectme_in,
          { "DisconnectMe in frame", "cba.disconnectme_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0,
            "This connection/frame DisconnectMe was in the packet with this number", HFILL }
        },
        { &hf_cba_data_first_in,
          { "First data in frame", "cba.data_first_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0,
            "The first data of this connection/frame in the packet with this number", HFILL }
        },
        { &hf_cba_data_last_in,
          { "Last data in frame", "cba.data_last_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0,
            "The last data of this connection/frame in the packet with this number", HFILL }
        },
    };

    ett5[0] = &ett_ICBAAccoMgt;
    ett5[1] = &ett_cba_addconnectionin;
    ett5[2] = &ett_cba_addconnectionout;
    ett5[3] = &ett_cba_getidout;
    ett5[4] = &ett_cba_getconnectionout;
    proto_ICBAAccoMgt = proto_register_protocol ("ICBAAccoMgt", "ICBAAccoMgt", "cba_acco_mgt");
    proto_register_field_array(proto_ICBAAccoMgt, hf_cba_acco_array, array_length(hf_cba_acco_array));
    proto_register_field_array(proto_ICBAAccoMgt, hf_cba_connect_array, array_length(hf_cba_connect_array));
    proto_register_field_array(proto_ICBAAccoMgt, hf_cba_connectcr_array, array_length(hf_cba_connectcr_array));
    proto_register_subtree_array (ett5, array_length (ett5));

    proto_ICBAAccoMgt2 = proto_register_protocol ("ICBAAccoMgt2", "ICBAAccoMgt2", "cba_acco_mgt2");

    ett3[0] = &ett_ICBAAccoCallback;
    ett3[1] = &ett_ICBAAccoCallback_Item;
    ett3[2] = &ett_ICBAAccoCallback_Buffer;
    proto_ICBAAccoCallback = proto_register_protocol ("ICBAAccoCallback", "ICBAAccoCB", "cba_acco_cb");
    proto_register_field_array(proto_ICBAAccoCallback, hf_cba_acco_cb, array_length(hf_cba_acco_cb));
    proto_register_subtree_array (ett3, array_length (ett3));

    proto_ICBAAccoCallback2 = proto_register_protocol ("ICBAAccoCallback2", "ICBAAccoCB2", "cba_acco_cb2");

    ett4[0] = &ett_ICBAAccoServer;
    ett4[1] = &ett_cba_connectin;
    ett4[2] = &ett_cba_connectout;
    ett4[3] = &ett_cba_getprovconnout;
    proto_ICBAAccoServer = proto_register_protocol ("ICBAAccoServer", "ICBAAccoServ", "cba_acco_server");
    proto_register_field_array(proto_ICBAAccoServer, hf_cba_acco_server, array_length(hf_cba_acco_server));
    proto_register_subtree_array (ett4, array_length (ett4));

    proto_ICBAAccoServer2 = proto_register_protocol ("ICBAAccoServer2", "ICBAAccoServ2", "cba_acco_server2");

    ett4[0] = &ett_ICBAAccoServerSRT;
    ett4[1] = &ett_cba_acco_serversrt_cr_flags;
    ett4[2] = &ett_cba_connectincr;
    ett4[3] = &ett_cba_connectoutcr;
    proto_ICBAAccoServerSRT = proto_register_protocol ("ICBAAccoServerSRT", "ICBAAccoServSRT", "cba_acco_server_srt");
    proto_register_subtree_array (ett4, array_length (ett4));

    ett5[0] = &ett_ICBAAccoSync;
    ett5[1] = &ett_cba_readitemout;
    ett5[2] = &ett_cba_writeitemin;
    ett5[3] = &ett_cba_frame_info;
    ett5[4] = &ett_cba_conn_info;
    proto_ICBAAccoSync = proto_register_protocol ("ICBAAccoSync", "ICBAAccoSync", "cba_acco_sync");
    proto_register_subtree_array (ett5, array_length (ett5));
}


/* handoff protocol */
void
proto_reg_handoff_dcom_cba_acco (void)
{
    /* Register the interfaces */
    dcerpc_init_uuid(proto_ICBAAccoMgt, ett_ICBAAccoMgt,
        &uuid_ICBAAccoMgt, ver_ICBAAccoMgt, ICBAAccoMgt_dissectors, hf_cba_acco_opnum);

    dcerpc_init_uuid(proto_ICBAAccoMgt2, ett_ICBAAccoMgt,
        &uuid_ICBAAccoMgt2, ver_ICBAAccoMgt2, ICBAAccoMgt_dissectors, hf_cba_acco_opnum);

    dcerpc_init_uuid(proto_ICBAAccoCallback, ett_ICBAAccoCallback,
        &uuid_ICBAAccoCallback, ver_ICBAAccoCallback, ICBAAccoCallback_dissectors, hf_cba_acco_opnum);

    dcerpc_init_uuid(proto_ICBAAccoCallback2, ett_ICBAAccoCallback,
        &uuid_ICBAAccoCallback2, ver_ICBAAccoCallback2, ICBAAccoCallback_dissectors, hf_cba_acco_opnum);

    dcerpc_init_uuid(proto_ICBAAccoServer, ett_ICBAAccoServer,
        &uuid_ICBAAccoServer, ver_ICBAAccoServer, ICBAAccoServer_dissectors, hf_cba_acco_opnum);

    dcerpc_init_uuid(proto_ICBAAccoServer2, ett_ICBAAccoServer,
        &uuid_ICBAAccoServer2, ver_ICBAAccoServer2, ICBAAccoServer_dissectors, hf_cba_acco_opnum);

    dcerpc_init_uuid(proto_ICBAAccoServerSRT, ett_ICBAAccoServerSRT,
        &uuid_ICBAAccoServerSRT, ver_ICBAAccoServerSRT, ICBAAccoServerSRT_dissectors, hf_cba_acco_opnum);

    dcerpc_init_uuid(proto_ICBAAccoSync, ett_ICBAAccoSync,
        &uuid_ICBAAccoSync, ver_ICBAAccoSync, ICBAAccoSync_dissectors, hf_cba_acco_opnum);


    heur_dissector_add("pn_rt", dissect_CBA_Connection_Data_heur, proto_ICBAAccoServer);
}
