/* packet-lls-slt.c
 * Routines for ATSC3 LLS(Low Level Signalling) SLT table dissection
 * Copyright 2023, Sergey V. Lobanov <sergey@lobanov.in>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * ATSC3 Signaling, Delivery, Synchronization, and Error Protection (A/331)
 * https://www.atsc.org/atsc-documents/3312017-signaling-delivery-synchronization-error-protection/
 */

#include <epan/packet.h>
#include <epan/proto_data.h>

#include <wsutil/inet_addr.h>
#include <wsutil/strtoi.h>

#include "packet-lls.h"
#include "packet-xml.h"


/* Saved SLT Table to use it from another protocols (e.g. ALC/LCT) */
wmem_map_t *lls_slt_table;

/* Hash functions */
static int
lls_slt_key_equal(const void *v, const void *w)
{
    const lls_slt_key_t *v1 = (const lls_slt_key_t *)v;
    const lls_slt_key_t *v2 = (const lls_slt_key_t *)w;
    int result;
    result = (v1->src_ip == v2->src_ip &&
              v1->dst_ip == v2->dst_ip &&
              v1->dst_port == v2->dst_port);
    return result;
}

static unsigned
lls_slt_key_hash(const void *v)
{
    const lls_slt_key_t *key = (const lls_slt_key_t *)v;
    unsigned hash_val = key->src_ip ^ key->dst_ip ^ (((uint32_t)(key->dst_port)) << 16);
    return hash_val;
}

/* Init hash table */
static void
lls_check_init_slt_table(void) {
    if(lls_slt_table == NULL) {
        lls_slt_table = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), lls_slt_key_hash, lls_slt_key_equal);
    }
}

static char *
xml_value_to_gchar(xml_frame_t *xml_frame, wmem_allocator_t *scope) {
    char *value = NULL;
    if (xml_frame->value != NULL) {
        unsigned l = tvb_reported_length(xml_frame->value);
        value = (char *)wmem_alloc0(scope, l + 1);
        tvb_memcpy(xml_frame->value, value, 0, l);
    }
    return value;
}

void
lls_extract_save_slt_table(packet_info *pinfo, dissector_handle_t xml_handle)
{
    /* Extract data saved by xml */
    int proto_xml = dissector_handle_get_protocol_index(xml_handle);
    xml_frame_t *xml_dissector_frame = (xml_frame_t *)p_get_proto_data(pinfo->pool, pinfo, proto_xml, 0);
    if (xml_dissector_frame == NULL) {
        return;
    }

    /* Data from XML dissector */
    /* Root level, find SLT tag */
    xml_frame_t *xml_frame = xml_dissector_frame->first_child;
    xml_frame_t *xml_frame_slt = NULL;
    while (xml_frame) {
        if (xml_frame->type == XML_FRAME_TAG && g_strcmp0("SLT", xml_frame->name_orig_case) == 0) {
            xml_frame_slt = xml_frame;
            break; /* SLT tag found */
        }
        xml_frame = xml_frame->next_sibling;
    }

    if (xml_frame_slt == NULL)
        return;

    /* SLT level*/
    xml_frame_t *slt_entry = xml_frame_slt->first_child;
    while (slt_entry) {
        if (!(slt_entry->type == XML_FRAME_TAG && g_strcmp0("Service", slt_entry->name_orig_case) == 0)) {
            slt_entry = slt_entry->next_sibling;
            continue;
        }

        /* Service level */
        xml_frame_t *service_entry = slt_entry->first_child;

        lls_slt_key_t slt_key = {0};
        lls_slt_value_t slt_val = {0};
        slt_val.major_channel_num = -1;
        slt_val.minor_channel_num = -1;
        while (service_entry) {
            char *value = xml_value_to_gchar(service_entry, pinfo->pool);
            if (service_entry->type == XML_FRAME_ATTRIB && value != NULL) {
                if(g_strcmp0("serviceId", service_entry->name_orig_case) == 0) {
                    ws_strtou16(value, NULL, &slt_val.service_id);
                } else if(g_strcmp0("majorChannelNo", service_entry->name_orig_case) == 0) {
                    ws_strtoi32(value, NULL, &slt_val.major_channel_num);
                } else if(g_strcmp0("minorChannelNo", service_entry->name_orig_case) == 0) {
                    ws_strtoi32(value, NULL, &slt_val.minor_channel_num);
                }
            }
            wmem_free(pinfo->pool, value);

            if (service_entry->type == XML_FRAME_TAG && g_strcmp0("BroadcastSvcSignaling", service_entry->name_orig_case) == 0) {
                /* Broadcast svc signalling level*/
                xml_frame_t *bcast_svc_entry = service_entry->first_child;

                while (bcast_svc_entry) {
                    value = xml_value_to_gchar(bcast_svc_entry, pinfo->pool);
                    if (bcast_svc_entry->type == XML_FRAME_ATTRIB && value != NULL) {
                        if (g_strcmp0("slsProtocol", bcast_svc_entry->name_orig_case) == 0) {
                            ws_strtou8(value, NULL, &slt_val.sls_protocol);
                        } else if (g_strcmp0("slsDestinationIpAddress", bcast_svc_entry->name_orig_case) == 0) {
                            ws_inet_pton4(value, &slt_key.dst_ip);
                        } else if (g_strcmp0("slsSourceIpAddress", bcast_svc_entry->name_orig_case) == 0) {
                            ws_inet_pton4(value, &slt_key.src_ip);
                        } else if (g_strcmp0("slsDestinationUdpPort", bcast_svc_entry->name_orig_case) == 0) {
                            ws_strtou16(value, NULL, &slt_key.dst_port);
                        }
                    }
                    wmem_free(pinfo->pool, value);
                    bcast_svc_entry = bcast_svc_entry->next_sibling;
                }
            }

            service_entry = service_entry->next_sibling;
        }
        if (slt_key.dst_ip != 0) {
            /* Save found service entry to hashmap */
            lls_slt_key_t *slt_key_m = wmem_new(wmem_file_scope(), lls_slt_key_t);
            lls_slt_value_t *slt_val_m = wmem_new(wmem_file_scope(), lls_slt_value_t);
            *slt_key_m = slt_key;
            *slt_val_m = slt_val;
            lls_check_init_slt_table();
            wmem_map_insert(lls_slt_table, (void *)slt_key_m, (void *)slt_val_m);
        }
        slt_entry = slt_entry->next_sibling;
    }
}

static lls_slt_value_t *
get_lls_slt_val(packet_info *pinfo) {
    /* This routine is for ATSC3 ALC/LCT packets (ipv4 only protocol by design)
       so ipv6 is not supported by this test */
    if (!(pinfo->net_src.type == AT_IPv4)) {
        return NULL;
    }

    /* No ability to lookup a record */
    if (lls_slt_table == NULL) {
        return NULL;
    }

    /* Prepare for lookup in LLS SLT table */
    lls_slt_key_t slt_key;
    slt_key.src_ip = *(uint32_t *)pinfo->net_src.data;
    slt_key.dst_ip = *(uint32_t *)pinfo->net_dst.data;
    slt_key.dst_port = (uint16_t)pinfo->destport;

    /* Try to lookup by src_ip + dst_ip + dst_port */
    lls_slt_value_t *slt_val = (lls_slt_value_t *)wmem_map_lookup(lls_slt_table, (const void *)(&slt_key));
    if(slt_val == NULL) {
        /* No record in SLT table. src_ip is optional according to A/331 so try to lookup by dst ip + port */
        slt_key.src_ip = 0; /* LLS SLT dissector sets it to 0 if source ip is not specified */
        slt_val = (lls_slt_value_t *)wmem_map_lookup(lls_slt_table, (const void *)(&slt_key));
        if (slt_val == NULL) {
            /* Record not found by dst ip + port */
            return NULL;
        }
    }

    return slt_val;
}

/* Heuristics test. Checks if packet is ALC using LLS SLT table */
bool
test_alc_over_slt(packet_info *pinfo, tvbuff_t *tvb _U_, int offset _U_, void *data _U_)
{
    lls_slt_value_t *slt_val = get_lls_slt_val(pinfo);
    if (slt_val == NULL)
        return false;

    if (slt_val->sls_protocol == 1) {
        /* slsProtocol=1 is ALC/LCT ROUTE/DASH */
        return true;
    } else {
        /* ACL/LCT is used only for ROUTE/DASH so return false */
        return false;
    }
}

/* Returns channel info or NULL if no info in SLT table*/
char *
get_slt_channel_info(packet_info *pinfo)
{
    lls_slt_value_t *slt_val = get_lls_slt_val(pinfo);
    if (slt_val == NULL)
        return NULL;

    int32_t major_channel_num = slt_val->major_channel_num;
    int32_t minor_channel_num = slt_val->minor_channel_num;
    char *ret;
    if (major_channel_num > 0 && minor_channel_num > 0) {
        ret = wmem_strdup_printf(pinfo->pool, "ServiceID: %u Channel: %d.%d", slt_val->service_id,
            major_channel_num, minor_channel_num);
    } else {
        ret = wmem_strdup_printf(pinfo->pool, "ServiceID: %u", slt_val->service_id);
    }

    return ret;
}
