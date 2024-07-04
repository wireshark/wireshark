/* packet-communityid.c
 *
 * A post-dissector for Community ID flow hashes in Wireshark/tshark.
 *
 * Community ID flow hashing provides a standardized way for mapping
 * flow tuples to string identifiers, used in SIEM searches, network
 * data post-processing/correlation, etc. For details, see:
 *
 * https://github.com/corelight/community-id-spec
 *
 * Copyright 2020, Corelight Inc
 * Contact: Christian Kreibich <christian@corelight.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 *
 * This module provides a stand-alone implementation of the spec.
 */

#include <config.h>

#include <epan/value_string.h>
#include <epan/ipproto.h>
#include <epan/packet.h>
#include <epan/proto_data.h>
#include <epan/prefs.h>

#include <wsutil/wsgcrypt.h>

#include "packet-icmp.h"

/* ---- Generic Community ID codebase, based on GLib & GCrypt ------------------
 *
 * The code between here and the corresponding end comment below
 * provides a reusable implementation of the Community ID. To avoid
 * dealing imperfectly with low-level implementation details, it
 * assumes GLib and GCrypt are available. Adaptation to other data
 * types should be straightforward.
 *
 * Version 1.0
 *
 * For updates or feedback please visit:
 * https://github.com/corelight/c-community-id
 *
 * Copyright (c) 2017-2020 by Corelight, Inc
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 * (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 * (3) Neither the name of Corelight, Inc, nor the names of contributors
 *     may be used to endorse or promote products derived from this software
 *     without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* 8-bit IP protocol numbers, likely redundant with similar
 * definitions in the surrounding project, but having these here keeps
 * the Community ID code self-contained.
 */
#define CID_PROTO_ICMP 1
#define CID_PROTO_IP 4
#define CID_PROTO_TCP 6
#define CID_PROTO_UDP 17
#define CID_PROTO_IPV6 41
#define CID_PROTO_ICMPV6 58
#define CID_PROTO_SCTP 132

/* Similarly, ICMP type numbers, to implement flow-like treatment of
 * the ICMPs via type & code values.
 */
#define CID_ICMP_ECHO_REPLY 0
#define CID_ICMP_ECHO 8
#define CID_ICMP_RTR_ADVERT 9
#define CID_ICMP_RTR_SOLICIT 10
#define CID_ICMP_TSTAMP 13
#define CID_ICMP_TSTAMP_REPLY 14
#define CID_ICMP_INFO 15
#define CID_ICMP_INFO_REPLY 16
#define CID_ICMP_MASK 17
#define CID_ICMP_MASK_REPLY 18

#define CID_ICMPV6_ECHO_REQUEST 128
#define CID_ICMPV6_ECHO_REPLY 129
#define CID_ICMPV6_MLD_LISTENER_QUERY 130
#define CID_ICMPV6_MLD_LISTENER_REPORT 131
#define CID_ICMPV6_ND_ROUTER_SOLICIT 133
#define CID_ICMPV6_ND_ROUTER_ADVERT 134
#define CID_ICMPV6_ND_NEIGHBOR_SOLICIT 135
#define CID_ICMPV6_ND_NEIGHBOR_ADVERT 136
#define CID_ICMPV6_WRU_REQUEST 139
#define CID_ICMPV6_WRU_REPLY 140
#define CID_ICMPV6_HAAD_REQUEST 144
#define CID_ICMPV6_HAAD_REPLY 145

/* There's currently only a v1, so we hardwire its prefix string. */
#define CID_VERSION_PREFIX "1:"

/* Largest IP address size currently supported, to simplify buffer
 * allocations in C90-compliant codebases.
 */
#define CID_ADDR_LEN_MAX 16

/* Set to 1 for debugging output to stderr. */
#define CID_DEBUG 0

typedef struct _communityid_cfg_t {
    bool cfg_do_base64;
    uint16_t cfg_seed;
} communityid_cfg_t;

#if CID_DEBUG
static void communityid_sha1_dbg(const char *msg, const void* data, size_t len)
{
    char *buf = (char*) g_malloc(len*2 + 1);
    char *ptr = buf;
    size_t i;

    for (i = 0; i < len; i++, ptr += 2) {
        snprintf(ptr, 3, "%02x", ((unsigned char*)data)[i]);
    }

    fprintf(stderr, "Community ID dbg [%s]: %s\n", msg, buf);
    g_free(buf);
}
#define COMMUNITYID_SHA1_DBG(...) communityid_sha1_dbg(__VA_ARGS__)
#else
#define COMMUNITYID_SHA1_DBG(...)
#endif

/* Helper function to determine whether a flow tuple is ordered
 * correctly or needs flipping for abstracting flow directionality.
 */
static bool communityid_tuple_lt(uint8_t addr_len,
                                     const unsigned char *saddr, const unsigned char  *daddr,
                                     const uint16_t *sport, const uint16_t *dport)
{
    int addrcmp = memcmp(saddr, daddr, addr_len);
    int ports_lt = (sport != NULL && dport != NULL) ? GUINT16_FROM_BE(*sport) < GUINT16_FROM_BE(*dport) : true;
    return addrcmp < 0 || (addrcmp == 0 && ports_lt);
}

/* Main Community ID computation routine. Arguments:
 *
 * - cfg: a pointer to a communityid_cfg_t instance with configuration
 *   information.
 *
 * - proto: an 8-bit unsigned value representing the IP protocol
 *   number of the transport layer (or equivalent) protocol.
 *
 * - addr_len: the length in octets of the network-layer addresses we
 *   use. Must be either 4 (for IPv4) or 16 (for IPv6).
 *
 * - saddr/daddr: pointers to the network-layer source/destination
 *   address, in NBO.
 *
 * - sport/dport: pointers to the transport-layer 16-bit port numbers,
 *   in NBO. These may be NULL pointers to signal that port numbers
 *   aren't available for the flow.
 *
 * - result: the address of a result pointer that will point at a
 *   newly allocated string containing the computed ID value upon
 *   return from the function. Callers take ownership of the allocated
 *   string and need to free it when finished.
 *
 * Return value: a Boolean, true if the computation was successful and
 * false otherwise. The function modifies the result pointer only when
 * the return value is true.
 */
static bool communityid_calc(communityid_cfg_t *cfg, uint8_t proto,
                                 uint8_t addr_len, const unsigned char *saddr, const unsigned char *daddr,
                                 const uint16_t *sport, const uint16_t *dport,
                                 char **result)
{
    bool is_one_way = false;
    uint8_t padding = 0;
    uint16_t seed_final = 0;
    gcry_md_hd_t sha1;
    unsigned char *sha1_buf = NULL;
    size_t sha1_buf_len = gcry_md_get_algo_dlen(GCRY_MD_SHA1);
    uint16_t sport_final, dport_final;

    g_return_val_if_fail(cfg != NULL, false);
    g_return_val_if_fail(result != NULL, false);
    g_return_val_if_fail(addr_len == 4 || addr_len == 16, false);
    g_return_val_if_fail(saddr != NULL && daddr != NULL, false);

    if (sport != NULL && dport != NULL) {
        sport_final = *sport;
        dport_final = *dport;

        /* Sort out directionality of this packet in the flow. For
         * regular bidirectional traffic we resort this by ordering
         * the flow tuple. ICMP is our corner-case; we use its type
         * and code values as port equivalents, and expand them when
         * feasible to provide directionality. This is based on Zeek's
         * internal model of ICMP traffic.
         */
        switch (proto) {
        case CID_PROTO_ICMP:
            {
                /* Get ports from network byte order: */
                sport_final = GUINT16_FROM_BE(sport_final);
                dport_final = GUINT16_FROM_BE(dport_final);

                switch (sport_final) {
                case CID_ICMP_ECHO:
                    dport_final = CID_ICMP_ECHO_REPLY;
                    break;
                case CID_ICMP_ECHO_REPLY:
                    dport_final = CID_ICMP_ECHO;
                    break;
                case CID_ICMP_TSTAMP:
                    dport_final = CID_ICMP_TSTAMP_REPLY;
                    break;
                case CID_ICMP_TSTAMP_REPLY:
                    dport_final = CID_ICMP_TSTAMP;
                    break;
                case CID_ICMP_INFO:
                    dport_final = CID_ICMP_INFO_REPLY;
                    break;
                case CID_ICMP_INFO_REPLY:
                    dport_final = CID_ICMP_INFO;
                    break;
                case CID_ICMP_RTR_SOLICIT:
                    dport_final = CID_ICMP_RTR_ADVERT;
                    break;
                case CID_ICMP_RTR_ADVERT:
                    dport_final = CID_ICMP_RTR_SOLICIT;
                    break;
                case CID_ICMP_MASK:
                    dport_final = CID_ICMP_MASK_REPLY;
                    break;
                case CID_ICMP_MASK_REPLY:
                    dport_final = CID_ICMP_MASK;
                    break;
                default:
                    is_one_way = true;
                }

                /* And back to NBO: */
                sport_final = GUINT16_TO_BE(sport_final);
                dport_final = GUINT16_TO_BE(dport_final);
            }
            break;
        case CID_PROTO_ICMPV6:
            {
                sport_final = GUINT16_FROM_BE(sport_final);
                dport_final = GUINT16_FROM_BE(dport_final);

                switch (sport_final) {
                case CID_ICMPV6_ECHO_REQUEST:
                    dport_final = CID_ICMPV6_ECHO_REPLY;
                    break;
                case CID_ICMPV6_ECHO_REPLY:
                    dport_final = CID_ICMPV6_ECHO_REQUEST;
                    break;
                case CID_ICMPV6_MLD_LISTENER_QUERY:
                    dport_final = CID_ICMPV6_MLD_LISTENER_REPORT;
                    break;
                case CID_ICMPV6_MLD_LISTENER_REPORT:
                    dport_final = CID_ICMPV6_MLD_LISTENER_QUERY;
                    break;
                case CID_ICMPV6_ND_ROUTER_SOLICIT:
                    dport_final = CID_ICMPV6_ND_ROUTER_ADVERT;
                    break;
                case CID_ICMPV6_ND_ROUTER_ADVERT:
                    dport_final = CID_ICMPV6_ND_ROUTER_SOLICIT;
                    break;
                case CID_ICMPV6_ND_NEIGHBOR_SOLICIT:
                    dport_final = CID_ICMPV6_ND_NEIGHBOR_ADVERT;
                    break;
                case CID_ICMPV6_ND_NEIGHBOR_ADVERT:
                    dport_final = CID_ICMPV6_ND_NEIGHBOR_SOLICIT;
                    break;
                case CID_ICMPV6_WRU_REQUEST:
                    dport_final = CID_ICMPV6_WRU_REPLY;
                    break;
                case CID_ICMPV6_WRU_REPLY:
                    dport_final = CID_ICMPV6_WRU_REQUEST;
                    break;
                case CID_ICMPV6_HAAD_REQUEST:
                    dport_final = CID_ICMPV6_HAAD_REPLY;
                    break;
                case CID_ICMPV6_HAAD_REPLY:
                    dport_final = CID_ICMPV6_HAAD_REQUEST;
                    break;
                default:
                    is_one_way = true;
                }

                sport_final = GUINT16_TO_BE(sport_final);
                dport_final = GUINT16_TO_BE(dport_final);
            }
        default:
            ;
        }

        sport = &sport_final;
        dport = &dport_final;
    }

    if (is_one_way || communityid_tuple_lt(addr_len, saddr, daddr,
                                           sport, dport)) {
        /* Ordered correctly, no need to flip. */
    } else {
        /* Need to flip endpoints for consistent hashing. */
        const unsigned char *tmp_addr = saddr;
        saddr = daddr;
        daddr = tmp_addr;

        if (sport != NULL && dport != NULL) {
            const uint16_t *tmp_port = sport;
            sport = dport;
            dport = tmp_port;
        }
    }

    seed_final = GUINT16_TO_BE(cfg->cfg_seed);

    /* SHA-1 computation */

    if (gcry_md_open(&sha1, GCRY_MD_SHA1, 0))
        return false;

    COMMUNITYID_SHA1_DBG("seed", &seed_final, 2);
    gcry_md_write(sha1, &seed_final, 2);

    COMMUNITYID_SHA1_DBG("saddr", saddr, addr_len);
    gcry_md_write(sha1, saddr, addr_len);

    COMMUNITYID_SHA1_DBG("daddr", daddr, addr_len);
    gcry_md_write(sha1, daddr, addr_len);

    COMMUNITYID_SHA1_DBG("proto", &proto, 1);
    gcry_md_write(sha1, &proto, 1);

    COMMUNITYID_SHA1_DBG("padding", &padding, 1);
    gcry_md_write(sha1, &padding, 1);

    if (sport != NULL && dport != NULL) {
        COMMUNITYID_SHA1_DBG("sport", sport, 2);
        gcry_md_write(sha1, sport, 2);

        COMMUNITYID_SHA1_DBG("dport", dport, 2);
        gcry_md_write(sha1, dport, 2);
    }

    sha1_buf = (unsigned char*) g_malloc(sha1_buf_len);
    memcpy(sha1_buf, gcry_md_read(sha1, 0), sha1_buf_len);
    gcry_md_close(sha1);

    if (cfg->cfg_do_base64) {
        char *str = g_base64_encode(sha1_buf, sha1_buf_len);
        size_t len = strlen(CID_VERSION_PREFIX) + strlen(str) + 1;

        *result = (char*) g_malloc(len);
        snprintf(*result, len, "%s%s", CID_VERSION_PREFIX, str);
        g_free(str);
    } else {
        /* Convert binary SHA-1 to ASCII representation.
         * 2 hex digits for every byte + 1 for trailing \0:
         */
        char *ptr;
        size_t i;

        *result = (char*) g_malloc(strlen(CID_VERSION_PREFIX) + sha1_buf_len*2 + 1);
        memcpy(*result, CID_VERSION_PREFIX, strlen(CID_VERSION_PREFIX));
        ptr = *result + strlen(CID_VERSION_PREFIX);
        for (i = 0; i < sha1_buf_len; i++, ptr += 2) {
            snprintf(ptr, 3, "%02x", sha1_buf[i]);
        }
    }

    g_free(sha1_buf);

    return true;
}

/* ---- End of generic Community ID codebase ----------------------------------- */

void proto_register_communityid(void);

static int proto_communityid;
static int proto_ip;
static int proto_ipv6;
static int proto_icmp;
static int proto_icmpv6;

static int hf_communityid_hash;

static dissector_handle_t communityid_handle;

/* Config settings as handled by Wireshark's preference framework ... */
static bool pref_cid_do_base64 = true;
static unsigned pref_cid_seed;
/* ... and as interpreted by the Community ID code. */
static communityid_cfg_t cid_cfg;

/* rapper mapping Wireshark's data types to the generic ones supported above. */
static bool communityid_calc_wrapper(communityid_cfg_t *cfg, uint8_t proto,
                                         address *saddr, address *daddr,
                                         const uint16_t *sport, const uint16_t *dport,
                                         char **result)
{
    /* IPv4 */
    if (4 == saddr->len && saddr->len == daddr->len)
        return communityid_calc(cfg, proto, 4,
                                (const unsigned char*)saddr->data, (const unsigned char*)daddr->data,
                                sport, dport, result);

    /* IPv6 */
    if (16 == saddr->len && saddr->len == daddr->len)
        return communityid_calc(cfg, proto, 16,
                                (const unsigned char*)saddr->data, (const unsigned char*)daddr->data,
                                sport, dport, result);

    /* Need another network protocol here? Please file a ticket at
     * https://github.com/corelight/community-id-spec!
     */

    return false;
}

static int communityid_dissector(tvbuff_t *tvb, packet_info *pinfo,
                                 proto_tree *tree, void *data _U_)
{
    /* We need to figure out whether this is one of the protocol
     * constellations supported by Community ID:
     *
     * - TCP/UDP/SCTP over IPv4/v6
     * - ICMP/ICMPv6
     * - Other IPv4/v6
     */
    char *cid = NULL;
    int proto_ip_found = -1;
    icmp_info_t *icmp_info = NULL;
    uint8_t proto = 0;

    /* All of this is to establish the Community ID value in the tree,
     * so if we don't have a tree, we're done.
     */
    if (tree == NULL)
        return 0;

    /* Map Wireshark-level config to Community ID configs. */
    cid_cfg.cfg_do_base64 = pref_cid_do_base64;
    cid_cfg.cfg_seed = (uint16_t) pref_cid_seed;

    /* If not yet done, establish global handles for required protocols. */
    if (proto_ip <= 0) {
        proto_ip = proto_get_id_by_filter_name("ip");
        proto_ipv6 = proto_get_id_by_filter_name("ipv6");
        proto_icmp = proto_get_id_by_filter_name("icmp");
        proto_icmpv6 = proto_get_id_by_filter_name("icmpv6");
    }

    if (pinfo->net_src.type == AT_IPv4 && pinfo->net_dst.type == AT_IPv4)
        proto_ip_found = proto_ip;
    if (pinfo->net_src.type == AT_IPv6 && pinfo->net_dst.type == AT_IPv6)
        proto_ip_found = proto_ipv6;

    /* If this frame isn't IP at all, we're done. */
    if (proto_ip_found <= 0)
        return 0;

    /* Next, look specifically for ICMP state stored by dissectors: */
    if (proto_ip_found == proto_ip) {
        icmp_info = (icmp_info_t*) p_get_proto_data(wmem_file_scope(),
                                                pinfo, proto_icmp, 0);
        if (icmp_info != NULL) {
            uint16_t sport = GUINT16_TO_BE(icmp_info->type);
            uint16_t dport = GUINT16_TO_BE(icmp_info->code);

            if (! communityid_calc_wrapper(&cid_cfg, CID_PROTO_ICMP,
                                           &pinfo->net_src, &pinfo->net_dst,
                                           &sport, &dport, &cid))
                return 0;
        }
    }

    /* It could also be ICMPv6. Try this before generic transport
     * layers, since the dissection can find transport layers in the
     * ICMP-contained snippets.
     */
    if (cid == NULL && proto_ip_found == proto_ipv6) {
        icmp_info = (icmp_info_t*) p_get_proto_data(wmem_file_scope(),
                                                    pinfo, proto_icmpv6, 0);
        if (icmp_info != NULL) {
            uint16_t sport = GUINT16_TO_BE(icmp_info->type);
            uint16_t dport = GUINT16_TO_BE(icmp_info->code);

            if (! communityid_calc_wrapper(&cid_cfg, CID_PROTO_ICMPV6,
                                           &pinfo->net_src, &pinfo->net_dst,
                                           &sport, &dport, &cid))
                return 0;
        }
    }

    /* Still no go? Try generic transport layers next. */
    if (cid == NULL) {
        uint16_t sport = GUINT16_TO_BE(pinfo->srcport);
        uint16_t dport = GUINT16_TO_BE(pinfo->destport);

        switch ( pinfo->ptype ) {
        case PT_SCTP:
            proto = CID_PROTO_SCTP;
            break;
        case PT_TCP:
            proto = CID_PROTO_TCP;
            break;
        case PT_UDP:
            proto = CID_PROTO_UDP;
            break;
        default:
            /* We'll fall through to the IP-only scenario below. */
            ;
        }

        if (proto != 0 && ! communityid_calc_wrapper(&cid_cfg, proto,
                                                     &pinfo->net_src, &pinfo->net_dst,
                                                     &sport, &dport, &cid)) {
            return 0;
        }
    }

    /* Final straw: IP-only. */
    if (cid == NULL) {
        /* We'd like to grab the outermost IP header's protocol field
         * value so we can grab its protocol field number. The IPv4
         * analyzer stores the field in its protocol data, but we need
         * the layer number. Inspired by proto_get_frame_protocols().
         */
        wmem_list_frame_t *protos = wmem_list_head(pinfo->layers);
        unsigned layer_num = 1;

        while (protos != NULL) {
            if (GPOINTER_TO_INT(wmem_list_frame_data(protos)) == proto_ip_found) {
                /* We take any protocol number present, so this can
                 * include values other than the defined CID_PROTO_*
                 * constants.
                 */
                proto = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo,
                                                          proto_ip_found, layer_num));
                break;
            }

            layer_num++;
            protos = wmem_list_frame_next(protos);
        }

        if (proto != 0) {
            if (! communityid_calc_wrapper(&cid_cfg, proto,
                                           &pinfo->net_src, &pinfo->net_dst,
                                           NULL, NULL, &cid))
                return 0;
        }
    }

    if (cid != NULL) {
        proto_item *it = proto_tree_add_string(tree, hf_communityid_hash, tvb, 0, 0, cid);
        proto_item_set_generated(it);
        g_free(cid);
    }

    return tvb_reported_length(tvb);
}

void proto_register_communityid(void)
{
    module_t *communityid_module;

    static hf_register_info hf[] = {
        { &hf_communityid_hash,
          { "Community ID", "communityid", FT_STRING, BASE_NONE, NULL, 0x00,
            "Community ID hash value for this packet's flow", HFILL }}
    };

    proto_communityid = proto_register_protocol("Community ID Flow Hashing",
        "CommunityID", "communityid");

    proto_register_field_array(proto_communityid, hf, array_length(hf));
    proto_disable_by_default(proto_communityid);

    communityid_handle = register_dissector("communityid", communityid_dissector,
                                                 proto_communityid);
    register_postdissector(communityid_handle);

    /* Preference handling */
    communityid_module = prefs_register_protocol(proto_communityid, NULL);
    prefs_register_bool_preference(communityid_module, "do_base64",
        "Use base64 encoding",
        "Whether to base64-encode the Community ID hash value",
        &pref_cid_do_base64);
    prefs_register_uint_preference(communityid_module, "seed",
        "Hash seed value",
        "A 16-bit seed value to add to the hashed data",
        10, &pref_cid_seed);
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
