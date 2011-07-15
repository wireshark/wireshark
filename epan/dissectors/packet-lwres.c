/* packet-lwres.c
 * Routines for light weight reslover (lwres, part of BIND9) packet disassembly
 *
 * $Id$
 *
 * Copyright (c) 2003 by Oleg Terletsky <oleg.terletsky@comverse.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-dns.h"

#define LWRES_LWPACKET_LENGTH           (4 * 5 + 2 * 4)
#define LWRES_LWPACKETFLAG_RESPONSE     0x0001U /* if set, pkt is a response */
#define LWRES_LWPACKETVERSION_0         0

#define LW_LENGTH_OFFSET         0
#define LW_VERSION_OFFSET        4
#define LW_PKTFLASG_OFFSET       6
#define LW_SERIAL_OFFSET         8
#define LW_OPCODE_OFFSET        12
#define LW_RESULT_OFFSET        16
#define LW_RECVLEN_OFFSET       20
#define LW_AUTHTYPE_OFFSET      24
#define LW_AUTHLEN_OFFSET       26

#define LWRES_OPCODE_NOOP               0x00000000U
#define LWRES_OPCODE_GETADDRSBYNAME     0x00010001U
#define LWRES_OPCODE_GETNAMEBYADDR      0x00010002U
#define LWRES_OPCODE_GETRDATABYNAME     0x00010003U

static const value_string opcode_values[] = {
    { LWRES_OPCODE_NOOP,            "Noop" },
    { LWRES_OPCODE_GETADDRSBYNAME,  "getaddrbyname" },
    { LWRES_OPCODE_GETNAMEBYADDR,   "getnamebyaddr" },
    { LWRES_OPCODE_GETRDATABYNAME,  "getrdatabyname" },
    { 0, NULL },
};


#define LWRES_R_SUCCESS                  0
#define LWRES_R_NOMEMORY                 1
#define LWRES_R_TIMEOUT                  2
#define LWRES_R_NOTFOUND                 3
#define LWRES_R_UNEXPECTEDEND            4       /* unexpected end of input */
#define LWRES_R_FAILURE                  5       /* generic failure */
#define LWRES_R_IOERROR                  6
#define LWRES_R_NOTIMPLEMENTED           7
#define LWRES_R_UNEXPECTED               8
#define LWRES_R_TRAILINGDATA             9
#define LWRES_R_INCOMPLETE              10
#define LWRES_R_RETRY                   11
#define LWRES_R_TYPENOTFOUND            12
#define LWRES_R_TOOLARGE                13

#define T_A     1
#define T_NS    2
#define T_MX    15
#define T_SRV   33


static const value_string t_types[] = {
    { T_A,      "T_A" },
    { T_NS,     "T_NS" },
    { T_MX,     "T_MX" },
    { T_SRV,    "T_SRV" },
    { 0,        NULL },
};




static const value_string result_values[]  = {
    { LWRES_R_SUCCESS,          "Success" },
    { LWRES_R_NOMEMORY,         "No memory" },
    { LWRES_R_TIMEOUT,          "Timeout" },
    { LWRES_R_NOTFOUND,         "Not found" },
    { LWRES_R_UNEXPECTEDEND,    "Unexpected end of input" },
    { LWRES_R_FAILURE,          "Generic failure" },
    { LWRES_R_IOERROR,          "I/O Error" },
    { LWRES_R_UNEXPECTED,       "Unexpected" },
    { LWRES_R_TRAILINGDATA,     "Trailing data" },
    { LWRES_R_INCOMPLETE,       "Incomplete" },
    { LWRES_R_RETRY,            "Retry" },
    { LWRES_R_TYPENOTFOUND,     "Type not found" },
    { LWRES_R_TOOLARGE,         "Too large" },
    { 0,                        NULL },
};

static int hf_length = -1;
static int hf_version = -1;
static int hf_flags = -1;
static int hf_serial = -1;
static int hf_opcode = -1;
static int hf_result = -1;
static int hf_recvlen = -1;
static int hf_authtype = -1;
static int hf_authlen = -1;

static int hf_rflags = -1;
static int hf_rdclass = -1;
static int hf_rdtype = -1;
static int hf_namelen = -1;
static int hf_req_name = -1;

static int hf_ttl = -1;
static int hf_nrdatas = -1;
static int hf_nsigs = -1;
static int hf_realnamelen = -1;
static int hf_realname = -1;


static int hf_a_record = -1;
static int hf_a_rec_len = -1;
static int hf_srv_prio = -1;
static int hf_srv_weight = -1;
static int hf_srv_port = -1;

static int hf_adn_flags = -1;
static int hf_adn_addrtype = -1;
static int hf_adn_namelen = -1;
static int hf_adn_name = -1;

static int hf_adn_realname = -1;
static int hf_adn_aliasname = -1;

static int hf_adn_naddrs = -1;
static int hf_adn_naliases = -1;
static int hf_adn_family = -1;
static int hf_adn_addr_len = -1;
static int hf_adn_addr_addr = -1;


static int ett_lwres = -1;
static int ett_rdata_req = -1;
static int ett_rdata_resp = -1;
static int ett_a_rec = -1;
static int ett_a_rec_addr = -1;
static int ett_srv_rec = -1;
static int ett_srv_rec_item = -1;
static int ett_adn_request = -1;
static int ett_adn_resp = -1;
static int ett_adn_alias = -1;
static int ett_adn_addr = -1;
static int ett_nba_request = -1;
static int ett_nba_resp = -1;
static int ett_noop = -1;

static int ett_mx_rec = -1;
static int ett_mx_rec_item = -1;

static int ett_ns_rec = -1;
static int ett_ns_rec_item = -1;



#define LWRES_UDP_PORT 921

static guint global_lwres_port = LWRES_UDP_PORT;

void proto_reg_handoff_lwres(void);


/* Define the lwres proto */
static int proto_lwres = -1;


/* Define many many headers for mgcp */

static const value_string message_types_values[] = {
    { 1,        "REQUEST " },
    { 2,        "RESPONSE" },
    { 0,        NULL },
};

static void dissect_getnamebyaddr_request(tvbuff_t* tvb, proto_tree* lwres_tree)
{
    guint32 flags,family;
    guint16 addrlen, slen;
    const char* addrs;

    proto_item* nba_request_item;
    proto_tree* nba_request_tree;

    flags = tvb_get_ntohl(tvb, LWRES_LWPACKET_LENGTH);
    family = tvb_get_ntohl(tvb, LWRES_LWPACKET_LENGTH + 4);
    addrlen = tvb_get_ntohs(tvb, LWRES_LWPACKET_LENGTH + 8);
    addrs = tvb_ip_to_str(tvb, LWRES_LWPACKET_LENGTH + 10);
    slen = (int)strlen(addrs);

    if(lwres_tree)
    {
        nba_request_item = proto_tree_add_text(lwres_tree,tvb,LWRES_LWPACKET_LENGTH,LWRES_LWPACKET_LENGTH+14,"getnamebyaddr parameters");
        nba_request_tree = proto_item_add_subtree(nba_request_item, ett_nba_request);
    }
    else return;

    proto_tree_add_uint(nba_request_tree, hf_adn_flags, tvb,
                LWRES_LWPACKET_LENGTH, 4, flags);

    proto_tree_add_uint(nba_request_tree, hf_adn_family, tvb,
                LWRES_LWPACKET_LENGTH + 4, 4, family);

    proto_tree_add_uint(nba_request_tree, hf_adn_addr_len, tvb,
                LWRES_LWPACKET_LENGTH + 8, 2, addrlen);

    proto_tree_add_string(nba_request_tree, hf_adn_addr_addr, tvb,
                  LWRES_LWPACKET_LENGTH + 10, slen, addrs);

}

static void dissect_getnamebyaddr_response(tvbuff_t* tvb, proto_tree* lwres_tree)
{
    guint32 i, offset;
    guint16 naliases,realnamelen,aliaslen;
    gchar *aliasname;


    proto_item* nba_resp_item;
    proto_tree* nba_resp_tree;

    proto_item* alias_item;
    proto_tree* alias_tree;

    if(lwres_tree)
    {
        nba_resp_item = proto_tree_add_text(lwres_tree, tvb, LWRES_LWPACKET_LENGTH, 10,"getnamebyaddr records");
        nba_resp_tree = proto_item_add_subtree(nba_resp_item, ett_nba_resp);
    }
    else return;

    naliases = tvb_get_ntohs(tvb, LWRES_LWPACKET_LENGTH + 4);
    realnamelen = tvb_get_ntohs(tvb,LWRES_LWPACKET_LENGTH + 4 + 2);

    proto_tree_add_item(nba_resp_tree,
                        hf_adn_flags,
                        tvb,
                        LWRES_LWPACKET_LENGTH,
                        4,
                        FALSE);
    proto_tree_add_item(nba_resp_tree,
                        hf_adn_naliases,
                        tvb,
                        LWRES_LWPACKET_LENGTH + 4,
                        2,
                        FALSE);

    proto_tree_add_item(nba_resp_tree,
                        hf_adn_namelen,
                        tvb,
                        LWRES_LWPACKET_LENGTH + 6,
                        2,
                        FALSE);

    proto_tree_add_item(nba_resp_tree,
                        hf_adn_realname,
                        tvb,
                        LWRES_LWPACKET_LENGTH + 8,
                        realnamelen,
                        FALSE);

    offset=LWRES_LWPACKET_LENGTH + 8 + realnamelen;

    if(naliases)
    {
        for(i=0; i<naliases; i++)
        {
            aliaslen = tvb_get_ntohs(tvb, offset);
            aliasname = tvb_get_ephemeral_string(tvb, offset + 2, aliaslen);

            alias_item = proto_tree_add_text(nba_resp_tree, tvb, offset, 2 + aliaslen, "Alias %s",aliasname);
            alias_tree = proto_item_add_subtree(alias_item, ett_adn_alias);

            proto_tree_add_item(alias_tree,
                                hf_adn_namelen,
                                tvb,
                                offset,
                                2,
                                FALSE);

            proto_tree_add_item(alias_tree,
                                hf_adn_aliasname,
                                tvb,
                                offset + 2,
                                aliaslen,
                                FALSE);

            offset+=(2 + aliaslen + 1);
        }
    }
}

static void dissect_getaddrsbyname_request(tvbuff_t* tvb, proto_tree* lwres_tree)
{
    guint16 namelen;

    proto_item* adn_request_item;
    proto_tree* adn_request_tree;

    namelen  = tvb_get_ntohs(tvb, LWRES_LWPACKET_LENGTH + 8);

    if(lwres_tree)
    {
        adn_request_item = proto_tree_add_text(lwres_tree,tvb,
                        LWRES_LWPACKET_LENGTH,10+namelen+1,
                        "getaddrbyname parameters");
        adn_request_tree = proto_item_add_subtree(adn_request_item, ett_adn_request);
    }
    else
        return;


    proto_tree_add_item(adn_request_tree,
                hf_adn_flags,
                tvb,
                LWRES_LWPACKET_LENGTH+0,
                sizeof(guint32),
                FALSE);

    proto_tree_add_item(adn_request_tree,
                hf_adn_addrtype,
                tvb,
                LWRES_LWPACKET_LENGTH+4,
                sizeof(guint32),
                FALSE);

    proto_tree_add_item(adn_request_tree,
                hf_adn_namelen,
                tvb,
                LWRES_LWPACKET_LENGTH+8,
                sizeof(guint16),
                FALSE);

    proto_tree_add_item(adn_request_tree,
                hf_adn_name,
                tvb,
                LWRES_LWPACKET_LENGTH+10,
                namelen,
                FALSE);

}


static void dissect_getaddrsbyname_response(tvbuff_t* tvb, proto_tree* lwres_tree)
{
    guint32 family ,i, offset;
    guint16 naliases, naddrs, realnamelen, length, aliaslen;
    const gchar* addrs;
    guint slen;
    gchar *aliasname;

    proto_item *adn_resp_item;
    proto_tree *adn_resp_tree;
    proto_item *alias_item;
    proto_tree *alias_tree;
    proto_item *addr_item;
    proto_tree *addr_tree;



    if(lwres_tree)
    {
        adn_resp_item = proto_tree_add_text(lwres_tree, tvb, LWRES_LWPACKET_LENGTH, 10, "getaddrbyname records");
        adn_resp_tree = proto_item_add_subtree(adn_resp_item, ett_adn_resp);
    }
    else return;

    naliases = tvb_get_ntohs(tvb, LWRES_LWPACKET_LENGTH + 4);
    naddrs   = tvb_get_ntohs(tvb, LWRES_LWPACKET_LENGTH + 6);
    realnamelen = tvb_get_ntohs(tvb, LWRES_LWPACKET_LENGTH + 8);


    proto_tree_add_item(adn_resp_tree, hf_adn_flags, tvb,
                LWRES_LWPACKET_LENGTH, 4, FALSE);

    proto_tree_add_item(adn_resp_tree, hf_adn_naliases, tvb,
                LWRES_LWPACKET_LENGTH + 4, 2, FALSE);

    proto_tree_add_item(adn_resp_tree, hf_adn_naddrs, tvb,
                LWRES_LWPACKET_LENGTH + 6, 2, FALSE);

    proto_tree_add_item(adn_resp_tree, hf_adn_namelen, tvb,
                LWRES_LWPACKET_LENGTH + 8, 2, FALSE);

    proto_tree_add_item(adn_resp_tree, hf_adn_realname, tvb,
                LWRES_LWPACKET_LENGTH + 10, realnamelen, FALSE);

    offset = LWRES_LWPACKET_LENGTH + 10 + realnamelen + 1;

    if(naliases)
    {
        for(i=0; i<naliases; i++)
        {
            aliaslen = tvb_get_ntohs(tvb, offset);
            aliasname = tvb_get_ephemeral_string(tvb, offset + 2, aliaslen);

            alias_item = proto_tree_add_text(adn_resp_tree, tvb, offset, 2 + aliaslen, "Alias %s",aliasname);
            alias_tree = proto_item_add_subtree(alias_item, ett_adn_alias);

            proto_tree_add_uint(alias_tree, hf_adn_namelen, tvb,
                        offset, 2, aliaslen);

            proto_tree_add_item(alias_tree, hf_adn_aliasname, tvb,
                        offset + 2, aliaslen, FALSE);

            offset+=(2 + aliaslen + 1);
        }
    }

    if(naddrs)
    {
        for(i=0; i < naddrs; i++)
        {
            family = tvb_get_ntohl(tvb, offset);
            length = tvb_get_ntohs(tvb, offset + 4);
            addrs = tvb_ip_to_str(tvb, offset + 6);
            slen = (int)strlen(addrs);

            addr_item = proto_tree_add_text(adn_resp_tree,tvb, offset, 4+2+4, "Address %s", addrs);
            addr_tree = proto_item_add_subtree(addr_item, ett_adn_addr);

            proto_tree_add_uint(addr_tree, hf_adn_family, tvb,
                        offset, 4, family);

            proto_tree_add_uint(addr_tree, hf_adn_addr_len, tvb,
                        offset + 4, 2, length);

            proto_tree_add_string(addr_tree, hf_adn_addr_addr, tvb,
                          offset + 6, slen, addrs);

            offset+= 4 + 2 + 4;
        }
    }


}

static void dissect_a_records(tvbuff_t* tvb, proto_tree* tree,guint32 nrec,int offset)
{
    guint32 i, curr;
    const gchar* addrs;
    guint16 len;
    proto_item* a_rec_item;
    proto_tree* a_rec_tree;
    proto_item* addr_item;
    proto_tree* addr_tree;

    if(tree)
    {
        a_rec_item = proto_tree_add_text(tree,tvb,offset,
                    ((sizeof(guint32) + sizeof(guint16)) * nrec),"A records");

        a_rec_tree = proto_item_add_subtree(a_rec_item, ett_a_rec);
    }
    else
        return;

    for(i=0; i<nrec; i++)
    {

        curr = offset + ((sizeof(guint32)+sizeof(guint16)) * i);

        len  = tvb_get_ntohs(tvb,curr);

        addrs = tvb_ip_to_str(tvb, curr+2);
        if(a_rec_tree)
        {
            addr_item = proto_tree_add_text(a_rec_tree, tvb, curr,
                            6, "Address %s", addrs);
            addr_tree = proto_item_add_subtree(addr_item, ett_a_rec_addr);
        }
        else return;

        proto_tree_add_uint(addr_tree, hf_a_rec_len, tvb, curr,
                    sizeof(guint16), len);

        proto_tree_add_text(addr_tree, tvb, curr + 2, 4, "Addr: %s",
                    addrs);

    }

}

static void dissect_srv_records(tvbuff_t* tvb, proto_tree* tree,guint32 nrec,int offset)
{
    guint32 i, curr;
    guint16 /*len, namelen,*/ priority, weight, port, dlen;
    const guchar *dname;

    proto_item* srv_rec_item, *rec_item;
    proto_item* srv_rec_tree, *rec_tree;

    if(tree)
    {
        srv_rec_item = proto_tree_add_text(tree, tvb, offset, offset, "SRV records");
        srv_rec_tree = proto_item_add_subtree(srv_rec_item, ett_srv_rec);
                   proto_item_set_text(srv_rec_item, "SRV records (%d)", nrec);
    }
    else return;

    curr = offset;

    for(i=0; i < nrec; i++)
    {
        /*len =      tvb_get_ntohs(tvb, curr);*/
        priority = tvb_get_ntohs(tvb, curr + 2);
        weight   = tvb_get_ntohs(tvb, curr + 4);
        port     = tvb_get_ntohs(tvb, curr + 6);
        /*namelen = len - 8;*/

        dlen = get_dns_name(tvb, curr + 8, 0, curr + 8, &dname);

        if(srv_rec_tree)
        {
            rec_item = proto_tree_add_text(srv_rec_tree, tvb, curr, 6,"  ");
            rec_tree = proto_item_add_subtree(rec_item, ett_srv_rec_item);
            proto_item_set_text(rec_item,
                        "SRV record:pri=%d,w=%d,port=%d,dname=%s",
                        priority,
                        weight,
                        port,
                        dname);
        }
        else return;

        proto_tree_add_uint(rec_tree,
                        hf_srv_prio,
                        tvb,
                        curr + 2,
                        2,
                        priority);

        proto_tree_add_uint(rec_tree,
                        hf_srv_weight,
                        tvb,
                        curr + 4,
                        2,
                        weight);

        proto_tree_add_uint(rec_tree,
                        hf_srv_port,
                        tvb,
                        curr + 6,
                        2,
                        port);


        proto_tree_add_text(rec_tree,
                            tvb,
                            curr + 8,
                            dlen,
                            "DNAME: %s", dname);

        curr+=((sizeof(short)*4) + dlen);

    }

}

static void dissect_mx_records(tvbuff_t* tvb, proto_tree* tree, guint32 nrec, int offset)
{

    guint i, curr;
    guint /*len, namelen,*/ priority, dlen;
    const guchar *dname;

    proto_item* mx_rec_item, *rec_item;
    proto_tree* mx_rec_tree, *rec_tree;


    if(tree)
    {
        mx_rec_item = proto_tree_add_text(tree, tvb, offset, offset, "MX records (%d)", nrec);
        mx_rec_tree = proto_item_add_subtree(mx_rec_item, ett_mx_rec);
    }
    else
        return;

    curr = offset;
    for(i=0; i < nrec; i++)
    {
        /*len =       tvb_get_ntohs(tvb, curr);*/
        priority =  tvb_get_ntohs(tvb, curr + 2);
        /*namelen  =  len - 4;*/

        dlen  = get_dns_name(tvb, curr + 4, 0, curr + 4, &dname);
        if(mx_rec_tree)
        {
            rec_item = proto_tree_add_text(mx_rec_tree, tvb, curr,6,"MX record: pri=%d,dname=%s",
                        priority,dname);
            rec_tree = proto_item_add_subtree(rec_item, ett_mx_rec_item);
        }
        else
            return;


        proto_tree_add_uint(rec_tree,
                            hf_srv_prio,
                            tvb,
                            curr + 2,
                            2,
                            priority);

        proto_tree_add_text(rec_tree,
                            tvb,
                            curr + 4,
                            dlen,
                            "name: %s", dname);

        curr+=((sizeof(short)*2) + dlen);


    }

}

static void dissect_ns_records(tvbuff_t* tvb, proto_tree* tree, guint32 nrec, int offset)
{
    guint i, curr;
    guint /*len, namelen,*/ dlen;
    const guchar *dname;

    proto_item* ns_rec_item, *rec_item;
    proto_tree* ns_rec_tree, *rec_tree;

    if(tree)
    {
        ns_rec_item = proto_tree_add_text(tree, tvb, offset, offset, "NS record (%d)", nrec);
        ns_rec_tree = proto_item_add_subtree(ns_rec_item, ett_ns_rec);
    }
    else
        return;
    curr=offset;

    for(i=0;i<nrec;i++)
    {
        /*len = tvb_get_ntohs(tvb, curr);*/
        /*namelen = len - 2;*/

        dlen = get_dns_name(tvb, curr + 2, 0, curr + 2, &dname);
        if(ns_rec_tree)
        {
            rec_item = proto_tree_add_text(ns_rec_tree, tvb, curr,4, "NS record: dname=%s",dname);
            rec_tree = proto_item_add_subtree(rec_item, ett_ns_rec_item);
        }
        else
            return;

        proto_tree_add_text(rec_tree,
                            tvb,
                            curr + 2,
                            dlen,
                            "Name: %s", dname);
        curr+=(sizeof(short) + dlen);

    }


}

static void dissect_rdata_request(tvbuff_t* tvb, proto_tree* lwres_tree)
{
    guint16 namelen;

    proto_item* rdata_request_item;
    proto_tree* rdata_request_tree;

    namelen = tvb_get_ntohs(tvb, LWRES_LWPACKET_LENGTH+8);

    if(lwres_tree)
    {
        rdata_request_item =
            proto_tree_add_text(lwres_tree,tvb,LWRES_LWPACKET_LENGTH,10+namelen+1,"RDATA request parameters");
        rdata_request_tree = proto_item_add_subtree(rdata_request_item, ett_rdata_req);
    }
    else
        return;

    proto_tree_add_item(rdata_request_tree,
            hf_rflags,
            tvb,
            LWRES_LWPACKET_LENGTH+0,
            sizeof(guint32),
            FALSE);

    proto_tree_add_item(rdata_request_tree,
            hf_rdclass,
            tvb,
            LWRES_LWPACKET_LENGTH+4,
            sizeof(guint16),
            FALSE);

    proto_tree_add_item(rdata_request_tree,
            hf_rdtype,
            tvb,
            LWRES_LWPACKET_LENGTH+6,
            sizeof(guint16),
            FALSE);

    proto_tree_add_item(rdata_request_tree,
            hf_namelen,
            tvb,
            LWRES_LWPACKET_LENGTH+8,
            sizeof(guint16),
            FALSE);

    proto_tree_add_item(rdata_request_tree,
            hf_req_name,
            tvb,
            LWRES_LWPACKET_LENGTH+10,
            namelen,
                FALSE);

}

static void dissect_rdata_response(tvbuff_t* tvb, proto_tree* lwres_tree)
{
    guint offset;
    guint rdtype, nrdatas, realnamelen;

    proto_item* rdata_resp_item;
    proto_tree* rdata_resp_tree;

    rdtype =  tvb_get_ntohs(tvb, LWRES_LWPACKET_LENGTH+6);
    nrdatas = tvb_get_ntohs(tvb, LWRES_LWPACKET_LENGTH+12);
    realnamelen = tvb_get_ntohs(tvb,LWRES_LWPACKET_LENGTH+16);

    offset = LWRES_LWPACKET_LENGTH + 18 + realnamelen + 1;

    if(lwres_tree)
    {
        rdata_resp_item = proto_tree_add_text(lwres_tree,tvb,LWRES_LWPACKET_LENGTH, 18+realnamelen+1,"RDATA response");
        rdata_resp_tree = proto_item_add_subtree(rdata_resp_item, ett_rdata_resp);
    }
    else
        return;

    proto_tree_add_item(rdata_resp_tree,
                        hf_rflags,
                        tvb,
                        LWRES_LWPACKET_LENGTH+0,
                        sizeof(guint32),
                        FALSE);

    proto_tree_add_item(rdata_resp_tree,
                        hf_rdclass,
                        tvb,
                        LWRES_LWPACKET_LENGTH+4,
                        sizeof(guint16),
                        FALSE);

    proto_tree_add_item(rdata_resp_tree,
                        hf_rdtype,
                        tvb,
                        LWRES_LWPACKET_LENGTH+6,
                        sizeof(guint16),
                        FALSE);

    proto_tree_add_item(rdata_resp_tree,
            hf_ttl,
            tvb,
            LWRES_LWPACKET_LENGTH+8,
            sizeof(guint32),
            FALSE);

    proto_tree_add_item(rdata_resp_tree,
            hf_nrdatas,
            tvb,
            LWRES_LWPACKET_LENGTH+12,
            sizeof(guint16),
            FALSE);

    proto_tree_add_item(rdata_resp_tree,
            hf_nsigs,
            tvb,
            LWRES_LWPACKET_LENGTH+14,
            sizeof(guint16),
            FALSE);

    proto_tree_add_item(rdata_resp_tree,
            hf_realnamelen,
            tvb,
            LWRES_LWPACKET_LENGTH+16,
            sizeof(guint16),
            FALSE);

    proto_tree_add_item(rdata_resp_tree,
                        hf_realname,
                        tvb,
                        LWRES_LWPACKET_LENGTH+18,
                        realnamelen,
                FALSE);

    switch(rdtype)
    {
        case T_A:
            dissect_a_records(tvb,rdata_resp_tree,nrdatas,offset);
        break;

        case T_SRV:
            dissect_srv_records(tvb,rdata_resp_tree,nrdatas, offset);
        break;

        case T_MX:
            dissect_mx_records(tvb,rdata_resp_tree,nrdatas, offset);
        break;

        case T_NS:
            dissect_ns_records(tvb,rdata_resp_tree,nrdatas, offset);
        break;
    }

}

static void dissect_noop(tvbuff_t* tvb, proto_tree* lwres_tree)
{
    guint16 datalen;

    proto_item* noop_item;
    proto_tree* noop_tree;

    datalen = tvb_get_ntohs(tvb, LWRES_LWPACKET_LENGTH);

    if(lwres_tree)
    {
        noop_item = proto_tree_add_text(lwres_tree, tvb, LWRES_LWPACKET_LENGTH, 10, "Noop record");
        noop_tree = proto_item_add_subtree(noop_item, ett_noop);
    }
    else
        return;

    proto_tree_add_uint(noop_tree, hf_length, tvb,
                LWRES_LWPACKET_LENGTH, sizeof(guint16), datalen);

    tvb_ensure_bytes_exist(tvb, LWRES_LWPACKET_LENGTH, datalen);

}

static void dissect_getaddrsbyname(tvbuff_t* tvb, proto_tree* lwres_tree, int type)
{
    if(type == 1)
        dissect_getaddrsbyname_request(tvb, lwres_tree);
    else
        dissect_getaddrsbyname_response(tvb, lwres_tree);
}

static void dissect_getnamebyaddr(tvbuff_t* tvb, proto_tree* lwres_tree, int type)
{
    if(type == 1)
        dissect_getnamebyaddr_request(tvb, lwres_tree);
    else
        dissect_getnamebyaddr_response(tvb, lwres_tree);
}

static void dissect_getrdatabyname(tvbuff_t* tvb, proto_tree* lwres_tree, int type)
{
    if(type == 1)
        dissect_rdata_request(tvb, lwres_tree);
    else
        dissect_rdata_response(tvb, lwres_tree);
}

static void
dissect_lwres(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint16 version, flags, authtype, authlength ;
    guint32 length, opcode, result, recvlength, serial;
    guint32 message_type;

    proto_item* lwres_item;
    proto_tree* lwres_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "lw_res");
    length = tvb_get_ntohl(tvb, LW_LENGTH_OFFSET);
    version = tvb_get_ntohs(tvb, LW_VERSION_OFFSET);
    flags = tvb_get_ntohs(tvb, LW_PKTFLASG_OFFSET);
    serial = tvb_get_ntohl(tvb, LW_SERIAL_OFFSET);
    opcode = tvb_get_ntohl(tvb,LW_OPCODE_OFFSET);
    result = tvb_get_ntohl(tvb, LW_RESULT_OFFSET);
    recvlength = tvb_get_ntohl(tvb, LW_RECVLEN_OFFSET);
    authtype = tvb_get_ntohs(tvb, LW_AUTHTYPE_OFFSET);
    authlength = tvb_get_ntohs(tvb, LW_AUTHLEN_OFFSET);

    message_type = (flags & LWRES_LWPACKETFLAG_RESPONSE) ? 2 : 1;

    if (check_col(pinfo->cinfo, COL_INFO)) {
            col_clear(pinfo->cinfo, COL_INFO);

        if(flags & LWRES_LWPACKETFLAG_RESPONSE)
        {
                col_add_fstr(pinfo->cinfo, COL_INFO,
                    "%s, opcode=%s, serial=0x%x, result=%s",
                        val_to_str((guint32)message_type,message_types_values,"unknown"),
                        val_to_str(opcode, opcode_values, "unknown"),
                        serial,
                        val_to_str(result,result_values,"unknown"));
            }
        else
        {
                col_add_fstr(pinfo->cinfo, COL_INFO,
                        "%s, opcode=%s, serial=0x%x",
                        val_to_str((guint32)message_type,message_types_values,"unknown"),
                        val_to_str(opcode, opcode_values, "unknown"),
                serial);
        }
    }

    if(tree)
    {
        lwres_item = proto_tree_add_item(tree,proto_lwres, tvb,0, -1, FALSE);
        lwres_tree = proto_item_add_subtree(lwres_item, ett_lwres);
    }
    else return;


    proto_tree_add_uint(lwres_tree,
            hf_length,
            tvb,
            LW_LENGTH_OFFSET,
            sizeof(guint32),
            length);


    proto_tree_add_uint(lwres_tree,
                hf_version,
                tvb,
                LW_VERSION_OFFSET,
                sizeof(guint16),
                version);




    proto_tree_add_uint(lwres_tree,
                hf_flags,
                tvb,
                LW_PKTFLASG_OFFSET,
                sizeof(guint16),
                flags);

    proto_tree_add_uint(lwres_tree,
                hf_serial,
                tvb,
                LW_SERIAL_OFFSET,
                sizeof(guint32),
                serial);

    proto_tree_add_uint(lwres_tree,
                hf_opcode,
                tvb,
                LW_OPCODE_OFFSET,
                sizeof(guint32),
                opcode);

    proto_tree_add_uint(lwres_tree,
                hf_result,
                tvb,
                LW_RESULT_OFFSET,
                sizeof(guint32),
                result);

    proto_tree_add_uint(lwres_tree,
                hf_recvlen,
                tvb,
                LW_RECVLEN_OFFSET,
                sizeof(guint32),
                recvlength);

    proto_tree_add_uint(lwres_tree,
                hf_authtype,
                tvb,
                LW_AUTHTYPE_OFFSET,
                sizeof(guint16),
                authtype);

    proto_tree_add_uint(lwres_tree,
                hf_authlen,
                tvb,
                LW_AUTHLEN_OFFSET,
                sizeof(guint16),
                authlength);

    if(!result)
    {
        switch(opcode)
        {
            case LWRES_OPCODE_NOOP:
                dissect_noop(tvb, lwres_tree);
            break;

            case LWRES_OPCODE_GETADDRSBYNAME:
                dissect_getaddrsbyname(tvb, lwres_tree, message_type);
            break;

            case LWRES_OPCODE_GETNAMEBYADDR:
                dissect_getnamebyaddr(tvb, lwres_tree, message_type);
            break;

            case LWRES_OPCODE_GETRDATABYNAME:
                dissect_getrdatabyname(tvb, lwres_tree, message_type);
            break;
        }
    }
}


void
proto_register_lwres(void)
{
    static hf_register_info hf[] = {
        { &hf_length,
          { "Length", "lwres.length", FT_UINT32, BASE_DEC, NULL, 0x0,
            "lwres length", HFILL }},

        { &hf_version,
          { "Version", "lwres.version", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres version", HFILL }},

        { &hf_flags,
          { "Packet Flags", "lwres.flags", FT_UINT16, BASE_HEX, NULL, 0x0,
            "lwres flags", HFILL }},

        { &hf_serial,
          { "Serial", "lwres.serial", FT_UINT32, BASE_HEX, NULL, 0x0,
            "lwres serial", HFILL }},

        { &hf_opcode,
          { "Operation code", "lwres.opcode", FT_UINT32, BASE_DEC, VALS(opcode_values), 0x0,
            "lwres opcode", HFILL }},

        { &hf_result,
          { "Result", "lwres.result", FT_UINT32, BASE_DEC, VALS(result_values), 0x0,
            "lwres result", HFILL }},

        { &hf_recvlen,
          { "Received length", "lwres.recvlen", FT_UINT32, BASE_DEC, NULL, 0x0,
            "lwres recvlen", HFILL }},

        { &hf_authtype,
          { "Auth. type", "lwres.authtype", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres authtype", HFILL }},

        { &hf_authlen,
          { "Auth. length", "lwres.authlen", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres authlen", HFILL }},

        { &hf_rflags,
          { "Flags", "lwres.rflags", FT_UINT32, BASE_HEX, NULL, 0x0,
            "lwres rflags", HFILL }},
        { &hf_rdclass,
          { "Class", "lwres.class", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres class", HFILL }},

        { &hf_rdtype,
          { "Type", "lwres.type", FT_UINT16, BASE_DEC, VALS(t_types), 0x0,
            "lwres type", HFILL }},

        { &hf_namelen,
          { "Name length", "lwres.namelen", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres namelen", HFILL }},

        { &hf_req_name,
          { "Domain name", "lwres.reqdname", FT_STRING, BASE_NONE, NULL, 0x0,
            "lwres reqdname", HFILL }},

        { &hf_ttl,
          { "Time To Live", "lwres.ttl", FT_UINT32, BASE_DEC, NULL, 0x0,
            "lwres ttl", HFILL }},

        { &hf_nrdatas,
          { "Number of rdata records", "lwres.nrdatas", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres nrdatas", HFILL }},

        { &hf_nsigs,
          { "Number of signature records", "lwres.nsigs", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres nsigs", HFILL }},

        { &hf_realnamelen,
          { "Real name length", "lwres.realnamelen", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres realnamelen", HFILL }},

        { &hf_realname,
          { "Real doname name", "lwres.realname", FT_STRING, BASE_NONE, NULL, 0x0,
            "lwres realname", HFILL }},

        { &hf_a_record,
          { "IPv4 Address", "lwres.arecord", FT_UINT32, BASE_DEC, NULL, 0x0,
            "lwres arecord", HFILL }},

        { &hf_a_rec_len,
          { "Length", "lwres.areclen", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres areclen", HFILL }},

        { &hf_srv_prio,
          { "Priority", "lwres.srv.priority", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres srv prio", HFILL }},

        { &hf_srv_weight,
          { "Weight", "lwres.srv.weight", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres srv weight", HFILL }},

        { &hf_srv_port,
          { "Port" , "lwres.srv.port", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres srv port", HFILL }},

        { &hf_adn_flags,
          { "Flags", "lwres.adn.flags", FT_UINT32, BASE_HEX, NULL, 0x0,
            "lwres adn flags", HFILL }},

        { &hf_adn_addrtype,
          { "Address type", "lwres.adn.addrtype", FT_UINT32, BASE_DEC, NULL, 0x0,
            "lwres adn addrtype", HFILL }},

        { &hf_adn_namelen,
          { "Name length", "lwres.adn.namelen", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres adn namelen", HFILL }},

        { &hf_adn_name,
          { "Name", "lwres.adn.name", FT_STRING, BASE_NONE, NULL, 0x0,
            "lwres adn name", HFILL }},

        { &hf_adn_naliases,
          { "Number of aliases", "lwres.adn.naliases", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres adn naliases", HFILL }},

        { &hf_adn_naddrs,
          { "Number of addresses", "lwres.adn.naddrs", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres adn naddrs", HFILL }},

        { &hf_adn_realname,
          { "Real name", "lwres.adn.realname", FT_STRING, BASE_NONE, NULL, 0x0,
            "lwres adn realname", HFILL }},

        { &hf_adn_aliasname,
          { "Alias name", "lwres.adn.aliasname", FT_STRING, BASE_NONE, NULL, 0x0,
            "lwres adn aliasname", HFILL }},

        { &hf_adn_family,
          { "Address family", "lwres.adn.addr.family", FT_UINT32, BASE_DEC, NULL, 0x0,
            "lwres adn addr family", HFILL }},

        { &hf_adn_addr_len,
          { "Address length", "lwres.adn.addr.length", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres adn addr length", HFILL }},

        { &hf_adn_addr_addr,
          { "IP Address", "lwres.adn.addr.addr", FT_STRING, BASE_NONE, NULL, 0x0,
            "lwres adn addr addr", HFILL }},

        /* Add more fields here */
    };

    static gint *ett[] = {
        &ett_lwres,
        &ett_rdata_req,
        &ett_rdata_resp,
        &ett_a_rec,
        &ett_a_rec_addr,
        &ett_srv_rec,
        &ett_srv_rec_item,
        &ett_adn_request,
        &ett_adn_resp,
        &ett_adn_alias,
        &ett_adn_addr,
        &ett_nba_request,
        &ett_nba_resp,
        &ett_mx_rec,
        &ett_mx_rec_item,
        &ett_ns_rec,
        &ett_ns_rec_item,
        &ett_noop,
    };


    module_t *lwres_module;

    proto_lwres = proto_register_protocol("Light Weight DNS RESolver (BIND9)",
                                          "LWRES", "lwres");

    proto_register_field_array(proto_lwres, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    lwres_module = prefs_register_protocol(proto_lwres, proto_reg_handoff_lwres);

    prefs_register_uint_preference(lwres_module, "udp.lwres_port",
                                   "lwres listener UDP Port",
                                   "Set the UDP port for lwres daemon"
                                   "(if other than the default of 921)",
                                   10, &global_lwres_port);

}

/* The registration hand-off routine */
void
proto_reg_handoff_lwres(void)
{
    static gboolean lwres_prefs_initialized = FALSE;
    static dissector_handle_t lwres_handle;
    static guint lwres_port;

    if(!lwres_prefs_initialized) {
        lwres_handle = create_dissector_handle(dissect_lwres, proto_lwres);
        lwres_prefs_initialized = TRUE;
    }
    else {
        dissector_delete_uint("udp.port", lwres_port, lwres_handle);
    }

    dissector_add_uint("udp.port", global_lwres_port, lwres_handle);
    lwres_port = global_lwres_port;

}
