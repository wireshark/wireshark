/* packet-ospf.c
 * Routines for OSPF packet disassembly
 * (c) Copyright Hannes R. Boehm <hannes@boehm.org>
 *
 * $Id: packet-ospf.c,v 1.21 2000/03/14 06:03:23 guy Exp $
 *
 * At this time, this module is able to analyze OSPF
 * packets as specified in RFC2328. MOSPF (RFC1584) and other
 * OSPF Extensions which introduce new Packet types
 * (e.g the External Atributes LSA) are not supported.
 *
 * TOS - support is not fully implemented
 * 
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 * 
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
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <stdio.h>
#include <string.h>

#include <glib.h>
#include "packet.h"
#include "packet-ospf.h"
#include "ieee-float.h"

static int proto_ospf = -1;

static gint ett_ospf = -1;
static gint ett_ospf_hdr = -1;
static gint ett_ospf_hello = -1;
static gint ett_ospf_desc = -1;
static gint ett_ospf_lsr = -1;
static gint ett_ospf_lsa = -1;
static gint ett_ospf_lsa_upd = -1;

/* Trees for opaque LSAs */
static gint ett_ospf_lsa_mpls = -1;
static gint ett_ospf_lsa_mpls_router = -1;
static gint ett_ospf_lsa_mpls_link = -1;
static gint ett_ospf_lsa_mpls_link_stlv = -1;

void 
dissect_ospf(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
    e_ospfhdr ospfh;
    e_ospf_crypto *crypto;
    int i, saved_len, ospflen;

    proto_tree *ospf_tree = NULL;
	proto_item *ti; 
    proto_tree *ospf_header_tree;
    char auth_data[(2 * 16) + 1]="";
    char *packet_type;
    static value_string pt_vals[] = { {OSPF_HELLO,   "Hello Packet"   },
                                      {OSPF_DB_DESC, "DB Descr."      },
                                      {OSPF_LS_REQ,  "LS Request"     },
                                      {OSPF_LS_UPD,  "LS Update"      },
                                      {OSPF_LS_ACK,  "LS Acknowledge" },
                                      {0,             NULL            } };

    memcpy(&ospfh, &pd[offset], sizeof(e_ospfhdr));

    packet_type = match_strval(ospfh.packet_type, pt_vals);
    if (check_col(fd, COL_PROTOCOL))
        col_add_str(fd, COL_PROTOCOL, "OSPF");
    if (check_col(fd, COL_INFO)) {
        if (packet_type != NULL)
            col_add_str(fd, COL_INFO, packet_type); 
        else
            col_add_fstr(fd, COL_INFO, "Unknown (%d)", ospfh.packet_type); 
    }  

    if (tree) {
	ti = proto_tree_add_item(tree, proto_ospf, offset, ntohs(ospfh.length), NULL);
	ospf_tree = proto_item_add_subtree(ti, ett_ospf);

	ti = proto_tree_add_text(ospf_tree, offset, OSPF_HEADER_LENGTH, "OSPF Header"); 
	ospf_header_tree = proto_item_add_subtree(ti, ett_ospf_hdr);

        proto_tree_add_text(ospf_header_tree, offset, 1, "OSPF Version: %d", ospfh.version);  
	proto_tree_add_text(ospf_header_tree, offset + 1 , 1, "OSPF Packet Type: %d (%s)", 
	                                                   ospfh.packet_type,
							   (packet_type != NULL ?
							     packet_type :
							     "Unknown"));
	proto_tree_add_text(ospf_header_tree, offset + 2 , 2, "Packet Length: %d", 
	                                                   ntohs(ospfh.length));
	proto_tree_add_text(ospf_header_tree, offset + 4 , 4, "Source OSPF Router ID: %s", 

	                                                   ip_to_str((guint8 *) &(ospfh.routerid)));
	if (!(ospfh.area)) {
	   proto_tree_add_text(ospf_header_tree, offset + 8 , 4, "Area ID: Backbone");
	} else {
	   proto_tree_add_text(ospf_header_tree, offset + 8 , 4, "Area ID: %s", ip_to_str((guint8 *) &(ospfh.area)));
	}
	proto_tree_add_text(ospf_header_tree, offset + 12 , 2, "Packet Checksum: 0x%x",
	      ntohs(ospfh.checksum));
	switch( ntohs(ospfh.auth_type) ) {
	    case OSPF_AUTH_NONE:
	         proto_tree_add_text(ospf_header_tree, offset + 14 , 2, "Auth Type: none");
	         proto_tree_add_text(ospf_header_tree, offset + 16 , 8, "Auth Data (none)");
		 break;
	    case OSPF_AUTH_SIMPLE:
	         proto_tree_add_text(ospf_header_tree, offset + 14 , 2, "Auth Type: simple");
                 strncpy(auth_data, (char *) &ospfh.auth_data, 8);
	         proto_tree_add_text(ospf_header_tree, offset + 16 , 8, "Auth Data: %s", auth_data);
		 break;
	    case OSPF_AUTH_CRYPT:
                 crypto = (e_ospf_crypto *)ospfh.auth_data;
	         proto_tree_add_text(ospf_header_tree, offset + 14 , 2, "Auth Type: crypt");
                 proto_tree_add_text(ospf_header_tree, offset + 18 , 1, "Auth Key ID: %d",
                                     crypto->key_id);
                 proto_tree_add_text(ospf_header_tree, offset + 19 , 1, "Auth Data Length: %d",
                                     crypto->length);
                 proto_tree_add_text(ospf_header_tree, offset + 20 , 4, "Auth Crypto Sequence Number: 0x%lx",
                                 (unsigned long)ntohl(crypto->sequence_num));
  
                 ospflen = ntohs(ospfh.length);
                 for (i = 0; i < crypto->length && i < (sizeof(auth_data)/2); i++)
                     sprintf(&auth_data[i*2],"%02x",pd[offset + ospflen + i]);
                 proto_tree_add_text(ospf_header_tree, offset + ospflen , 16, "Auth Data: %s", auth_data);
		 break;
            default:
	         proto_tree_add_text(ospf_header_tree, offset + 14 , 2, "Auth Type (unknown)");
	         proto_tree_add_text(ospf_header_tree, offset + 16 , 8, "Auth Data (unknown)");
	}

    }

    /* Temporarily adjust the captured length to match the size of the OSPF
     * packet (since the dissect routines use it to work out where the end of
     * the ospf packet is).
     */
    saved_len = pi.captured_len;
    if (BYTES_ARE_IN_FRAME(offset, ntohs(ospfh.length))) {
      pi.captured_len = offset + ntohs(ospfh.length);
    }

    /*  Skip over header */
    offset += OSPF_HEADER_LENGTH;

    switch(ospfh.packet_type){
	case OSPF_HELLO:
	    dissect_ospf_hello(pd, offset, fd, ospf_tree); 
	    break;
	case OSPF_DB_DESC:
	    dissect_ospf_db_desc(pd, offset, fd, ospf_tree);   
	    break;
	case OSPF_LS_REQ:
	    dissect_ospf_ls_req(pd, offset, fd, ospf_tree);   
	    break;
	case OSPF_LS_UPD:
	    dissect_ospf_ls_upd(pd, offset, fd, ospf_tree);
	    break;
	case OSPF_LS_ACK:
	    dissect_ospf_ls_ack(pd, offset, fd, ospf_tree);
	    break;
	default:
            pi.captured_len = saved_len;
            dissect_data(pd, offset, fd, tree); 
    }
    pi.captured_len = saved_len;
}

void
dissect_ospf_hello(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
    e_ospf_hello ospfhello;
    guint32 *ospfneighbor;
    char options[20]="";
    int options_offset;

    proto_tree *ospf_hello_tree;
	proto_item *ti; 

    memcpy(&ospfhello, &pd[offset], sizeof(e_ospf_hello));

    if (tree) {
	ti = proto_tree_add_text(tree, offset, END_OF_FRAME, "OSPF Hello Packet"); 
	ospf_hello_tree = proto_item_add_subtree(ti, ett_ospf_hello);


	proto_tree_add_text(ospf_hello_tree, offset , 4, "Network Mask: %s",  ip_to_str((guint8 *) &ospfhello.network_mask));
	proto_tree_add_text(ospf_hello_tree, offset + 4, 2, "Hello Interval: %d seconds",  ntohs(ospfhello.hellointervall));

	/* ATTENTION !!! no check for length of options string */
	options_offset=0;
	if(( ospfhello.options & OSPF_OPTIONS_E ) == OSPF_OPTIONS_E){
	    strcpy( (char *)(options + options_offset), "E");
	    options_offset+=1;
	}
	if(( ospfhello.options & OSPF_OPTIONS_MC ) == OSPF_OPTIONS_MC){
	    strcpy((char *) (options + options_offset), "/MC");
	    options_offset+=3;
	}
	if(( ospfhello.options & OSPF_OPTIONS_NP ) == OSPF_OPTIONS_NP){
	    strcpy((char *) (options + options_offset), "/NP");
	    options_offset+=3;
	}
	if(( ospfhello.options & OSPF_OPTIONS_EA ) == OSPF_OPTIONS_EA){
	    strcpy((char *) (options + options_offset) , "/EA");
	    options_offset+=3;
	}
	if(( ospfhello.options & OSPF_OPTIONS_DC ) == OSPF_OPTIONS_DC){
	    strcpy((char *) (options + options_offset) , "/DC");
	    options_offset+=3;
	}

	proto_tree_add_text(ospf_hello_tree, offset + 6, 1, "Options: %d (%s)",  ospfhello.options, options);
	proto_tree_add_text(ospf_hello_tree, offset + 7, 1, "Router Priority: %d",  ospfhello.priority);
	proto_tree_add_text(ospf_hello_tree, offset + 8, 4, "Router Dead Interval: %ld seconds",  (long)ntohl(ospfhello.dead_interval));
	proto_tree_add_text(ospf_hello_tree, offset + 12, 4, "Designated Router: %s",  ip_to_str((guint8 *) &ospfhello.drouter));
	proto_tree_add_text(ospf_hello_tree, offset + 16, 4, "Backup Designated Router: %s",  ip_to_str((guint8 *) &ospfhello.bdrouter));


	offset+=20;
	while(((int)(pi.captured_len - offset)) >= 4){
	    ospfneighbor=(guint32 *) &pd[offset];
	    proto_tree_add_text(ospf_hello_tree, offset, 4, "Active Neighbor: %s",  ip_to_str((guint8 *) ospfneighbor));
	    offset+=4;
	}
    }
}

void
dissect_ospf_db_desc(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
    e_ospf_dbd ospf_dbd;
    char options[20]="";
    int options_offset;
    char flags[20]="";
    int flags_offset;

    proto_tree *ospf_db_desc_tree=NULL;
	proto_item *ti; 

    memcpy(&ospf_dbd, &pd[offset], sizeof(e_ospf_dbd));

    if (tree) {
	ti = proto_tree_add_text(tree, offset, END_OF_FRAME, "OSPF DB Description"); 
	ospf_db_desc_tree = proto_item_add_subtree(ti, ett_ospf_desc);

	proto_tree_add_text(ospf_db_desc_tree, offset, 2, "Interface MTU: %d", ntohs(ospf_dbd.interface_mtu) );


	options_offset=0;
	if(( ospf_dbd.options & OSPF_OPTIONS_E ) == OSPF_OPTIONS_E){
	    strcpy( (char *)(options + options_offset), "_E_");
	    options_offset+=1;
	}
	if(( ospf_dbd.options & OSPF_OPTIONS_MC ) == OSPF_OPTIONS_MC){
	    strcpy((char *) (options + options_offset), "_MC_");
	    options_offset+=3;
	}
	if(( ospf_dbd.options & OSPF_OPTIONS_NP ) == OSPF_OPTIONS_NP){
	    strcpy((char *) (options + options_offset), "_NP_");
	    options_offset+=3;
	}
	if(( ospf_dbd.options & OSPF_OPTIONS_EA ) == OSPF_OPTIONS_EA){
	    strcpy((char *) (options + options_offset) , "_EA_");
	    options_offset+=3;
	}
	if(( ospf_dbd.options & OSPF_OPTIONS_DC ) == OSPF_OPTIONS_DC){
	    strcpy((char *) (options + options_offset) , "_DC_");
	    options_offset+=3;
	}

	proto_tree_add_text(ospf_db_desc_tree, offset + 2 , 1, "Options: %d (%s)", ospf_dbd.options, options );


	flags_offset=0;
	if(( ospf_dbd.flags & OSPF_DBD_FLAG_MS ) == OSPF_DBD_FLAG_MS){
	    strcpy( (char *)(flags + flags_offset), "_I_");
	    flags_offset+=1;
	}
	if(( ospf_dbd.flags & OSPF_DBD_FLAG_M ) == OSPF_DBD_FLAG_M){
	    strcpy((char *) (flags + flags_offset), "_M_");
	    flags_offset+=3;
	}
	if(( ospf_dbd.flags & OSPF_DBD_FLAG_I ) == OSPF_DBD_FLAG_I){
	    strcpy((char *) (flags + flags_offset), "_I_");
	    flags_offset+=3;
	}

	proto_tree_add_text(ospf_db_desc_tree, offset + 3 , 1, "Flags: %d (%s)", ospf_dbd.flags, flags );
	proto_tree_add_text(ospf_db_desc_tree, offset + 4 , 4, "DD Sequence: %ld", (long)ntohl(ospf_dbd.dd_sequence) );
    }
    /* LS Headers will be processed here */
    /* skip to the end of DB-Desc header */
    offset+=8;
    while( ((int) (pi.captured_len - offset)) >= OSPF_LSA_HEADER_LENGTH ) {
       dissect_ospf_lsa(pd, offset, fd, tree, FALSE);
       offset+=OSPF_LSA_HEADER_LENGTH;
    }
}

void
dissect_ospf_ls_req(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
    e_ospf_ls_req ospf_lsr;

    proto_tree *ospf_lsr_tree;
	proto_item *ti; 


    /* zero or more LS requests may be within a LS Request */
    /* we place every request for a LSA in a single subtree */
    if (tree) {
	while( ((int) (pi.captured_len - offset)) >= OSPF_LS_REQ_LENGTH ){
             memcpy(&ospf_lsr, &pd[offset], sizeof(e_ospf_ls_req));
	     ti = proto_tree_add_text(tree, offset, OSPF_LS_REQ_LENGTH, "Link State Request"); 
	     ospf_lsr_tree = proto_item_add_subtree(ti, ett_ospf_lsr);

	     switch( ntohl( ospf_lsr.ls_type ) ){
		 case OSPF_LSTYPE_ROUTER:
	             proto_tree_add_text(ospf_lsr_tree, offset, 4, "LS Type: Router-LSA (%ld)", 
	                               (long)ntohl( ospf_lsr.ls_type ) );
		     break;
		 case OSPF_LSTYPE_NETWORK:
	             proto_tree_add_text(ospf_lsr_tree, offset, 4, "LS Type: Network-LSA (%ld)", 
	                               (long)ntohl( ospf_lsr.ls_type ) );
		     break;
		 case OSPF_LSTYPE_SUMMERY:
	             proto_tree_add_text(ospf_lsr_tree, offset, 4, "LS Type: Summary-LSA (IP network) (%ld)", 
	                               (long)ntohl( ospf_lsr.ls_type ) );
		     break;
		 case OSPF_LSTYPE_ASBR:
	             proto_tree_add_text(ospf_lsr_tree, offset, 4, "LS Type: Summary-LSA (ASBR) (%ld)", 
	                               (long)ntohl( ospf_lsr.ls_type ) );
		     break;
		 case OSPF_LSTYPE_ASEXT:
	             proto_tree_add_text(ospf_lsr_tree, offset, 4, "LS Type: AS-External-LSA (ASBR) (%ld)", 
	                               (long)ntohl( ospf_lsr.ls_type ) );
		     break;
		 default:
	             proto_tree_add_text(ospf_lsr_tree, offset, 4, "LS Type: %ld (unknown)", 
	                               (long)ntohl( ospf_lsr.ls_type ) );
	     }

             proto_tree_add_text(ospf_lsr_tree, offset + 4, 4, "Link State ID : %s", 
	                                 ip_to_str((guint8 *) &(ospf_lsr.ls_id)));
             proto_tree_add_text(ospf_lsr_tree, offset + 8, 4, "Advertising Router : %s", 
	                                 ip_to_str((guint8 *) &(ospf_lsr.adv_router)));

	     offset+=12;
	}
    }
}
void
dissect_ospf_ls_upd(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
    e_ospf_lsa_upd_hdr upd_hdr;
    guint32 lsa_counter; 

    proto_tree *ospf_lsa_upd_tree=NULL;
	proto_item *ti; 

    memcpy(&upd_hdr, &pd[offset], sizeof(e_ospf_lsa_upd_hdr));

    if (tree) {
	ti = proto_tree_add_text(tree, offset, END_OF_FRAME, "LS Update Packet"); 
	ospf_lsa_upd_tree = proto_item_add_subtree(ti, ett_ospf_lsa_upd);

	proto_tree_add_text(ospf_lsa_upd_tree, offset, 4, "Nr oF LSAs: %ld", (long)ntohl(upd_hdr.lsa_nr) );
    }
    /* skip to the beginning of the first LSA */
    offset+=4; /* the LS Upd PAcket contains only a 32 bit #LSAs field */
    
    lsa_counter = 0;
    while(lsa_counter < ntohl(upd_hdr.lsa_nr)){
        offset+=dissect_ospf_lsa(pd, offset, fd, ospf_lsa_upd_tree, TRUE);
        lsa_counter += 1;
    }
}

void
dissect_ospf_ls_ack(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

    /* the body of a LS Ack packet simply contains zero or more LSA Headers */
    while( ((int)(pi.captured_len - offset)) >= OSPF_LSA_HEADER_LENGTH ) {
       dissect_ospf_lsa(pd, offset, fd, tree, FALSE);
       offset+=OSPF_LSA_HEADER_LENGTH;
    }

}

/*
 * Returns if an LSA is opaque, i.e. requires special treatment 
 */
int is_opaque(int lsa_type)
{
    return (lsa_type >= 9 && lsa_type <= 11);
}

/* MPLS/TE TLV types */
#define MPLS_TLV_ROUTER    1
#define MPLS_TLV_LINK      2

/* MPLS/TE Link STLV types */
enum {
    MPLS_LINK_TYPE       = 1,
    MPLS_LINK_ID,
    MPLS_LINK_LOCAL_IF,
    MPLS_LINK_REMOTE_IF,
    MPLS_LINK_TE_METRIC,
    MPLS_LINK_MAX_BW,
    MPLS_LINK_MAX_RES_BW,
    MPLS_LINK_UNRES_BW,
    MPLS_LINK_COLOR,
};

static value_string mpls_link_stlv_str[] = {
    {MPLS_LINK_TYPE, "Link Type"},
    {MPLS_LINK_ID, "Link ID"},
    {MPLS_LINK_LOCAL_IF, "Local Interface IP Address"},
    {MPLS_LINK_REMOTE_IF, "Remote Interface IP Address"},
    {MPLS_LINK_TE_METRIC, "Traffic Engineering Metric"},
    {MPLS_LINK_MAX_BW, "Maximum Bandwidth"},
    {MPLS_LINK_MAX_RES_BW, "Maximum Reservable Bandwidth"},
    {MPLS_LINK_UNRES_BW, "Unreserved Bandwidth"},
    {MPLS_LINK_COLOR, "Resource Class/Color"},
};

/* 
 * Dissect MPLS/TE opaque LSA 
 */

void dissect_ospf_lsa_mpls(const u_char *pd, 
			  int offset, 
			  frame_data *fd, 
			  proto_tree *tree,
			  e_ospf_lsa_hdr *lsa_hdr) {
    proto_item *ti; 
    proto_tree *mpls_tree;
    proto_tree *tlv_tree;
    proto_tree *stlv_tree;

    int length;
    int tlv_type;
    int tlv_length;

    int link_len;
    int stlv_type, stlv_len;
    char *stlv_name;
    int i;

    ti = proto_tree_add_text(tree, offset, ntohs(lsa_hdr->length) - 20,
			     "MPLS Traffic Engineering LSA");
    mpls_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls);

    for (length = 0; length < ntohs(lsa_hdr->length) - 20; length += 4) {
	tlv_type = pntohs(pd+offset+length);
	tlv_length = pntohs(pd+offset+length + 2);

	switch(tlv_type) {
	case MPLS_TLV_ROUTER:
	    ti = proto_tree_add_text(mpls_tree, offset+length, tlv_length+4, 
				     "Router Address: %s", 
				     ip_to_str((pd+offset+length+4)));
	    tlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_router);
	    proto_tree_add_text(tlv_tree, offset+length, 2, "TLV Type: 1 - Router Address");
	    proto_tree_add_text(tlv_tree, offset+length+2, 2, "TLV Length: %d", tlv_length);
	    proto_tree_add_text(tlv_tree, offset+length+4, 4, "Router Address: %s", 
				ip_to_str((pd+offset+length+4)));
	    break;
	case MPLS_TLV_LINK:
	    ti = proto_tree_add_text(mpls_tree, offset+length, tlv_length+4, 
				     "Link Information");
	    tlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link);
	    proto_tree_add_text(tlv_tree, offset+length, 2, "TLV Type: 2 - Link Information");
	    proto_tree_add_text(tlv_tree, offset+length+2, 2, "TLV Length: %d", tlv_length);

	    /* Walk down the sub-TLVs for link information */
	    for (link_len = length + 4; link_len < length + 4 + tlv_length; link_len += 4) {
		stlv_type = pntohs(pd+offset+link_len);
		stlv_len = pntohs(pd+offset+link_len + 2);
		stlv_name = val_to_str(stlv_type, mpls_link_stlv_str, "Unknown sub-TLV");
		switch(stlv_type) {

		case MPLS_LINK_TYPE:
		    ti = proto_tree_add_text(tlv_tree, offset+link_len, stlv_len+4, 
					     "%s: %d", stlv_name,
					     *((guint8 *)pd + offset + link_len + 4));
		    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
		    proto_tree_add_text(stlv_tree, offset+link_len, 2, 
					"TLV Type: %d: %s", stlv_type, stlv_name);
		    proto_tree_add_text(stlv_tree, offset+link_len+2, 2, "TLV Length: %d", stlv_len);
		    proto_tree_add_text(stlv_tree, offset+link_len+4, 1, "%s: %d", stlv_name,
					*((guint8 *)pd + offset + link_len + 4));
		    break;
		    
		case MPLS_LINK_ID:
		    ti = proto_tree_add_text(tlv_tree, offset+link_len, stlv_len+4, 
					     "%s: %s (%x)", stlv_name, 
					     ip_to_str(pd + offset + link_len + 4),
					     pntohl(pd + offset + link_len + 4));
		    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
		    proto_tree_add_text(stlv_tree, offset+link_len, 2, 
					"TLV Type: %d: %s", stlv_type, stlv_name);
		    proto_tree_add_text(stlv_tree, offset+link_len+2, 2, "TLV Length: %d", stlv_len);
		    proto_tree_add_text(stlv_tree, offset+link_len+4, 4, "%s: %s (%x)", stlv_name, 
					ip_to_str(pd + offset + link_len + 4),
					pntohl(pd + offset + link_len + 4));
		    break;
		    
		case MPLS_LINK_LOCAL_IF:
		case MPLS_LINK_REMOTE_IF:
		    ti = proto_tree_add_text(tlv_tree, offset+link_len, stlv_len+4, 
					     "%s: %s", stlv_name, 
					     ip_to_str(pd+offset+link_len+4));
		    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
		    proto_tree_add_text(stlv_tree, offset+link_len, 2, 
					"TLV Type: %d: %s", stlv_type, stlv_name);
		    proto_tree_add_text(stlv_tree, offset+link_len+2, 2, "TLV Length: %d", stlv_len);
		    proto_tree_add_text(stlv_tree, offset+link_len+4, 4, "%s: %s", stlv_name, 
					ip_to_str(pd+offset+link_len+4));

		    break;

		case MPLS_LINK_TE_METRIC:
		case MPLS_LINK_COLOR:
		    ti = proto_tree_add_text(tlv_tree, offset+link_len, stlv_len+4, 
					     "%s: %d", stlv_name, 
					     pntohl(pd + offset + link_len + 4));
		    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
		    proto_tree_add_text(stlv_tree, offset+link_len, 2, 
					"TLV Type: %d: %s", stlv_type, stlv_name);
		    proto_tree_add_text(stlv_tree, offset+link_len+2, 2, "TLV Length: %d", stlv_len);
		    proto_tree_add_text(stlv_tree, offset+link_len+4, 4, "%s: %d", stlv_name, 
					pntohl(pd + offset + link_len + 4));
		    break;
		    
		case MPLS_LINK_MAX_BW:
		case MPLS_LINK_MAX_RES_BW:
		    ti = proto_tree_add_text(tlv_tree, offset+link_len, stlv_len+4, 
					     "%s: %ld", stlv_name, 
					     pieee_to_long(pd + offset + link_len + 4));
		    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
		    proto_tree_add_text(stlv_tree, offset+link_len, 2, 
					"TLV Type: %d: %s", stlv_type, stlv_name);
		    proto_tree_add_text(stlv_tree, offset+link_len+2, 2, "TLV Length: %d", stlv_len);
		    proto_tree_add_text(stlv_tree, offset+link_len+4, 4, "%s: %ld", stlv_name, 
					pieee_to_long(pd + offset + link_len + 4));
		    break;
		    
		case MPLS_LINK_UNRES_BW:
		    ti = proto_tree_add_text(tlv_tree, offset+link_len, stlv_len+4, 
					     "%s", stlv_name);
		    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
		    proto_tree_add_text(stlv_tree, offset+link_len, 2, 
					"TLV Type: %d: %s", stlv_type, stlv_name);
		    proto_tree_add_text(stlv_tree, offset+link_len+2, 2, "TLV Length: %d", stlv_len);
		    for (i=0; i<8; i++) 
			proto_tree_add_text(stlv_tree, offset+link_len+4+(i*4), 4, 
					    "Pri %d: %ld", i,
					    pieee_to_long(pd + offset + link_len + 4 + i*4));
		    break;
		    
		default:
		    proto_tree_add_text(tlv_tree, offset+link_len, stlv_len+4, 
					"Unknown Link sub-TLV: %d", stlv_type);
		}
		link_len += ((stlv_len+3)/4)*4;
	    }

	    break;

	default:
	    ti = proto_tree_add_text(mpls_tree, offset+length, tlv_length+4, 
				     "Unknown LSA: %d", tlv_type);
	    tlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link);
	    proto_tree_add_text(tlv_tree, offset+length, 2, "TLV Type: %d - Unknown", tlv_type);
	    proto_tree_add_text(tlv_tree, offset+length+2, 2, "TLV Length: %d", tlv_length);
	    proto_tree_add_text(tlv_tree, offset+length+4, tlv_length, "TLV Data");
	    break;
	}

	length += tlv_length;

    }
}

/*
 * Dissect opaque LSAs
 */
void dissect_ospf_lsa_opaque(const u_char *pd, 
			    int offset, 
			    frame_data *fd, 
			    proto_tree *tree,
			    e_ospf_lsa_hdr *lsa_hdr) {
    guint8 opaque_id = *((guint8 *) &(lsa_hdr->ls_id));

    switch(opaque_id) {

    case OSPF_LSA_MPLS_TE:
	dissect_ospf_lsa_mpls(pd, offset, fd, tree, lsa_hdr);
	break;

    default:
	proto_tree_add_text(tree, offset, END_OF_FRAME, "Unknown LSA Type");
	break;
    } /* switch on opaque LSA id */
}

int
dissect_ospf_lsa(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int disassemble_body) {
    e_ospf_lsa_hdr 	 lsa_hdr;
    char		*lsa_type;
    int			 lsa_end;

    /* data strutures for the router LSA */
    e_ospf_router_lsa 		router_lsa;
    e_ospf_router_data 		router_data;
    e_ospf_router_metric 	tos_data;
    guint16 			link_counter;
    guint8 			tos_counter;
    char  			*link_type;
    char  			*link_id;

    /* data structures for the network lsa */
    e_ospf_network_lsa 	network_lsa;
    guint32		*attached_router;

    /* data structures for the summary and ASBR LSAs */
    e_ospf_summary_lsa 	summary_lsa;

    /* data structures for the AS-External LSA */
    e_ospf_asexternal_lsa       asext_lsa;
    guint32                   asext_metric;

    /* data structures for opaque LSA */
    guint32                     ls_id;

    proto_tree *ospf_lsa_tree;
	proto_item *ti; 

    memcpy(&lsa_hdr, &pd[offset], sizeof(e_ospf_lsa_hdr));

             

    switch(lsa_hdr.ls_type) {
        case OSPF_LSTYPE_ROUTER:
	    lsa_type="Router LSA";
            break;
        case OSPF_LSTYPE_NETWORK:
	    lsa_type="Network LSA";
            break;
        case OSPF_LSTYPE_SUMMERY:
	    lsa_type="Summary LSA";
            break;
        case OSPF_LSTYPE_ASBR:
	    lsa_type="ASBR LSA";
            break;
        case OSPF_LSTYPE_ASEXT:
	    lsa_type="AS-external-LSA";
            break;
        case OSPF_LSTYPE_OP_LINKLOCAL:
	    lsa_type="Opaque LSA, Link-local scope";
            break;
        case OSPF_LSTYPE_OP_AREALOCAL:
	    lsa_type="Opaque LSA, Area-local scope";
            break;
        case OSPF_LSTYPE_OP_ASWIDE:
	    lsa_type="Opaque LSA, AS-wide scope";
            break;
        default:
	    lsa_type="unknown";
    }

    if (tree) {
	if(disassemble_body){
             ti = proto_tree_add_text(tree, offset, ntohs(lsa_hdr.length), 
	                                              "%s (Type: %d)", lsa_type, lsa_hdr.ls_type); 
        } else {
             ti = proto_tree_add_text(tree, offset, OSPF_LSA_HEADER_LENGTH, "LSA Header"); 
        }
        ospf_lsa_tree = proto_item_add_subtree(ti, ett_ospf_lsa);

	
        proto_tree_add_text(ospf_lsa_tree, offset, 2, "LS Age: %d seconds", ntohs(lsa_hdr.ls_age));
        proto_tree_add_text(ospf_lsa_tree, offset + 2, 1, "Options: %d ", lsa_hdr.options);
        proto_tree_add_text(ospf_lsa_tree, offset + 3, 1, "LSA Type: %d (%s)", lsa_hdr.ls_type, lsa_type);

	if (is_opaque(lsa_hdr.ls_type)) {
	    ls_id = ntohl(lsa_hdr.ls_id);
	    proto_tree_add_text(ospf_lsa_tree, offset + 4, 1, "Link State ID Opaque Type: %u ", 
				(ls_id >> 24) & 0xff);
	    proto_tree_add_text(ospf_lsa_tree, offset + 5, 3, "Link State ID Opaque ID: %u ", 
				ls_id & 0xffffff);
	} else
	    proto_tree_add_text(ospf_lsa_tree, offset + 4, 4, "Link State ID: %s ", 
				ip_to_str((guint8 *) &(lsa_hdr.ls_id)));

        proto_tree_add_text(ospf_lsa_tree, offset + 8, 4, "Advertising Router: %s ", 
	                                             ip_to_str((guint8 *) &(lsa_hdr.adv_router)));
        proto_tree_add_text(ospf_lsa_tree, offset + 12, 4, "LS Sequence Number: 0x%04lx ", 
	                                             (unsigned long)ntohl(lsa_hdr.ls_seq));
        proto_tree_add_text(ospf_lsa_tree, offset + 16, 2, "LS Checksum: %d ", ntohs(lsa_hdr.ls_checksum));

        proto_tree_add_text(ospf_lsa_tree, offset + 18, 2, "Length: %d ", ntohs(lsa_hdr.length));

	if(!disassemble_body){
           return OSPF_LSA_HEADER_LENGTH;
        }

	lsa_end = offset + ntohs(lsa_hdr.length);
	/* the LSA body starts after 20 bytes of LSA Header */
	offset+=20;

        switch(lsa_hdr.ls_type){
            case(OSPF_LSTYPE_ROUTER):
                memcpy(&router_lsa, &pd[offset], sizeof(e_ospf_router_lsa));

		/* again: flags should be secified in detail */
		proto_tree_add_text(ospf_lsa_tree, offset, 1, "Flags: 0x%02x ", router_lsa.flags);
		proto_tree_add_text(ospf_lsa_tree, offset + 2, 2, "Nr. of Links: %d ", 
		                                                   ntohs(router_lsa.nr_links));
		offset += 4;
		/* router_lsa.nr_links links follow 
		 * maybe we should put each of the links into its own subtree ???
		 */
		for(link_counter = 1 ; link_counter <= ntohs(router_lsa.nr_links); link_counter++){

                    memcpy(&router_data, &pd[offset], sizeof(e_ospf_router_data));
		    /* check the Link Type and ID */
                    switch(router_data.link_type) {
                        case OSPF_LINK_PTP:
                	    link_type="Point-to-point connection to another router";
			    link_id="Neighboring router's Router ID";
                            break;
                        case OSPF_LINK_TRANSIT:
                	    link_type="Connection to a transit network";
			    link_id="IP address of Designated Router";
                            break;
                        case OSPF_LINK_STUB:
                	    link_type="Connection to a stub network";
			    link_id="IP network/subnet number";
                            break;
                        case OSPF_LINK_VIRTUAL:
                	    link_type="Virtual link";
			    link_id="Neighboring router's Router ID";
                            break;
                        default:
	                    link_type="unknown link type";
			    link_id="unknown link id";
                    }

		    proto_tree_add_text(ospf_lsa_tree, offset, 4, "%s: %s", link_id,
		                                   ip_to_str((guint8 *) &(router_data.link_id)));

		    /* link_data should be specified in detail (e.g. network mask) (depends on link type)*/
		    proto_tree_add_text(ospf_lsa_tree, offset + 4, 4, "Link Data: %s", 
		                                   ip_to_str((guint8 *) &(router_data.link_data)));

		    proto_tree_add_text(ospf_lsa_tree, offset + 8, 1, "Link Type: %d - %s", 
		                                              router_data.link_type, link_type);
		    proto_tree_add_text(ospf_lsa_tree, offset + 9, 1, "Nr. of TOS metrics: %d", router_data.nr_tos);
		    proto_tree_add_text(ospf_lsa_tree, offset + 10, 2, "TOS 0 metric: %d", ntohs( router_data.tos0_metric ));

		    offset += 12;

		    /* router_data.nr_tos metrics may follow each link 
		     * ATTENTION: TOS metrics are not tested (I don't have TOS based routing)
		     * please send me a mail if it is/isn't working
		     */

		    for(tos_counter = 1 ; link_counter <= ntohs(router_data.nr_tos); tos_counter++){
                        memcpy(&tos_data, &pd[offset], sizeof(e_ospf_router_metric));
			proto_tree_add_text(ospf_lsa_tree, offset, 1, "TOS: %d, Metric: %d", 
			                        tos_data.tos, ntohs(tos_data.metric));
			offset += 4;
		    }
		}
                break;
            case(OSPF_LSTYPE_NETWORK):
                memcpy(&network_lsa, &pd[offset], sizeof(e_ospf_network_lsa));
		proto_tree_add_text(ospf_lsa_tree, offset, 4, "Netmask: %s", 
                                                 ip_to_str((guint8 *) &(network_lsa.network_mask)));
		offset += 4;

		while( (lsa_end - offset) >= 4){
		    attached_router = (guint32 *) &pd[offset];
		    proto_tree_add_text(ospf_lsa_tree, offset, 4, "Attached Router: %s", 
                                                 ip_to_str((guint8 *) attached_router));
		    offset += 4;
		}
                break;
            case(OSPF_LSTYPE_SUMMERY):
                /* Type 3 and 4 LSAs have the same format */
            case(OSPF_LSTYPE_ASBR):
                memcpy(&summary_lsa, &pd[offset], sizeof(e_ospf_summary_lsa));
                proto_tree_add_text(ospf_lsa_tree, offset, 4, "Netmask: %s", 
                                                 ip_to_str((guint8 *) &(summary_lsa.network_mask)));
                /* returns only the TOS 0 metric (even if there are more TOS metrics) */
                break;
            case(OSPF_LSTYPE_ASEXT):
                memcpy(&summary_lsa, &pd[offset], sizeof(e_ospf_summary_lsa));
                proto_tree_add_text(ospf_lsa_tree, offset, 4, "Netmask: %s", 
                                                  ip_to_str((guint8 *) &(summary_lsa.network_mask)));

                /* asext_lsa = (e_ospf_asexternal_lsa *) &pd[offset + 4]; */
                memcpy(&asext_lsa, &pd[offset + 4], sizeof(asext_lsa));
                if( (asext_lsa.options & 128) == 128 ) { /* check wether or not E bit is set */
                   proto_tree_add_text(ospf_lsa_tree, offset, 1, 
                            "External Type: Type 2 (metric is larger than any other link state path)");
                } else {
                   proto_tree_add_text(ospf_lsa_tree, offset + 4, 1, 
                            "External Type: Type 1 (metric is specified in the same units as interface cost)");
                }
                /* the metric field of a AS-external LAS is specified in 3 bytes -> not well aligned */
                /* this routine returns only the TOS 0 metric (even if there are more TOS metrics) */
                memcpy(&asext_metric, &pd[offset+4], 4); 
                
                /* erase the leading 8 bits (the dont belong to the metric */
                asext_metric = ntohl(asext_metric) & 0x00ffffff ;

                proto_tree_add_text(ospf_lsa_tree, offset + 5,  3,"Metric: %d", asext_metric);
                proto_tree_add_text(ospf_lsa_tree, offset + 8,  4,"Forwarding Address: %s", 
                                                 ip_to_str((guint8 *) &(asext_lsa.gateway)));
                proto_tree_add_text(ospf_lsa_tree, offset + 12, 4,"External Route Tag: %ld", (long)ntohl(asext_lsa.external_tag)); 
                    
                break;

        case OSPF_LSTYPE_OP_LINKLOCAL:
        case OSPF_LSTYPE_OP_AREALOCAL:
        case OSPF_LSTYPE_OP_ASWIDE:
	    dissect_ospf_lsa_opaque(pd, offset, fd, ospf_lsa_tree, &lsa_hdr);
            break;

	default:
               /* unknown LSA type */
	        proto_tree_add_text(ospf_lsa_tree, offset, END_OF_FRAME, "Unknown LSA Type");
        }
    }
    /* return the length of this LSA */
    return ntohs(lsa_hdr.length);
}

void
proto_register_ospf(void)
{
/*        static hf_register_info hf[] = {
                { &variable,
                { "Name",           "ospf.abbreviation", TYPE, VALS_POINTER }},
        };*/
	static gint *ett[] = {
		&ett_ospf,
		&ett_ospf_hdr,
		&ett_ospf_hello,
		&ett_ospf_desc,
		&ett_ospf_lsr,
		&ett_ospf_lsa,
		&ett_ospf_lsa_upd,
		&ett_ospf_lsa_mpls,
		&ett_ospf_lsa_mpls_router,
		&ett_ospf_lsa_mpls_link,
		&ett_ospf_lsa_mpls_link_stlv
	};

        proto_ospf = proto_register_protocol("Open Shortest Path First", "ospf");
 /*       proto_register_field_array(proto_ospf, hf, array_length(hf));*/
	proto_register_subtree_array(ett, array_length(ett));
}
