/* packet-hdfs.c
 * HDFS Protocol and dissectors
 *
 * Copyright (c) 2011 by Isilon Systems.
 *
 * Author: Allison Obourn <aobourn@isilon.com>
 *
 * $Id$
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
# include "config.h"
#endif

#include <stdlib.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#define NAMENODE_PORT 8020
#define REQUEST_STR "hrpc"

#define SEND_DEC 1936027236
#define SEND_OFFSET 13
#define HEAR_DEC 1214603634
#define HEAR_OFFSET 9
#define TBEA_DEC 1952605537
#define TBEA_OFFSET 5
#define T_DEC 116
#define T_OFFSET 1

#define FIRST_READ_FRAGMENT_LEN 15
#define SECOND_READ_FRAGMENT_LEN 29


static const int START = 0;
static const int AUTHENTICATION = 1;
static const int DATA = 2;

static guint tcp_port = 0;

static int proto_hdfs = -1;
static int hf_hdfs_pdu_type = -1;
static int hf_hdfs_flags = -1;
static int hf_hdfs_sequenceno = -1;
static int hf_hdfs_packetno = -1;
static int hf_hdfs_authlen = -1;
static int hf_hdfs_success = -1;
static int hf_hdfs_auth = -1;
static int hf_hdfs_len = -1;
static int hf_hdfs_strcall = -1;
static int hf_hdfs_params = -1;
static int hf_hdfs_paramtype = -1;
static int hf_hdfs_paramval = -1;
static int hf_hdfs_paramvalnum = -1;
static int hf_hdfs_rest = -1;
static int hf_hdfs_fileperm = -1;
static int hf_hdfs_blockloc = -1;
static int hf_hdfs_endblockloc = -1;
static int hf_hdfs_blockgen = -1; 
static int hf_hdfs_prover = -1;
static int hf_hdfs_objname = -1;
static int hf_hdfs_filename = -1;
static int hf_hdfs_blockcount = -1;
static int hf_hdfs_ownername = -1;
static int hf_hdfs_groupname = -1;
static int hf_hdfs_namelenone = -1;
static int hf_hdfs_namelentwo = -1;
static int hf_hdfs_accesstime = -1;
static int hf_hdfs_modtime = -1;
static int hf_hdfs_blockrep = -1;
static int hf_hdfs_isdir = -1;
static int hf_hdfs_blocksize = -1;
static int hf_hdfs_filelen = -1;
static int hf_hdfs_construct = -1;
static int hf_hdfs_hostname = -1;
static int hf_hdfs_rackloc = -1;
static int hf_hdfs_adminstate = -1;
static int hf_hdfs_activecon = -1;
static int hf_hdfs_lastupdate = -1;
static int hf_hdfs_remaining = -1;
static int hf_hdfs_dfsused = -1;
static int hf_hdfs_capacity = -1;
static int hf_hdfs_ipcport = -1;
static int hf_hdfs_infoport = -1;
static int hf_hdfs_storageid = -1;
static int hf_hdfs_datanodeid = -1;
static int hf_hdfs_locations = -1;
static int hf_hdfs_offset = -1;
static int hf_hdfs_corrupt = -1;
static int hf_hdfs_identifier = -1;
static int hf_hdfs_password = -1;
static int hf_hdfs_kind = -1;
static int hf_hdfs_service = -1;



static gint ett_hdfs = -1;

void proto_reg_handoff_hdfs(void);

/* Parses the parameters of a function.
   Parses the type length which is always in 2 bytes.
   Next the type which is the previously found length.
   If this type is variable length it then reads the length of the data
   from 2 bytes and then the data.
   Otherwise reads just the data. */
static void
dissect_params (tvbuff_t *tvb, proto_tree *hdfs_tree, guint offset, int params) {

	guint length;
	int i =  0;
	const guint8* type_name;
	for (i = 0; i < params; i++) {

		/* get length that we just dissected */
		length = tvb_get_ntohs(tvb, offset);

		/* 2 bytes = parameter type length */
		proto_tree_add_item(hdfs_tree, hf_hdfs_namelentwo, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		/* length bytes = parameter type */
		proto_tree_add_item(hdfs_tree, hf_hdfs_paramtype, tvb, offset, length, ENC_BIG_ENDIAN);
		offset += length;

		if (offset >= length && (!tvb_memeql(tvb, offset - length, "long", length) || !tvb_memeql(tvb, offset - length, "int", length) ||
		    !tvb_memeql(tvb, offset - length, "short", length) || !tvb_memeql(tvb, offset - length, "char", length) ||
		    !tvb_memeql(tvb, offset - length, "byte", length) || !tvb_memeql(tvb, offset - length, "float", length)
			|| !tvb_memeql(tvb, offset - length, "double", length) || !tvb_memeql(tvb, offset - length, "boolean", length))) {

            if (!tvb_memeql(tvb, offset - length, "boolean", length)) {
                length = 1;
            } else if (!tvb_memeql(tvb, offset - length, "short", length)) {
                length = 2;
            } else {
    			length = sizeof(type_name);
            }
            
			proto_tree_add_item(hdfs_tree, hf_hdfs_paramvalnum, tvb, offset, length, ENC_BIG_ENDIAN);
			offset += length;

		} else {
			/* get length */
			length = tvb_get_ntohs(tvb, offset);

			/* 2 bytes = parameter value length */
			proto_tree_add_item(hdfs_tree, hf_hdfs_namelentwo, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			proto_tree_add_item(hdfs_tree, hf_hdfs_paramval, tvb, offset, length, ENC_BIG_ENDIAN);
			offset += length;
			
			if (!tvb_memeql(tvb, offset - length, "org.apache.hadoop.fs.permission.FsPermission", length)) {
			    proto_tree_add_item(hdfs_tree, hf_hdfs_fileperm, tvb, offset, 2, ENC_BIG_ENDIAN);
			    offset += 2;
			}
		}
	}
}


/* Dissects a data packet of the form:
   method name length 	: 2B
   method name		: above value
   number of parameters 	: 4B
    -- list of parameters the length of above --
   parameter type length	: 2B
   parameter type		: above value
   -- if the type is variable size --
   parameter value length	: 2B
   parameter value		: above value
   -- otherwise --
   parameter value 	: length of the type  */
static void
dissect_data (tvbuff_t *tvb, proto_tree *hdfs_tree, guint offset) {
	int params = 0;
	guint length = 0;

	/* get length */
	length = tvb_get_ntohs(tvb, offset);

	/* method name length = 2 B */
	proto_tree_add_item(hdfs_tree, hf_hdfs_namelentwo, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* length bytes = method name */
	proto_tree_add_item(hdfs_tree, hf_hdfs_strcall, tvb, offset, length, ENC_BIG_ENDIAN);
	offset += length;

	/* we only want to parse the packet if it is not a heartbeat (random looking numbers are the decimal
	   representation of sendHeartbeat */
	if (!(tvb_get_ntohl(tvb, offset - SEND_OFFSET) == SEND_DEC && tvb_get_ntohl(tvb, offset - HEAR_OFFSET) == HEAR_DEC &&
		tvb_get_ntohl(tvb, offset - TBEA_OFFSET) == TBEA_DEC && tvb_get_guint8(tvb, offset - T_OFFSET) == T_DEC)) {

		/* get number of params */
		params = tvb_get_ntohl(tvb, offset);

		/* 4 bytes = # of parameters */
		proto_tree_add_item(hdfs_tree, hf_hdfs_params, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		/* go through all params and dissect their type length, type, value length and value */
		dissect_params (tvb, hdfs_tree, offset, params);
	}
}

/*
response to a get protocol version message
contains a type length, type name and the value
*/
static void
dissect_resp_long (tvbuff_t *tvb, proto_tree *hdfs_tree, int offset) {
    /* get length that we just dissected */
    int length = tvb_get_ntohs(tvb, offset);

    /* 2 bytes = parameter type length */
    proto_tree_add_item(hdfs_tree, hf_hdfs_namelentwo, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* length bytes = parameter type */
    proto_tree_add_item(hdfs_tree, hf_hdfs_paramtype, tvb, offset, length, ENC_BIG_ENDIAN);
    offset += length;
    
    /* the value */
    proto_tree_add_item(hdfs_tree, hf_hdfs_prover, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
}

/*
Response to a file status message
*/
static void
dissect_resp_filestatus (tvbuff_t *tvb, proto_tree *hdfs_tree, int offset) {

    int length;

    /* file status */
    proto_tree_add_item(hdfs_tree, hf_hdfs_fileperm, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;            
    		            
    /* get length */
    length = tvb_get_ntohs(tvb, offset);

    /* 2 bytes = file name length */
    proto_tree_add_item(hdfs_tree, hf_hdfs_namelentwo, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* file name */
    proto_tree_add_item(hdfs_tree, hf_hdfs_filename, tvb, offset, length, ENC_BIG_ENDIAN);
    offset += length;	            
		            

    /* 8 file size / end location  */
    proto_tree_add_item(hdfs_tree, hf_hdfs_endblockloc, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    
    /* is directory */
    proto_tree_add_item(hdfs_tree, hf_hdfs_isdir, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    
    /* block replication factor */
    proto_tree_add_item(hdfs_tree, hf_hdfs_blockrep, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    
    /* block size */
    proto_tree_add_item(hdfs_tree, hf_hdfs_blocksize, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    
    /* modified time */
    proto_tree_add_item(hdfs_tree, hf_hdfs_modtime, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /* access time */
    proto_tree_add_item(hdfs_tree, hf_hdfs_accesstime, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /* 2 of file permissions */
    proto_tree_add_item(hdfs_tree, hf_hdfs_fileperm, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    

    /* get length */
    length = tvb_get_guint8 (tvb, offset);

    /* owner name length */
    proto_tree_add_item(hdfs_tree, hf_hdfs_namelenone, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* owner name */
    proto_tree_add_item(hdfs_tree, hf_hdfs_ownername, tvb, offset, length, ENC_BIG_ENDIAN);
    offset += length;
    
    /* get length */
    length = tvb_get_guint8 (tvb, offset);

    /* group name length */
    proto_tree_add_item(hdfs_tree, hf_hdfs_namelenone, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* group name */
    proto_tree_add_item(hdfs_tree, hf_hdfs_groupname, tvb, offset, length, ENC_BIG_ENDIAN);
    offset += length;
}


/*
Response to the get block info message
parses the sent back information about each blcok
*/
static int
dissect_block_info (tvbuff_t *tvb, proto_tree *hdfs_tree, int offset) {
    
    int length;
    
    length = tvb_get_guint8(tvb, offset);
    
    /* identifier length */
    proto_tree_add_item(hdfs_tree, hf_hdfs_namelenone, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    
    /* identifier */
    proto_tree_add_item(hdfs_tree, hf_hdfs_identifier, tvb, offset, length, ENC_BIG_ENDIAN);
    offset += length;
    
    length = tvb_get_guint8(tvb, offset);
    
    /* password length */
    proto_tree_add_item(hdfs_tree, hf_hdfs_namelenone, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    
    /* password */
    proto_tree_add_item(hdfs_tree, hf_hdfs_password, tvb, offset, length, ENC_BIG_ENDIAN);
    offset += length;
    
    length = tvb_get_guint8(tvb, offset);
    
    /* kind length */
    proto_tree_add_item(hdfs_tree, hf_hdfs_namelenone, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    
    /* kind */
    proto_tree_add_item(hdfs_tree, hf_hdfs_kind, tvb, offset, length, ENC_BIG_ENDIAN);
    offset += length;
    
    length = tvb_get_guint8(tvb, offset);
    
    /* service length */
    proto_tree_add_item(hdfs_tree, hf_hdfs_namelenone, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    
    /* service */
    proto_tree_add_item(hdfs_tree, hf_hdfs_service, tvb, offset, length, ENC_BIG_ENDIAN);
    offset += length;
    
    /* corrupt */
    proto_tree_add_item(hdfs_tree, hf_hdfs_corrupt, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    
    /* offset */
    proto_tree_add_item(hdfs_tree, hf_hdfs_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    
    
    /* block info section */
    
    /* block location */
    proto_tree_add_item(hdfs_tree, hf_hdfs_blockloc, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /* block size */
    proto_tree_add_item(hdfs_tree, hf_hdfs_blocksize, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    
    /* gen id 8 */
    proto_tree_add_item(hdfs_tree, hf_hdfs_blockgen, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;    
    
    /* locations */
    proto_tree_add_item(hdfs_tree, hf_hdfs_locations, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;


    /* address section */

    /* get length */
    length = tvb_get_ntohs(tvb, offset);

    /* length of addr */
    proto_tree_add_item(hdfs_tree, hf_hdfs_namelentwo, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* datanode id */
    proto_tree_add_item(hdfs_tree, hf_hdfs_datanodeid, tvb, offset, length, ENC_BIG_ENDIAN);
    offset += length;
    
    length = tvb_get_ntohs(tvb, offset);
    
    /* length of addr */
    proto_tree_add_item(hdfs_tree, hf_hdfs_namelentwo, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* storageid */
    proto_tree_add_item(hdfs_tree, hf_hdfs_storageid, tvb, offset, length, ENC_BIG_ENDIAN);
    offset += length;
    
    /* info port */
    proto_tree_add_item(hdfs_tree, hf_hdfs_infoport, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    

    /* default name node port */
    proto_tree_add_item(hdfs_tree, hf_hdfs_ipcport, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* capacity */
    proto_tree_add_item(hdfs_tree, hf_hdfs_capacity, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    
    /* dfs used */
    proto_tree_add_item(hdfs_tree, hf_hdfs_dfsused, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    
    /* remaining */
    proto_tree_add_item(hdfs_tree, hf_hdfs_remaining, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    
    /* last update */
    proto_tree_add_item(hdfs_tree, hf_hdfs_lastupdate, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    
    /* num active connections */
    proto_tree_add_item(hdfs_tree, hf_hdfs_activecon, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    
    
    length = tvb_get_guint8(tvb, offset);
    
    /* location rack length */
    proto_tree_add_item(hdfs_tree, hf_hdfs_namelenone, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    
    /* location rack */
    proto_tree_add_item(hdfs_tree, hf_hdfs_rackloc, tvb, offset, length, ENC_BIG_ENDIAN);
    offset += length;
    
    length = tvb_get_guint8(tvb, offset);
    
    /* hostname length */
    proto_tree_add_item(hdfs_tree, hf_hdfs_namelenone, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    
    /* hostname */
    proto_tree_add_item(hdfs_tree, hf_hdfs_hostname, tvb, offset, length, ENC_BIG_ENDIAN);
    offset += length;
      
    length = tvb_get_guint8(tvb, offset);
    
    /* admin state length */
    proto_tree_add_item(hdfs_tree, hf_hdfs_namelenone, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    
    /* admin state */
    proto_tree_add_item(hdfs_tree, hf_hdfs_adminstate, tvb, offset, length, ENC_BIG_ENDIAN);
    offset += length;
       
    return offset;

}



/* 
dissects the response from get block info. 
*/
static void
dissect_resp_locatedblocks (tvbuff_t *tvb, proto_tree *hdfs_tree, int offset) {
    
    
    /* file length = 8  */
    proto_tree_add_item(hdfs_tree, hf_hdfs_filelen, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    
    /* under construction = 1  */
    proto_tree_add_item(hdfs_tree, hf_hdfs_construct, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    
    /* number of blocks */
    proto_tree_add_item(hdfs_tree, hf_hdfs_blockcount, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    
    /* dissect info for each block */
    while (tvb_reported_length(tvb) - offset > 0) {
        offset = dissect_block_info (tvb, hdfs_tree, offset);
    }

}


static void
dissect_hdfs_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset = 0;
	int success = 0;
	guint length = 0;


	col_set_str(pinfo->cinfo, COL_PROTOCOL, "HDFS");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);

	if (tree) {

		proto_item *ti = NULL;
		proto_tree *hdfs_tree = NULL;

		ti = proto_tree_add_item(tree, proto_hdfs, tvb, 0, -1, ENC_BIG_ENDIAN);
		hdfs_tree = proto_item_add_subtree(ti, ett_hdfs);

		/* Response */
		if (pinfo->srcport == NAMENODE_PORT) {
			/* 4 bytes = sequence number */ 
			proto_tree_add_item(hdfs_tree, hf_hdfs_packetno, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			/* 4 bytes = status -> 0000 = success, 0001 = error, ffff = fatal */
		    success = tvb_get_ntohl(tvb, offset);
			proto_tree_add_item(hdfs_tree, hf_hdfs_success, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

		    if (success != 0) {
		        return;
		    }
		    
	        if (!tvb_memeql(tvb, offset + 2, "long", 4)) {
			    dissect_resp_long (tvb, hdfs_tree,  offset);
		    
			} else {
	    
			    /* name length = 2 B */
			    length = tvb_get_ntohs(tvb, offset);
			    proto_tree_add_item(hdfs_tree, hf_hdfs_namelentwo, tvb, offset, 2, ENC_BIG_ENDIAN); 
			    offset += 2;

			    /* length bytes = method name */
			    proto_tree_add_item(hdfs_tree, hf_hdfs_objname, tvb, offset, length, ENC_BIG_ENDIAN);
			    offset += length;

                /* get length that we just dissected */
	            length = tvb_get_ntohs(tvb, offset);

	            /* 2 bytes = objects length */
	            proto_tree_add_item(hdfs_tree, hf_hdfs_namelentwo, tvb, offset, 2, ENC_BIG_ENDIAN);
	            offset += 2;

	            /* length bytes = object name */
	            proto_tree_add_item(hdfs_tree, hf_hdfs_objname, tvb, offset, length, ENC_BIG_ENDIAN);
	            offset += length;
		        
		        /* responses about block location info */
		        if (!tvb_memeql(tvb, offset - length, "org.apache.hadoop.hdfs.protocol.LocatedBlocks", length)) {
                    dissect_resp_locatedblocks (tvb, hdfs_tree, offset);
                    
                /* responses about file statuses */
                } else if (!tvb_memeql(tvb, offset - length, "org.apache.hadoop.hdfs.protocol.HdfsFileStatus", length)) {
                        dissect_resp_filestatus (tvb, hdfs_tree, offset);
                        
                } else {
		            /* get length */
		            length = tvb_get_ntohs(tvb, offset);

		            /* 2 bytes = parameter value length */
		            proto_tree_add_item(hdfs_tree, hf_hdfs_namelentwo, tvb, offset, 2, ENC_BIG_ENDIAN);
		            offset += 2;

                    /* the value of the parameter */
		            proto_tree_add_item(hdfs_tree, hf_hdfs_paramval, tvb, offset, length, ENC_BIG_ENDIAN);
		            offset += length;                    
                }
            }	

	    /* Request to namenode */
	    } else {

		    /* check the packet length */
		    guint auth = tvb_get_ntohl(tvb, offset);

		    /* first setup packet starts with "hrpc" */
		    if (!tvb_memeql(tvb, offset, REQUEST_STR, sizeof(REQUEST_STR) - 1)) {
			
			    proto_tree_add_item(hdfs_tree, hf_hdfs_sequenceno, tvb, offset, sizeof(REQUEST_STR) - 1, ENC_BIG_ENDIAN);
			    offset += sizeof(REQUEST_STR) - 1;

			    proto_tree_add_item(hdfs_tree, hf_hdfs_pdu_type, tvb, offset, 1, ENC_BIG_ENDIAN);
			    offset += 1;

			    proto_tree_add_item(hdfs_tree, hf_hdfs_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
			    offset += 1;

		    } else {
			    /* second authentication packet */
			    if (auth + 4 != tvb_reported_length(tvb)) {
				
				    /* authentication length (read out of first 4 bytes) */
				    length = tvb_get_ntohl(tvb, offset);
				    proto_tree_add_item(hdfs_tree, hf_hdfs_authlen, tvb, offset, 4, ENC_BIG_ENDIAN);
				    offset += 4;

				    /* authentication (length the number we just got) */
				    proto_tree_add_item(hdfs_tree, hf_hdfs_auth, tvb, offset, length, ENC_BIG_ENDIAN);
				    offset += length;
			    }

			    /* data packets */

			    /* 4 bytes = length */
			    proto_tree_add_item(hdfs_tree, hf_hdfs_len, tvb, offset, 4, ENC_BIG_ENDIAN);
			    offset += 4;

			    /* 4 bytes = sequence number */
			    proto_tree_add_item(hdfs_tree, hf_hdfs_packetno, tvb, offset, 4, ENC_BIG_ENDIAN);
			    offset += 4;

			    /* dissect packet data */
			    dissect_data (tvb, hdfs_tree, offset);
		    }
	    }
	}
}

/* determine PDU length of protocol  */
static guint get_hdfs_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_)
{
    int len = tvb_reported_length(tvb);
    
    if (tvb_reported_length(tvb) == 1448 || tvb_reported_length(tvb) == 1321) {
        len = 150 * tvb_get_ntohs(tvb, 113) + 115 ;  
    }
    
    return len;

}

static void
dissect_hdfs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int frame_header_len = 0;
    gboolean need_reassemble = FALSE;
    
    frame_header_len = tvb_reported_length(tvb);
    
    if (frame_header_len == 1448 || frame_header_len ==  1321) {
        need_reassemble = TRUE;
    }
    
    
    tcp_dissect_pdus(tvb, pinfo, tree, need_reassemble, frame_header_len, get_hdfs_message_len, dissect_hdfs_message);
}

/* registers the protcol with the given names */
void
proto_register_hdfs(void)
{

    static hf_register_info hf[] = {

	/* list of all options for dissecting the protocol */

	/*************************************************
	First packet
	**************************************************/
	{ &hf_hdfs_sequenceno,
		{ "HDFS protocol type", "hdfs.type",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_pdu_type,
		{ "HDFS protocol version", "hdfs.version",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_flags,
		{ "HDFS authentication type", "hdfs.auth",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	/***********************************************
	Authentication packet
	***********************************************/
	{ &hf_hdfs_authlen,
		{ "HDFS authentication length", "hdfs.authlen",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_auth,
		{ "HDFS authorization bits", "hdfs.auth",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
	},
	/**********************************************
	Response
	**********************************************/
	{ &hf_hdfs_packetno,
		{ "HDFS packet number", "hdfs.seqno",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_success,
		{ "HDFS success", "hdfs.success",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_strcall,
		{ "HDFS method name", "hdfs.strcall",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_rest,
		{ "HDFS value", "hdfs.rest",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_blockloc,
		{ "HDFS block location", "hdfs.blockloc",
			FT_UINT64, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_blocksize,
		{ "HDFS block size", "hdfs.blocksize",
			FT_UINT64, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_endblockloc,
		{ "HDFS file size", "hdfs.endblockloc",
			FT_UINT64, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_blockgen,
		{ "HDFS block gen", "hdfs.blockgen",
			FT_UINT64, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_prover,
		{ "HDFS protocol version", "hdfs.prover",
			FT_UINT64, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_objname,
		{ "HDFS object name", "hdfs.objname",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_filename,
		{ "HDFS file name", "hdfs.filename",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_blockcount,
		{ "HDFS block count", "hdfs.blockcount",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_ownername,
		{ "HDFS owner name", "hdfs.ownername",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_groupname,
		{ "HDFS group name", "hdfs.groupname",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_accesstime,
		{ "HDFS access time", "hdfs.accesstime",
			FT_UINT64, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_modtime,
		{ "HDFS modified time", "hdfs.modtime",
			FT_UINT64, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_blockrep,
		{ "HDFS block replication factor", "hdfs.blockrep",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_isdir,
		{ "HDFS is directory", "hdfs.isdir",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_filelen,
		{ "HDFS file length", "hdfs.filelen",
			FT_UINT64, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_construct,
		{ "HDFS under construction", "hdfs.construct",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_rackloc,
		{ "HDFS rack location", "hdfs.rackloc",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_adminstate,
		{ "HDFS admin state", "hdfs.adminstate",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_hostname,
		{ "HDFS hostname", "hdfs.hostname",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
	},
	
	
	{ &hf_hdfs_namelenone,
		{ "HDFS name length", "hdfs.namelenone",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_namelentwo,
		{ "HDFS name length", "hdfs.namelentwo",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	
	
	/***************************************
	file info response
	***************************************/
	{ &hf_hdfs_activecon,
		{ "HDFS active connections", "hdfs.activecon",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_lastupdate,
		{ "HDFS lastupdate", "hdfs.lastupdate",
			FT_UINT64, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_remaining,
		{ "HDFS remaining", "hdfs.remaining",
			FT_UINT64, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_dfsused,
		{ "HDFS dfs used", "hdfs.dfsused",
			FT_UINT64, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_capacity,
		{ "HDFS capacity", "hdfs.capacity",
			FT_UINT64, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_ipcport,
		{ "HDFS ipcport", "hdfs.ipcport",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_infoport,
		{ "HDFS info port", "hdfs.infoport",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_storageid,
		{ "HDFS storage id", "hdfs.storageid",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_datanodeid,
		{ "HDFS datanodeid", "hdfs.datanodeid",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_locations,
		{ "HDFS locations", "hdfs.locations",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	
	{ &hf_hdfs_identifier,
		{ "HDFS locations", "hdfs.identifier",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_password,
		{ "HDFS password", "hdfs.password",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_kind,
		{ "HDFS kind", "hdfs.kind",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_service,
		{ "HDFS locations", "hdfs.service",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_corrupt,
		{ "HDFS corrupt", "hdfs.corrupt",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_offset,
		{ "HDFS offset", "hdfs.offset",
			FT_UINT64, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	
	
	/***********************************************
	Data request
	***********************************************/
	{ &hf_hdfs_len,
		{ "HDFS length", "hdfs.len",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	/* packet number, same as in response
	   method name length, same as in response
	   string call, same as in response */
	{ &hf_hdfs_params,
		{ "HDFS number of parameters", "hdfs.params",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_paramtype,
		{ "HDFS parameter type", "hdfs.paramtype",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_hdfs_paramval,
		{ "HDFS parameter value", "hdfs.paramval",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
	},
	/* param value that is displayed as a number not a string */
	{ &hf_hdfs_paramvalnum,
		{ "HDFS parameter value", "hdfs.paramvalnum",
			FT_INT64, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
    { &hf_hdfs_fileperm,
		{ "HDFS File permission", "hdfs.fileperm",
			FT_INT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},

    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_hdfs
    };

    module_t *hdfs_module;

    proto_hdfs = proto_register_protocol (
        "HDFS Protocol", /* name       */
        "HDFS",      /* short name */
        "hdfs"       /* abbrev     */
        );

    proto_register_field_array(proto_hdfs, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    hdfs_module = prefs_register_protocol(proto_hdfs, proto_reg_handoff_hdfs);

    prefs_register_uint_preference(hdfs_module,
                                  "tcp.port",
                                  "TCP port for HDFS",
                                  "Set the TCP port for HDFS",
                                  10,
                                  &tcp_port);

    register_dissector("hdfs", dissect_hdfs, proto_hdfs);
}

/* registers handoff */
void
proto_reg_handoff_hdfs(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t hdfs_handle;
    static guint saved_tcp_port;

    if (!initialized) {
        hdfs_handle = create_dissector_handle(dissect_hdfs, proto_hdfs);
        dissector_add_handle("tcp.port", hdfs_handle);  /* for "decode as" */
        initialized = TRUE;
    } else if (saved_tcp_port != 0) {
        dissector_delete_uint("tcp.port", saved_tcp_port, hdfs_handle);
    }

    if (tcp_port != 0) {
        dissector_add_uint("tcp.port", tcp_port, hdfs_handle);
    }

    saved_tcp_port = tcp_port;
}
/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab
 * :indentSize=2:tabSize=8:noTabs=true:
 */
