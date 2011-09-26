/* packet-distcc.c
 * Routines for distcc dissection
 * Copyright 2003, Brad Hards <bradh@frogmouth.net>
 * Copyright 2003, Ronnie Sahlberg, added TCP desegmentation.
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
/* This dissector supports version 1 of the DISTCC protocol */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <time.h>
#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>

#include <epan/prefs.h>


static int proto_distcc = -1;
static int hf_distcc_version = -1;
static int hf_distcc_argc = -1;
static int hf_distcc_argv = -1;
static int hf_distcc_doti_source = -1;
static int hf_distcc_stat = -1;
static int hf_distcc_serr = -1;
static int hf_distcc_sout = -1;
static int hf_distcc_doto_object = -1;


static gint ett_distcc = -1;

static dissector_handle_t data_handle;


static gboolean distcc_desegment = TRUE;


#define TCP_PORT_DISTCC	3632

static guint glb_distcc_tcp_port = TCP_PORT_DISTCC;

extern void proto_reg_handoff_distcc(void);

#define CHECK_PDU_LEN(x) \
	if(parameter>tvb_length_remaining(tvb, offset) || parameter < 1){\
		len=tvb_length_remaining(tvb, offset);\
		col_append_str(pinfo->cinfo, COL_INFO, "[Short" x " PDU]");\
	} \
	tvb_ensure_bytes_exist(tvb, offset, len);


#define DESEGMENT_TCP(x) \
	if(distcc_desegment && pinfo->can_desegment){\
		/* only attempt reassembly if whe have the full segment */\
		if(tvb_length_remaining(tvb, offset)==tvb_reported_length_remaining(tvb, offset)){\
			if(parameter>tvb_length_remaining(tvb, offset)){\
				proto_tree_add_text(tree, tvb, offset-12, -1, "[Short " x " PDU]");\
				pinfo->desegment_offset=offset-12;\
				pinfo->desegment_len=parameter-tvb_length_remaining(tvb, offset);\
				return offset+len;\
			}\
		}\
	}





static int
dissect_distcc_dist(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint32 parameter)
{
	proto_tree_add_uint_format(tree, hf_distcc_version, tvb, offset-12, 12, parameter, "DIST: %d", parameter);

	col_append_fstr(pinfo->cinfo, COL_INFO, "DIST:%d ", parameter);

	return offset;
}

static int
dissect_distcc_done(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint32 parameter)
{
	proto_tree_add_uint_format(tree, hf_distcc_version, tvb, offset-12, 12, parameter, "DONE: %d", parameter);

	col_append_fstr(pinfo->cinfo, COL_INFO, "DONE:%d ", parameter);

	return offset;
}

static int
dissect_distcc_stat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint32 parameter)
{
	proto_tree_add_uint_format(tree, hf_distcc_stat, tvb, offset-12, 12, parameter, "STAT: %d", parameter);

	col_append_fstr(pinfo->cinfo, COL_INFO, "STAT:%d ", parameter);

	return offset;
}

static int
dissect_distcc_argc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint32 parameter)
{
	proto_tree_add_uint_format(tree, hf_distcc_argc, tvb, offset-12, 12, parameter, "ARGC: %d", parameter);

	col_append_fstr(pinfo->cinfo, COL_INFO, "ARGC:%d ", parameter);

	return offset;
}

static int
dissect_distcc_argv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gint parameter)
{
	char argv[256]; 
	int argv_len;
	gint len=parameter;


	CHECK_PDU_LEN("ARGV");

	/* see if we need to desegment the PDU */
	DESEGMENT_TCP("ARGV");



	argv_len=len>255?255:len;
	tvb_memcpy(tvb, argv, offset, argv_len);
	argv[argv_len]=0;

	proto_tree_add_item(tree, hf_distcc_argv, tvb, offset, len, ENC_BIG_ENDIAN);

	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", argv);

	if(len!=parameter){
		proto_tree_add_text(tree, tvb, 0, 0, "[Short ARGV PDU]");
	}
	return offset+len;
}

static int
dissect_distcc_serr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gint parameter)
{
	char argv[256]; 
	int argv_len;
	gint len=parameter;


	CHECK_PDU_LEN("SERR");

	/* see if we need to desegment the PDU */
	DESEGMENT_TCP("SERR");



	argv_len=len>255?255:len;
	tvb_memcpy(tvb, argv, offset, argv_len);
	argv[argv_len]=0;

	proto_tree_add_item(tree, hf_distcc_serr, tvb, offset, len, ENC_BIG_ENDIAN);

	col_append_fstr(pinfo->cinfo, COL_INFO, "SERR:%s ", argv);

	if(len!=parameter){
		proto_tree_add_text(tree, tvb, 0, 0, "[Short SERR PDU]");
	}
	return offset+len;
}

static int
dissect_distcc_sout(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gint parameter)
{
	char argv[256]; 
	int argv_len;
	gint len=parameter;


	CHECK_PDU_LEN("SOUT");

	/* see if we need to desegment the PDU */
	DESEGMENT_TCP("SOUT");



	argv_len=len>255?255:len;
	tvb_memcpy(tvb, argv, offset, argv_len);
	argv[argv_len]=0;

	proto_tree_add_item(tree, hf_distcc_sout, tvb, offset, len, ENC_BIG_ENDIAN);

	col_append_fstr(pinfo->cinfo, COL_INFO, "SOUT:%s ", argv);

	if(len!=parameter){
		proto_tree_add_text(tree, tvb, 0, 0, "[Short SOUT PDU]");
	}
	return offset+len;
}


static int
dissect_distcc_doti(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, gint parameter)
{
	gint len=parameter;


	CHECK_PDU_LEN("DOTI");

	/* see if we need to desegment the PDU */
	DESEGMENT_TCP("DOTI");

	col_append_str(pinfo->cinfo, COL_INFO, "DOTI source ");

	proto_tree_add_item(tree, hf_distcc_doti_source, tvb, offset, len, ENC_BIG_ENDIAN);
	if(len!=parameter){
		proto_tree_add_text(tree, tvb, 0, 0, "[Short DOTI PDU]");
	}
	return offset+len;
}

static int
dissect_distcc_doto(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, gint parameter)
{
	gint len=parameter;


	CHECK_PDU_LEN("DOTO");

	/* see if we need to desegment the PDU */
	DESEGMENT_TCP("DOTO");

	col_append_str(pinfo->cinfo, COL_INFO, "DOTO object ");

	proto_tree_add_item(tree, hf_distcc_doto_object, tvb, offset, len, ENC_BIG_ENDIAN);
	if(len!=parameter){
		proto_tree_add_text(tree, tvb, 0, 0, "[Short DOTO PDU]");
	}
	return offset+len;
}



/* Packet dissection routine called by tcp (& udp) when port 3632 detected */
static void
dissect_distcc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset=0;
	proto_tree *tree=NULL;
	proto_item *item=NULL;
	char token[4];
	guint32 parameter;
	

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DISTCC ");

	col_clear(pinfo->cinfo, COL_INFO);

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, proto_distcc, tvb, offset,
			-1, ENC_BIG_ENDIAN);
		tree = proto_item_add_subtree(item, ett_distcc);
	}

	while(1){
		/* we must have at least 12 bytes so we can read the 
		   token and the parameter */
		if(tvb_length_remaining(tvb, offset)<12){
			return;
		}

		/* read the token */
		tvb_memcpy(tvb, token, offset, 4);
		offset+=4;

		/* read the parameter */
		if (sscanf(tvb_get_ptr(tvb, offset, 8), "%08x", &parameter) != 1)
			return;
		offset+=8;

		if(!strncmp(token, "DIST", 4)){
			offset=dissect_distcc_dist(tvb, pinfo, tree, offset, parameter);
		} else if(!strncmp(token, "ARGC", 4)){
			offset=dissect_distcc_argc(tvb, pinfo, tree, offset, parameter);
		} else if(!strncmp(token, "ARGV", 4)){
			offset=dissect_distcc_argv(tvb, pinfo, tree, offset, parameter);
		} else if(!strncmp(token, "DOTI", 4)){
			offset=dissect_distcc_doti(tvb, pinfo, tree, offset, parameter);
		} else if(!strncmp(token, "DONE", 4)){
			offset=dissect_distcc_done(tvb, pinfo, tree, offset, parameter);
		} else if(!strncmp(token, "STAT", 4)){
			offset=dissect_distcc_stat(tvb, pinfo, tree, offset, parameter);
		} else if(!strncmp(token, "SERR", 4)){
			offset=dissect_distcc_serr(tvb, pinfo, tree, offset, parameter);
		} else if(!strncmp(token, "SOUT", 4)){
			offset=dissect_distcc_sout(tvb, pinfo, tree, offset, parameter);
		} else if(!strncmp(token, "DOTO", 4)){
			offset=dissect_distcc_doto(tvb, pinfo, tree, offset, parameter);
		} else {
			call_dissector(data_handle, tvb, pinfo, tree);
			return;
		}		
	}


}

/* Register protocol with Wireshark. */
void
proto_register_distcc(void)
{
    static hf_register_info hf[] = {
	{&hf_distcc_version,
	 {"DISTCC Version", "distcc.version",
	  FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
	},
	{&hf_distcc_argc,
	 {"ARGC", "distcc.argc",
	  FT_UINT32, BASE_DEC, NULL, 0x0, "Number of arguments", HFILL }
	},
	{&hf_distcc_argv,
	 {"ARGV", "distcc.argv",
	  FT_STRING, BASE_NONE, NULL, 0x0, "ARGV argument", HFILL }
	},
	{&hf_distcc_doti_source,
	 {"Source", "distcc.doti_source",
	  FT_STRING, BASE_NONE, NULL, 0x0, "DOTI Preprocessed Source File (.i)", HFILL }
	},
	{&hf_distcc_stat,
	 {"Status", "distcc.status",
	  FT_UINT32, BASE_DEC, NULL, 0x0, "Unix wait status for command completion", HFILL }
	},
	{&hf_distcc_serr,
	 {"SERR", "distcc.serr",
	  FT_STRING, BASE_NONE, NULL, 0x0, "STDERR output", HFILL }
	},
	{&hf_distcc_sout,
	 {"SOUT", "distcc.sout",
	  FT_STRING, BASE_NONE, NULL, 0x0, "STDOUT output", HFILL }
	},
	{&hf_distcc_doto_object,
	 {"Object", "distcc.doto_object",
	  FT_BYTES, BASE_NONE, NULL, 0x0, "DOTO Compiled object file (.o)", HFILL }
	}

	};

	static gint *ett[] = {
		&ett_distcc,
	};

	module_t *distcc_module;

	proto_distcc = proto_register_protocol("Distcc Distributed Compiler",
					   "DISTCC", "distcc");
	proto_register_field_array(proto_distcc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	distcc_module = prefs_register_protocol(proto_distcc,
	    proto_reg_handoff_distcc);
	prefs_register_uint_preference(distcc_module, "tcp.port",
				   "DISTCC TCP Port",
				   "Set the TCP port for DISTCC messages",
				   10,
				   &glb_distcc_tcp_port);
	prefs_register_bool_preference(distcc_module, "desegment_distcc_over_tcp",
        "Reassemble DISTCC-over-TCP messages\nspanning multiple TCP segments",
		"Whether the DISTCC dissector should reassemble messages spanning multiple TCP segments."
		" To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
		&distcc_desegment);
}

void
proto_reg_handoff_distcc(void)
{
	static gboolean registered_dissector = FALSE;
	static int distcc_tcp_port;
	static dissector_handle_t distcc_handle;

	if (!registered_dissector) {
		/*
		 * We haven't registered the dissector yet; get a handle
		 * for it.
		 */
		distcc_handle = create_dissector_handle(dissect_distcc,
		    proto_distcc);
		data_handle = find_dissector("data");
		registered_dissector = TRUE;
	} else {
		/*
		 * We've registered the dissector with a TCP port number
		 * of "distcc_tcp_port"; we might be changing the TCP port
		 * number, so remove that registration.
		 */
		dissector_delete_uint("tcp.port", distcc_tcp_port, distcc_handle);
	}
	distcc_tcp_port = glb_distcc_tcp_port;
	dissector_add_uint("tcp.port", distcc_tcp_port, distcc_handle);
}
