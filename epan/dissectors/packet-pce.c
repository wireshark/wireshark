/* packet-pce.c
 * Routines for PCE packet disassembly
 *
 * (c) Copyright 2007 Silvia Cristina Tejedor <silviacristina.tejedor@gmail.com> 
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/dissectors/packet-tcp.h>

#include <epan/prefs.h>
#include "packet-frame.h"

/*differents types of objects*/
#define PCE_OPEN_OBJ			1
#define PCE_RP_OBJ			2
#define PCE_NO_PATH_OBJ			3
#define PCE_END_POINT_OBJ		4
#define PCE_BANDWIDTH_OBJ		5
#define PCE_METRIC_OBJ			6
#define PCE_EXPLICIT_ROUTE_OBJ		7
#define PCE_RECORD_ROUTE_OBJ		8
#define PCE_LSPA_OBJ			9
#define PCE_IRO_OBJ			10
#define PCE_SVEC_OBJ			11
#define PCE_NOTIFICATION_OBJ		12
#define PCE_PCEP_ERROR_OBJ		13
#define PCE_LOAD_BALANCING_OBJ		14
#define PCE_CLOSE_OBJ			15
#define NO_DEFINED_OBJ			16
#define PCE_XRO_OBJ			17

/*Subobjects of EXPLICIT ROUTE Object*/
#define PCE_SUB_IPv4			1
#define PCE_SUB_IPv6			2	
#define PCE_SUB_LABEL_CONTROL		3	
#define PCE_SUB_UNNUMB_INTERFACE_ID	4
#define PCE_SUB_SRLG			5	
#define PCE_SUB_AUTONOMOUS_SYS_NUM	32
#define PCE_SUB_EXRS			33
#define PCE_SUB_AUTONOMOUS_SYS_NUM_XRO	4
#define PCE_SUB_UNNUMB_INTERFACE_ID_XRO	3
	
/*Possible values of the NI in the NO-PATH object*/
#define NO_SATISFYING			0
#define CHAIN_BROKEN			1

/*Possible values of "Type (T)" in the METRIC object */
#define NO_DEFINED			0
#define IGP_METRIC			1
#define TE_METRIC			2
#define HOP_COUNTS			3

/*Possible values of L in the ERO and IRO objects */
#define STRICT_HOP			0
#define LOOSE_HOP			1

/*Possible values of U in the ERO and RRO objects */
#define DOWNSTREAM_LABEL		0
#define UPSTREAM_LABEL			1

/*Possible values of Notification Type */
#define NOT_REQ_CANCEL			1
#define PCE_CONGESTION			2

/*Possible values of Notification Value for NT=1*/
#define NOTI_PCC_CANCEL_REQ		1	
#define NOTI_PCE_CANCEL_REQ		2

/*Possible values of Notification Value for NT=2*/
#define NOTI_PCE_CONGEST		1	
#define NOTI_PCE_NO_CONGEST		2

/*Possible types of errors */
#define ESTABLISH_FAILURE		1
#define CAP_NOT_SUPPORTED		2
#define UNKNOWN_OBJ			3	
#define NOT_SUPP_OBJ			4
#define POLICY_VIOLATION		5
#define MANDATORY_OBJ_MIS		6	
#define SYNCH_PCREQ_MIS			7	
#define UNKNOWN_REQ_REF			8
#define ATTEMPT_2_SESSION		9
#define UNRECO_IRO_SUBOBJ		11
#define UNRECO_EXRS_SUBOBJ		12

/*Different values of errors type=1*/
#define RX_MALFORM_PKT			1
#define NO_OPEN_MSG			2
#define UNACEP_NO_NEGO_SSESION		3
#define UNACEP_NEG_SESSION		4	
#define TWO_OPEN_MSG_UNACEP		5
#define RX_PCEERR_UNACEP_SESSION	6	
#define NO_KEEPALIVE_PCEERR		7

/*Different values of errors type=3*/
#define UNRECON_OBJ_CLASS		1
#define UNRECON_OBJ_TYPE		2

/*Different values of errors type=4*/
#define NO_SUPP_OBJ			1
#define NO_SUPP_TYPE			2

/*Different values of errors type=5*/
#define C_METRIC_SET			1
#define O_OBJ_SET			2

/*Different values of errors type=6*/
#define RP_OBJ_MISS			1
#define RRO_OBJ_MISS			2
#define END_POINT_OBJ_MISS		3

/*Different values of Reason in the CLOSE object */
#define NO_EXP_PROV			1
#define DEADTIME_PROV			2
#define RECEP_MALFORM_MSG		3 

/*Different values of Atribute in the XRO object */
#define INTERFACE			0
#define NODE				1
#define SRLG				2

/*Mask for the flags of HEADER of Messages*/
#define  PCE_HDR_MSG_RESERVED		0x1f

/*Mask for the type of HEADER of Objects*/
#define  MASK_OBJ_TYPE			0xF0

/*Mask for the flags of HEADER of Objects*/
#define  PCE_HDR_OBJ_RESERVED		0x0C
#define  PCE_HDR_OBJ_P			0x02
#define  PCE_HDR_OBJ_I			0x01

/*Mask for the flags of OPEN Object*/
#define  PCE_OPEN_RES			0x1F

/*Mask for the flags of RP Object*/
#define  PCE_RP_PRI			0x000007
#define  PCE_RP_R			0x000008
#define  PCE_RP_B			0x000010
#define  PCE_RP_O			0x000020
#define  PCE_RP_RESERVED		0xFFFFC0

/*Mask for the flags of NO PATH Object*/
#define  PCE_NO_PATH_C			0x8000

/*Mask for the flags of METRIC Object*/
#define  PCE_METRIC_C			0x01
#define  PCE_METRIC_B			0x02

/*Mask for the flags of LSPA Object*/
#define  PCE_LSPA_L			0x01

/* Mask to differentiate the value of L and Type (Explicit Object)*/
#define Mask_L				0x80
#define Mask_Type			0x7f

#define TCP_PORT_PPCE			1010 	

#define IPv4				1
#define IPv6				2

/*Mask for the flags os SVEC Object*/
#define  PCE_SVEC_L			0x000001
#define  PCE_SVEC_N			0x000002
#define  PCE_SVEC_S			0x000004

/*Mask for the flags of XRO Object*/
#define  PCE_XRO_F			0x0001

/*Mask for the flags of IPv4, IPv6 and UNnumbered InterfaceID Subobjects of RRO Object*/
#define PCE_SUB_LPA			0x01
#define PCE_SUB_LPU			0x02

/*Mask for the flags of Label SubObject*/
#define PCE_SUB_LABEL_GL		0x01


static int proto_pce = -1;
static gint ett_pce = -1;
static gint ett_pce_hdr = -1;
static gint pce_hdr_msg_flags_reserved= -1;
static gint ett_pce_msg_open = -1;
static gint ett_pce_msg_keepalive = -1;
static gint ett_pce_msg_request = -1;
static gint ett_pce_msg_reply = -1;
static gint ett_pce_msg_notification = -1;
static gint ett_pce_msg_error = -1;
static gint ett_pce_msg_close = -1;
static gint ett_pce_obj_hdr = -1;
static gint pce_hdr_obj_flags_reserved= -1;
static gint pce_hdr_obj_flags_p= -1;
static gint pce_hdr_obj_flags_i= -1;
static gint ett_pce_obj_open = -1;
static gint pce_open_flags_res = -1;
static gint ett_pce_obj_request_parameters = -1;
static gint pce_rp_flags_pri = -1;
static gint pce_rp_flags_r = -1;
static gint pce_rp_flags_b = -1;
static gint pce_rp_flags_o = -1;
static gint pce_rp_flags_reserved = -1;
static gint ett_pce_obj_no_path = -1;
static gint pce_no_path_flags_c = -1;
static gint ett_pce_obj_end_point = -1;
static gint ett_pce_obj_bandwidth = -1;
static gint ett_pce_obj_metric = -1;
static gint pce_metric_flags_c = -1;
static gint pce_metric_flags_b = -1;
static gint ett_pce_obj_explicit_route = -1;
static gint ett_pce_obj_record_route = -1;
static gint ett_pce_obj_lspa = -1;
static gint pce_lspa_flags_l= -1;
static gint ett_pce_obj_iro = -1;
static gint ett_pce_obj_svec = -1;
static gint pce_svec_flags_l= -1;
static gint pce_svec_flags_n= -1;
static gint pce_svec_flags_s= -1;
static gint ett_pce_obj_notification = -1;
static gint ett_pce_obj_error = -1;
static gint ett_pce_obj_load_balancing = -1;
static gint ett_pce_obj_close = -1;
static gint ett_pce_obj_xro = -1;
static gint pce_xro_flags_f= -1;
static gint pce_subobj_flags_lpa= -1;
static gint pce_subobj_flags_lpu= -1;
static gint pce_subobj_label_flags_gl= -1;
static dissector_table_t pce_dissector_table;
static dissector_handle_t data_handle;

/* PCE message types.*/
typedef enum {
	PCE_MSG_NO_VALID,
	PCE_MSG_OPEN,
	PCE_MSG_KEEPALIVE, 
	PCE_MSG_PATH_COMPUTATION_REQUEST,
	PCE_MSG_PATH_COMPUTATION_REPLY,	
	PCE_MSG_NOTIFICATION,		
	PCE_MSG_ERROR,	
	PCE_MSG_CLOSE   
} pce_message_types;
    
static const value_string message_type_vals[] = {
	{PCE_MSG_OPEN,				"OPEN MESSAGE"				},
	{PCE_MSG_KEEPALIVE, 			"KEEPALIVE MESSAGE"			},
	{PCE_MSG_PATH_COMPUTATION_REQUEST,	"PATH COMPUTATION REQUEST MESSAGE"	},
	{PCE_MSG_PATH_COMPUTATION_REPLY,	"PATH COMPUTATION REPLY MESSAGE"        },
	{PCE_MSG_NOTIFICATION,			"NOTIFICATION MESSAGE"			},
	{PCE_MSG_ERROR,				"ERROR MESSAGE"			  	},	
	{PCE_MSG_CLOSE,				"CLOSE MESSAGE"			  	},
	{0,			         	NULL            		  	}
};

static const value_string pce_class_vals[] = {
	{PCE_OPEN_OBJ,			"OPEN OBJECT" 			},
	{PCE_RP_OBJ, 			"RP OBJECT"			},
	{PCE_NO_PATH_OBJ,		"NO-PATH OBJECT"		},
	{PCE_END_POINT_OBJ,		"END-POINT OBJECT"      	},
	{PCE_BANDWIDTH_OBJ,		"BANDWIDTH OBJECT"		},
	{PCE_METRIC_OBJ,		"METRIC OBJECT"			},	
	{PCE_EXPLICIT_ROUTE_OBJ,	"EXPLICIT ROUTE OBJECT (ERO)"	},	
	{PCE_RECORD_ROUTE_OBJ,		"RECORD ROUTE OBJECT (RRO)"	}, 
	{PCE_LSPA_OBJ,			"LSPA OBJECT"			},
	{PCE_IRO_OBJ,			"IRO OBJECT"			},
	{PCE_SVEC_OBJ,			"SVEC OBJECT"			},
	{PCE_NOTIFICATION_OBJ,		"NOTIFICATION OBJECT"		},
	{PCE_PCEP_ERROR_OBJ,		"PCEP ERROR OBJECT"		},
	{PCE_LOAD_BALANCING_OBJ,	"LOAD BALANCING OBJECT"		},
	{PCE_CLOSE_OBJ,			"CLOSE OBJECT"			},
	{NO_DEFINED_OBJ,		"Non Defined OBJECT"		},
	{PCE_XRO_OBJ,			"EXCLUDE ROUTE OBJECT (XRO)"	},
	{0,			         NULL            		}
};

static const value_string pce_subobj_vals[] = {
	{PCE_SUB_IPv4,			"SUBOBJECT IPv4" 			},
	{PCE_SUB_IPv6, 			"SUBOBJECT IPv6"			},
	{PCE_SUB_LABEL_CONTROL,		"SUBOBJECT LABEL"			},
	{PCE_SUB_UNNUMB_INTERFACE_ID,	"SUBOBJECT UNNUMBERED INTERFACE-ID"	},
	{PCE_SUB_SRLG,			"SUBOBJECT SRLG"      			},
	{PCE_SUB_AUTONOMOUS_SYS_NUM,	"SUBOBJECT AUTONOMOUS SYSTEM NUMBER"	},
	{0,			         NULL            			}
};


static const value_string pce_subobj_xro_vals[] = {
	{PCE_SUB_IPv4,			"SUBOBJECT IPv4" 			},
	{PCE_SUB_IPv6, 			"SUBOBJECT IPv6"			},
	{PCE_SUB_UNNUMB_INTERFACE_ID_XRO,"SUBOBJECT UNNUMBERED INTERFACE-ID"	}, 
	{PCE_SUB_AUTONOMOUS_SYS_NUM_XRO,"SUBOBJECT AUTONOMOUS SYSTEM NUMBER"	},
	{PCE_SUB_SRLG,			"SUBOBJECT SRLG"      			},
	{0,			         NULL            			}
};

/*In the NO-PATH Object the two different possibilities that NI can have*/ 
static const value_string pce_no_path_obj_vals[] = {
	{NO_SATISFYING, 		"Nature of Issue: No path satisfying the set of constraints could be found (0x0)"	},
	{CHAIN_BROKEN,			"Nature of Issue: PCE Chain Broken (0x1)"						},
	{0,			         NULL            									}
};

/*Different values of "Type (T)" in the METRIC Obj */ 	
static const value_string pce_metric_obj_vals[] = {
	{NO_DEFINED,	 	"Type not defined"		},
	{IGP_METRIC, 		"Type: IGP Metric (T=1)"	},
	{TE_METRIC,		"Type: TE Metric (T=2)"		},
	{HOP_COUNTS,		"Type: Hop Counts (T=3)"	},	
	{0,		         NULL 				}
};

/*Different values for (L) in the ERO and IRO Objs */ 
static const value_string pce_route_l_obj_vals[] = {
	{STRICT_HOP,			"L=0 Strict Hop in the Explicit Route"		},
	{LOOSE_HOP, 			"L=1 Loose Hop in the Explicit Route"	 	},
	{0,			         NULL            				}
};

/*Different values of the direction of the label (U) in the ERO and RRO Objs */ 
static const value_string pce_route_u_obj_vals[] = {
	{DOWNSTREAM_LABEL,			"U=0 S Downstream Label" },
	{UPSTREAM_LABEL, 			"U=1 Upstream Label"	 },
	{0,			        	NULL			 }
};

/*Values of Notification type*/
static const value_string pce_notification_types_vals[] = {
	{NOT_REQ_CANCEL,		"Pending Request Cancelled"	},
	{PCE_CONGESTION, 		"PCE Congestion" 		},
	{0,			         NULL            					}
};

/*Values of Notification value for Notification Type=1*/
static const value_string pce_notification_values1_vals[] = {
	{NOTI_PCC_CANCEL_REQ,		"PCC Cancels a set of Pending Request (s)"	},
	{NOTI_PCE_CANCEL_REQ, 		"PCE Cancels a set of Pending Request (s)"	},
	{0,			         NULL            				}
};

/*Values of Notification value for Notification Type=2*/
static const value_string pce_notification_values2_vals[] = {
	{NOTI_PCE_CONGEST,		"PCE in Congested State "		},
	{NOTI_PCE_NO_CONGEST, 		"PCE no Longer in Congested state"	},
	{0,			         NULL          				}
};


/*Values of different types of errors*/
static const value_string pce_error_types_obj_vals[] = {
	{ESTABLISH_FAILURE,		"1 PCEP Session Establishment Failure"		},
	{CAP_NOT_SUPPORTED, 		"2 Capability non supported" 			},
	{UNKNOWN_OBJ, 			"3 Unknown Object"					},
	{NOT_SUPP_OBJ, 			"4 Not Supported Object"				},
	{POLICY_VIOLATION, 		"5 Policy Violation"				},
	{MANDATORY_OBJ_MIS, 		"6 Mandatory Object Missing"			},
	{SYNCH_PCREQ_MIS, 		"7 Synchronized Path Computation Request Missing"	},
	{UNKNOWN_REQ_REF, 		"8 Unknown Request Reference"			},
	{ATTEMPT_2_SESSION, 		"9 Attempt to Establish a Second PCEP Session"	},
	{UNRECO_IRO_SUBOBJ, 		"11 Unrecognized IRO Subobject"	},
	{UNRECO_EXRS_SUBOBJ, 		"12 Unrecognized EXRS Subobject"	},
	{0,			         NULL            					}
};

static const value_string pce_close_reason_obj_vals[] = {
	{NO_DEFINED,	 		"Reason = 0 no defined"					},
	{NO_EXP_PROV,			"Reason = 1 No Explanation Provided "			},
	{DEADTIME_PROV, 		"Reason = 2 Deadtime Expired"	 			},
	{RECEP_MALFORM_MSG, 		"Reason = 3 Reception of a Malformed PCEP Message"	},
	{0,			         NULL            					}
};

static const value_string pce_xro_atribute_obj_vals[] = {
	{INTERFACE,	 	"Atribute = 0 Interface"	},
	{NODE,			"Atribute = 1 Node "		},
	{SRLG, 			"Atribute = 2 SRLG"		},
	{0,			         NULL           	}
};

/* The PCE filtering keys */
enum pce_filter_keys{

    PCEF_MSG,
    
    PCEF_OPEN,
    PCEF_KEEPALIVE,
    PCEF_PATH_COMPUTATION_REQUEST,
    PCEF_PATH_COMPUTATION_REPLY,
    PCEF_NOTIFICATION,
    PCEF_ERROR,
    PCEF_CLOSE,     
    
    PCEF_OBJ_HEADER,
    PCEF_OBJECT,
    PCEF_OBJ_OPEN,
    PCEF_OBJ_RP,
    PCEF_OBJ_NO_PATH,
    PCEF_OBJ_END_POINT,
    PCEF_OBJ_BANDWIDTH,
    PCEF_OBJ_METRIC,
    PCEF_OBJ_EXPLICIT_ROUTE,
    PCEF_OBJ_RECORD_ROUTE,
    PCEF_OBJ_LSPA,
    PCEF_OBJ_IRO,
    PCEF_OBJ_SVEC,
    PCEF_OBJ_NOTIFICATION,
    PCEF_NOTI_TYPE,
    PCEF_NOTI_VAL1,
    PCEF_NOTI_VAL2,
    PCEF_OBJ_PCEP_ERROR,
    PCEF_ERROR_TYPE,
    PCEF_OBJ_LOAD_BALANCING,
    PCEF_OBJ_CLOSE,
    PCEF_OBJ_NO_DEF,
    PCEF_OBJ_XRO,
    PCEF_SUBOBJ,
    PCEF_SUBOBJ_IPv4,
    PCEF_SUBOBJ_IPv6,
    PCEF_SUBOBJ_LABEL_CONTROL,
    PCEF_SUBOBJ_UNNUM_INTERFACEID,
    PCEF_SUBOBJ_AUTONOMOUS_SYS_NUM,
    PCEF_SUBOBJ_SRLG,
    PCEF_SUBOBJ_EXRS,
    PCEF_SUBOBJ_XRO,
    PCEF_SUB_XRO_ATRIB,
       
    PCEF_MAX
     
};


/*Registering data structures*/

static gint *ett[] = {
	&ett_pce,
	&ett_pce_hdr,
	&ett_pce_msg_open,
	&ett_pce_msg_keepalive,
	&ett_pce_msg_request,
	&ett_pce_msg_reply,
        &ett_pce_msg_notification,
	&ett_pce_msg_error,
	&ett_pce_msg_close,
	&ett_pce_obj_hdr,
	&ett_pce_obj_open,
	&ett_pce_obj_request_parameters,
	&ett_pce_obj_no_path,
	&ett_pce_obj_end_point,
        &ett_pce_obj_bandwidth,
        &ett_pce_obj_metric,
        &ett_pce_obj_explicit_route,
        &ett_pce_obj_record_route,
        &ett_pce_obj_lspa,
	&ett_pce_obj_iro,
	&ett_pce_obj_svec,
	&ett_pce_obj_notification,
	&ett_pce_obj_error,
	&ett_pce_obj_load_balancing,
	&ett_pce_obj_close, 
	&ett_pce_obj_xro
};
    
/*Registering data structures*/    

static int pce_filter[PCEF_MAX];

static hf_register_info pcef_info[] = {

    /* Message type number */
   {&pce_filter[PCEF_MSG],
     { "Message Type", "pce.msg", FT_UINT8, BASE_DEC, VALS(message_type_vals), 0x0,
     	"", HFILL }},
		{ &pce_hdr_msg_flags_reserved,
		{ "Reserved Flags", "pce.hdr.msg.flags.reserved", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCE_HDR_MSG_RESERVED,
			"", HFILL }},     	
    {&pce_filter[PCEF_OPEN],
     { "Open Message", "pce.msg.open", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
    {&pce_filter[PCEF_KEEPALIVE],
     { "Keepalive Message", "pce.msg.keepalive", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
    {&pce_filter[PCEF_PATH_COMPUTATION_REQUEST],
     { "Path Computation Request Message", "pce.msg.path.computation.request", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
    {&pce_filter[PCEF_PATH_COMPUTATION_REPLY],
     { "Path Computation Reply Mesagge", "pce.msg.path.computation.reply", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
    {&pce_filter[PCEF_NOTIFICATION],
     { "Notification Message", "pce.msg.notification", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "", HFILL }},
    {&pce_filter[PCEF_ERROR],
     { "Error Message", "pce.msg.error", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "", HFILL }},
      {&pce_filter[PCEF_CLOSE],
     { "Close Message", "pce.msg.close", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "", HFILL }},    

	/*Object header*/
		{ &pce_hdr_obj_flags_reserved,
		{ "Reserved Flags", "pce.hdr.obj.flags.reserved", FT_BOOLEAN, 4, TFS(&tfs_set_notset), PCE_HDR_OBJ_RESERVED,
			"", HFILL }},
		{ &pce_hdr_obj_flags_p,
		{ "Processing-Rule (P)", "pce.hdr.obj.flags.p", FT_BOOLEAN, 4, TFS(&tfs_set_notset), PCE_HDR_OBJ_P,
			"", HFILL }},
		{ &pce_hdr_obj_flags_i,
		{ "Ignore (I)", "pce.hdr.obj.flags.i", FT_BOOLEAN, 4, TFS(&tfs_set_notset), PCE_HDR_OBJ_I,
			"", HFILL }},	
    /* Object class */
    {&pce_filter[PCEF_OBJECT],
     { "Object Class", "pce.object", FT_UINT32, BASE_DEC, VALS(pce_class_vals), 0x0,
     	"", HFILL }},
	
    /* Object types */
    {&pce_filter[PCEF_OBJ_OPEN],
     { "PCE OPEN OBJECT Body", "pce.obj.open", FT_NONE, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
		{ &pce_open_flags_res,
		{ "Reserved Flags", "pce.open.flags.res", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCE_OPEN_RES,
			"", HFILL }},
    {&pce_filter[PCEF_OBJ_RP],
     { "PCE RP OBJECT Body", "pce.obj.rp", FT_NONE, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
		{ &pce_rp_flags_reserved,
		{ "Reserved Flags", "pce.rp.flags.reserved", FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCE_RP_RESERVED,
			"", HFILL }},
		{ &pce_rp_flags_pri,
		{ "Priority (PRI)", "pce.rp.flags.pri", FT_BOOLEAN, 24, TFS(&tfs_on_off), PCE_RP_PRI,
			"", HFILL }},
		{ &pce_rp_flags_r,
		{ "Reoptimization (R)", "pce.rp.flags.r", FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCE_RP_R,
			"", HFILL }},
		{ &pce_rp_flags_b,
		{ "Bi-directional (L)", "pce.rp.flags.b", FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCE_RP_B,
			"", HFILL }},
		{ &pce_rp_flags_o,
		{ "Strict/Loose (L)", "pce.rp.flags.o", FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCE_RP_O,
			"", HFILL }},
    {&pce_filter[PCEF_OBJ_NO_PATH],
     { "PCE NO PATH OBJECT Body", "pce.obj.nopath", FT_NONE, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
		{ &pce_no_path_flags_c,
		{ "C", "pce.no.path.flags.c", FT_BOOLEAN, 16, TFS(&tfs_set_notset), PCE_NO_PATH_C,
			"", HFILL }},
    {&pce_filter[PCEF_OBJ_END_POINT],
     { "PCE END POINT OBJECT Body", "pce.obj.endpoint", FT_NONE, BASE_NONE, NULL, 0x0,
     	"", HFILL }},	
    {&pce_filter[PCEF_OBJ_BANDWIDTH],
     { "PCE BANDWIDTH OBJECT Body", "pce.obj.bandwidth", FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL }},
    {&pce_filter[PCEF_OBJ_METRIC],
     { "PCE METRIC OBJECT Body", "pce.obj.metric", FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL }},
		{ &pce_metric_flags_c,
		{ "Cost (C)", "pce.metric.flags.c", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCE_METRIC_C,
			"", HFILL }},
		{ &pce_metric_flags_b,
		{ "Bound (B)", "pce.metric.flags.b", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCE_METRIC_B,
			"", HFILL }},
      {&pce_filter[PCEF_OBJ_EXPLICIT_ROUTE],
     { "PCE EXPLICIT ROUTE OBJECT (ERO) Body", "pce.obj.ero", FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL }},
      {&pce_filter[PCEF_OBJ_RECORD_ROUTE],
     { "PCE RECORD ROUTE OBJECT (RRO) Body", "pce.obj.rro", FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL }},     
      {&pce_filter[PCEF_OBJ_LSPA],
     { "PCE LSPA OBJECT Body", "pce.obj.lspa", FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL }},    
		{ &pce_lspa_flags_l,
		{ "Local Protection Desired (L)", "pce.lspa.flags.l", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCE_LSPA_L,
			"", HFILL }},
      {&pce_filter[PCEF_OBJ_IRO],
     { "PCE IRO OBJECT Body", "pce.obj.iro", FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL }},     
      {&pce_filter[PCEF_OBJ_SVEC],
     { "PCE SVEC OBJECT Body", "pce.obj.svec", FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL }},  
		
		{ &pce_svec_flags_l,
		{ "Link diverse (L)", "pce.svec.flags.l", FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCE_SVEC_L,
			"", HFILL }},

		{ &pce_svec_flags_n,
		{ "Node diverse (N)", "pce.svec.flags.n", FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCE_SVEC_N,
			"", HFILL }},

		{ &pce_svec_flags_s,
		{ "SRLG diverse (S)", "pce.svec.flags.s", FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCE_SVEC_S,
			"", HFILL }},		
	   
      {&pce_filter[PCEF_OBJ_NOTIFICATION],
     { "PCE NOTIFICATION OBJECT Body", "pce.obj.notification", FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL }},   
	
      {&pce_filter[PCEF_NOTI_TYPE],
     { "Notification Value", "pce.notification.value1", FT_UINT32, BASE_DEC, VALS(pce_notification_types_vals), 0x0,
     	"", HFILL }},
      {&pce_filter[PCEF_NOTI_VAL1],
     { "Notification Type", "pce.notification.type2", FT_UINT32, BASE_DEC, VALS(pce_notification_values1_vals), 0x0,
     	"", HFILL }},
      {&pce_filter[PCEF_NOTI_VAL2],
     { "Notification Type", "pce.notification.type", FT_UINT32, BASE_DEC, VALS(pce_notification_values2_vals), 0x0,
     	"", HFILL }},
	  
      {&pce_filter[PCEF_OBJ_PCEP_ERROR],
     { "PCE ERROR OBJECT Body", "pce.obj.error", FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL }},   
      {&pce_filter[PCEF_ERROR_TYPE],
     { "Error-Type", "pce.error.type", FT_UINT8, BASE_DEC, VALS(pce_error_types_obj_vals), 0x0,
     	"", HFILL }},  
      {&pce_filter[PCEF_OBJ_LOAD_BALANCING],
     { "PCE LOAD BALANCING OBJECT Body", "pce.obj.load.balancing", FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL }},     
      {&pce_filter[PCEF_OBJ_CLOSE],
     { "PCE CLOSE OBJECT Body", "pce.obj.close", FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL }}, 	
	{&pce_filter[PCEF_OBJ_NO_DEF],
     { "NO DEFINED OBJECT", "pce.obj.no.defined", FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL }}, 
	{&pce_filter[PCEF_OBJ_XRO],
     { "PCE EXCLUDE ROUTE OBJECT (XRO) Body", "pce.obj.xro", FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL }},
	
	/*SUbobjects*/	
	{&pce_filter[PCEF_SUBOBJ],
     { "Type", "pce.subobj", FT_UINT8, BASE_DEC, VALS(pce_subobj_vals), 0x0,
        "", HFILL }}, 
	
        {&pce_filter[PCEF_SUBOBJ_IPv4],
     { "SUBOBJECT: IPv4 Prefix", "pce.subobj.ipv4", FT_NONE, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
        {&pce_filter[PCEF_SUBOBJ_IPv6],
     { "SUBOBJECT: IPv6 Prefix", "pce.subobj.ipv6", FT_NONE, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
	{&pce_filter[PCEF_SUBOBJ_LABEL_CONTROL],
     { "SUBOBJECT: Label Control", "pce.subobj.label.control", FT_NONE, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
	{&pce_filter[PCEF_SUBOBJ_UNNUM_INTERFACEID],
     { "SUBOBJECT: Unnumbered Interface ID", "pce.subobj.unnum.interfaceid", FT_NONE, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
	{&pce_filter[PCEF_SUBOBJ_AUTONOMOUS_SYS_NUM],
     { "SUBOBJECT: Autonomous System Number", "pce.subobj.auntonomus.sys.num", FT_NONE, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
	{&pce_filter[PCEF_SUBOBJ_SRLG],
     { "SUBOBJECT: SRLG", "pce.subobj.srlg", FT_NONE, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
	{&pce_filter[PCEF_SUBOBJ_EXRS],
     { "SUBOBJECT: EXRS", "pce.subobj.exrs", FT_NONE, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
	{&pce_filter[PCEF_SUBOBJ_XRO],

     { "Type", "pce.subobj.label", FT_UINT32, BASE_DEC, VALS(pce_subobj_xro_vals), 0x0,
        "", HFILL }},
		{ &pce_xro_flags_f,
		{ "Fail (F)", "pce.xro.flags.f", FT_BOOLEAN, 16, TFS(&tfs_set_notset), PCE_XRO_F,
			"", HFILL }},
	{&pce_filter[PCEF_SUB_XRO_ATRIB],
     { "Attribute", "pce.xro.sub.atribute", FT_UINT32, BASE_DEC, VALS(pce_xro_atribute_obj_vals), 0x0,
	"", HFILL }},
	
		{ &pce_subobj_flags_lpa,
		{ "Local Protection Available", "pce.subobj.flags.lpa", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCE_SUB_LPA,
			"", HFILL }},
		{ &pce_subobj_flags_lpu,
		{ "Local protection in Use", "pce.subobj.flags.lpu", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCE_SUB_LPU,
			"", HFILL }},	
		{ &pce_subobj_label_flags_gl,
		{ "Global Label", "pce.subobj.label.flags.gl", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCE_SUB_LABEL_GL,
			"", HFILL }},	

};


static void
dissect_pce_tlv(proto_item *ti, proto_tree *pce_obj, tvbuff_t *tvb, int *offset2, gint hdr_obj, gint body_obj_obl, gint obj_length, gint ett_pce_obj, gint *len){
	
	proto_tree *tlv;
	guint16 tlv_length = 0;
	guint16 tlv_type;
	int j = 0;
	int m  = 0;
	int padding = 0;	
	if (obj_length>(hdr_obj+body_obj_obl)){	

		for(j=0; j<(obj_length - (hdr_obj+body_obj_obl)); ){
		m=m+1;
		
			tlv_type = tvb_get_ntohs(tvb, *offset2+j);
			tlv_length = tvb_get_ntohs(tvb, *offset2 + j + 2);
			ti = proto_tree_add_text(pce_obj, tvb, *offset2 + j, tlv_length+4, "TLV %u", m);
			tlv = proto_item_add_subtree(ti, ett_pce_obj);
			proto_tree_add_text(tlv, tvb, *offset2 + j, 2, "Type: %u", tlv_type);
			proto_tree_add_text(tlv, tvb, *offset2 + 2 + j, 2, "Length: %u", tlv_length);
			proto_tree_add_text(tlv, tvb, *offset2+4+j, tlv_length, "Data: %s", 
					bytestring_to_str(tvb_get_ptr(tvb, (*offset2) + 4 + j, tlv_length), tlv_length, ' '));
			padding = (4 - (tlv_length % 4)) % 4;
			if (padding != 0){
				proto_tree_add_text(tlv, tvb, *offset2+4+j+tlv_length, padding, "Padding: %s", 
					bytestring_to_str(tvb_get_ptr(tvb, (*offset2) + 4 + j + tlv_length, padding), padding, ' '));
		
			}	
			j=(j + tlv_length + 4 + padding);	
		}
		
	*offset2 = (*offset2) + obj_length - (hdr_obj+body_obj_obl);	
	*len = *len + obj_length - hdr_obj; 

	}	 
	else 
	*len = (*len) + body_obj_obl;
	
};

/*------------------------------------------------------------------------------
 *SUBOBJECTS
 *------------------------------------------------------------------------------*/
static void
dissect_subobj_ipv4(proto_item *ti, proto_tree *pce_subobj_tree, tvbuff_t *tvb, int *offset2, int *len, int obj_class, gint ett_pce_obj, guint l_and_or_type, guint length){

	proto_tree *pce_subobj_ipv4;
	proto_tree *pce_subobj_ipv4_flags;
	guint8 prefix_length;
	guint8 resvd;
	guint l;
	prefix_length = tvb_get_guint8(tvb, *offset2+6);
	resvd = tvb_get_guint8(tvb, *offset2+7);
		
	ti = proto_tree_add_item(pce_subobj_tree, pce_filter[PCEF_SUBOBJ_IPv4], tvb, *offset2, length, FALSE);
	pce_subobj_ipv4 = proto_item_add_subtree(ti, ett_pce_obj);
	
	switch(obj_class){
	
	case PCE_EXPLICIT_ROUTE_OBJ:
	l = (l_and_or_type& Mask_L)>>7;
	proto_tree_add_text(pce_subobj_ipv4, tvb, *offset2, 1, val_to_str(l, pce_route_l_obj_vals, "Unknown Object (%u). "));
	proto_tree_add_uint(pce_subobj_ipv4, pce_filter[PCEF_SUBOBJ], tvb, *offset2, 1, (l_and_or_type & 0x7f));
	proto_tree_add_text(pce_subobj_ipv4, tvb, *offset2+1, 1, "Length: %u", length);
	proto_tree_add_text(pce_subobj_ipv4, tvb, *offset2+2, 4, "IPv4 Address: (%s)", ip_to_str(tvb_get_ptr(tvb, *offset2+2, 4)));
	proto_tree_add_text(pce_subobj_ipv4, tvb, *offset2+6, 1, "Prefix Length: %u", prefix_length);	
	proto_tree_add_text(pce_subobj_ipv4, tvb, *offset2+7, 1, "Padding: 0x%02x", resvd);	
	break;
	
	case PCE_RECORD_ROUTE_OBJ:
	proto_tree_add_uint(pce_subobj_ipv4, pce_filter[PCEF_SUBOBJ], tvb, *offset2, 1, l_and_or_type);
	proto_tree_add_text(pce_subobj_ipv4, tvb, *offset2+1, 1, "Length: %u", length);
	proto_tree_add_text(pce_subobj_ipv4, tvb, *offset2+2, 4, "IPv4 Address: (%s)", ip_to_str(tvb_get_ptr(tvb, *offset2+2, 4)));
	proto_tree_add_text(pce_subobj_ipv4, tvb, *offset2+6, 1, "Prefix Length: %u", prefix_length);	
	ti = proto_tree_add_text(pce_subobj_ipv4, tvb, *offset2+7, 1, "Flags: 0x%02x ", resvd);
	pce_subobj_ipv4_flags = proto_item_add_subtree(ti, ett_pce_obj);
	proto_tree_add_boolean(pce_subobj_ipv4_flags, pce_subobj_flags_lpa, tvb, *offset2+7, 1, resvd);
	proto_tree_add_boolean(pce_subobj_ipv4_flags, pce_subobj_flags_lpu, tvb, *offset2+7, 1, resvd);
	break;
	
	case PCE_IRO_OBJ:
	proto_tree_add_text(pce_subobj_ipv4, tvb, *offset2, 1, "l: %x", (l_and_or_type & 0x80)>>7);
	proto_tree_add_uint(pce_subobj_ipv4, pce_filter[PCEF_SUBOBJ], tvb, *offset2, 1, (l_and_or_type & 0x7f));
	proto_tree_add_text(pce_subobj_ipv4, tvb, *offset2+1, 1, "Length: %u", length);
	proto_tree_add_text(pce_subobj_ipv4, tvb, *offset2+2, 4, "IPv4 Address: (%s)", ip_to_str(tvb_get_ptr(tvb, *offset2+2, 4)));
	proto_tree_add_text(pce_subobj_ipv4, tvb, *offset2+6, 1, "Prefix Length: %u", prefix_length);	
	proto_tree_add_text(pce_subobj_ipv4, tvb, *offset2+7, 1, "Padding: 0x%02x", resvd);
	break;
	
	case PCE_XRO_OBJ:
	proto_tree_add_text(pce_subobj_ipv4, tvb, *offset2, 1, "X: %x", (l_and_or_type & 0x01)>>7);
	proto_tree_add_uint(pce_subobj_ipv4, pce_filter[PCEF_SUBOBJ_XRO], tvb, *offset2, 1, (l_and_or_type & 0x7f));
	proto_tree_add_text(pce_subobj_ipv4, tvb, *offset2, 1, "Type: %u", (l_and_or_type & 0x7f));
	proto_tree_add_text(pce_subobj_ipv4, tvb, *offset2+1, 1, "Length: %u", length);
	proto_tree_add_text(pce_subobj_ipv4, tvb, *offset2+2, 4, "IPv4 Address: (%s)", ip_to_str(tvb_get_ptr(tvb, *offset2+2, 4)));
	proto_tree_add_text(pce_subobj_ipv4, tvb, *offset2+6, 1, "Prefix Length: %u", prefix_length);	
	proto_tree_add_text(pce_subobj_ipv4, tvb, *offset2+7, 1, val_to_str(resvd, pce_xro_atribute_obj_vals, "Unknown Atribute (%u). "));
	break;
	
	default:
	proto_tree_add_text(pce_subobj_ipv4, tvb, *offset2, 8, "Non defined subobject for this object");
	break;
	}
	
	*len = *len + 8;
	*offset2 = *offset2 + 8;
}

static void
dissect_subobj_ipv6(proto_item *ti, proto_tree *pce_subobj_tree, tvbuff_t *tvb, int *offset2, int *len, int obj_class, gint ett_pce_obj, guint l_and_or_type, guint length){

	proto_tree *pce_subobj_ipv6;
	proto_tree *pce_subobj_ipv6_flags;
	guint8 prefix_length;
	guint8 resv;
	int l;
	
	prefix_length = tvb_get_guint8(tvb, *offset2+18);
	resv = tvb_get_guint8(tvb, *offset2+19);
	ti = proto_tree_add_item(pce_subobj_tree, pce_filter[PCEF_SUBOBJ_IPv6], tvb, *offset2, length, FALSE);
	pce_subobj_ipv6 = proto_item_add_subtree(ti, ett_pce_obj);	
	
	switch(obj_class){
	case PCE_EXPLICIT_ROUTE_OBJ:
	l = (l_and_or_type& Mask_L)>>7;
	proto_tree_add_text(pce_subobj_ipv6, tvb, *offset2, 1, val_to_str(l, pce_route_l_obj_vals, "Unknown Object (%u). "));
	proto_tree_add_uint(pce_subobj_ipv6, pce_filter[PCEF_SUBOBJ], tvb, *offset2, 1, (l_and_or_type & 0x7f));
	proto_tree_add_text(pce_subobj_ipv6, tvb, *offset2+1, 1, "Length: %u", length);
	proto_tree_add_text(pce_subobj_ipv6, tvb, *offset2+2, 16, "IPv6 Address: %s", ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(tvb, *offset2+2, 16)));
	proto_tree_add_text(pce_subobj_ipv6, tvb, *offset2+18, 1, "Prefix Length: %u", prefix_length);
	proto_tree_add_text(pce_subobj_ipv6, tvb, *offset2+19, 1, "Padding: 0x%02x", resv);
	break;
	
	case PCE_RECORD_ROUTE_OBJ:
	proto_tree_add_uint(pce_subobj_ipv6, pce_filter[PCEF_SUBOBJ], tvb, *offset2, 1, l_and_or_type);
	proto_tree_add_text(pce_subobj_ipv6, tvb, *offset2+1, 1, "Length: %u", length);
	proto_tree_add_text(pce_subobj_ipv6, tvb, *offset2+2, 16, "IPv6 Address: %s", ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(tvb, *offset2+2, 16)));
	proto_tree_add_text(pce_subobj_ipv6, tvb, *offset2+18, 1, "Prefix Length: %u", prefix_length);	
	ti = proto_tree_add_text(pce_subobj_ipv6, tvb, *offset2+19, 1, "Flags: 0x%02x ", resv);
	pce_subobj_ipv6_flags = proto_item_add_subtree(ti, ett_pce_obj);
	proto_tree_add_boolean(pce_subobj_ipv6_flags, pce_subobj_flags_lpa, tvb, *offset2+19, 1, resv);
	proto_tree_add_boolean(pce_subobj_ipv6_flags, pce_subobj_flags_lpu, tvb, *offset2+19, 1, resv);
	break;
	
	case PCE_IRO_OBJ:
	proto_tree_add_text(pce_subobj_ipv6, tvb, *offset2, 1, "l: %x", (l_and_or_type & 0x80)>>7);
	proto_tree_add_uint(pce_subobj_ipv6, pce_filter[PCEF_SUBOBJ], tvb, *offset2, 1, (l_and_or_type & 0x7f));
	proto_tree_add_text(pce_subobj_ipv6, tvb, *offset2+1, 1, "Length: %u", length);
	proto_tree_add_text(pce_subobj_ipv6, tvb, *offset2+2, 16, "IPv6 Address: %s", ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(tvb, *offset2+2, 16)));
	proto_tree_add_text(pce_subobj_ipv6, tvb, *offset2+18, 1, "Prefix Length: %u", prefix_length);
	proto_tree_add_text(pce_subobj_ipv6, tvb, *offset2+19, 1, "Padding: 0x%02x", resv);
	break;
	
	case PCE_XRO_OBJ:
	proto_tree_add_text(pce_subobj_ipv6, tvb, *offset2, 1, "X: %x", (l_and_or_type & 0x01)>>7);
	proto_tree_add_uint(pce_subobj_ipv6, pce_filter[PCEF_SUBOBJ_XRO], tvb, *offset2, 1, (l_and_or_type & 0x7f));
	proto_tree_add_text(pce_subobj_ipv6, tvb, *offset2+1, 1, "Length: %u", length);
	proto_tree_add_text(pce_subobj_ipv6, tvb, *offset2+2, 16, "IPv6 Address: %s", ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(tvb, *offset2+2, 16)));
	proto_tree_add_text(pce_subobj_ipv6, tvb, *offset2+18, 1, "Prefix Length: %u", prefix_length);
	proto_tree_add_text(pce_subobj_ipv6, tvb, *offset2+19, 1, val_to_str(resv, pce_xro_atribute_obj_vals, "Unknown Atribute (%u). "));
	break;	
	
	default:
	proto_tree_add_text(pce_subobj_ipv6, tvb, *offset2, 20, "Non defined subobject for this object");
	    break;
	}	
	
	*len = *len + 20;	
	*offset2 = *offset2 + 20;

}

	
static void
dissect_subobj_label_control(proto_item *ti, proto_tree *pce_subobj_tree,  tvbuff_t *tvb,  int *offset2, int *len, int obj_class, gint ett_pce_obj, guint l_and_or_type, guint length){

	proto_tree *pce_subobj_label_control;
	proto_tree *pce_subobj_label_flags;
	guint8 u_reserved;
	guint8 c_type;
	int l;
	int u;
		
	u_reserved = tvb_get_guint8(tvb, *offset2+2);
	c_type = tvb_get_guint8(tvb, *offset2+3);
		
	ti = proto_tree_add_item(pce_subobj_tree, pce_filter[PCEF_SUBOBJ_LABEL_CONTROL], tvb, *offset2, length, FALSE);
	pce_subobj_label_control = proto_item_add_subtree(ti, ett_pce_obj);	
		
	switch(obj_class){
	
	case PCE_EXPLICIT_ROUTE_OBJ:
	l = (l_and_or_type& Mask_L)>>7;
	proto_tree_add_text(pce_subobj_label_control, tvb, *offset2, 1, val_to_str(l, pce_route_l_obj_vals, "Unknown Object (%u). "));
	proto_tree_add_uint(pce_subobj_label_control, pce_filter[PCEF_SUBOBJ], tvb, *offset2, 1, (l_and_or_type & 0x7f));
	proto_tree_add_text(pce_subobj_label_control, tvb, *offset2+1, 1, "Length: %u", length);
	u = (u_reserved & 0x80)>>7;
	proto_tree_add_text(pce_subobj_label_control, tvb, *offset2+2, 1, val_to_str(u, pce_route_u_obj_vals, "Unknown Object (%u). "));
	proto_tree_add_text(pce_subobj_label_control, tvb, *offset2+2, 1, "Reserved: %u", (u_reserved & 0x7f));	
	proto_tree_add_text(pce_subobj_label_control, tvb, *offset2+3, 1, "C-Type: %u", c_type);
	proto_tree_add_text(pce_subobj_label_control, tvb, *offset2+4, length-4, "Label: %s", 
				bytestring_to_str(tvb_get_ptr(tvb, *offset2+4, length-4), length-4, ' '));
	break;
	
	case PCE_RECORD_ROUTE_OBJ:	
	proto_tree_add_uint(pce_subobj_label_control, pce_filter[PCEF_SUBOBJ], tvb, *offset2, 1, l_and_or_type);
	proto_tree_add_text(pce_subobj_label_control, tvb, *offset2+1, 1, "Length: %u", length);
	u = (u_reserved & 0x80)>>7;
	proto_tree_add_text(pce_subobj_label_control, tvb, *offset2+2, 1, val_to_str(u, pce_route_u_obj_vals, "Unknown Object (%u). "));
	
	ti = proto_tree_add_text(pce_subobj_label_control, tvb, *offset2+2, 1, "Flags: 0x%02x ", (u_reserved & 0x7f));
	pce_subobj_label_flags = proto_item_add_subtree(ti, ett_pce_obj);
	proto_tree_add_boolean(pce_subobj_label_flags, pce_subobj_label_flags_gl, tvb, *offset2+2, 1, (u_reserved & 0x7f));
	proto_tree_add_text(pce_subobj_label_control, tvb, *offset2+3, 1, "C-Type: %u", c_type);
	proto_tree_add_text(pce_subobj_label_control, tvb, *offset2+4, length-4, "Label: %s", 
				bytestring_to_str(tvb_get_ptr(tvb, *offset2+4, length-4), length-4, ' '));
	break;
	
	default:
	proto_tree_add_text(pce_subobj_label_control, tvb, *offset2, length, "Non defined subobject for this object");
	break;
	}		

	*len = *len + 8;
	*offset2 = *offset2 + 8;
}

static void
dissect_subobj_unnumb_interfaceID(proto_item *ti, proto_tree *pce_subobj_tree, tvbuff_t *tvb, int *offset2, int *len, int obj_class, gint ett_pce_obj, guint l_and_or_type, guint length){

	proto_tree *pce_subobj_unnumb_interfaceID;
	proto_tree *pce_subobj_unnumb_interfaceID_flags;
	guint32 router_ID;
	guint32 interface_ID;
	guint16 reserved_flags;	
	int l;
		
	reserved_flags = tvb_get_ntohs(tvb, *offset2+2);
	router_ID = tvb_get_ntohl(tvb, *offset2+4);
	interface_ID = tvb_get_ntohl(tvb, *offset2+8);
	
	ti = proto_tree_add_item(pce_subobj_tree, pce_filter[PCEF_SUBOBJ_UNNUM_INTERFACEID], tvb, *offset2, length, FALSE);
	pce_subobj_unnumb_interfaceID = proto_item_add_subtree(ti, ett_pce_obj);
		
	switch(obj_class){
	
	case PCE_EXPLICIT_ROUTE_OBJ:
	l = (l_and_or_type& Mask_L)>>7;
	proto_tree_add_text(pce_subobj_unnumb_interfaceID, tvb, *offset2, 1, val_to_str(l, pce_route_l_obj_vals, "Unknown Object (%u). "));
	proto_tree_add_uint(pce_subobj_unnumb_interfaceID, pce_filter[PCEF_SUBOBJ], tvb, *offset2, 1, (l_and_or_type & 0x7f));
	proto_tree_add_text(pce_subobj_unnumb_interfaceID, tvb, *offset2+1, 1, "Length: %u", length);	
	proto_tree_add_text(pce_subobj_unnumb_interfaceID, tvb, *offset2+2, 2, "Reserved: 0x%04x", reserved_flags);	
	break;
	
	case PCE_RECORD_ROUTE_OBJ:
	proto_tree_add_uint(pce_subobj_unnumb_interfaceID, pce_filter[PCEF_SUBOBJ], tvb, *offset2, 1, l_and_or_type);
	proto_tree_add_text(pce_subobj_unnumb_interfaceID, tvb, *offset2+1, 1, "Length: %u", length);
	
	ti = proto_tree_add_text(pce_subobj_unnumb_interfaceID, tvb, *offset2+2, 2, "Flags: 0x%02x ", (reserved_flags & 0xff00)>>8);
	pce_subobj_unnumb_interfaceID_flags = proto_item_add_subtree(ti, ett_pce_obj);
	proto_tree_add_boolean(pce_subobj_unnumb_interfaceID_flags, pce_subobj_flags_lpa, tvb, *offset2+2, 1, (reserved_flags & 0xff00)>>8);
	proto_tree_add_boolean(pce_subobj_unnumb_interfaceID_flags, pce_subobj_flags_lpu, tvb, *offset2+2, 1, (reserved_flags & 0xff00)>>8);
	
	proto_tree_add_text(pce_subobj_unnumb_interfaceID, tvb, *offset2+3, 1, "Reserved: 0x%02x", (reserved_flags & 0x00ff));
	break;
	
	case PCE_IRO_OBJ:
	proto_tree_add_text(pce_subobj_unnumb_interfaceID, tvb, *offset2, 1, "l: %x", (l_and_or_type & 0x80)>>7);
	proto_tree_add_uint(pce_subobj_unnumb_interfaceID, pce_filter[PCEF_SUBOBJ], tvb, *offset2, 1, (l_and_or_type & 0x7f));
	proto_tree_add_text(pce_subobj_unnumb_interfaceID, tvb, *offset2+1, 1, "Length: %u", length);
	proto_tree_add_text(pce_subobj_unnumb_interfaceID, tvb, *offset2+2, 2, "Reserved: 0x%04x", reserved_flags);	
	break;
	
	case PCE_XRO_OBJ:
	proto_tree_add_text(pce_subobj_unnumb_interfaceID, tvb, *offset2, 1, "X: %x", (l_and_or_type & 0x01)>>7);
	proto_tree_add_uint(pce_subobj_unnumb_interfaceID, pce_filter[PCEF_SUBOBJ_XRO], tvb, *offset2, 1, (l_and_or_type & 0x7f));
	proto_tree_add_text(pce_subobj_unnumb_interfaceID, tvb, *offset2+2, 1, "Reserved: 0x%02x", (reserved_flags & 0xff00)>>4);	
	proto_tree_add_text(pce_subobj_unnumb_interfaceID, tvb, *offset2+3, 1, val_to_str((reserved_flags & 0x00ff), pce_xro_atribute_obj_vals, "Unknown Atribute (%u). "));
	break;
	
	default:
	proto_tree_add_text(pce_subobj_unnumb_interfaceID, tvb, *offset2, 12, "Non defined subobject for this object");
	break;
	}	
	
	proto_tree_add_text(pce_subobj_unnumb_interfaceID, tvb, *offset2+4, 4, "Router ID: 0x%08x", router_ID);
	proto_tree_add_text(pce_subobj_unnumb_interfaceID, tvb, *offset2+8, 4, "Interface ID: 0x%08x", interface_ID);
	
	*offset2 = *offset2 + 12;
	*len = *len + 12;
	
}

static void
dissect_subobj_autonomous_sys_num(proto_item *ti, proto_tree *pce_subobj_tree, tvbuff_t *tvb, int *offset2, int *len, int obj_class, guint ett_pce_obj, guint l_and_or_type, guint length){

	proto_tree *pce_subobj_autonomous_sys_num;
	guint16 AS_number;
	guint8 reserved;
	guint8 attribute;
	guint16 op_AS_nu_high_oct;
	int l;
	l = (l_and_or_type& Mask_L)>>7;
		
	if(obj_class == PCE_XRO_OBJ){	
		reserved = tvb_get_guint8(tvb, *offset2+2);
		attribute = tvb_get_guint8(tvb, *offset2+3);
		op_AS_nu_high_oct = tvb_get_ntohs(tvb, *offset2+4);
		AS_number = tvb_get_ntohs(tvb, *offset2+6);

		ti = proto_tree_add_item(pce_subobj_tree, pce_filter[PCEF_SUBOBJ_AUTONOMOUS_SYS_NUM], tvb, *offset2, length, FALSE);
		pce_subobj_autonomous_sys_num = proto_item_add_subtree(ti, ett_pce_obj);
		proto_tree_add_text(pce_subobj_autonomous_sys_num, tvb, *offset2, 1, "X: %x", (l_and_or_type & 0x01)>>7);
		proto_tree_add_uint(pce_subobj_autonomous_sys_num, pce_filter[PCEF_SUBOBJ_XRO], tvb, *offset2, 1, (l_and_or_type & 0x7f));
		proto_tree_add_text(pce_subobj_autonomous_sys_num, tvb, *offset2+1, 1, "Length: %u", length);
	
		proto_tree_add_text(pce_subobj_autonomous_sys_num, tvb, *offset2+2, 1, "Reserved: 0x%02x", reserved);
		proto_tree_add_text(pce_subobj_autonomous_sys_num, tvb, *offset2+3, 1, val_to_str(attribute, pce_xro_atribute_obj_vals, "Unknown Object (%u)."));
		proto_tree_add_text(pce_subobj_autonomous_sys_num, tvb, *offset2+4, 2, "Optional AS Number High Octets: 0x%04x", AS_number);
		proto_tree_add_text(pce_subobj_autonomous_sys_num, tvb, *offset2+6, 2, "AS Number: 0x%04x", AS_number);
	
		*offset2 = *offset2 + 8;
		*len = *len + 8;
		}
	
	else{	AS_number = tvb_get_ntohs(tvb, *offset2+2);	
		ti = proto_tree_add_item(pce_subobj_tree, pce_filter[PCEF_SUBOBJ_AUTONOMOUS_SYS_NUM], tvb, *offset2, length, FALSE);
		pce_subobj_autonomous_sys_num = proto_item_add_subtree(ti, ett_pce_obj);
		
		if(obj_class == PCE_IRO_OBJ)
			proto_tree_add_text(pce_subobj_autonomous_sys_num, tvb, *offset2, 1, "l: %x", (l_and_or_type & 0x80)>>7);
		else	
			proto_tree_add_text(pce_subobj_autonomous_sys_num, tvb, *offset2, 1, val_to_str(l, pce_route_l_obj_vals, "Unknown Object (%u). "));
		proto_tree_add_uint(pce_subobj_autonomous_sys_num, pce_filter[PCEF_SUBOBJ], tvb, *offset2, 1, (l_and_or_type & 0x7f));	
		proto_tree_add_text(pce_subobj_autonomous_sys_num, tvb, *offset2+1, 1, "Length: %u", length);
		proto_tree_add_text(pce_subobj_autonomous_sys_num, tvb, *offset2+2, 2, "AS Number: 0x%04x", AS_number);
		
		*offset2 = *offset2 + 4;
		*len = *len + 4;	
	}
}

static void
dissect_subobj_srlg(proto_item *ti, proto_tree *pce_subobj_tree, tvbuff_t *tvb, int *offset2, int *len, guint ett_pce_obj, guint l_and_or_type, guint length){
	
	proto_tree *pce_subobj_srlg;
	guint32 srlg_id;
	guint8 reserved;
	guint8 attribute;
		
	srlg_id = tvb_get_ntohl(tvb, *offset2+2);
	reserved = tvb_get_guint8(tvb, *offset2+6);
	attribute = tvb_get_guint8(tvb, *offset2+7);
	
	ti = proto_tree_add_item(pce_subobj_tree, pce_filter[PCEF_SUBOBJ_SRLG], tvb, *offset2, length, FALSE);
	pce_subobj_srlg = proto_item_add_subtree(ti, ett_pce_obj);
	
	proto_tree_add_text(pce_subobj_srlg, tvb, *offset2, 1, "X: %x", (l_and_or_type & 0x01)>>7);
	proto_tree_add_uint(pce_subobj_srlg, pce_filter[PCEF_SUBOBJ_XRO], tvb, *offset2, 1, (l_and_or_type & 0x7f));
	proto_tree_add_text(pce_subobj_srlg, tvb, *offset2+1, 1, "Length: %u", length);
	
	proto_tree_add_text(pce_subobj_srlg, tvb, *offset2+2, 4, "SRLG ID: 0x%08x", srlg_id);
	proto_tree_add_text(pce_subobj_srlg, tvb, *offset2+6, 1, "Reserved: 0x%02x", reserved);
	proto_tree_add_text(pce_subobj_srlg, tvb, *offset2+7, 1, val_to_str(attribute, pce_xro_atribute_obj_vals, "Unknown Object (%u)."));
	
	*offset2 = *offset2 + 8;
	*len = *len + 8;
	
}

static void
dissect_subobj_exrs(proto_item *ti, proto_tree *pce_subobj_tree, tvbuff_t *tvb, int *offset2, int *len, int obj_class, guint ett_pce_obj, guint type_iro, guint l_and_or_type, guint length){
	
	proto_tree *pce_subobj_exrs;
	guint16 reserved;
	guint8 l_type;
	guint8 length2;	
	guint type_exrs;
	guint offset_exrs = 0;
	guint l;
	
	ti = proto_tree_add_item(pce_subobj_tree, pce_filter[PCEF_SUBOBJ_EXRS], tvb, *offset2, length, FALSE);
	pce_subobj_exrs = proto_item_add_subtree(ti, ett_pce_obj);
	
	l = (l_and_or_type& Mask_L)>>7;
	proto_tree_add_text(pce_subobj_exrs, tvb, *offset2, 1, val_to_str(l, pce_route_l_obj_vals, "Unknown Object (%u). "));
	proto_tree_add_text(pce_subobj_exrs, tvb, *offset2, 1, "Type: %u", (l_and_or_type & 0x7f));
	proto_tree_add_text(pce_subobj_exrs, tvb, *offset2+1, 1, "Length: %u", length);
	
	reserved = tvb_get_ntohs(tvb, *offset2+2);
	proto_tree_add_text(pce_subobj_exrs, tvb, *offset2+2, 2, "Reserved: 0x%04x", reserved);
	
	*len = *len + 4;
	*offset2 = *offset2 + 4;
	
	while(offset_exrs<length-4){
		
	l_type = tvb_get_guint8(tvb, *offset2);
	length2 = tvb_get_guint8(tvb, *offset2+1);
	type_exrs = (l_type & Mask_Type);	
		
	if(type_iro==PCE_SUB_EXRS){
		obj_class = PCE_XRO_OBJ;}
		
	switch(type_exrs) {
	  
	case PCE_SUB_IPv4:
		dissect_subobj_ipv4(ti, pce_subobj_exrs, tvb, offset2, len,  obj_class, ett_pce_obj, l_type, length2);
		break;
	case PCE_SUB_IPv6:
		dissect_subobj_ipv6(ti, pce_subobj_exrs, tvb, offset2, len, obj_class, ett_pce_obj, l_type, length2);
		break;
	case PCE_SUB_UNNUMB_INTERFACE_ID_XRO:
		dissect_subobj_unnumb_interfaceID(ti, pce_subobj_exrs, tvb, offset2, len, obj_class, ett_pce_obj, l_type, length2);
		break;
	case PCE_SUB_AUTONOMOUS_SYS_NUM_XRO:
		dissect_subobj_autonomous_sys_num(ti, pce_subobj_exrs, tvb, offset2, len,  obj_class, ett_pce_obj, l_type, length2);
		break;
	case PCE_SUB_SRLG:
		dissect_subobj_srlg(ti, pce_subobj_exrs, tvb, offset2, len, ett_pce_obj, l_type, length2);
		break;	
	default:
	    ti = proto_tree_add_text(pce_subobj_exrs, tvb, *offset2+2, length-2,
				"Non defined subobject (%d)", type_exrs);
	    break;

	}	
	
	offset_exrs = offset_exrs + length2;

	}
}

/*------------------------------------------------------------------------------
 * OPEN OBJECT
 *------------------------------------------------------------------------------*/
static void
dissect_pce_open_obj (proto_item *ti, proto_tree *pce_tree, tvbuff_t *tvb, int *offset2, int obj_length, int *len)
{
    proto_tree *pce_open_obj;
    proto_tree *pce_open_obj_flags;
    guint8 version_flags;
    guint8 keepalive;
    guint8 deadtimer;
    guint8 SID;
    guint hdr_obj=4;
    guint body_obj_obl=4;
            
	version_flags = tvb_get_guint8(tvb, *offset2);
	keepalive = tvb_get_guint8(tvb, *offset2+1);
    	deadtimer = tvb_get_guint8(tvb, *offset2+2);
    	SID = tvb_get_guint8(tvb, *offset2+3);
   
	ti = proto_tree_add_item(pce_tree, pce_filter[PCEF_OBJ_OPEN], tvb, *offset2, obj_length-4, FALSE);
	pce_open_obj = proto_item_add_subtree(ti, ett_pce_obj_open);
	
	proto_tree_add_text(pce_open_obj, tvb, *offset2, 1, "PCE Version: %u", (version_flags & 0xe0)>>5);
			
	ti = proto_tree_add_text(pce_open_obj, tvb, *offset2, 1, "Flags: ");
	pce_open_obj_flags = proto_item_add_subtree(ti, ett_pce_obj_open);
	
	proto_tree_add_boolean(pce_open_obj_flags, pce_open_flags_res, tvb, *offset2, 1, version_flags & 0x1f);
 	proto_tree_add_text(pce_open_obj, tvb, *offset2+1, 1, "Keepalive: %u", keepalive);
	proto_tree_add_text(pce_open_obj, tvb, *offset2+2, 1, "Deadtime: %u", deadtimer);	
	proto_tree_add_text(pce_open_obj, tvb, *offset2+3, 1, "SID: %u", SID);

	*offset2 =  (*offset2) + body_obj_obl;
	
	dissect_pce_tlv(ti, pce_open_obj, tvb, offset2, hdr_obj, body_obj_obl, obj_length, ett_pce_obj_open, len);
		
}

/*------------------------------------------------------------------------------
 * RP OBJECT
 *------------------------------------------------------------------------------*/
static void 
dissect_pce_rp_obj(proto_item *ti, proto_tree *pce_tree,
		  tvbuff_t *tvb, int *offset2, int obj_length, int *len)
{ 
		   
	proto_tree *pce_rp_obj;
	proto_tree *pce_rp_obj_flags;
	guint8 reserved;
	guint32 flags;
	guint32 requested_id_number;
	guint hdr_obj=4;
   	guint body_obj_obl=8;	
	
	reserved = tvb_get_guint8(tvb, *offset2);
	flags = tvb_get_ntoh24(tvb, *offset2+1);
	requested_id_number = tvb_get_ntohl(tvb, *offset2+4);
	 
	ti = proto_tree_add_item(pce_tree, pce_filter[PCEF_OBJ_RP], tvb, *offset2, obj_length-4, FALSE);
	pce_rp_obj = proto_item_add_subtree(ti, ett_pce_obj_request_parameters);
	
	proto_tree_add_text(pce_rp_obj, tvb, *offset2, 1, "Reserved: 0x%02x", reserved);
	
	ti = proto_tree_add_text(pce_rp_obj, tvb, *offset2+1, 3, "Flags: 0x%06x ", flags);
	pce_rp_obj_flags = proto_item_add_subtree(ti, ett_pce_obj_request_parameters);
	
	proto_tree_add_boolean(pce_rp_obj_flags, pce_rp_flags_reserved, tvb, *offset2+1, 3, flags);
	proto_tree_add_boolean(pce_rp_obj_flags, pce_rp_flags_o, tvb, *offset2+1, 3, flags);
	proto_tree_add_boolean(pce_rp_obj_flags, pce_rp_flags_b, tvb, *offset2+1, 3, flags);
	proto_tree_add_boolean(pce_rp_obj_flags, pce_rp_flags_r, tvb, *offset2+1, 3, flags);
	proto_tree_add_boolean(pce_rp_obj_flags, pce_rp_flags_pri, tvb, *offset2+1, 3, flags);
		
	proto_tree_add_text(pce_rp_obj, tvb, *offset2+4, 4, "Requested ID Number: 0x%08x", requested_id_number);
	*offset2 =  (*offset2) + body_obj_obl;

	dissect_pce_tlv(ti, pce_rp_obj, tvb, offset2, hdr_obj, body_obj_obl, obj_length, ett_pce_obj_request_parameters, len);
	
}

/*------------------------------------------------------------------------------
 * NO PATH OBJECT
 *------------------------------------------------------------------------------*/
static void 
dissect_pce_no_path_obj(proto_item *ti, proto_tree *pce_tree,
		  tvbuff_t *tvb, int *offset2, int obj_length, int *len)
{    
		  
	proto_tree *pce_no_path_obj;	
	proto_tree *pce_no_path_obj_flags;
	guint8 ni;
	guint16 flags;
	guint8 reserved;
	guint hdr_obj=4;
   	guint body_obj_obl=4;
	
	ni = tvb_get_guint8(tvb, *offset2);
	flags = tvb_get_ntohs(tvb, *offset2+1);
	reserved = tvb_get_guint8(tvb, *offset2+3);
	
	ti = proto_tree_add_item(pce_tree, pce_filter[PCEF_OBJ_NO_PATH], tvb, *offset2, obj_length-4, FALSE);
	pce_no_path_obj = proto_item_add_subtree(ti, ett_pce_obj_no_path);
	
	proto_tree_add_text(pce_no_path_obj, tvb, *offset2, 1, val_to_str(ni, pce_no_path_obj_vals, "Unknown Object (%u). "));
	
	ti = proto_tree_add_text(pce_no_path_obj, tvb, *offset2+1, 2, "Flags: 0x%04x", flags);
	pce_no_path_obj_flags = proto_item_add_subtree(ti, ett_pce_obj_no_path);	
	
	proto_tree_add_boolean(pce_no_path_obj_flags, pce_no_path_flags_c, tvb, *offset2+1, 2, flags);
	proto_tree_add_text(pce_no_path_obj, tvb, *offset2+3, 1, "Reserved: 0x%02x", reserved);
	
	*offset2 =  (*offset2) + body_obj_obl;
	dissect_pce_tlv(ti, pce_no_path_obj, tvb, offset2, hdr_obj, body_obj_obl, obj_length, ett_pce_obj_no_path, len);
		  
}

/*------------------------------------------------------------------------------
 * END POINT OBJECT
 *------------------------------------------------------------------------------*/
static void 
dissect_pce_end_point_obj(proto_item *ti, proto_tree *pce_tree,
		  tvbuff_t *tvb, int *offset2, int obj_length, int *len, int type)
{
	proto_tree *pce_end_point_obj;
	
	switch(type)
	{
	  case IPv4:{		
		ti = proto_tree_add_item(pce_tree, pce_filter[PCEF_OBJ_END_POINT], tvb, *offset2, obj_length-4, FALSE);
		pce_end_point_obj = proto_item_add_subtree(ti, ett_pce_obj_end_point);
		
		proto_tree_add_text(pce_end_point_obj, tvb, *offset2, 4, "Source IPv4 Address: (%s)", ip_to_str(tvb_get_ptr(tvb, *offset2, 4)));
		proto_tree_add_text(pce_end_point_obj, tvb, *offset2+4, 4, "Destination IPv4 Address: (%s)", ip_to_str(tvb_get_ptr(tvb, *offset2+4, 4)));
		
		*len = *len + 8;
		
		break;	
	  	 	
	  	   }
	  case IPv6:{
		
		ti = proto_tree_add_item(pce_tree, pce_filter[PCEF_OBJ_END_POINT], tvb, *offset2, obj_length-4, FALSE);
		pce_end_point_obj = proto_item_add_subtree(ti, ett_pce_obj_end_point);
		
		proto_tree_add_text(pce_end_point_obj, tvb, *offset2, 16, "Source IPv6 Address: %s",
			    ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(tvb, *offset2, 16)));	
		proto_tree_add_text(pce_end_point_obj, tvb, *offset2+16, 16, "Destination IPv6 Address: %s",
			    ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(tvb, *offset2+16, 16)));
		
		*len = *len + 32;
		
		break;
			 	 
		   }
	  default:
		 ti = proto_tree_add_item(pce_tree, pce_filter[PCEF_OBJ_END_POINT], tvb, *offset2, obj_length-4, FALSE);
		 pce_end_point_obj = proto_item_add_subtree(ti, ett_pce_obj_end_point);
		 proto_tree_add_text(pce_end_point_obj, tvb, *offset2, 1, "UNKNOWN Type Object (%u)", type);
		 break;
	  
	}     
	     
}



/*------------------------------------------------------------------------------
 * BANDWIDTH OBJECT
 *------------------------------------------------------------------------------*/
static void 
dissect_pce_bandwidth_obj(proto_item *ti, proto_tree *pce_tree, tvbuff_t *tvb, int *offset2, int obj_length, int *len)
		  {    
	proto_tree *pce_bandwidth_obj;
	guint32 bandwidth;
	
	bandwidth = tvb_get_ntohl(tvb, *offset2);
	
	ti = proto_tree_add_item(pce_tree, pce_filter[PCEF_OBJ_BANDWIDTH], tvb, *offset2, obj_length-4, FALSE);	  
	pce_bandwidth_obj = proto_item_add_subtree(ti, ett_pce_obj_bandwidth);	  
	proto_tree_add_text(pce_bandwidth_obj, tvb, *offset2, 4, "Bandwidth: 0x%x", bandwidth);	  
	
	*len = *len + 8;
		  
}

/*------------------------------------------------------------------------------
 * METRIC OBJECT
 *------------------------------------------------------------------------------*/
static void 
dissect_pce_metric_obj(proto_item *ti, proto_tree *pce_tree,
		  tvbuff_t *tvb, int *offset2, int obj_length, int *len)
		  {    
	
	proto_tree *pce_metric_obj;
	proto_tree *pce_metric_obj_flags;
	guint16 reserved;
	guint8 flags; 
	guint8 metric_type;
	guint32 metric_value;
	
	reserved = tvb_get_ntohs(tvb, *offset2);
	flags = tvb_get_guint8(tvb, *offset2+2);
	metric_type =	tvb_get_guint8(tvb, *offset2+3);  
	metric_value = tvb_get_ntohl(tvb, *offset2+4);
	
	ti = proto_tree_add_item(pce_tree, pce_filter[PCEF_OBJ_METRIC], tvb, *offset2, obj_length-4, FALSE);
	pce_metric_obj = proto_item_add_subtree(ti, ett_pce_obj_metric);	  
	
	proto_tree_add_text(pce_metric_obj, tvb, *offset2, 2, "Reserved: %u", reserved);	  
		  
	ti = proto_tree_add_text(pce_metric_obj, tvb, *offset2+2, 1, "Flags: 0x%02x", flags);
	pce_metric_obj_flags = proto_item_add_subtree(ti, ett_pce_obj_metric);
	
	proto_tree_add_boolean(pce_metric_obj_flags, pce_metric_flags_c, tvb, *offset2+2, 1, flags);
	proto_tree_add_boolean(pce_metric_obj_flags, pce_metric_flags_b, tvb, *offset2+2, 1, flags);
	proto_tree_add_text(pce_metric_obj, tvb, *offset2+3, 1, val_to_str(metric_type, pce_metric_obj_vals, "Unknown Object (%u). "));
	proto_tree_add_text(pce_metric_obj, tvb, *offset2+4, 4, "Metric Value: 0x%x", metric_value);
	
	*len = *len + 8;
}

/*------------------------------------------------------------------------------
 * EXPLICIT ROUTE OBJECT (ERO)
 *------------------------------------------------------------------------------*/
static void 
dissect_pce_explicit_route_obj(proto_item *ti, proto_tree *pce_tree,
		  tvbuff_t *tvb, int *offset2, int obj_length, int obj_class, int *len, int *msg_length)
{   
	proto_tree *pce_explicit_route_obj;
	guint8 l_type;
	guint8 length;
	guint type_exp_route;
	guint body_obj_len;
	body_obj_len = obj_length - 4;
	
	ti = proto_tree_add_item(pce_tree, pce_filter[PCEF_OBJ_EXPLICIT_ROUTE], tvb, *offset2, obj_length-4, FALSE);	  
	pce_explicit_route_obj = proto_item_add_subtree(ti, ett_pce_obj_explicit_route);
	
	while(body_obj_len){
	
	l_type = tvb_get_guint8(tvb, *offset2);	  
	length = tvb_get_guint8(tvb, *offset2+1);
	type_exp_route = (l_type & Mask_Type);
	if (body_obj_len <length) {
		proto_tree_add_text(pce_explicit_route_obj, tvb, *offset2, length, "The packet is bad coded!! \nObject Length = %u", body_obj_len); 
		body_obj_len = 0;
		*len = *msg_length;
		}		
	else{
	body_obj_len = body_obj_len - length;
	
	switch(type_exp_route) {
	  
	case PCE_SUB_IPv4:
		dissect_subobj_ipv4(ti, pce_explicit_route_obj, tvb, offset2, len,  obj_class, ett_pce_obj_explicit_route, l_type, length);
		break;
	case PCE_SUB_IPv6:
		dissect_subobj_ipv6(ti, pce_explicit_route_obj, tvb, offset2, len, obj_class, ett_pce_obj_explicit_route, l_type, length);
		break;
	case PCE_SUB_LABEL_CONTROL:
		dissect_subobj_label_control(ti, pce_explicit_route_obj, tvb, offset2, len, obj_class, ett_pce_obj_explicit_route, l_type, length);
		break;
	case PCE_SUB_UNNUMB_INTERFACE_ID:
		dissect_subobj_unnumb_interfaceID(ti, pce_explicit_route_obj, tvb, offset2, len, obj_class, ett_pce_obj_explicit_route, l_type, length);
		break;
	case PCE_SUB_AUTONOMOUS_SYS_NUM:
		dissect_subobj_autonomous_sys_num(ti, pce_explicit_route_obj, tvb, offset2, len,  obj_class, ett_pce_obj_explicit_route, l_type, length);
		break;
	default:
	    ti = proto_tree_add_text(pce_explicit_route_obj, tvb, *offset2, length, "Non defined subobject (%d)", type_exp_route);
	    *offset2 =  *offset2 + length;
	    break;

	}			
	}
	}	   
}

/*------------------------------------------------------------------------------
 * RECORD ROUTE OBJECT (RRO)
 *------------------------------------------------------------------------------*/
static void 
dissect_pce_record_route_obj(proto_item *ti, proto_tree *pce_tree, tvbuff_t *tvb, int *offset2, int obj_length, int obj_class, int *len, int *msg_length)
{
	proto_tree *pce_record_route_obj;
	guint8 type;
	guint8 length;
	guint body_obj_len;	
	body_obj_len = obj_length - 4;   	
	
	ti = proto_tree_add_item(pce_tree, pce_filter[PCEF_OBJ_RECORD_ROUTE], tvb, *offset2, obj_length-4, FALSE);	  
	pce_record_route_obj = proto_item_add_subtree(ti, ett_pce_obj_record_route);
		
	while(body_obj_len){
	
	type = tvb_get_guint8(tvb, *offset2);	  
	length = tvb_get_guint8(tvb, *offset2+1);

	if (body_obj_len <length) {
		proto_tree_add_text(pce_record_route_obj, tvb, *offset2, length, "The packet is bad coded!! \nObject Length = %u", body_obj_len); 
		body_obj_len = 0;
		*len = *msg_length;
		}		
	else{
	body_obj_len = body_obj_len - length;
	
	switch(type) {
	  
	case PCE_SUB_IPv4:
		dissect_subobj_ipv4(ti, pce_record_route_obj, tvb, offset2, len,  obj_class, ett_pce_obj_record_route, type, length);
		break;
	case PCE_SUB_IPv6:
		dissect_subobj_ipv6(ti, pce_record_route_obj, tvb, offset2, len, obj_class, ett_pce_obj_record_route, type, length);
		break;
	case PCE_SUB_LABEL_CONTROL:
		dissect_subobj_label_control(ti, pce_record_route_obj, tvb, offset2, len, obj_class, ett_pce_obj_record_route, type, length);
		break;
	case PCE_SUB_UNNUMB_INTERFACE_ID:
		dissect_subobj_unnumb_interfaceID(ti, pce_record_route_obj, tvb, offset2, len, obj_class, ett_pce_obj_record_route, type, length);
		break;
			
	default:
	    ti = proto_tree_add_text(pce_record_route_obj, tvb, *offset2, length, "Non defined subobject (%d)", type);
	    *offset2 =  *offset2 + length;
	    break;

	}
	}
	}			
	  
}

/*------------------------------------------------------------------------------
 * LSPA OBJECT
 *------------------------------------------------------------------------------*/
static void 
dissect_pce_lspa_obj(proto_item *ti, proto_tree *pce_tree, tvbuff_t *tvb, int *offset2, int obj_length, int *len)
{    
	proto_tree *pce_lspa_obj;
	proto_tree *pce_lspa_obj_flags;
	guint32 exclude_any;
	guint32 include_any;
	guint32 include_all;
	guint8 setup_prio;
	guint8 holding_prio;
	guint8 flags;
	guint8 reserved;
	guint hdr_obj=4;
   	guint body_obj_obl=16;	
	
	exclude_any = tvb_get_ntohl(tvb, *offset2);
	include_any = tvb_get_ntohl(tvb, *offset2+4);
	include_all = tvb_get_ntohl(tvb, *offset2+8);	  
	setup_prio = tvb_get_guint8(tvb, *offset2+12);
	holding_prio = tvb_get_guint8(tvb, *offset2+13);
	flags = tvb_get_guint8(tvb, *offset2+14);
	reserved = tvb_get_guint8(tvb, *offset2+15);
	
	ti = proto_tree_add_item(pce_tree, pce_filter[PCEF_OBJ_LSPA], tvb, *offset2, obj_length-4, FALSE);	  
	pce_lspa_obj = proto_item_add_subtree(ti, ett_pce_obj_lspa);	  
	
	proto_tree_add_text(pce_lspa_obj, tvb, *offset2, 4, "Exclude-Any: 0x%08x", exclude_any);	 
	proto_tree_add_text(pce_lspa_obj, tvb, *offset2+4, 4, "Include-Any: 0x%08x", include_any);
	proto_tree_add_text(pce_lspa_obj, tvb, *offset2+8, 4, "Include-All: 0x%08x", include_all); 
	proto_tree_add_text(pce_lspa_obj, tvb, *offset2+12, 1, "Setup Priority: %u", setup_prio);
	proto_tree_add_text(pce_lspa_obj, tvb, *offset2+13, 1, "Holding Priority: %u", holding_prio);
	
	ti = proto_tree_add_text(pce_lspa_obj, tvb, *offset2+14, 1, "Flags: 0x%02x", flags);
	pce_lspa_obj_flags = proto_item_add_subtree(ti, ett_pce_obj_metric);
	
	proto_tree_add_boolean(pce_lspa_obj_flags, pce_lspa_flags_l, tvb, *offset2+14, 1, flags);
	proto_tree_add_text(pce_lspa_obj, tvb, *offset2+15, 1, "Reserved: 0x%02x", reserved);
	
	/*it's suppose that obj_length is a a valid date. The object can have optional TLV(s)*/
	*offset2 =  (*offset2) + body_obj_obl;
	*len = *len + body_obj_obl;
	
	dissect_pce_tlv(ti, pce_lspa_obj, tvb, offset2, hdr_obj, body_obj_obl, obj_length, ett_pce_obj_lspa, len);
	
		
}

/*------------------------------------------------------------------------------
 * INCLUDE ROUTE OBJECT (IRO)
 *------------------------------------------------------------------------------*/
static void 
dissect_pce_iro_obj(proto_item *ti, proto_tree *pce_tree,
		    tvbuff_t *tvb, int *offset2, int obj_length, int obj_class, int *len, int *msg_length)
{    
	proto_tree *pce_iro_obj;
	guint8 l_type;
	guint8 length;
	int type_iro;
	guint body_obj_len;	
	body_obj_len = obj_length - 4; 

	ti = proto_tree_add_item(pce_tree, pce_filter[PCEF_OBJ_IRO], tvb, *offset2, obj_length-4, FALSE);	  
	pce_iro_obj = proto_item_add_subtree(ti, ett_pce_obj_iro);
	
	while(body_obj_len){
	
	l_type = tvb_get_guint8(tvb, *offset2);	  
	length = tvb_get_guint8(tvb, *offset2+1);
	type_iro = (l_type & Mask_Type);
	
	if (body_obj_len <length) {
		proto_tree_add_text(pce_iro_obj, tvb, *offset2, length, "The packet is bad coded!! \nObject Length = %u", body_obj_len); 
		body_obj_len = 0;
		*len = *msg_length;
		}		
	else{
	body_obj_len = body_obj_len - length; 
	
	switch(type_iro) {
	  
	case PCE_SUB_IPv4:
		dissect_subobj_ipv4(ti, pce_iro_obj, tvb, offset2, len,  obj_class, ett_pce_obj_iro, l_type, length);
		break;
	case PCE_SUB_IPv6:
		dissect_subobj_ipv6(ti, pce_iro_obj, tvb, offset2, len, obj_class, ett_pce_obj_iro, l_type, length);
		break;
	case PCE_SUB_UNNUMB_INTERFACE_ID:
		dissect_subobj_unnumb_interfaceID(ti, pce_iro_obj, tvb, offset2, len, obj_class, ett_pce_obj_iro, l_type, length);
		break;
	case PCE_SUB_AUTONOMOUS_SYS_NUM:
		dissect_subobj_autonomous_sys_num(ti, pce_iro_obj, tvb, offset2, len,  obj_class, ett_pce_obj_iro, l_type, length);
		break;
	case PCE_SUB_EXRS:
		dissect_subobj_exrs(ti, pce_iro_obj, tvb, offset2, len,  obj_class, ett_pce_obj_iro, type_iro, l_type, length);
		break;	
	default:
	    ti = proto_tree_add_text(pce_iro_obj, tvb, *offset2, length, "Non defined subobject (%d)", type_iro);
	    *offset2 = *offset2 + length;
	    break;

	}	
	} 
	}
 }

/*------------------------------------------------------------------------------
 * SVEC OBJECT 
 *------------------------------------------------------------------------------*/
static void 
dissect_pce_svec_obj(proto_item *ti, proto_tree *pce_tree,
		  tvbuff_t *tvb, int *offset2, int obj_length, int *len)
{
	proto_tree *pce_svec_obj;
	proto_tree *pce_svec_flags_obj;
	guint8 reserved;
	guint32 flags;
	int m = 1;
	int i = 0;
	
	reserved = tvb_get_guint8(tvb, *offset2);
	flags = tvb_get_ntoh24(tvb, *offset2+1);

	ti = proto_tree_add_item(pce_tree, pce_filter[PCEF_OBJ_SVEC], tvb, *offset2, obj_length-4, FALSE);	  
	pce_svec_obj = proto_item_add_subtree(ti, ett_pce_obj_svec);

	proto_tree_add_text(pce_svec_obj, tvb, *offset2, 1, "Reserved: 0x%02x", reserved);
	
	ti =  proto_tree_add_text(pce_svec_obj, tvb, *offset2+1, 3, "Flags 0x%06x ", flags);	
	pce_svec_flags_obj = proto_item_add_subtree(ti, ett_pce_obj_svec);
		
	proto_tree_add_boolean(pce_svec_flags_obj, pce_svec_flags_l, tvb, *offset2 + 1, 3, flags);
    	proto_tree_add_boolean(pce_svec_flags_obj, pce_svec_flags_n, tvb, *offset2 + 1, 3, flags);
   	proto_tree_add_boolean(pce_svec_flags_obj, pce_svec_flags_s, tvb, *offset2 + 1, 3, flags);
	
	for ( i=4 ; i<(obj_length-4) ; ){
	
	proto_tree_add_text(pce_svec_obj, tvb, *offset2+i, 4, "Request-ID-Number %u: 0x%s", m,
			bytestring_to_str(tvb_get_ptr(tvb, *offset2+i, 4), 4, ' '));
	
	i=i+4;
	}
	*offset2 = *offset2 + obj_length- 4;
	*len = *len + obj_length - 4;	  
}

/*------------------------------------------------------------------------------
 * NOTIFICATION OBJECT 
 *------------------------------------------------------------------------------*/		      
static void 
dissect_pce_notification_obj(proto_item *ti, proto_tree *pce_tree, tvbuff_t *tvb, int *offset2, int obj_length, int *len)
{    
	proto_tree *pce_notification_obj;
	guint8 reserved;
	guint8 flags;
	guint8 nt;
	guint8 nv;
	gint hdr_obj=4;
	gint body_obj_obl=4;
	
	reserved = tvb_get_guint8(tvb, *offset2);
	flags = tvb_get_guint8(tvb, *offset2+1);
	nt = tvb_get_guint8(tvb, *offset2+2);
	nv = tvb_get_guint8(tvb, *offset2+3);
	
	ti = proto_tree_add_item(pce_tree, pce_filter[PCEF_OBJ_NOTIFICATION], tvb, *offset2, obj_length-4, FALSE);  
	pce_notification_obj = proto_item_add_subtree(ti, ett_pce_obj_notification);	
	
	proto_tree_add_text(pce_notification_obj, tvb, *offset2, 1, "Reserved: 0x%02x", reserved);
	proto_tree_add_text(pce_notification_obj, tvb, *offset2+1, 1, "Flags: 0x%02x", flags);
	proto_tree_add_uint(pce_notification_obj, pce_filter[PCEF_NOTI_TYPE], tvb, *offset2+2, 1, nt);
	
	switch(nt){
	
	case 1:
	proto_tree_add_uint(pce_notification_obj, pce_filter[PCEF_NOTI_VAL1], tvb, *offset2+2, 1, nt);
		break;
	
	case 2:	
	proto_tree_add_uint(pce_notification_obj, pce_filter[PCEF_NOTI_VAL2], tvb, *offset2+2, 1, nt);
		break;
	default:
	proto_tree_add_text(pce_notification_obj, tvb, *offset2+2, 1, "Notification Type: %u", nt);
	
	}
		
	/*it's suppose that obj_length is a a valid date. The object can have optional TLV(s)*/
	*offset2 =  (*offset2) + body_obj_obl;
	
	dissect_pce_tlv(ti, pce_notification_obj, tvb, offset2, hdr_obj, body_obj_obl, obj_length, ett_pce_obj_notification, len);
		  
		  
}

/*------------------------------------------------------------------------------
 * ERROR OBJECT 
 *------------------------------------------------------------------------------*/		      
static void 
dissect_pce_error_obj(proto_item *ti, proto_tree *pce_tree, tvbuff_t *tvb, int *offset2, int obj_length, int *len)
{	
	proto_tree *pce_error_obj;
	proto_tree *pce_error_types_obj;
	guint8 reserved;
	guint8 flags;
	guint8 error_type;
	guint8 error_value;
	gint hdr_obj=4;
	gint body_obj_obl=4;
	
	reserved = tvb_get_guint8(tvb, *offset2);
	flags = tvb_get_guint8(tvb, *offset2+1);
	error_type = tvb_get_guint8(tvb, *offset2+2);
	error_value = tvb_get_guint8(tvb, *offset2+3);
	
	ti = proto_tree_add_item(pce_tree, pce_filter[PCEF_OBJ_PCEP_ERROR], tvb, *offset2, obj_length-4, FALSE);	  
	pce_error_obj = proto_item_add_subtree(ti, ett_pce_obj_error);
	
	proto_tree_add_text(pce_error_obj, tvb, *offset2, 1, "Reserved: 0x%02x", reserved);
	proto_tree_add_text(pce_error_obj, tvb, *offset2+1, 1, "Flags: 0x%02x", flags);
	
	ti = proto_tree_add_uint(pce_error_obj, pce_filter[PCEF_ERROR_TYPE], tvb, *offset2+2, 1, error_type);
	pce_error_types_obj = proto_item_add_subtree(ti, ett_pce_obj_error);
	
	switch(error_type){	
	case ESTABLISH_FAILURE:
	
		switch(error_value){
		case RX_MALFORM_PKT:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1, "Error-value: %u Reception of a Malformed Message ", error_value);
		break;
		case NO_OPEN_MSG:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1, "Error-value: %u No Open Message received before the expiration of the OpenWait Timer ", error_value);
		break;
		case UNACEP_NO_NEGO_SSESION:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1, "Error-value: %u Unacceptable and non Negotiable session characteristics", error_value);
		break;
		case UNACEP_NEG_SESSION:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1, "Error-value: %u Unacceptable but Negotiable session characteristics", error_value);
		break;
		case TWO_OPEN_MSG_UNACEP:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1, "Error-value: %u Reception of a second Open Message with still Unacceptable Session characteristics", error_value);
		break;
		case RX_PCEERR_UNACEP_SESSION:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1, "Error-value: %u Reception of a PCErr message proposing unacceptable session characteristics", error_value);
		break;
		case NO_KEEPALIVE_PCEERR:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1, "Error-value: %u NO Keepalive or PCErr message received before the expiration of the Keepwait timer supported", error_value);
		break;
		default:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1,
				"Error-value: %u Non defined Error-Value", error_value);
		}
		break;
	
	case CAP_NOT_SUPPORTED:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1, "Error-Value: %u ", error_value);
		break;
		
	case UNKNOWN_OBJ:
		switch(error_value){
		case UNRECON_OBJ_CLASS:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1, "Error-value: %u Unrecognized object class", error_value);
		break;
		case UNRECON_OBJ_TYPE:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1, "Error-value: %u Unrecognized object type", error_value);
		break;
		default:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1,
				"Error-value: %u Non defined Error-Value", error_value);
		} 
		break;
	case NOT_SUPP_OBJ:
		switch(error_value){
		case NO_SUPP_OBJ:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1, "Error-value: %u Not Supported Object Class", error_value);
		break;
		case NO_SUPP_TYPE:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1, "Error-value: %u Not Supported Object Type", error_value);
		break;
		default:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1,
				"Error-value: %u Non defined Error-Value", error_value);
		}
		break;	
	case POLICY_VIOLATION:
		switch(error_value){
		case C_METRIC_SET:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1, "Error-value: %u C bit of the METRIC object set (Request Rejected)", error_value);
		break;
		case O_OBJ_SET:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1, "Error-value: %u O bit of the RP object set (Request Rejected)", error_value);
		break;
		default:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1,
				"Error-value: %u Non defined Error-Value", error_value);
		}
		break;
	case MANDATORY_OBJ_MIS:	
		switch(error_value){
		case RP_OBJ_MISS:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1, "Error-value: %u RP Object missing", error_value);
		break;
		case RRO_OBJ_MISS:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1, "Error-value: %u RRO Object missing for a reoptimization request (R bit of the RP Object set) when bandwidth is not equal to 0", error_value);
		break;
		case END_POINT_OBJ_MISS:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1, "Error-value: %u END-POINTS Objects missing", error_value);
		break;
		default:  
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1,
				"Error-value: %u Non defined Error-Value", error_value);
		}
		break;
	case SYNCH_PCREQ_MIS:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1, "Error-Value: %u ", error_value);
		break;
	case UNKNOWN_REQ_REF:	
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1, "Error-Value: %u ", error_value);
		break;
	case ATTEMPT_2_SESSION:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1, "Error-Value: %u ", error_value);
		break;
	case UNRECO_IRO_SUBOBJ:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1, "Error-Value: %u ", error_value);
		break;	
	case UNRECO_EXRS_SUBOBJ:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+3, 1, "Error-Value: %u ", error_value);
		break;
	
	default:
		proto_tree_add_text(pce_error_types_obj, tvb, *offset2+2, 1, "Error-Type: %u Non defined Error-Value", error_type);
	}
	
	/*it's suppose that obj_length is a a valid date. The object can have optional TLV(s)*/
	*offset2 =  (*offset2) + body_obj_obl;
	
	dissect_pce_tlv(ti, pce_error_obj, tvb, offset2, hdr_obj, body_obj_obl, obj_length, ett_pce_obj_error, len);
}


/*------------------------------------------------------------------------------
 * LOAD-BALANCING OBJECT 
 *------------------------------------------------------------------------------*/		      
static void 
dissect_pce_balancing_obj(proto_item *ti, proto_tree *pce_tree, tvbuff_t *tvb, int *offset2, int obj_length, int *len)
{    
	proto_tree *pce_load_balancing_obj;
	guint16 reserved;
	guint8 flags;
	guint8 max_LSP;
	guint32 min_bandwidth;
	gint hdr_obj=4;
	gint body_obj_obl=8;
	
	reserved = tvb_get_ntohs(tvb, *offset2);
	flags = tvb_get_guint8(tvb, *offset2+2);
	max_LSP = tvb_get_guint8(tvb, *offset2+3);
	min_bandwidth = tvb_get_ntohl(tvb, *offset2+4);
	
	ti = proto_tree_add_item(pce_tree, pce_filter[PCEF_OBJ_LOAD_BALANCING], tvb, *offset2, obj_length-4, FALSE); 
	pce_load_balancing_obj = proto_item_add_subtree(ti, ett_pce_obj_load_balancing);
	
	proto_tree_add_text(pce_load_balancing_obj, tvb, *offset2, 2, "Reserved: 0x%04x", reserved);
	proto_tree_add_text(pce_load_balancing_obj, tvb, *offset2+2, 1, "Flags: 0x%02x", flags);	
	proto_tree_add_text(pce_load_balancing_obj, tvb, *offset2+3, 1, "Maximun Number of TE LSPs: 0x%02x", max_LSP);
	proto_tree_add_text(pce_load_balancing_obj, tvb, *offset2+4, 4, "Minimun Bandwidth: 0x%08x", min_bandwidth);
	
	/*it's suppose that obj_length is a a valid date. The object can have optional TLV(s)*/
	*offset2 =  (*offset2) + body_obj_obl;	
	dissect_pce_tlv(ti, pce_load_balancing_obj, tvb, offset2, hdr_obj, body_obj_obl, obj_length, ett_pce_obj_load_balancing, len);
}

/*------------------------------------------------------------------------------
 * CLOSE OBJECT 
 *------------------------------------------------------------------------------*/		      
static void 
dissect_pce_close_obj(proto_item *ti, proto_tree *pce_tree, tvbuff_t *tvb, int *offset2, int obj_length, int *len)
{
	proto_tree *pce_close_obj;
	guint16 reserved;
	guint8 flags;
	guint8 reason;
	gint hdr_obj=4;
	gint body_obj_obl=4;
		
	reserved = tvb_get_ntohs(tvb, *offset2);
	flags = tvb_get_guint8(tvb, *offset2+2);
	reason = tvb_get_guint8(tvb, *offset2+3);
	
	ti = proto_tree_add_item(pce_tree, pce_filter[PCEF_OBJ_CLOSE], tvb, *offset2, obj_length-4, FALSE);  
	pce_close_obj = proto_item_add_subtree(ti, ett_pce_obj_close);	  
	
	proto_tree_add_text(pce_close_obj, tvb, *offset2, 2, "Reserved: 0x%04x", reserved);
	proto_tree_add_text(pce_close_obj, tvb, *offset2+2, 1, "Flags: 0x%01x", flags);
	proto_tree_add_text(pce_close_obj, tvb, *offset2+3, 1, val_to_str(reason, pce_close_reason_obj_vals, "Unknown Object (%u). ")); 
	
	/*it's suppose that obj_length is a a valid date. The object can have optional TLV(s)*/
	*offset2 =  (*offset2) + body_obj_obl;	
	dissect_pce_tlv(ti, pce_close_obj, tvb, offset2, hdr_obj, body_obj_obl, obj_length, ett_pce_obj_load_balancing, len);
	
	}

/*------------------------------------------------------------------------------
 * XRO OBJECT 
 *------------------------------------------------------------------------------*/	
static void 
dissect_pce_xro_obj(proto_item *ti, proto_tree *pce_tree, tvbuff_t *tvb, int *offset2, int obj_length, int obj_class, int *len, int *msg_length)
{
	proto_tree *pce_xro_obj;
	proto_tree *pce_xro_flags_obj;
	guint16 reserved;
	guint16 flags;
	guint8 x_type;
	guint8 length;
	guint type_xro;
	guint body_subobj_len;
	body_subobj_len = obj_length - 8;
	
	reserved = tvb_get_ntohs(tvb, *offset2);
	flags = tvb_get_ntohs(tvb, *offset2+2);
	
	ti = proto_tree_add_item(pce_tree, pce_filter[PCEF_OBJ_XRO], tvb, *offset2, obj_length-4, FALSE);  
	pce_xro_obj = proto_item_add_subtree(ti, ett_pce_obj_xro);	  
	proto_tree_add_text(pce_xro_obj, tvb, *offset2, 2, "Reserved: 0x%04x", reserved);	
	ti =  proto_tree_add_text(pce_xro_obj, tvb, *offset2+2, 2, "Flags: 0x%04x ", flags);	
	pce_xro_flags_obj = proto_item_add_subtree(ti, ett_pce_obj_xro);		
	proto_tree_add_boolean(pce_xro_flags_obj, pce_xro_flags_f, tvb, *offset2 + 2, 2, flags);
	
	*len = *len + 4;
	*offset2 = *offset2 + 4;
	
	while(body_subobj_len){

	x_type = tvb_get_guint8(tvb, *offset2);	  
	length = tvb_get_guint8(tvb, *offset2+1);
	type_xro = (x_type & Mask_Type);

	if (body_subobj_len <length) {
		proto_tree_add_text(pce_xro_flags_obj, tvb, *offset2, length, "The packet is bad coded!! \nObject Length = %u", body_subobj_len); 
		body_subobj_len = 0;
		*len = *msg_length;
		}		
	else{
	body_subobj_len = body_subobj_len - length; 	

	switch(type_xro) {
	  
	case PCE_SUB_IPv4:
		dissect_subobj_ipv4(ti, pce_xro_obj, tvb, offset2, len,  obj_class, ett_pce_obj_xro, x_type, length);
		break;
	case PCE_SUB_IPv6:
		dissect_subobj_ipv6(ti, pce_xro_obj, tvb, offset2, len, obj_class, ett_pce_obj_xro, x_type, length);
		break;
	case PCE_SUB_UNNUMB_INTERFACE_ID_XRO:
		dissect_subobj_unnumb_interfaceID(ti, pce_xro_obj, tvb, offset2, len, obj_class, ett_pce_obj_xro, x_type, length);
		break;
	case PCE_SUB_AUTONOMOUS_SYS_NUM_XRO:
		dissect_subobj_autonomous_sys_num(ti, pce_xro_obj, tvb, offset2, len,  obj_class, ett_pce_obj_xro, x_type, length);
		break;
	case PCE_SUB_SRLG:
		dissect_subobj_srlg(ti, pce_xro_obj, tvb, offset2, len, ett_pce_obj_xro, x_type, length);
		break;	
	default:
	    ti = proto_tree_add_text(pce_xro_obj, tvb, *offset2-4, length, "Non defined subobject (%d)", type_xro);
	    *offset2 = *offset2 + length;
	    *len = *len + length;
	    break;
	}	
	}
	}
}

/*------------------------------------------------------------------------------*/	
/* Dissect in Objects */
/*------------------------------------------------------------------------------*/
static void
dissect_pce_obj_tree(proto_tree *ti, tvbuff_t *tvb, proto_tree *pce_tree, int len, int offset, int msg_length)  
{  
    	
	guint8 obj_class;
	guint8 ot_res_p_i; 
	guint8 obj_length;
	int type;
	int offset2;
	proto_tree *pce_object_tree;
	proto_tree *pce_header_obj_flags;
 
  while (len < msg_length) {
  
	obj_class = tvb_get_guint8(tvb, offset);
	ot_res_p_i = tvb_get_guint8(tvb, offset+1);
	obj_length = tvb_get_ntohs(tvb, offset+2);
	type = (ot_res_p_i & MASK_OBJ_TYPE)>>4;
				 
	ti = proto_tree_add_text(pce_tree, tvb, offset, 4, "PCE %s Header", val_to_str(obj_class, pce_class_vals, "Unknown Message (%u). "));
	pce_object_tree = proto_item_add_subtree(ti, ett_pce_obj_hdr);
	
	proto_tree_add_text(pce_object_tree, tvb, offset+1, 1, "Object Type: %u", type);
	
	ti = proto_tree_add_text(pce_object_tree, tvb, offset+1, 1, "Flags");
	pce_header_obj_flags = proto_item_add_subtree(ti, ett_pce_hdr);
	proto_tree_add_boolean(pce_header_obj_flags, pce_hdr_obj_flags_reserved, tvb, offset+1, 1, ot_res_p_i);
	proto_tree_add_boolean(pce_header_obj_flags, pce_hdr_obj_flags_p, tvb, offset+1, 1, ot_res_p_i);
	proto_tree_add_boolean(pce_header_obj_flags, pce_hdr_obj_flags_i, tvb, offset+1, 1, ot_res_p_i);
		
	if (obj_length < 4) {
	    proto_tree_add_text(pce_object_tree, tvb, offset+2, 2, "Length: %u (bogus, must be >= 4)", obj_length);
	    break;
	}
	
	proto_tree_add_text(pce_object_tree, tvb, offset+2, 2, "Object Length: %u", obj_length);
	proto_tree_add_uint(pce_object_tree, pce_filter[PCEF_OBJECT], tvb, offset, 1, obj_class);

	offset2 = offset+4;
	len = len + 4;
	
	switch(obj_class) {

	case PCE_OPEN_OBJ:
	    dissect_pce_open_obj(ti, pce_tree, tvb, &offset2, obj_length, &len);
	    break;

	case PCE_RP_OBJ:
	    dissect_pce_rp_obj(ti, pce_tree, tvb, &offset2, obj_length, &len);
	    break;
	
	case PCE_NO_PATH_OBJ:
	    dissect_pce_no_path_obj(ti, pce_tree, tvb, &offset2, obj_length, &len);
	    break;

	case PCE_END_POINT_OBJ:
	    dissect_pce_end_point_obj(ti, pce_tree, tvb, &offset2, obj_length, &len, type);
	    break;

	case PCE_BANDWIDTH_OBJ:
	    dissect_pce_bandwidth_obj(ti, pce_tree, tvb, &offset2, obj_length, &len);
	    break;

	case PCE_METRIC_OBJ:
	    dissect_pce_metric_obj(ti, pce_tree, tvb, &offset2, obj_length, &len);
	    break;

	case PCE_EXPLICIT_ROUTE_OBJ:
	    dissect_pce_explicit_route_obj(ti, pce_tree, tvb, &offset2, obj_length, obj_class, &len, &msg_length);
	    break;

	case PCE_RECORD_ROUTE_OBJ:
	    dissect_pce_record_route_obj(ti, pce_tree, tvb, &offset2, obj_length, obj_class, &len, &msg_length);
	    break;

	case PCE_LSPA_OBJ:
	    dissect_pce_lspa_obj(ti, pce_tree, tvb, &offset2, obj_length, &len);
	    break;

	case PCE_IRO_OBJ:
	    dissect_pce_iro_obj(ti, pce_tree, tvb, &offset2, obj_length, obj_class, &len, &msg_length);
	    break;

	case PCE_SVEC_OBJ:
	    dissect_pce_svec_obj(ti, pce_tree, tvb, &offset2, obj_length, &len);
	    break;

	case PCE_NOTIFICATION_OBJ:
	    dissect_pce_notification_obj(ti, pce_tree, tvb, &offset2, obj_length, &len);
	    break;

	case PCE_PCEP_ERROR_OBJ:
	    dissect_pce_error_obj(ti, pce_tree, tvb, &offset2, obj_length, &len);
	    break;

	case PCE_LOAD_BALANCING_OBJ:
	    dissect_pce_balancing_obj(ti, pce_tree, tvb, &offset2, obj_length, &len);
	    break;

	case PCE_CLOSE_OBJ:
	    dissect_pce_close_obj(ti, pce_tree, tvb, &offset2, obj_length, &len);
	    break;
	    
	case PCE_XRO_OBJ:
	    dissect_pce_xro_obj(ti, pce_tree, tvb, &offset2, obj_length, obj_class, &len, &msg_length);
	    break;
	
	default:
	    ti = proto_tree_add_text(pce_tree, tvb, offset2, obj_length-4, "PCE Object BODY non defined (%u)", type);	  
	    break;

	}

	offset += obj_length; 
    }	
}


/*------------------------------------------------------------------------------
 * Dissect a single PCE message in a tree
 *------------------------------------------------------------------------------*/
static void
dissect_pce_msg_tree(tvbuff_t *tvb, proto_tree *tree, guint tree_mode, packet_info *pinfo)
{
    proto_tree *pce_tree = NULL;
    proto_tree *pce_header_tree; 
    proto_tree *ti;
    proto_tree *pce_header_msg_flags;
    
    int offset = 0;
    int len=0;
    guint8 ver_flags;
    guint8 message_type;
    guint16 msg_length;  

    ver_flags = tvb_get_guint8(tvb, 0);
    message_type = tvb_get_guint8(tvb, 1);
    msg_length = tvb_get_ntohs(tvb, 2);
    
    if (check_col(pinfo->cinfo, COL_INFO)) {
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(message_type, message_type_vals, "Unknown Message (%u). "));
    }
    
    ti = proto_tree_add_item(tree, proto_pce, tvb, offset, msg_length, FALSE);
    pce_tree = proto_item_add_subtree(ti, tree_mode);
    
    proto_item_append_text(pce_tree, ": ");
    proto_item_append_text(pce_tree, "Path Computation Element communication protocol");
        
    ti = proto_tree_add_text(pce_tree, tvb, offset, 4, "PCE %s Header", val_to_str(message_type, message_type_vals, "Unknown Message (%u). "));

    pce_header_tree = proto_item_add_subtree(ti, ett_pce_hdr);

    proto_tree_add_text(pce_header_tree, tvb, offset, 1, "PCE Version: %x", (ver_flags & 0x20)>>5);
			
    ti = proto_tree_add_text(pce_header_tree, tvb, offset, 1, "Flags: ");
    pce_header_msg_flags = proto_item_add_subtree(ti, ett_pce_hdr);
    proto_tree_add_boolean(pce_header_msg_flags, pce_hdr_msg_flags_reserved, tvb, offset, 1, (ver_flags & 0x1f));
    proto_tree_add_uint(pce_header_tree, pce_filter[PCEF_MSG], tvb, offset+1, 1, message_type);
    proto_tree_add_text(pce_header_tree, tvb, offset+2, 2, "Message length: %u", msg_length);
			
    switch (PCEF_MSG + message_type) {
   
    case PCEF_OPEN:
    case PCEF_KEEPALIVE:
    case PCEF_PATH_COMPUTATION_REQUEST:
    case PCEF_PATH_COMPUTATION_REPLY:
    case PCEF_NOTIFICATION:
    case PCEF_ERROR:
    case PCEF_CLOSE:
      	
	proto_tree_add_boolean_hidden(pce_header_tree, pce_filter[PCEF_MSG + message_type], tvb, offset+1, 1, 1);
	break;

    default:
	proto_tree_add_protocol_format(pce_header_tree, proto_malformed, tvb, offset+1, 1, "Invalid message type: %u", message_type);
	return;
    }

    offset = 4;
    len = 4;
    
    dissect_pce_obj_tree(ti, tvb, pce_tree, len, offset, msg_length);    
}


static guint
get_pce_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  guint16 plen;

  /* Get the length of the PCE packet.*/
  plen = tvb_get_ntohs(tvb, offset+2);

  return plen;
}

static void
dissect_pce_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	
/* Set up structures needed to add the protocol subtree and manage it */
	
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "PCE");
		
	/* Clear out stuff in the info column */
	if(check_col(pinfo->cinfo,COL_INFO))
		col_clear(pinfo->cinfo,COL_INFO);
		
	if (tree) {
		dissect_pce_msg_tree(tvb, tree, ett_pce, pinfo);
	}
		
};


static void
dissect_pce(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 4, get_pce_message_len,
	dissect_pce_pdu);
}

/*Register le protocol with wireshark*/
void
proto_register_pce(void){

/*Register the protocol name and description*/
	proto_pce = proto_register_protocol (
			"PCE Protocol",	/* name*/
			"PCE",		/* short name */
			"pce"		/* abbrev*/);
			
/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_pce, pcef_info, array_length(pcef_info));
	proto_register_subtree_array(ett, array_length(ett));
	pce_dissector_table = register_dissector_table("pce.proto", "PCE Protocol", FT_UINT8, BASE_DEC);

}

/*Dissector Handoff*/
void
proto_reg_handoff_pce(void)
{

	dissector_handle_t pce_handle;
	pce_handle = create_dissector_handle(dissect_pce, proto_pce);
	dissector_add("tcp.port", TCP_PORT_PPCE, pce_handle);
	data_handle = find_dissector("data");

}
















