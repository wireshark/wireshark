/* packet-pcep.c
 * Routines for PCEP packet disassembly
 * draft-ietf-pce-pcep-09
 * draft-ietf-pce-pcep-xro-02
 * See also RFC 4655 and RFC 4657
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
#include <epan/dissectors/packet-tcp.h>

#include "packet-frame.h"

/*differents types of objects*/
#define PCEP_OPEN_OBJ			1
#define PCEP_RP_OBJ			2
#define PCEP_NO_PATH_OBJ		3
#define PCEP_END_POINT_OBJ		4
#define PCEP_BANDWIDTH_OBJ		5
#define PCEP_METRIC_OBJ			6
#define PCEP_EXPLICIT_ROUTE_OBJ		7
#define PCEP_RECORD_ROUTE_OBJ		8
#define PCEP_LSPA_OBJ			9
#define PCEP_IRO_OBJ			10
#define PCEP_SVEC_OBJ			11
#define PCEP_NOTIFICATION_OBJ		12
#define PCEP_PCEP_ERROR_OBJ		13
#define PCEP_LOAD_BALANCING_OBJ		14
#define PCEP_CLOSE_OBJ			15
#define NO_DEFINED_OBJ			16
#define PCEP_XRO_OBJ			17

/*Subobjects of EXPLICIT ROUTE Object*/
#define PCEP_SUB_IPv4				1
#define PCEP_SUB_IPv6				2	
#define PCEP_SUB_LABEL_CONTROL			3	
#define PCEP_SUB_UNNUMB_INTERFACE_ID		4
#define PCEP_SUB_SRLG				5	
#define PCEP_SUB_AUTONOMOUS_SYS_NUM		32
#define PCEP_SUB_EXRS				33
#define PCEP_SUB_AUTONOMOUS_SYS_NUM_XRO		4
#define PCEP_SUB_UNNUMB_INTERFACE_ID_XRO	3

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
#define PCEP_CONGESTION			2

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
#define RX_PCEPERR_UNACEP_SESSION	6	
#define NO_KEEPALIVE_PCEPERR		7

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

/*Different values of Attribute in the XRO object */
#define ATTR_INTERFACE			0
#define ATTR_NODE			1
#define ATTR_SRLG			2

/*Mask for the flags of HEADER of Messages*/
#define  PCEP_HDR_MSG_RESERVED		0x1f

/*Mask for the type of HEADER of Objects*/
#define  MASK_OBJ_TYPE			0xF0

/*Mask for the flags of HEADER of Objects*/
#define  PCEP_HDR_OBJ_RESERVED		0x0C
#define  PCEP_HDR_OBJ_P			0x02
#define  PCEP_HDR_OBJ_I			0x01

/*Mask for the flags of OPEN Object*/
#define  PCEP_OPEN_RES			0x1F

/*Mask for the flags of RP Object*/
#define  PCEP_RP_PRI			0x000007
#define  PCEP_RP_R			0x000008
#define  PCEP_RP_B			0x000010
#define  PCEP_RP_O			0x000020
#define  PCEP_RP_RESERVED		0xFFFFC0

/*Mask for the flags of NO PATH Object*/
#define  PCEP_NO_PATH_C			0x8000

/*Mask for the flags of METRIC Object*/
#define  PCEP_METRIC_C			0x01
#define  PCEP_METRIC_B			0x02

/*Mask for the flags of LSPA Object*/
#define  PCEP_LSPA_L			0x01

/* Mask to differentiate the value of L and Type (Explicit Object)*/
#define Mask_L				0x80
#define Mask_Type			0x7f

#define TCP_PORT_PCEP			1010 	

#define IPv4				1
#define IPv6				2

/*Mask for the flags os SVEC Object*/
#define  PCEP_SVEC_L			0x000001
#define  PCEP_SVEC_N			0x000002
#define  PCEP_SVEC_S			0x000004

/*Mask for the flags of XRO Object*/
#define  PCEP_XRO_F			0x0001

/*Mask for the flags of IPv4, IPv6 and UNnumbered InterfaceID Subobjects of RRO Object*/
#define PCEP_SUB_LPA			0x01
#define PCEP_SUB_LPU			0x02

/*Mask for the flags of Label SubObject*/
#define PCEP_SUB_LABEL_GL		0x01


static int proto_pcep = -1;
static gint ett_pcep = -1;
static gint ett_pcep_hdr = -1;
static gint pcep_hdr_msg_flags_reserved= -1;
static gint pcep_hdr_obj_flags_reserved= -1;
static gint pcep_hdr_obj_flags_p= -1;
static gint pcep_hdr_obj_flags_i= -1;
static gint ett_pcep_obj_open = -1;
static gint pcep_open_flags_res = -1;
static gint ett_pcep_obj_request_parameters = -1;
static gint pcep_rp_flags_pri = -1;
static gint pcep_rp_flags_r = -1;
static gint pcep_rp_flags_b = -1;
static gint pcep_rp_flags_o = -1;
static gint pcep_rp_flags_reserved = -1;
static gint ett_pcep_obj_no_path = -1;
static gint pcep_no_path_flags_c = -1;
static gint ett_pcep_obj_end_point = -1;
static gint ett_pcep_obj_bandwidth = -1;
static gint ett_pcep_obj_metric = -1;
static gint pcep_metric_flags_c = -1;
static gint pcep_metric_flags_b = -1;
static gint ett_pcep_obj_explicit_route = -1;
static gint ett_pcep_obj_record_route = -1;
static gint ett_pcep_obj_lspa = -1;
static gint pcep_lspa_flags_l= -1;
static gint ett_pcep_obj_iro = -1;
static gint ett_pcep_obj_svec = -1;
static gint pcep_svec_flags_l= -1;
static gint pcep_svec_flags_n= -1;
static gint pcep_svec_flags_s= -1;
static gint ett_pcep_obj_notification = -1;
static gint ett_pcep_obj_error = -1;
static gint ett_pcep_obj_load_balancing = -1;
static gint ett_pcep_obj_close = -1;
static gint ett_pcep_obj_xro = -1;
static gint pcep_xro_flags_f= -1;
static gint pcep_subobj_flags_lpa= -1;
static gint pcep_subobj_flags_lpu= -1;
static gint pcep_subobj_label_flags_gl= -1;
static gint ett_pcep_obj_unknown = -1;

/* PCEP message types.*/
typedef enum {
	PCEP_MSG_NO_VALID,
	PCEP_MSG_OPEN,
	PCEP_MSG_KEEPALIVE, 
	PCEP_MSG_PATH_COMPUTATION_REQUEST,
	PCEP_MSG_PATH_COMPUTATION_REPLY,	
	PCEP_MSG_NOTIFICATION,		
	PCEP_MSG_ERROR,	
	PCEP_MSG_CLOSE   
} pcep_message_types;

static const value_string message_type_vals[] = {
	{PCEP_MSG_OPEN,				"OPEN MESSAGE"				},
	{PCEP_MSG_KEEPALIVE, 			"KEEPALIVE MESSAGE"			},
	{PCEP_MSG_PATH_COMPUTATION_REQUEST,	"PATH COMPUTATION REQUEST MESSAGE"	},
	{PCEP_MSG_PATH_COMPUTATION_REPLY,	"PATH COMPUTATION REPLY MESSAGE"        },
	{PCEP_MSG_NOTIFICATION,			"NOTIFICATION MESSAGE"			},
	{PCEP_MSG_ERROR,			"ERROR MESSAGE"			  	},	
	{PCEP_MSG_CLOSE,			"CLOSE MESSAGE"			  	},
	{0,			         	NULL            		  	}
};

static const value_string pcep_class_vals[] = {
	{PCEP_OPEN_OBJ,			"OPEN OBJECT" 			},
	{PCEP_RP_OBJ, 			"RP OBJECT"			},
	{PCEP_NO_PATH_OBJ,		"NO-PATH OBJECT"		},
	{PCEP_END_POINT_OBJ,		"END-POINT OBJECT"      	},
	{PCEP_BANDWIDTH_OBJ,		"BANDWIDTH OBJECT"		},
	{PCEP_METRIC_OBJ,		"METRIC OBJECT"			},	
	{PCEP_EXPLICIT_ROUTE_OBJ,	"EXPLICIT ROUTE OBJECT (ERO)"	},	
	{PCEP_RECORD_ROUTE_OBJ,		"RECORD ROUTE OBJECT (RRO)"	}, 
	{PCEP_LSPA_OBJ,			"LSPA OBJECT"			},
	{PCEP_IRO_OBJ,			"IRO OBJECT"			},
	{PCEP_SVEC_OBJ,			"SVEC OBJECT"			},
	{PCEP_NOTIFICATION_OBJ,		"NOTIFICATION OBJECT"		},
	{PCEP_PCEP_ERROR_OBJ,		"PCEP ERROR OBJECT"		},
	{PCEP_LOAD_BALANCING_OBJ,	"LOAD BALANCING OBJECT"		},
	{PCEP_CLOSE_OBJ,		"CLOSE OBJECT"			},
	{NO_DEFINED_OBJ,		"Non Defined OBJECT"		},
	{PCEP_XRO_OBJ,			"EXCLUDE ROUTE OBJECT (XRO)"	},
	{0,			         NULL            		}
};

static const value_string pcep_subobj_vals[] = {
	{PCEP_SUB_IPv4,			"SUBOBJECT IPv4" 			},
	{PCEP_SUB_IPv6, 		"SUBOBJECT IPv6"			},
	{PCEP_SUB_LABEL_CONTROL,	"SUBOBJECT LABEL"			},
	{PCEP_SUB_UNNUMB_INTERFACE_ID,	"SUBOBJECT UNNUMBERED INTERFACE-ID"	},
	{PCEP_SUB_SRLG,			"SUBOBJECT SRLG"      			},
	{PCEP_SUB_AUTONOMOUS_SYS_NUM,	"SUBOBJECT AUTONOMOUS SYSTEM NUMBER"	},
	{0,			         NULL            			}
};


static const value_string pcep_subobj_xro_vals[] = {
	{PCEP_SUB_IPv4,			"SUBOBJECT IPv4" 			},
	{PCEP_SUB_IPv6, 		"SUBOBJECT IPv6"			},
	{PCEP_SUB_UNNUMB_INTERFACE_ID_XRO,"SUBOBJECT UNNUMBERED INTERFACE-ID"	}, 
	{PCEP_SUB_AUTONOMOUS_SYS_NUM_XRO,"SUBOBJECT AUTONOMOUS SYSTEM NUMBER"	},
	{PCEP_SUB_SRLG,			"SUBOBJECT SRLG"      			},
	{0,			         NULL            			}
};

/*In the NO-PATH Object the two different possibilities that NI can have*/ 
static const value_string pcep_no_path_obj_vals[] = {
	{NO_SATISFYING, 		"Nature of Issue: No path satisfying the set of constraints could be found (0x0)"	},
	{CHAIN_BROKEN,			"Nature of Issue: PCEP Chain Broken (0x1)"						},
	{0,			         NULL            									}
};

/*Different values of "Type (T)" in the METRIC Obj */ 	
static const value_string pcep_metric_obj_vals[] = {
	{NO_DEFINED,	 	"Type not defined"		},
	{IGP_METRIC, 		"Type: IGP Metric (T=1)"	},
	{TE_METRIC,		"Type: TE Metric (T=2)"		},
	{HOP_COUNTS,		"Type: Hop Counts (T=3)"	},	
	{0,		         NULL 				}
};

/*Different values for (L) in the ERO and IRO Objs */ 
static const value_string pcep_route_l_obj_vals[] = {
	{STRICT_HOP,			"L=0 Strict Hop in the Explicit Route"		},
	{LOOSE_HOP, 			"L=1 Loose Hop in the Explicit Route"	 	},
	{0,			         NULL            				}
};

/*Different values of the direction of the label (U) in the ERO and RRO Objs */ 
static const value_string pcep_route_u_obj_vals[] = {
	{DOWNSTREAM_LABEL,			"U=0 S Downstream Label" },
	{UPSTREAM_LABEL, 			"U=1 Upstream Label"	 },
	{0,			        	NULL			 }
};

/*Values of Notification type*/
static const value_string pcep_notification_types_vals[] = {
	{NOT_REQ_CANCEL,		"Pending Request Cancelled"	},
	{PCEP_CONGESTION, 		"PCE Congestion" 		},
	{0,			         NULL            					}
};

/*Values of Notification value for Notification Type=1*/
static const value_string pcep_notification_values1_vals[] = {
	{NOTI_PCC_CANCEL_REQ,		"PCC Cancels a set of Pending Request (s)"	},
	{NOTI_PCE_CANCEL_REQ, 		"PCE Cancels a set of Pending Request (s)"	},
	{0,			         NULL            				}
};

/*Values of Notification value for Notification Type=2*/
static const value_string pcep_notification_values2_vals[] = {
	{NOTI_PCE_CONGEST,		"PCE in Congested State"		},
	{NOTI_PCE_NO_CONGEST, 		"PCE no Longer in Congested state"	},
	{0,			         NULL          				}
};


/*Values of different types of errors*/
static const value_string pcep_error_types_obj_vals[] = {
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

static const value_string pcep_close_reason_obj_vals[] = {
	{NO_DEFINED,	 		"Reason = 0 no defined"					},
	{NO_EXP_PROV,			"Reason = 1 No Explanation Provided "			},
	{DEADTIME_PROV, 		"Reason = 2 Deadtime Expired"	 			},
	{RECEP_MALFORM_MSG, 		"Reason = 3 Reception of a Malformed PCEP Message"	},
	{0,			         NULL            					}
};

static const value_string pcep_xro_atribute_obj_vals[] = {
	{ATTR_INTERFACE,	 	"Atribute = 0 Interface"	},
	{ATTR_NODE,			"Atribute = 1 Node "		},
	{ATTR_SRLG, 			"Atribute = 2 SRLG"		},
	{0,			         NULL           	}
};

/* The PCEP filtering keys */
enum pcep_filter_keys{

    PCEPF_MSG,

    PCEPF_OPEN,
    PCEPF_KEEPALIVE,
    PCEPF_PATH_COMPUTATION_REQUEST,
    PCEPF_PATH_COMPUTATION_REPLY,
    PCEPF_NOTIFICATION,
    PCEPF_ERROR,
    PCEPF_CLOSE,     

    PCEPF_OBJECT_CLASS,
    PCEPF_OBJ_OPEN,
    PCEPF_OBJ_RP,
    PCEPF_OBJ_NO_PATH,
    PCEPF_OBJ_END_POINT,
    PCEPF_OBJ_BANDWIDTH,
    PCEPF_OBJ_METRIC,
    PCEPF_OBJ_EXPLICIT_ROUTE,
    PCEPF_OBJ_RECORD_ROUTE,
    PCEPF_OBJ_LSPA,
    PCEPF_OBJ_IRO,
    PCEPF_OBJ_SVEC,
    PCEPF_OBJ_NOTIFICATION,
    PCEPF_NOTI_TYPE,
    PCEPF_NOTI_VAL1,
    PCEPF_NOTI_VAL2,
    PCEPF_OBJ_PCEP_ERROR,
    PCEPF_ERROR_TYPE,
    PCEPF_OBJ_LOAD_BALANCING,
    PCEPF_OBJ_CLOSE,
    PCEPF_OBJ_XRO,
    PCEPF_SUBOBJ,
    PCEPF_SUBOBJ_IPv4,
    PCEPF_SUBOBJ_IPv6,
    PCEPF_SUBOBJ_LABEL_CONTROL,
    PCEPF_SUBOBJ_UNNUM_INTERFACEID,
    PCEPF_SUBOBJ_AUTONOMOUS_SYS_NUM,
    PCEPF_SUBOBJ_SRLG,
    PCEPF_SUBOBJ_EXRS,
    PCEPF_SUBOBJ_XRO,
    PCEPF_SUB_XRO_ATRIB,

    PCEPF_MAX
};


/*Registering data structures*/

static gint *ett[] = {
	&ett_pcep,
	&ett_pcep_hdr,
	&ett_pcep_obj_open,
	&ett_pcep_obj_request_parameters,
	&ett_pcep_obj_no_path,
	&ett_pcep_obj_end_point,
        &ett_pcep_obj_bandwidth,
        &ett_pcep_obj_metric,
        &ett_pcep_obj_explicit_route,
        &ett_pcep_obj_record_route,
        &ett_pcep_obj_lspa,
	&ett_pcep_obj_iro,
	&ett_pcep_obj_svec,
	&ett_pcep_obj_notification,
	&ett_pcep_obj_error,
	&ett_pcep_obj_load_balancing,
	&ett_pcep_obj_close, 
	&ett_pcep_obj_xro,
	&ett_pcep_obj_unknown
};

/*Registering data structures*/    

static int pcep_filter[PCEPF_MAX];

static hf_register_info pcepf_info[] = {

    /* Message type number */
    {&pcep_filter[PCEPF_MSG],
     { "Message Type", "pcep.msg", FT_UINT8, BASE_DEC, VALS(message_type_vals), 0x0,
     	"", HFILL }},
    {&pcep_hdr_msg_flags_reserved,
     { "Reserved Flags", "pcep.hdr.msg.flags.reserved", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCEP_HDR_MSG_RESERVED,
        "", HFILL }},     	
    {&pcep_filter[PCEPF_OPEN],
     { "Open Message", "pcep.msg.open", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
    {&pcep_filter[PCEPF_KEEPALIVE],
     { "Keepalive Message", "pcep.msg.keepalive", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
    {&pcep_filter[PCEPF_PATH_COMPUTATION_REQUEST],
     { "Path Computation Request Message", "pcep.msg.path.computation.request", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
    {&pcep_filter[PCEPF_PATH_COMPUTATION_REPLY],
     { "Path Computation Reply Mesagge", "pcep.msg.path.computation.reply", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
    {&pcep_filter[PCEPF_NOTIFICATION],
     { "Notification Message", "pcep.msg.notification", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "", HFILL }},
    {&pcep_filter[PCEPF_ERROR],
     { "Error Message", "pcep.msg.error", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "", HFILL }},
    {&pcep_filter[PCEPF_CLOSE],
     { "Close Message", "pcep.msg.close", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "", HFILL }},    

    /*Object header*/
    {&pcep_hdr_obj_flags_reserved,
     { "Reserved Flags", "pcep.hdr.obj.flags.reserved", FT_BOOLEAN, 4, TFS(&tfs_set_notset), PCEP_HDR_OBJ_RESERVED,
	"", HFILL }},
    {&pcep_hdr_obj_flags_p,
     { "Processing-Rule (P)", "pcep.hdr.obj.flags.p", FT_BOOLEAN, 4, TFS(&tfs_set_notset), PCEP_HDR_OBJ_P,
	"", HFILL }},
    {&pcep_hdr_obj_flags_i,
     { "Ignore (I)", "pcep.hdr.obj.flags.i", FT_BOOLEAN, 4, TFS(&tfs_set_notset), PCEP_HDR_OBJ_I,
	"", HFILL }},	
    /* Object class */
    {&pcep_filter[PCEPF_OBJECT_CLASS],
     { "Object Class", "pcep.object", FT_UINT32, BASE_DEC, VALS(pcep_class_vals), 0x0,
     	"", HFILL }},

    /* Object types */
    {&pcep_filter[PCEPF_OBJ_OPEN],
     { "OPEN object", "pcep.obj.open", FT_NONE, BASE_NONE, NULL, 0x0,
    	"", HFILL }},
    {&pcep_open_flags_res,
     { "Reserved Flags", "pcep.open.flags.res", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCEP_OPEN_RES,
	"", HFILL }},
    {&pcep_filter[PCEPF_OBJ_RP],
     { "RP object", "pcep.obj.rp", FT_NONE, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
    {&pcep_rp_flags_reserved,
     { "Reserved Flags", "pcep.rp.flags.reserved", FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_RP_RESERVED,
	"", HFILL }},
    {&pcep_rp_flags_pri,
     { "Priority (PRI)", "pcep.rp.flags.pri", FT_BOOLEAN, 24, TFS(&tfs_on_off), PCEP_RP_PRI,
	"", HFILL }},
    {&pcep_rp_flags_r,
     { "Reoptimization (R)", "pcep.rp.flags.r", FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_RP_R,
	"", HFILL }},
    {&pcep_rp_flags_b,
     { "Bi-directional (L)", "pcep.rp.flags.b", FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_RP_B,
	"", HFILL }},
    {&pcep_rp_flags_o,
     { "Strict/Loose (L)", "pcep.rp.flags.o", FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_RP_O,
	"", HFILL }},
    {&pcep_filter[PCEPF_OBJ_NO_PATH],
     { "NO-PATH object", "pcep.obj.nopath", FT_NONE, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
    {&pcep_no_path_flags_c,
     { "C", "pcep.no.path.flags.c", FT_BOOLEAN, 16, TFS(&tfs_set_notset), PCEP_NO_PATH_C,
	"", HFILL }},
    {&pcep_filter[PCEPF_OBJ_END_POINT],
     { "END-POINT object", "pcep.obj.endpoint", FT_NONE, BASE_NONE, NULL, 0x0,
     	"", HFILL }},	
    {&pcep_filter[PCEPF_OBJ_BANDWIDTH],
     { "BANDWIDTH object", "pcep.obj.bandwidth", FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL }},
    {&pcep_filter[PCEPF_OBJ_METRIC],
     { "METRIC object", "pcep.obj.metric", FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL }},
    {&pcep_metric_flags_c,
     { "Cost (C)", "pcep.metric.flags.c", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCEP_METRIC_C,
	"", HFILL }},
    {&pcep_metric_flags_b,
     { "Bound (B)", "pcep.metric.flags.b", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCEP_METRIC_B,
	"", HFILL }},
    {&pcep_filter[PCEPF_OBJ_EXPLICIT_ROUTE],
     { "EXPLICIT ROUTE object (ERO)", "pcep.obj.ero", FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL }},
    {&pcep_filter[PCEPF_OBJ_RECORD_ROUTE],
     { "RECORD ROUTE object (RRO)", "pcep.obj.rro", FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL }},     
    {&pcep_filter[PCEPF_OBJ_LSPA],
     { "LSPA object", "pcep.obj.lspa", FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL }},    
    {&pcep_lspa_flags_l,
     { "Local Protection Desired (L)", "pcep.lspa.flags.l", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCEP_LSPA_L,
	"", HFILL }},
    {&pcep_filter[PCEPF_OBJ_IRO],
     { "IRO object", "pcep.obj.iro", FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL }},     
    {&pcep_filter[PCEPF_OBJ_SVEC],
     { "SVEC object", "pcep.obj.svec", FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL }},  

    {&pcep_svec_flags_l,
     { "Link diverse (L)", "pcep.svec.flags.l", FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_SVEC_L,
	"", HFILL }},

    {&pcep_svec_flags_n,
     { "Node diverse (N)", "pcep.svec.flags.n", FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_SVEC_N,
	"", HFILL }},

    {&pcep_svec_flags_s,
     { "SRLG diverse (S)", "pcep.svec.flags.s", FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_SVEC_S,
	"", HFILL }},		

    {&pcep_filter[PCEPF_OBJ_NOTIFICATION],
     { "NOTIFICATION object", "pcep.obj.notification", FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL }},   

    {&pcep_filter[PCEPF_NOTI_TYPE],
     { "Notification Value", "pcep.notification.value1", FT_UINT32, BASE_DEC, VALS(pcep_notification_types_vals), 0x0,
     	"", HFILL }},
    {&pcep_filter[PCEPF_NOTI_VAL1],
     { "Notification Type", "pcep.notification.type2", FT_UINT32, BASE_DEC, VALS(pcep_notification_values1_vals), 0x0,
     	"", HFILL }},
    {&pcep_filter[PCEPF_NOTI_VAL2],
     { "Notification Type", "pcep.notification.type", FT_UINT32, BASE_DEC, VALS(pcep_notification_values2_vals), 0x0,
     	"", HFILL }},

    {&pcep_filter[PCEPF_OBJ_PCEP_ERROR],
     { "ERROR object", "pcep.obj.error", FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL }},   
    {&pcep_filter[PCEPF_ERROR_TYPE],
     { "Error-Type", "pcep.error.type", FT_UINT8, BASE_DEC, VALS(pcep_error_types_obj_vals), 0x0,
     	"", HFILL }},  
    {&pcep_filter[PCEPF_OBJ_LOAD_BALANCING],
     { "LOAD BALANCING object", "pcep.obj.loadbalancing", FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL }},     
    {&pcep_filter[PCEPF_OBJ_CLOSE],
     { "CLOSE object", "pcep.obj.close", FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL }}, 	
    {&pcep_filter[PCEPF_OBJ_XRO],
     { "EXCLUDE ROUTE object (XRO)", "pcep.obj.xro", FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL }},

    /*Subobjects*/	
    {&pcep_filter[PCEPF_SUBOBJ],
     { "Type", "pcep.subobj", FT_UINT8, BASE_DEC, VALS(pcep_subobj_vals), 0x0,
        "", HFILL }}, 

    {&pcep_filter[PCEPF_SUBOBJ_IPv4],
     { "SUBOBJECT: IPv4 Prefix", "pcep.subobj.ipv4", FT_NONE, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
    {&pcep_filter[PCEPF_SUBOBJ_IPv6],
     { "SUBOBJECT: IPv6 Prefix", "pcep.subobj.ipv6", FT_NONE, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
    {&pcep_filter[PCEPF_SUBOBJ_LABEL_CONTROL],
     { "SUBOBJECT: Label Control", "pcep.subobj.label.control", FT_NONE, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
    {&pcep_filter[PCEPF_SUBOBJ_UNNUM_INTERFACEID],
     { "SUBOBJECT: Unnumbered Interface ID", "pcep.subobj.unnum.interfaceid", FT_NONE, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
    {&pcep_filter[PCEPF_SUBOBJ_AUTONOMOUS_SYS_NUM],
     { "SUBOBJECT: Autonomous System Number", "pcep.subobj.auntonomus.sys.num", FT_NONE, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
    {&pcep_filter[PCEPF_SUBOBJ_SRLG],
     { "SUBOBJECT: SRLG", "pcep.subobj.srlg", FT_NONE, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
    {&pcep_filter[PCEPF_SUBOBJ_EXRS],
     { "SUBOBJECT: EXRS", "pcep.subobj.exrs", FT_NONE, BASE_NONE, NULL, 0x0,
     	"", HFILL }},
    {&pcep_filter[PCEPF_SUBOBJ_XRO],
     { "Type", "pcep.subobj.label", FT_UINT32, BASE_DEC, VALS(pcep_subobj_xro_vals), 0x0,
        "", HFILL }},
    {&pcep_xro_flags_f,
     { "Fail (F)", "pcep.xro.flags.f", FT_BOOLEAN, 16, TFS(&tfs_set_notset), PCEP_XRO_F,
	"", HFILL }},
    {&pcep_filter[PCEPF_SUB_XRO_ATRIB],
     { "Attribute", "pcep.xro.sub.atribute", FT_UINT32, BASE_DEC, VALS(pcep_xro_atribute_obj_vals), 0x0,
	"", HFILL }},

    {&pcep_subobj_flags_lpa,
     { "Local Protection Available", "pcep.subobj.flags.lpa", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCEP_SUB_LPA,
	"", HFILL }},
    {&pcep_subobj_flags_lpu,
     { "Local protection in Use", "pcep.subobj.flags.lpu", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCEP_SUB_LPU,
	"", HFILL }},	
    {&pcep_subobj_label_flags_gl,
     { "Global Label", "pcep.subobj.label.flags.gl", FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCEP_SUB_LABEL_GL,
	"", HFILL }},	
};

#define	OBJ_HDR_LEN	4	/* length of object header */

static void
dissect_pcep_tlvs(proto_tree *pcep_obj, tvbuff_t *tvb, int offset, gint length, gint ett_pcep_obj)
{
	proto_tree *tlv;
	proto_item *ti;
	guint16 tlv_length;
	guint16 tlv_type;
	int j;
	int m = 0;
	int padding = 0;

	for (j = 0; j < length; j += 4 + tlv_length + padding){
		m = m+1;

		tlv_type = tvb_get_ntohs(tvb, offset+j);
		tlv_length = tvb_get_ntohs(tvb, offset + j + 2);
		ti = proto_tree_add_text(pcep_obj, tvb, offset + j, tlv_length+4, "TLV %u", m);
		tlv = proto_item_add_subtree(ti, ett_pcep_obj);
		proto_tree_add_text(tlv, tvb, offset + j, 2, "Type: %u", tlv_type);
		proto_tree_add_text(tlv, tvb, offset + 2 + j, 2, "Length: %u", tlv_length);
		proto_tree_add_text(tlv, tvb, offset+4+j, tlv_length, "Data: %s", 
				bytestring_to_str(tvb_get_ptr(tvb, (offset) + 4 + j, tlv_length), tlv_length, ' '));
		padding = (4 - (tlv_length % 4)) % 4;
		if (padding != 0){
			proto_tree_add_text(tlv, tvb, offset+4+j+tlv_length, padding, "Padding: %s", 
				bytestring_to_str(tvb_get_ptr(tvb, (offset) + 4 + j + tlv_length, padding), padding, ' '));
		}	
	}
}

/*------------------------------------------------------------------------------
 *SUBOBJECTS
 *------------------------------------------------------------------------------*/
static void
dissect_subobj_ipv4(proto_tree *pcep_subobj_tree, tvbuff_t *tvb, int offset, int obj_class, gint ett_pcep_obj, guint l_and_or_type, guint length)
{
	proto_tree *pcep_subobj_ipv4;
	proto_tree *pcep_subobj_ipv4_flags;
	proto_item *ti;
	guint8 prefix_length;
	guint8 resvd;
	guint l;

	prefix_length = tvb_get_guint8(tvb, offset+6);
	resvd = tvb_get_guint8(tvb, offset+7);

	ti = proto_tree_add_item(pcep_subobj_tree, pcep_filter[PCEPF_SUBOBJ_IPv4], tvb, offset, length, FALSE);
	pcep_subobj_ipv4 = proto_item_add_subtree(ti, ett_pcep_obj);

	if (length != 8) {
		proto_tree_add_text(pcep_subobj_ipv4, tvb, offset, length,
		    "Bad IPv4 subobject: length %u != 8", length);
		return;
	}

	switch(obj_class){

	case PCEP_EXPLICIT_ROUTE_OBJ:
		l = (l_and_or_type& Mask_L)>>7;
		proto_tree_add_text(pcep_subobj_ipv4, tvb, offset, 1, val_to_str(l, pcep_route_l_obj_vals, "Unknown Object (%u). "));
		proto_tree_add_uint(pcep_subobj_ipv4, pcep_filter[PCEPF_SUBOBJ], tvb, offset, 1, (l_and_or_type & 0x7f));
		proto_tree_add_text(pcep_subobj_ipv4, tvb, offset+1, 1, "Length: %u", length);
		proto_tree_add_text(pcep_subobj_ipv4, tvb, offset+2, 4, "IPv4 Address: (%s)", ip_to_str(tvb_get_ptr(tvb, offset+2, 4)));
		proto_tree_add_text(pcep_subobj_ipv4, tvb, offset+6, 1, "Prefix Length: %u", prefix_length);
		proto_tree_add_text(pcep_subobj_ipv4, tvb, offset+7, 1, "Padding: 0x%02x", resvd);
		break;

	case PCEP_RECORD_ROUTE_OBJ:
		proto_tree_add_uint(pcep_subobj_ipv4, pcep_filter[PCEPF_SUBOBJ], tvb, offset, 1, l_and_or_type);
		proto_tree_add_text(pcep_subobj_ipv4, tvb, offset+1, 1, "Length: %u", length);
		proto_tree_add_text(pcep_subobj_ipv4, tvb, offset+2, 4, "IPv4 Address: (%s)", ip_to_str(tvb_get_ptr(tvb, offset+2, 4)));
		proto_tree_add_text(pcep_subobj_ipv4, tvb, offset+6, 1, "Prefix Length: %u", prefix_length);
		ti = proto_tree_add_text(pcep_subobj_ipv4, tvb, offset+7, 1, "Flags: 0x%02x ", resvd);
		pcep_subobj_ipv4_flags = proto_item_add_subtree(ti, ett_pcep_obj);
		proto_tree_add_boolean(pcep_subobj_ipv4_flags, pcep_subobj_flags_lpa, tvb, offset+7, 1, resvd);
		proto_tree_add_boolean(pcep_subobj_ipv4_flags, pcep_subobj_flags_lpu, tvb, offset+7, 1, resvd);
		break;

	case PCEP_IRO_OBJ:
		proto_tree_add_text(pcep_subobj_ipv4, tvb, offset, 1, "l: %x", (l_and_or_type & 0x80)>>7);
		proto_tree_add_uint(pcep_subobj_ipv4, pcep_filter[PCEPF_SUBOBJ], tvb, offset, 1, (l_and_or_type & 0x7f));
		proto_tree_add_text(pcep_subobj_ipv4, tvb, offset+1, 1, "Length: %u", length);
		proto_tree_add_text(pcep_subobj_ipv4, tvb, offset+2, 4, "IPv4 Address: (%s)", ip_to_str(tvb_get_ptr(tvb, offset+2, 4)));
		proto_tree_add_text(pcep_subobj_ipv4, tvb, offset+6, 1, "Prefix Length: %u", prefix_length);
		proto_tree_add_text(pcep_subobj_ipv4, tvb, offset+7, 1, "Padding: 0x%02x", resvd);
		break;

	case PCEP_XRO_OBJ:
		proto_tree_add_text(pcep_subobj_ipv4, tvb, offset, 1, "X: %x", (l_and_or_type & 0x01)>>7);
		proto_tree_add_uint(pcep_subobj_ipv4, pcep_filter[PCEPF_SUBOBJ_XRO], tvb, offset, 1, (l_and_or_type & 0x7f));
		proto_tree_add_text(pcep_subobj_ipv4, tvb, offset, 1, "Type: %u", (l_and_or_type & 0x7f));
		proto_tree_add_text(pcep_subobj_ipv4, tvb, offset+1, 1, "Length: %u", length);
		proto_tree_add_text(pcep_subobj_ipv4, tvb, offset+2, 4, "IPv4 Address: (%s)", ip_to_str(tvb_get_ptr(tvb, offset+2, 4)));
		proto_tree_add_text(pcep_subobj_ipv4, tvb, offset+6, 1, "Prefix Length: %u", prefix_length);
		proto_tree_add_text(pcep_subobj_ipv4, tvb, offset+7, 1, val_to_str(resvd, pcep_xro_atribute_obj_vals, "Unknown Atribute (%u). "));
		break;

	default:
		proto_tree_add_text(pcep_subobj_ipv4, tvb, offset, 8, "Non defined subobject for this object");
		break;
	}
}

static void
dissect_subobj_ipv6(proto_tree *pcep_subobj_tree, tvbuff_t *tvb, int offset, int obj_class, gint ett_pcep_obj, guint l_and_or_type, guint length)
{
	proto_tree *pcep_subobj_ipv6;
	proto_tree *pcep_subobj_ipv6_flags;
	proto_item *ti;
	guint8 prefix_length;
	guint8 resv;
	int l;

	prefix_length = tvb_get_guint8(tvb, offset+18);
	resv = tvb_get_guint8(tvb, offset+19);
	ti = proto_tree_add_item(pcep_subobj_tree, pcep_filter[PCEPF_SUBOBJ_IPv6], tvb, offset, length, FALSE);
	pcep_subobj_ipv6 = proto_item_add_subtree(ti, ett_pcep_obj);

	if (length != 20) {
		proto_tree_add_text(pcep_subobj_ipv6, tvb, offset, length,
		    "Bad IPv6 subobject: length %u != 20", length);
		return;
	}

	switch(obj_class){
	case PCEP_EXPLICIT_ROUTE_OBJ:
		l = (l_and_or_type& Mask_L)>>7;
		proto_tree_add_text(pcep_subobj_ipv6, tvb, offset, 1, val_to_str(l, pcep_route_l_obj_vals, "Unknown Object (%u). "));
		proto_tree_add_uint(pcep_subobj_ipv6, pcep_filter[PCEPF_SUBOBJ], tvb, offset, 1, (l_and_or_type & 0x7f));
		proto_tree_add_text(pcep_subobj_ipv6, tvb, offset+1, 1, "Length: %u", length);
		proto_tree_add_text(pcep_subobj_ipv6, tvb, offset+2, 16, "IPv6 Address: %s", ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(tvb, offset+2, 16)));
		proto_tree_add_text(pcep_subobj_ipv6, tvb, offset+18, 1, "Prefix Length: %u", prefix_length);
		proto_tree_add_text(pcep_subobj_ipv6, tvb, offset+19, 1, "Padding: 0x%02x", resv);
		break;

	case PCEP_RECORD_ROUTE_OBJ:
		proto_tree_add_uint(pcep_subobj_ipv6, pcep_filter[PCEPF_SUBOBJ], tvb, offset, 1, l_and_or_type);
		proto_tree_add_text(pcep_subobj_ipv6, tvb, offset+1, 1, "Length: %u", length);
		proto_tree_add_text(pcep_subobj_ipv6, tvb, offset+2, 16, "IPv6 Address: %s", ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(tvb, offset+2, 16)));
		proto_tree_add_text(pcep_subobj_ipv6, tvb, offset+18, 1, "Prefix Length: %u", prefix_length);
		ti = proto_tree_add_text(pcep_subobj_ipv6, tvb, offset+19, 1, "Flags: 0x%02x ", resv);
		pcep_subobj_ipv6_flags = proto_item_add_subtree(ti, ett_pcep_obj);
		proto_tree_add_boolean(pcep_subobj_ipv6_flags, pcep_subobj_flags_lpa, tvb, offset+19, 1, resv);
		proto_tree_add_boolean(pcep_subobj_ipv6_flags, pcep_subobj_flags_lpu, tvb, offset+19, 1, resv);
		break;

	case PCEP_IRO_OBJ:
		proto_tree_add_text(pcep_subobj_ipv6, tvb, offset, 1, "l: %x", (l_and_or_type & 0x80)>>7);
		proto_tree_add_uint(pcep_subobj_ipv6, pcep_filter[PCEPF_SUBOBJ], tvb, offset, 1, (l_and_or_type & 0x7f));
		proto_tree_add_text(pcep_subobj_ipv6, tvb, offset+1, 1, "Length: %u", length);
		proto_tree_add_text(pcep_subobj_ipv6, tvb, offset+2, 16, "IPv6 Address: %s", ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(tvb, offset+2, 16)));
		proto_tree_add_text(pcep_subobj_ipv6, tvb, offset+18, 1, "Prefix Length: %u", prefix_length);
		proto_tree_add_text(pcep_subobj_ipv6, tvb, offset+19, 1, "Padding: 0x%02x", resv);
		break;

	case PCEP_XRO_OBJ:
		proto_tree_add_text(pcep_subobj_ipv6, tvb, offset, 1, "X: %x", (l_and_or_type & 0x01)>>7);
		proto_tree_add_uint(pcep_subobj_ipv6, pcep_filter[PCEPF_SUBOBJ_XRO], tvb, offset, 1, (l_and_or_type & 0x7f));
		proto_tree_add_text(pcep_subobj_ipv6, tvb, offset+1, 1, "Length: %u", length);
		proto_tree_add_text(pcep_subobj_ipv6, tvb, offset+2, 16, "IPv6 Address: %s", ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(tvb, offset+2, 16)));
		proto_tree_add_text(pcep_subobj_ipv6, tvb, offset+18, 1, "Prefix Length: %u", prefix_length);
		proto_tree_add_text(pcep_subobj_ipv6, tvb, offset+19, 1, val_to_str(resv, pcep_xro_atribute_obj_vals, "Unknown Atribute (%u). "));
		break;

	default:
		proto_tree_add_text(pcep_subobj_ipv6, tvb, offset, 20, "Non defined subobject for this object");
		break;
	}	
}


static void
dissect_subobj_label_control(proto_tree *pcep_subobj_tree,  tvbuff_t *tvb,  int offset, int obj_class, gint ett_pcep_obj, guint l_and_or_type, guint length)
{
	proto_tree *pcep_subobj_label_control;
	proto_tree *pcep_subobj_label_flags;
	proto_item *ti;
	guint8 u_reserved;
	guint8 c_type;
	int l;
	int u;

	u_reserved = tvb_get_guint8(tvb, offset+2);
	c_type = tvb_get_guint8(tvb, offset+3);

	ti = proto_tree_add_item(pcep_subobj_tree, pcep_filter[PCEPF_SUBOBJ_LABEL_CONTROL], tvb, offset, length, FALSE);
	pcep_subobj_label_control = proto_item_add_subtree(ti, ett_pcep_obj);

	if (length < 5) {
		proto_tree_add_text(pcep_subobj_label_control, tvb, offset, length,
		    "Bad label control subobject: length %u < 5", length);
		return;
	}

	switch(obj_class){

	case PCEP_EXPLICIT_ROUTE_OBJ:
		l = (l_and_or_type& Mask_L)>>7;
		proto_tree_add_text(pcep_subobj_label_control, tvb, offset, 1, val_to_str(l, pcep_route_l_obj_vals, "Unknown Object (%u). "));
		proto_tree_add_uint(pcep_subobj_label_control, pcep_filter[PCEPF_SUBOBJ], tvb, offset, 1, (l_and_or_type & 0x7f));
		proto_tree_add_text(pcep_subobj_label_control, tvb, offset+1, 1, "Length: %u", length);
		u = (u_reserved & 0x80)>>7;
		proto_tree_add_text(pcep_subobj_label_control, tvb, offset+2, 1, val_to_str(u, pcep_route_u_obj_vals, "Unknown Object (%u). "));
		proto_tree_add_text(pcep_subobj_label_control, tvb, offset+2, 1, "Reserved: %u", (u_reserved & 0x7f));
		proto_tree_add_text(pcep_subobj_label_control, tvb, offset+3, 1, "C-Type: %u", c_type);
		proto_tree_add_text(pcep_subobj_label_control, tvb, offset+4, length-4, "Label: %s", 
				bytestring_to_str(tvb_get_ptr(tvb, offset+4, length-4), length-4, ' '));
		break;

	case PCEP_RECORD_ROUTE_OBJ:	
		proto_tree_add_uint(pcep_subobj_label_control, pcep_filter[PCEPF_SUBOBJ], tvb, offset, 1, l_and_or_type);
		proto_tree_add_text(pcep_subobj_label_control, tvb, offset+1, 1, "Length: %u", length);
		u = (u_reserved & 0x80)>>7;
		proto_tree_add_text(pcep_subobj_label_control, tvb, offset+2, 1, val_to_str(u, pcep_route_u_obj_vals, "Unknown Object (%u). "));

		ti = proto_tree_add_text(pcep_subobj_label_control, tvb, offset+2, 1, "Flags: 0x%02x ", (u_reserved & 0x7f));
		pcep_subobj_label_flags = proto_item_add_subtree(ti, ett_pcep_obj);
		proto_tree_add_boolean(pcep_subobj_label_flags, pcep_subobj_label_flags_gl, tvb, offset+2, 1, (u_reserved & 0x7f));
		proto_tree_add_text(pcep_subobj_label_control, tvb, offset+3, 1, "C-Type: %u", c_type);
		proto_tree_add_text(pcep_subobj_label_control, tvb, offset+4, length-4, "Label: %s", 
				bytestring_to_str(tvb_get_ptr(tvb, offset+4, length-4), length-4, ' '));
		break;

	default:
		proto_tree_add_text(pcep_subobj_label_control, tvb, offset, length, "Non defined subobject for this object");
		break;
	}		
}

static void
dissect_subobj_unnumb_interfaceID(proto_tree *pcep_subobj_tree, tvbuff_t *tvb, int offset, int obj_class, gint ett_pcep_obj, guint l_and_or_type, guint length)
{
	proto_tree *pcep_subobj_unnumb_interfaceID;
	proto_tree *pcep_subobj_unnumb_interfaceID_flags;
	proto_item *ti;
	guint32 router_ID;
	guint32 interface_ID;
	guint16 reserved_flags;
	int l;

	reserved_flags = tvb_get_ntohs(tvb, offset+2);
	router_ID = tvb_get_ntohl(tvb, offset+4);
	interface_ID = tvb_get_ntohl(tvb, offset+8);

	ti = proto_tree_add_item(pcep_subobj_tree, pcep_filter[PCEPF_SUBOBJ_UNNUM_INTERFACEID], tvb, offset, length, FALSE);
	pcep_subobj_unnumb_interfaceID = proto_item_add_subtree(ti, ett_pcep_obj);

	if (length != 12) {
		proto_tree_add_text(pcep_subobj_unnumb_interfaceID, tvb, offset, length,
		    "Bad unnumbered interface ID subobject: length %u != 12", length);
		return;
	}

	switch(obj_class){

	case PCEP_EXPLICIT_ROUTE_OBJ:
		l = (l_and_or_type& Mask_L)>>7;
		proto_tree_add_text(pcep_subobj_unnumb_interfaceID, tvb, offset, 1, val_to_str(l, pcep_route_l_obj_vals, "Unknown Object (%u). "));
		proto_tree_add_uint(pcep_subobj_unnumb_interfaceID, pcep_filter[PCEPF_SUBOBJ], tvb, offset, 1, (l_and_or_type & 0x7f));
		proto_tree_add_text(pcep_subobj_unnumb_interfaceID, tvb, offset+1, 1, "Length: %u", length);
		proto_tree_add_text(pcep_subobj_unnumb_interfaceID, tvb, offset+2, 2, "Reserved: 0x%04x", reserved_flags);
		break;

	case PCEP_RECORD_ROUTE_OBJ:
		proto_tree_add_uint(pcep_subobj_unnumb_interfaceID, pcep_filter[PCEPF_SUBOBJ], tvb, offset, 1, l_and_or_type);
		proto_tree_add_text(pcep_subobj_unnumb_interfaceID, tvb, offset+1, 1, "Length: %u", length);

		ti = proto_tree_add_text(pcep_subobj_unnumb_interfaceID, tvb, offset+2, 2, "Flags: 0x%02x ", (reserved_flags & 0xff00)>>8);
		pcep_subobj_unnumb_interfaceID_flags = proto_item_add_subtree(ti, ett_pcep_obj);
		proto_tree_add_boolean(pcep_subobj_unnumb_interfaceID_flags, pcep_subobj_flags_lpa, tvb, offset+2, 1, (reserved_flags & 0xff00)>>8);
		proto_tree_add_boolean(pcep_subobj_unnumb_interfaceID_flags, pcep_subobj_flags_lpu, tvb, offset+2, 1, (reserved_flags & 0xff00)>>8);

		proto_tree_add_text(pcep_subobj_unnumb_interfaceID, tvb, offset+3, 1, "Reserved: 0x%02x", (reserved_flags & 0x00ff));
		break;

	case PCEP_IRO_OBJ:
		proto_tree_add_text(pcep_subobj_unnumb_interfaceID, tvb, offset, 1, "l: %x", (l_and_or_type & 0x80)>>7);
		proto_tree_add_uint(pcep_subobj_unnumb_interfaceID, pcep_filter[PCEPF_SUBOBJ], tvb, offset, 1, (l_and_or_type & 0x7f));
		proto_tree_add_text(pcep_subobj_unnumb_interfaceID, tvb, offset+1, 1, "Length: %u", length);
		proto_tree_add_text(pcep_subobj_unnumb_interfaceID, tvb, offset+2, 2, "Reserved: 0x%04x", reserved_flags);
		break;

	case PCEP_XRO_OBJ:
		proto_tree_add_text(pcep_subobj_unnumb_interfaceID, tvb, offset, 1, "X: %x", (l_and_or_type & 0x01)>>7);
		proto_tree_add_uint(pcep_subobj_unnumb_interfaceID, pcep_filter[PCEPF_SUBOBJ_XRO], tvb, offset, 1, (l_and_or_type & 0x7f));
		proto_tree_add_text(pcep_subobj_unnumb_interfaceID, tvb, offset+2, 1, "Reserved: 0x%02x", (reserved_flags & 0xff00)>>4);
		proto_tree_add_text(pcep_subobj_unnumb_interfaceID, tvb, offset+3, 1, val_to_str((reserved_flags & 0x00ff), pcep_xro_atribute_obj_vals, "Unknown Atribute (%u). "));
		break;

	default:
		proto_tree_add_text(pcep_subobj_unnumb_interfaceID, tvb, offset, 12, "Non defined subobject for this object");
		break;
	}	

	proto_tree_add_text(pcep_subobj_unnumb_interfaceID, tvb, offset+4, 4, "Router ID: 0x%08x", router_ID);
	proto_tree_add_text(pcep_subobj_unnumb_interfaceID, tvb, offset+8, 4, "Interface ID: 0x%08x", interface_ID);
}

static void
dissect_subobj_autonomous_sys_num(proto_tree *pcep_subobj_tree, tvbuff_t *tvb, int offset, int obj_class, guint ett_pcep_obj, guint l_and_or_type, guint length)
{
	proto_tree *pcep_subobj_autonomous_sys_num;
	proto_item *ti;
	guint16 AS_number;
	guint8 reserved;
	guint8 attribute;
	guint16 op_AS_nu_high_oct;

	int l;
	l = (l_and_or_type& Mask_L)>>7;

	if(obj_class == PCEP_XRO_OBJ){	
		reserved = tvb_get_guint8(tvb, offset+2);
		attribute = tvb_get_guint8(tvb, offset+3);
		op_AS_nu_high_oct = tvb_get_ntohs(tvb, offset+4);
		AS_number = tvb_get_ntohs(tvb, offset+6);

		ti = proto_tree_add_item(pcep_subobj_tree, pcep_filter[PCEPF_SUBOBJ_AUTONOMOUS_SYS_NUM], tvb, offset, length, FALSE);
		pcep_subobj_autonomous_sys_num = proto_item_add_subtree(ti, ett_pcep_obj);
		if (length != 8) {
			proto_tree_add_text(pcep_subobj_autonomous_sys_num, tvb, offset, length,
			    "Bad autonomous system number subobject: length %u != 8", length);
			return;
		}

		proto_tree_add_text(pcep_subobj_autonomous_sys_num, tvb, offset, 1, "X: %x", (l_and_or_type & 0x01)>>7);
		proto_tree_add_uint(pcep_subobj_autonomous_sys_num, pcep_filter[PCEPF_SUBOBJ_XRO], tvb, offset, 1, (l_and_or_type & 0x7f));
		proto_tree_add_text(pcep_subobj_autonomous_sys_num, tvb, offset+1, 1, "Length: %u", length);

		proto_tree_add_text(pcep_subobj_autonomous_sys_num, tvb, offset+2, 1, "Reserved: 0x%02x", reserved);
		proto_tree_add_text(pcep_subobj_autonomous_sys_num, tvb, offset+3, 1, val_to_str(attribute, pcep_xro_atribute_obj_vals, "Unknown Object (%u)."));
		proto_tree_add_text(pcep_subobj_autonomous_sys_num, tvb, offset+4, 2, "Optional AS Number High Octets: 0x%04x", AS_number);
		proto_tree_add_text(pcep_subobj_autonomous_sys_num, tvb, offset+6, 2, "AS Number: 0x%04x", AS_number);
	} else {
		AS_number = tvb_get_ntohs(tvb, offset+2);

		ti = proto_tree_add_item(pcep_subobj_tree, pcep_filter[PCEPF_SUBOBJ_AUTONOMOUS_SYS_NUM], tvb, offset, length, FALSE);
		pcep_subobj_autonomous_sys_num = proto_item_add_subtree(ti, ett_pcep_obj);

		if (length != 4) {
			proto_tree_add_text(pcep_subobj_autonomous_sys_num, tvb, offset, length,
			    "Bad autonomous system number subobject: length %u != 4", length);
			return;
		}

		if(obj_class == PCEP_IRO_OBJ)
			proto_tree_add_text(pcep_subobj_autonomous_sys_num, tvb, offset, 1, "l: %x", (l_and_or_type & 0x80)>>7);
		else	
			proto_tree_add_text(pcep_subobj_autonomous_sys_num, tvb, offset, 1, val_to_str(l, pcep_route_l_obj_vals, "Unknown Object (%u). "));
		proto_tree_add_uint(pcep_subobj_autonomous_sys_num, pcep_filter[PCEPF_SUBOBJ], tvb, offset, 1, (l_and_or_type & 0x7f));
		proto_tree_add_text(pcep_subobj_autonomous_sys_num, tvb, offset+1, 1, "Length: %u", length);
		proto_tree_add_text(pcep_subobj_autonomous_sys_num, tvb, offset+2, 2, "AS Number: 0x%04x", AS_number);
	}
}

static void
dissect_subobj_srlg(proto_tree *pcep_subobj_tree, tvbuff_t *tvb, int offset, guint ett_pcep_obj, guint l_and_or_type, guint length)
{
	proto_tree *pcep_subobj_srlg;
	proto_item *ti;
	guint32 srlg_id;
	guint8 reserved;
	guint8 attribute;

	srlg_id = tvb_get_ntohl(tvb, offset+2);
	reserved = tvb_get_guint8(tvb, offset+6);
	attribute = tvb_get_guint8(tvb, offset+7);

	ti = proto_tree_add_item(pcep_subobj_tree, pcep_filter[PCEPF_SUBOBJ_SRLG], tvb, offset, length, FALSE);
	pcep_subobj_srlg = proto_item_add_subtree(ti, ett_pcep_obj);

	if (length != 8) {
		proto_tree_add_text(pcep_subobj_srlg, tvb, offset, length,
		    "Bad SRLG subobject: length %u != 8", length);
		return;
	}

	proto_tree_add_text(pcep_subobj_srlg, tvb, offset, 1, "X: %x", (l_and_or_type & 0x01)>>7);
	proto_tree_add_uint(pcep_subobj_srlg, pcep_filter[PCEPF_SUBOBJ_XRO], tvb, offset, 1, (l_and_or_type & 0x7f));
	proto_tree_add_text(pcep_subobj_srlg, tvb, offset+1, 1, "Length: %u", length);

	proto_tree_add_text(pcep_subobj_srlg, tvb, offset+2, 4, "SRLG ID: 0x%08x", srlg_id);
	proto_tree_add_text(pcep_subobj_srlg, tvb, offset+6, 1, "Reserved: 0x%02x", reserved);
	proto_tree_add_text(pcep_subobj_srlg, tvb, offset+7, 1, val_to_str(attribute, pcep_xro_atribute_obj_vals, "Unknown Object (%u)."));
}

static void
dissect_subobj_exrs(proto_tree *pcep_subobj_tree, tvbuff_t *tvb, int offset, int obj_class, guint ett_pcep_obj, guint type_iro, guint l_and_or_type, guint length)
{
	proto_tree *pcep_subobj_exrs;
	proto_item *ti;
	guint16 reserved;
	guint8 l_type;
	guint8 length2;
	guint type_exrs;
	guint offset_exrs = 0;
	guint l;

	ti = proto_tree_add_item(pcep_subobj_tree, pcep_filter[PCEPF_SUBOBJ_EXRS], tvb, offset, length, FALSE);
	pcep_subobj_exrs = proto_item_add_subtree(ti, ett_pcep_obj);

	if (length < 4) {
		proto_tree_add_text(pcep_subobj_exrs, tvb, offset, length,
		    "Bad EXRS subobject: length %u < 4", length);
		return;
	}

	l = (l_and_or_type& Mask_L)>>7;
	proto_tree_add_text(pcep_subobj_exrs, tvb, offset, 1, val_to_str(l, pcep_route_l_obj_vals, "Unknown Object (%u). "));
	proto_tree_add_text(pcep_subobj_exrs, tvb, offset, 1, "Type: %u", (l_and_or_type & 0x7f));
	proto_tree_add_text(pcep_subobj_exrs, tvb, offset+1, 1, "Length: %u", length);

	reserved = tvb_get_ntohs(tvb, offset+2);
	proto_tree_add_text(pcep_subobj_exrs, tvb, offset+2, 2, "Reserved: 0x%04x", reserved);

	offset += 4;

	while(offset_exrs<length-4){

		l_type = tvb_get_guint8(tvb, offset);
		length2 = tvb_get_guint8(tvb, offset+1);

		if (length2 < 2) {
			proto_tree_add_text(pcep_subobj_exrs, tvb, offset, 0,
			    "Bad packet: subobject length %u < 2",
			    length2);
			break;
		}

		type_exrs = (l_type & Mask_Type);

		if(type_iro==PCEP_SUB_EXRS)
			obj_class = PCEP_XRO_OBJ;

		switch(type_exrs) {

		case PCEP_SUB_IPv4:
			dissect_subobj_ipv4(pcep_subobj_exrs, tvb, offset,  obj_class, ett_pcep_obj, l_type, length2);
			break;
		case PCEP_SUB_IPv6:
			dissect_subobj_ipv6(pcep_subobj_exrs, tvb, offset, obj_class, ett_pcep_obj, l_type, length2);
			break;
		case PCEP_SUB_UNNUMB_INTERFACE_ID_XRO:
			dissect_subobj_unnumb_interfaceID(pcep_subobj_exrs, tvb, offset, obj_class, ett_pcep_obj, l_type, length2);
			break;
		case PCEP_SUB_AUTONOMOUS_SYS_NUM_XRO:
			dissect_subobj_autonomous_sys_num(pcep_subobj_exrs, tvb, offset, obj_class, ett_pcep_obj, l_type, length2);
			break;
		case PCEP_SUB_SRLG:
			dissect_subobj_srlg(pcep_subobj_exrs, tvb, offset, ett_pcep_obj, l_type, length2);
			break;
		default:
			proto_tree_add_text(pcep_subobj_exrs, tvb, offset+2, length-2,
				"Non defined subobject (%d)", type_exrs);
			break;
		}
		offset_exrs += length2;
		offset += length2;
	}
}

/*------------------------------------------------------------------------------
 * OPEN OBJECT
 *------------------------------------------------------------------------------*/
#define OPEN_OBJ_MIN_LEN	4

static void
dissect_pcep_open_obj (proto_tree *pcep_object_tree, tvbuff_t *tvb, int offset2, int obj_length)
{
    proto_tree *pcep_open_obj_flags;
    proto_item *ti;
    guint8 version_flags;
    guint8 keepalive;
    guint8 deadtimer;
    guint8 SID;

    if (obj_length < OBJ_HDR_LEN+OPEN_OBJ_MIN_LEN) {
	proto_tree_add_text(pcep_object_tree, tvb, offset2, obj_length,
	    "Bad OPEN object length %u, should be >= %u", obj_length,
	    OBJ_HDR_LEN+OPEN_OBJ_MIN_LEN);
	return;
    }

    version_flags = tvb_get_guint8(tvb, offset2);
    proto_tree_add_text(pcep_object_tree, tvb, offset2, 1, "PCEP Version: %u", (version_flags & 0xe0)>>5);

    ti = proto_tree_add_text(pcep_object_tree, tvb, offset2, 1, "Flags: 0x%02x", version_flags & 0x1f);
    pcep_open_obj_flags = proto_item_add_subtree(ti, ett_pcep_obj_open);
    proto_tree_add_boolean(pcep_open_obj_flags, pcep_open_flags_res, tvb, offset2, 1, version_flags & 0x1f);

    keepalive = tvb_get_guint8(tvb, offset2+1);
    proto_tree_add_text(pcep_object_tree, tvb, offset2+1, 1, "Keepalive: %u", keepalive);

    deadtimer = tvb_get_guint8(tvb, offset2+2);
    proto_tree_add_text(pcep_object_tree, tvb, offset2+2, 1, "Deadtime: %u", deadtimer);

    SID = tvb_get_guint8(tvb, offset2+3);
    proto_tree_add_text(pcep_object_tree, tvb, offset2+3, 1, "SID: %u", SID);

    /*it's suppose that obj_length is a a valid date. The object can have optional TLV(s)*/
    offset2 += OPEN_OBJ_MIN_LEN;
    obj_length -= OBJ_HDR_LEN+OPEN_OBJ_MIN_LEN;
    dissect_pcep_tlvs(pcep_object_tree, tvb, offset2, obj_length, ett_pcep_obj_open);
}

/*------------------------------------------------------------------------------
 * RP OBJECT
 *------------------------------------------------------------------------------*/
#define RP_OBJ_MIN_LEN	8

static void 
dissect_pcep_rp_obj(proto_tree *pcep_object_tree,
		  tvbuff_t *tvb, int offset2, int obj_length)
{ 
	proto_tree *pcep_rp_obj_flags;
	proto_item *ti;
	guint8 reserved;
	guint32 flags;
	guint32 requested_id_number;

	if (obj_length < OBJ_HDR_LEN+RP_OBJ_MIN_LEN) {
		proto_tree_add_text(pcep_object_tree, tvb, offset2, obj_length,
		    "Bad RP object length %u, should be >= %u", obj_length,
		    OBJ_HDR_LEN+RP_OBJ_MIN_LEN);
		return;
	}

	reserved = tvb_get_guint8(tvb, offset2);
	proto_tree_add_text(pcep_object_tree, tvb, offset2, 1, "Reserved: 0x%02x", reserved);

	flags = tvb_get_ntoh24(tvb, offset2+1);
	ti = proto_tree_add_text(pcep_object_tree, tvb, offset2+1, 3, "Flags: 0x%06x ", flags);
	pcep_rp_obj_flags = proto_item_add_subtree(ti, ett_pcep_obj_request_parameters);

	proto_tree_add_boolean(pcep_rp_obj_flags, pcep_rp_flags_reserved, tvb, offset2+1, 3, flags);
	proto_tree_add_boolean(pcep_rp_obj_flags, pcep_rp_flags_o, tvb, offset2+1, 3, flags);
	proto_tree_add_boolean(pcep_rp_obj_flags, pcep_rp_flags_b, tvb, offset2+1, 3, flags);
	proto_tree_add_boolean(pcep_rp_obj_flags, pcep_rp_flags_r, tvb, offset2+1, 3, flags);
	proto_tree_add_boolean(pcep_rp_obj_flags, pcep_rp_flags_pri, tvb, offset2+1, 3, flags);

	requested_id_number = tvb_get_ntohl(tvb, offset2+4);
	proto_tree_add_text(pcep_object_tree, tvb, offset2+4, 4, "Requested ID Number: 0x%08x", requested_id_number);

	/*it's suppose that obj_length is a a valid date. The object can have optional TLV(s)*/
	offset2 += RP_OBJ_MIN_LEN;
	obj_length -= OBJ_HDR_LEN+RP_OBJ_MIN_LEN;
	dissect_pcep_tlvs(pcep_object_tree, tvb, offset2, obj_length, ett_pcep_obj_request_parameters);
}

/*------------------------------------------------------------------------------
 * NO PATH OBJECT
 *------------------------------------------------------------------------------*/
#define NO_PATH_OBJ_MIN_LEN	4

static void 
dissect_pcep_no_path_obj(proto_tree *pcep_object_tree,
		  tvbuff_t *tvb, int offset2, int obj_length)
{    
	proto_tree *pcep_no_path_obj_flags;
	proto_item *ti;
	guint8 ni;
	guint16 flags;
	guint8 reserved;

	if (obj_length < OBJ_HDR_LEN+NO_PATH_OBJ_MIN_LEN) {
		proto_tree_add_text(pcep_object_tree, tvb, offset2, obj_length,
		    "Bad NO-PATH object length %u, should be >= %u", obj_length,
		    OBJ_HDR_LEN+NO_PATH_OBJ_MIN_LEN);
		return;
	}

	ni = tvb_get_guint8(tvb, offset2);
	proto_tree_add_text(pcep_object_tree, tvb, offset2, 1, val_to_str(ni, pcep_no_path_obj_vals, "Unknown Object (%u). "));

	flags = tvb_get_ntohs(tvb, offset2+1);
	ti = proto_tree_add_text(pcep_object_tree, tvb, offset2+1, 2, "Flags: 0x%04x", flags);
	pcep_no_path_obj_flags = proto_item_add_subtree(ti, ett_pcep_obj_no_path);
	proto_tree_add_boolean(pcep_no_path_obj_flags, pcep_no_path_flags_c, tvb, offset2+1, 2, flags);

	reserved = tvb_get_guint8(tvb, offset2+3);
	proto_tree_add_text(pcep_object_tree, tvb, offset2+3, 1, "Reserved: 0x%02x", reserved);

	/*it's suppose that obj_length is a a valid date. The object can have optional TLV(s)*/
	offset2 += NO_PATH_OBJ_MIN_LEN;
	obj_length -= OBJ_HDR_LEN+NO_PATH_OBJ_MIN_LEN;
	dissect_pcep_tlvs(pcep_object_tree, tvb, offset2, obj_length, ett_pcep_obj_no_path);
}

/*------------------------------------------------------------------------------
 * END POINT OBJECT
 *------------------------------------------------------------------------------*/
#define END_POINT_IPV4_OBJ_LEN	8
#define END_POINT_IPV6_OBJ_LEN	32

static void 
dissect_pcep_end_point_obj(proto_tree *pcep_object_tree,
		  tvbuff_t *tvb, int offset2, int obj_length, int type)
{
	switch(type)
	{
	  case IPv4:	
		if (obj_length != OBJ_HDR_LEN+END_POINT_IPV4_OBJ_LEN) {
			proto_tree_add_text(pcep_object_tree, tvb, offset2, obj_length,
			    "Bad IPv4 END-POINTS object length %u, should be %u", obj_length,
			    OBJ_HDR_LEN+END_POINT_IPV4_OBJ_LEN);
			return;
		}

		proto_tree_add_text(pcep_object_tree, tvb, offset2, 4, "Source IPv4 Address: (%s)", ip_to_str(tvb_get_ptr(tvb, offset2, 4)));
		proto_tree_add_text(pcep_object_tree, tvb, offset2+4, 4, "Destination IPv4 Address: (%s)", ip_to_str(tvb_get_ptr(tvb, offset2+4, 4)));
		break;

	  case IPv6:
		if (obj_length != OBJ_HDR_LEN+END_POINT_IPV6_OBJ_LEN) {
			proto_tree_add_text(pcep_object_tree, tvb, offset2, obj_length,
			    "Bad IPv6 END-POINTS object length %u, should be %u", obj_length,
			    OBJ_HDR_LEN+END_POINT_IPV6_OBJ_LEN);
			return;
		}

		proto_tree_add_text(pcep_object_tree, tvb, offset2, 16, "Source IPv6 Address: %s",
			    ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(tvb, offset2, 16)));
		proto_tree_add_text(pcep_object_tree, tvb, offset2+16, 16, "Destination IPv6 Address: %s",
			    ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(tvb, offset2+16, 16)));
		break;

	  default:
		 proto_tree_add_text(pcep_object_tree, tvb, offset2, obj_length-OBJ_HDR_LEN, "UNKNOWN Type Object (%u)", type);
		 break;
	}     
}



/*------------------------------------------------------------------------------
 * BANDWIDTH OBJECT
 *------------------------------------------------------------------------------*/
#define BANDWIDTH_OBJ_LEN	4

static void 
dissect_pcep_bandwidth_obj(proto_tree *pcep_object_tree, tvbuff_t *tvb, int offset2, int obj_length)
{    
	guint32 bandwidth;

	if (obj_length != OBJ_HDR_LEN+BANDWIDTH_OBJ_LEN) {
		proto_tree_add_text(pcep_object_tree, tvb, offset2, obj_length,
		    "Bad BANDWIDTH object length %u, should be %u", obj_length,
		    OBJ_HDR_LEN+BANDWIDTH_OBJ_LEN);
		return;
	}
		
	bandwidth = tvb_get_ntohl(tvb, offset2);
	proto_tree_add_text(pcep_object_tree, tvb, offset2, 4, "Bandwidth: 0x%x", bandwidth);
}

/*------------------------------------------------------------------------------
 * METRIC OBJECT
 *------------------------------------------------------------------------------*/
#define METRIC_OBJ_LEN	8

static void 
dissect_pcep_metric_obj(proto_tree *pcep_object_tree,
		  tvbuff_t *tvb, int offset2, int obj_length)
{    
	proto_tree *pcep_metric_obj_flags;
	proto_item *ti;
	guint16 reserved;
	guint8 flags;
	guint8 metric_type;
	guint32 metric_value;

	if (obj_length != OBJ_HDR_LEN+METRIC_OBJ_LEN) {
		proto_tree_add_text(pcep_object_tree, tvb, offset2, obj_length,
		    "Bad METRIC object length %u, should be %u", obj_length,
		    OBJ_HDR_LEN+METRIC_OBJ_LEN);
		return;
	}

	reserved = tvb_get_ntohs(tvb, offset2);
	proto_tree_add_text(pcep_object_tree, tvb, offset2, 2, "Reserved: %u", reserved);

	flags = tvb_get_guint8(tvb, offset2+2);
	ti = proto_tree_add_text(pcep_object_tree, tvb, offset2+2, 1, "Flags: 0x%02x", flags);
	pcep_metric_obj_flags = proto_item_add_subtree(ti, ett_pcep_obj_metric);
	proto_tree_add_boolean(pcep_metric_obj_flags, pcep_metric_flags_c, tvb, offset2+2, 1, flags);
	proto_tree_add_boolean(pcep_metric_obj_flags, pcep_metric_flags_b, tvb, offset2+2, 1, flags);

	metric_type = tvb_get_guint8(tvb, offset2+3);
	proto_tree_add_text(pcep_object_tree, tvb, offset2+3, 1, val_to_str(metric_type, pcep_metric_obj_vals, "Unknown Object (%u). "));

	metric_value = tvb_get_ntohl(tvb, offset2+4);
	proto_tree_add_text(pcep_object_tree, tvb, offset2+4, 4, "Metric Value: 0x%x", metric_value);
}

/*------------------------------------------------------------------------------
 * EXPLICIT ROUTE OBJECT (ERO)
 *------------------------------------------------------------------------------*/
static void 
dissect_pcep_explicit_route_obj(proto_tree *pcep_object_tree,
		  tvbuff_t *tvb, int offset2, int obj_length, int obj_class)
{
	guint8 l_type;
	guint8 length;
	guint type_exp_route;
	guint body_obj_len;

	body_obj_len = obj_length - OBJ_HDR_LEN;

	while(body_obj_len){
		if (body_obj_len < 2) {
			proto_tree_add_text(pcep_object_tree, tvb, offset2, 0,
			    "Bad ERO object: subobject goes past end of object");
			break;
		}

		l_type = tvb_get_guint8(tvb, offset2);
		length = tvb_get_guint8(tvb, offset2+1);

		if (length < 2) {
			proto_tree_add_text(pcep_object_tree, tvb, offset2, 0,
			    "Bad ERO object: subobject length %u < 2",
			    length);
			break;
		}

		type_exp_route = (l_type & Mask_Type);
		if (body_obj_len <length) {
			proto_tree_add_text(pcep_object_tree, tvb, offset2, length,
			    "Bad ERO object: subobject length %u > remaining length %u",
			        length, body_obj_len);
			break;
		}

		switch(type_exp_route) {

		case PCEP_SUB_IPv4:
			dissect_subobj_ipv4(pcep_object_tree, tvb, offset2, obj_class, ett_pcep_obj_explicit_route, l_type, length);
			break;
		case PCEP_SUB_IPv6:
			dissect_subobj_ipv6(pcep_object_tree, tvb, offset2, obj_class, ett_pcep_obj_explicit_route, l_type, length);
			break;
		case PCEP_SUB_LABEL_CONTROL:
			dissect_subobj_label_control(pcep_object_tree, tvb, offset2, obj_class, ett_pcep_obj_explicit_route, l_type, length);
			break;
		case PCEP_SUB_UNNUMB_INTERFACE_ID:
			dissect_subobj_unnumb_interfaceID(pcep_object_tree, tvb, offset2, obj_class, ett_pcep_obj_explicit_route, l_type, length);
			break;
		case PCEP_SUB_AUTONOMOUS_SYS_NUM:
			dissect_subobj_autonomous_sys_num(pcep_object_tree, tvb, offset2, obj_class, ett_pcep_obj_explicit_route, l_type, length);
			break;
		default:
			proto_tree_add_text(pcep_object_tree, tvb, offset2, length, "Non defined subobject (%d)", type_exp_route);
			break;
		}			
		offset2 += length;
		body_obj_len -= length;
	}	   
}

/*------------------------------------------------------------------------------
 * RECORD ROUTE OBJECT (RRO)
 *------------------------------------------------------------------------------*/
static void 
dissect_pcep_record_route_obj(proto_tree *pcep_object_tree, tvbuff_t *tvb, int offset2, int obj_length, int obj_class)
{
	guint8 type;
	guint8 length;
	guint body_obj_len;

	body_obj_len = obj_length - OBJ_HDR_LEN;

	while(body_obj_len){
		if (body_obj_len < 2) {
			proto_tree_add_text(pcep_object_tree, tvb, offset2, 0,
			    "Bad RRO object: subobject goes past end of object");
			break;
		}

		type = tvb_get_guint8(tvb, offset2);
		length = tvb_get_guint8(tvb, offset2+1);

		if (length < 2) {
			proto_tree_add_text(pcep_object_tree, tvb, offset2, 0,
			    "Bad RRO object: subobject length %u < 2",
			    length);
			break;
		}

		if (body_obj_len <length) {
			proto_tree_add_text(pcep_object_tree, tvb, offset2, length,
			    "Bad RRO subobject: subobject length %u > remaining length %u",
			        length, body_obj_len);
			break;
		}

		switch(type) {

		case PCEP_SUB_IPv4:
			dissect_subobj_ipv4(pcep_object_tree, tvb, offset2, obj_class, ett_pcep_obj_record_route, type, length);
			break;
		case PCEP_SUB_IPv6:
			dissect_subobj_ipv6(pcep_object_tree, tvb, offset2, obj_class, ett_pcep_obj_record_route, type, length);
			break;
		case PCEP_SUB_LABEL_CONTROL:
			dissect_subobj_label_control(pcep_object_tree, tvb, offset2, obj_class, ett_pcep_obj_record_route, type, length);
			break;
		case PCEP_SUB_UNNUMB_INTERFACE_ID:
			dissect_subobj_unnumb_interfaceID(pcep_object_tree, tvb, offset2, obj_class, ett_pcep_obj_record_route, type, length);
			break;
		default:
			proto_tree_add_text(pcep_object_tree, tvb, offset2, length, "Non defined subobject (%d)", type);
			break;
		}
		offset2 += length;
		body_obj_len -= length;
	}			
}

/*------------------------------------------------------------------------------
 * LSPA OBJECT
 *------------------------------------------------------------------------------*/
#define LSPA_OBJ_MIN_LEN	16

static void 
dissect_pcep_lspa_obj(proto_tree *pcep_object_tree, tvbuff_t *tvb, int offset2, int obj_length)
{    
	proto_tree *pcep_lspa_obj_flags;
	proto_item *ti;
	guint32 exclude_any;
	guint32 include_any;
	guint32 include_all;
	guint8 setup_prio;
	guint8 holding_prio;
	guint8 flags;
	guint8 reserved;

	if (obj_length < OBJ_HDR_LEN+LSPA_OBJ_MIN_LEN) {
		proto_tree_add_text(pcep_object_tree, tvb, offset2, obj_length,
		    "Bad LSPA object length %u, should be >= %u", obj_length,
		    OBJ_HDR_LEN+LSPA_OBJ_MIN_LEN);
		return;
	}

	exclude_any = tvb_get_ntohl(tvb, offset2);
	proto_tree_add_text(pcep_object_tree, tvb, offset2, 4, "Exclude-Any: 0x%08x", exclude_any);

	include_any = tvb_get_ntohl(tvb, offset2+4);
	proto_tree_add_text(pcep_object_tree, tvb, offset2+4, 4, "Include-Any: 0x%08x", include_any);

	include_all = tvb_get_ntohl(tvb, offset2+8);
	proto_tree_add_text(pcep_object_tree, tvb, offset2+8, 4, "Include-All: 0x%08x", include_all);

	setup_prio = tvb_get_guint8(tvb, offset2+12);
	proto_tree_add_text(pcep_object_tree, tvb, offset2+12, 1, "Setup Priority: %u", setup_prio);

	holding_prio = tvb_get_guint8(tvb, offset2+13);
	proto_tree_add_text(pcep_object_tree, tvb, offset2+13, 1, "Holding Priority: %u", holding_prio);

	flags = tvb_get_guint8(tvb, offset2+14);
	ti = proto_tree_add_text(pcep_object_tree, tvb, offset2+14, 1, "Flags: 0x%02x", flags);
	pcep_lspa_obj_flags = proto_item_add_subtree(ti, ett_pcep_obj_metric);
	proto_tree_add_boolean(pcep_lspa_obj_flags, pcep_lspa_flags_l, tvb, offset2+14, 1, flags);

	reserved = tvb_get_guint8(tvb, offset2+15);
	proto_tree_add_text(pcep_object_tree, tvb, offset2+15, 1, "Reserved: 0x%02x", reserved);

	/*it's suppose that obj_length is a a valid date. The object can have optional TLV(s)*/
	offset2 += LSPA_OBJ_MIN_LEN;
	obj_length -= OBJ_HDR_LEN+LSPA_OBJ_MIN_LEN;
	dissect_pcep_tlvs(pcep_object_tree, tvb, offset2, obj_length, ett_pcep_obj_lspa);
}

/*------------------------------------------------------------------------------
 * INCLUDE ROUTE OBJECT (IRO)
 *------------------------------------------------------------------------------*/
static void 
dissect_pcep_iro_obj(proto_tree *pcep_object_tree,
		    tvbuff_t *tvb, int offset2, int obj_length, int obj_class)
{    
	guint8 l_type;
	guint8 length;
	int type_iro;
	guint body_obj_len;

	body_obj_len = obj_length - OBJ_HDR_LEN;

	while(body_obj_len){
		if (body_obj_len < 2) {
			proto_tree_add_text(pcep_object_tree, tvb, offset2, 0,
			    "Bad IRO object: subobject goes past end of object");
			break;
		}

		l_type = tvb_get_guint8(tvb, offset2);
		length = tvb_get_guint8(tvb, offset2+1);

		if (length < 2) {
			proto_tree_add_text(pcep_object_tree, tvb, offset2, 0,
			    "Bad IRO object: subobject length %u < 2",
			    length);
			break;
		}

		type_iro = (l_type & Mask_Type);

		if (body_obj_len <length) {
			proto_tree_add_text(pcep_object_tree, tvb, offset2, length,
			    "Bad IRO object: subobject length %u > remaining length %u",
			        length, body_obj_len);
			break;
		}

		switch(type_iro) {

		case PCEP_SUB_IPv4:
			dissect_subobj_ipv4(pcep_object_tree, tvb, offset2, obj_class, ett_pcep_obj_iro, l_type, length);
			break;
		case PCEP_SUB_IPv6:
			dissect_subobj_ipv6(pcep_object_tree, tvb, offset2, obj_class, ett_pcep_obj_iro, l_type, length);
			break;
		case PCEP_SUB_UNNUMB_INTERFACE_ID:
			dissect_subobj_unnumb_interfaceID(pcep_object_tree, tvb, offset2, obj_class, ett_pcep_obj_iro, l_type, length);
			break;
		case PCEP_SUB_AUTONOMOUS_SYS_NUM:
			dissect_subobj_autonomous_sys_num(pcep_object_tree, tvb, offset2, obj_class, ett_pcep_obj_iro, l_type, length);
			break;
		case PCEP_SUB_EXRS:
			dissect_subobj_exrs(pcep_object_tree, tvb, offset2, obj_class, ett_pcep_obj_iro, type_iro, l_type, length);
			break;
		default:
			proto_tree_add_text(pcep_object_tree, tvb, offset2, length, "Non defined subobject (%d)", type_iro);
			break;
		} 
		offset2 += length;
		body_obj_len -= length;
	}
}

/*------------------------------------------------------------------------------
 * SVEC OBJECT 
 *------------------------------------------------------------------------------*/
#define SVEC_OBJ_MIN_LEN	4

static void 
dissect_pcep_svec_obj(proto_tree *pcep_object_tree,
		  tvbuff_t *tvb, int offset2, int obj_length)
{
	proto_item *ti;
	proto_tree *pcep_svec_flags_obj;
	guint8 reserved;
	guint32 flags;
	int m = 1;
	int i = 0;

	if (obj_length < OBJ_HDR_LEN+SVEC_OBJ_MIN_LEN) {
		proto_tree_add_text(pcep_object_tree, tvb, offset2, obj_length,
		    "Bad SVEC object length %u, should be >= %u", obj_length,
		    OBJ_HDR_LEN+SVEC_OBJ_MIN_LEN);
		return;
	}

	reserved = tvb_get_guint8(tvb, offset2);
	proto_tree_add_text(pcep_object_tree, tvb, offset2, 1, "Reserved: 0x%02x", reserved);

	flags = tvb_get_ntoh24(tvb, offset2+1);
	ti = proto_tree_add_text(pcep_object_tree, tvb, offset2+1, 3, "Flags: 0x%06x", flags);
	pcep_svec_flags_obj = proto_item_add_subtree(ti, ett_pcep_obj_svec);
	proto_tree_add_boolean(pcep_svec_flags_obj, pcep_svec_flags_l, tvb, offset2 + 1, 3, flags);
    	proto_tree_add_boolean(pcep_svec_flags_obj, pcep_svec_flags_n, tvb, offset2 + 1, 3, flags);
   	proto_tree_add_boolean(pcep_svec_flags_obj, pcep_svec_flags_s, tvb, offset2 + 1, 3, flags);

	for ( i=4 ; i<(obj_length-OBJ_HDR_LEN) ; ){
		proto_tree_add_text(pcep_object_tree, tvb, offset2+i, 4, "Request-ID-Number %u: 0x%s", m,
			bytestring_to_str(tvb_get_ptr(tvb, offset2+i, 4), 4, ' '));
		i += 4;
	}
}

/*------------------------------------------------------------------------------
 * NOTIFICATION OBJECT 
 *------------------------------------------------------------------------------*/		      
#define NOTIFICATION_OBJ_MIN_LEN	4

static void 
dissect_pcep_notification_obj(proto_tree *pcep_object_tree, tvbuff_t *tvb, int offset2, int obj_length)
{    
	guint8 reserved;
	guint8 flags;
	guint8 nt;
	guint8 nv;

	if (obj_length < OBJ_HDR_LEN+NOTIFICATION_OBJ_MIN_LEN) {
		proto_tree_add_text(pcep_object_tree, tvb, offset2, obj_length,
		    "Bad NOTIFICATION object length %u, should be >= %u", obj_length,
		    OBJ_HDR_LEN+NOTIFICATION_OBJ_MIN_LEN);
		return;
	}

	reserved = tvb_get_guint8(tvb, offset2);
	proto_tree_add_text(pcep_object_tree, tvb, offset2, 1, "Reserved: 0x%02x", reserved);

	flags = tvb_get_guint8(tvb, offset2+1);
	proto_tree_add_text(pcep_object_tree, tvb, offset2+1, 1, "Flags: 0x%02x", flags);

	nt = tvb_get_guint8(tvb, offset2+2);
	proto_tree_add_uint(pcep_object_tree, pcep_filter[PCEPF_NOTI_TYPE], tvb, offset2+2, 1, nt);

	switch(nt){

	case 1:
		proto_tree_add_uint(pcep_object_tree, pcep_filter[PCEPF_NOTI_VAL1], tvb, offset2+2, 1, nt);
		break;

	case 2:	
		proto_tree_add_uint(pcep_object_tree, pcep_filter[PCEPF_NOTI_VAL2], tvb, offset2+2, 1, nt);
		break;

	default:
		proto_tree_add_text(pcep_object_tree, tvb, offset2+2, 1, "Notification Type: %u", nt);
		break;
	}

	nv = tvb_get_guint8(tvb, offset2+3);
	proto_tree_add_text(pcep_object_tree, tvb, offset2+3, 1, "Notification Value: 0x%02x", nv);

	/*it's suppose that obj_length is a a valid date. The object can have optional TLV(s)*/
	offset2 += NOTIFICATION_OBJ_MIN_LEN;
	obj_length -= OBJ_HDR_LEN+NOTIFICATION_OBJ_MIN_LEN;
	dissect_pcep_tlvs(pcep_object_tree, tvb, offset2, obj_length, ett_pcep_obj_notification);
}

/*------------------------------------------------------------------------------
 * ERROR OBJECT 
 *------------------------------------------------------------------------------*/		      
#define ERROR_OBJ_MIN_LEN	4

static void 
dissect_pcep_error_obj(proto_tree *pcep_object_tree, tvbuff_t *tvb, int offset2, int obj_length)
{	
	proto_tree *pcep_error_types_obj;
	proto_item *ti;
	guint8 reserved;
	guint8 flags;
	guint8 error_type;
	guint8 error_value;

	if (obj_length < OBJ_HDR_LEN+ERROR_OBJ_MIN_LEN) {
		proto_tree_add_text(pcep_object_tree, tvb, offset2, obj_length,
		    "Bad ERROR object length %u, should be >= %u", obj_length,
		    OBJ_HDR_LEN+ERROR_OBJ_MIN_LEN);
		return;
	}

	reserved = tvb_get_guint8(tvb, offset2);
	proto_tree_add_text(pcep_object_tree, tvb, offset2, 1, "Reserved: 0x%02x", reserved);

	flags = tvb_get_guint8(tvb, offset2+1);
	proto_tree_add_text(pcep_object_tree, tvb, offset2+1, 1, "Flags: 0x%02x", flags);

	error_type = tvb_get_guint8(tvb, offset2+2);
	ti = proto_tree_add_uint(pcep_object_tree, pcep_filter[PCEPF_ERROR_TYPE], tvb, offset2+2, 1, error_type);
	pcep_error_types_obj = proto_item_add_subtree(ti, ett_pcep_obj_error);

	error_value = tvb_get_guint8(tvb, offset2+3);
	switch(error_type){	
	case ESTABLISH_FAILURE:
		switch(error_value){
		case RX_MALFORM_PKT:
			proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1, "Error-value: %u Reception of a Malformed Message ", error_value);
			break;
		case NO_OPEN_MSG:
			proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1, "Error-value: %u No Open Message received before the expiration of the OpenWait Timer ", error_value);
			break;
		case UNACEP_NO_NEGO_SSESION:
			proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1, "Error-value: %u Unacceptable and non Negotiable session characteristics", error_value);
			break;
		case UNACEP_NEG_SESSION:
			proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1, "Error-value: %u Unacceptable but Negotiable session characteristics", error_value);
			break;
		case TWO_OPEN_MSG_UNACEP:
			proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1, "Error-value: %u Reception of a second Open Message with still Unacceptable Session characteristics", error_value);
			break;
		case RX_PCEPERR_UNACEP_SESSION:
			proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1, "Error-value: %u Reception of a PCEPrr message proposing unacceptable session characteristics", error_value);
			break;
		case NO_KEEPALIVE_PCEPERR:
			proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1, "Error-value: %u NO Keepalive or PCEPrr message received before the expiration of the Keepwait timer supported", error_value);
			break;
		default:
			proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1,
				"Error-value: %u Non defined Error-Value", error_value);
		}
		break;

	case CAP_NOT_SUPPORTED:
		proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1, "Error-Value: %u ", error_value);
		break;

	case UNKNOWN_OBJ:
		switch(error_value){
		case UNRECON_OBJ_CLASS:
			proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1, "Error-value: %u Unrecognized object class", error_value);
			break;
		case UNRECON_OBJ_TYPE:
			proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1, "Error-value: %u Unrecognized object type", error_value);
			break;
		default:
			proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1,
				"Error-value: %u Non defined Error-Value", error_value);
		} 
		break;
	case NOT_SUPP_OBJ:
		switch(error_value){
		case NO_SUPP_OBJ:
			proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1, "Error-value: %u Not Supported Object Class", error_value);
			break;
		case NO_SUPP_TYPE:
			proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1, "Error-value: %u Not Supported Object Type", error_value);
			break;
		default:
			proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1,
				"Error-value: %u Non defined Error-Value", error_value);
		}
		break;
	case POLICY_VIOLATION:
		switch(error_value){
		case C_METRIC_SET:
			proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1, "Error-value: %u C bit of the METRIC object set (Request Rejected)", error_value);
			break;
		case O_OBJ_SET:
			proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1, "Error-value: %u O bit of the RP object set (Request Rejected)", error_value);
			break;
		default:
			proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1,
				"Error-value: %u Non defined Error-Value", error_value);
		}
		break;
	case MANDATORY_OBJ_MIS:	
		switch(error_value){
		case RP_OBJ_MISS:
			proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1, "Error-value: %u RP Object missing", error_value);
			break;
		case RRO_OBJ_MISS:
			proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1, "Error-value: %u RRO Object missing for a reoptimization request (R bit of the RP Object set) when bandwidth is not equal to 0", error_value);
			break;
		case END_POINT_OBJ_MISS:
			proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1, "Error-value: %u END-POINTS Objects missing", error_value);
			break;
		default:  
			proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1,
				"Error-value: %u Non defined Error-Value", error_value);
		}
		break;
	case SYNCH_PCREQ_MIS:
		proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1, "Error-Value: %u ", error_value);
		break;
	case UNKNOWN_REQ_REF:	
		proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1, "Error-Value: %u ", error_value);
		break;
	case ATTEMPT_2_SESSION:
		proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1, "Error-Value: %u ", error_value);
		break;
	case UNRECO_IRO_SUBOBJ:
		proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1, "Error-Value: %u ", error_value);
		break;
	case UNRECO_EXRS_SUBOBJ:
		proto_tree_add_text(pcep_error_types_obj, tvb, offset2+3, 1, "Error-Value: %u ", error_value);
		break;

	default:
		proto_tree_add_text(pcep_error_types_obj, tvb, offset2+2, 1, "Error-Type: %u Non defined Error-Value", error_type);
	}

	/*it's suppose that obj_length is a a valid date. The object can have optional TLV(s)*/
	offset2 += ERROR_OBJ_MIN_LEN;
	obj_length -= OBJ_HDR_LEN+ERROR_OBJ_MIN_LEN;
	dissect_pcep_tlvs(pcep_object_tree, tvb, offset2, obj_length, ett_pcep_obj_error);
}


/*------------------------------------------------------------------------------
 * LOAD-BALANCING OBJECT 
 *------------------------------------------------------------------------------*/		      
#define LOAD_BALANCING_OBJ_LEN	8

static void 
dissect_pcep_balancing_obj(proto_tree *pcep_object_tree, tvbuff_t *tvb, int offset2, int obj_length)
{    
	guint16 reserved;
	guint8 flags;
	guint8 max_LSP;
	guint32 min_bandwidth;

	if (obj_length != OBJ_HDR_LEN+LOAD_BALANCING_OBJ_LEN) {
		proto_tree_add_text(pcep_object_tree, tvb, offset2, obj_length,
		    "Bad LOAD-BALANCING object length %u, should be %u", obj_length,
		    OBJ_HDR_LEN+LOAD_BALANCING_OBJ_LEN);
		return;
	}

	reserved = tvb_get_ntohs(tvb, offset2);
	proto_tree_add_text(pcep_object_tree, tvb, offset2, 2, "Reserved: 0x%04x", reserved);

	flags = tvb_get_guint8(tvb, offset2+2);
	proto_tree_add_text(pcep_object_tree, tvb, offset2+2, 1, "Flags: 0x%02x", flags);

	max_LSP = tvb_get_guint8(tvb, offset2+3);
	proto_tree_add_text(pcep_object_tree, tvb, offset2+3, 1, "Maximun Number of TE LSPs: 0x%02x", max_LSP);

	min_bandwidth = tvb_get_ntohl(tvb, offset2+4);
	proto_tree_add_text(pcep_object_tree, tvb, offset2+4, 4, "Minimun Bandwidth: 0x%08x", min_bandwidth);
}

/*------------------------------------------------------------------------------
 * CLOSE OBJECT 
 *------------------------------------------------------------------------------*/		      
#define CLOSE_OBJ_MIN_LEN	4

static void 
dissect_pcep_close_obj(proto_tree *pcep_object_tree, tvbuff_t *tvb, int offset2, int obj_length)
{
	guint16 reserved;
	guint8 flags;
	guint8 reason;

	if (obj_length < OBJ_HDR_LEN+CLOSE_OBJ_MIN_LEN) {
		proto_tree_add_text(pcep_object_tree, tvb, offset2, obj_length,
		    "Bad CLOSE object length %u, should be >= %u", obj_length,
		    OBJ_HDR_LEN+CLOSE_OBJ_MIN_LEN);
		return;
	}

	reserved = tvb_get_ntohs(tvb, offset2);
	proto_tree_add_text(pcep_object_tree, tvb, offset2, 2, "Reserved: 0x%04x", reserved);

	flags = tvb_get_guint8(tvb, offset2+2);
	proto_tree_add_text(pcep_object_tree, tvb, offset2+2, 1, "Flags: 0x%02x", flags);

	reason = tvb_get_guint8(tvb, offset2+3);
	proto_tree_add_text(pcep_object_tree, tvb, offset2+3, 1, val_to_str(reason, pcep_close_reason_obj_vals, "Unknown Object (%u). "));

	/*it's suppose that obj_length is a a valid date. The object can have optional TLV(s)*/
	offset2 += CLOSE_OBJ_MIN_LEN;
	obj_length -= OBJ_HDR_LEN+CLOSE_OBJ_MIN_LEN;
	dissect_pcep_tlvs(pcep_object_tree, tvb, offset2, obj_length, ett_pcep_obj_load_balancing);
}

/*------------------------------------------------------------------------------
 * XRO OBJECT 
 *------------------------------------------------------------------------------*/	
#define XRO_OBJ_MIN_LEN	4

static void 
dissect_pcep_xro_obj(proto_tree *pcep_object_tree, tvbuff_t *tvb, int offset2, int obj_length, int obj_class)
{
	proto_tree *pcep_xro_flags_obj;
	proto_item *ti;
	guint16 reserved;
	guint16 flags;
	guint8 x_type;
	guint8 length;
	guint type_xro;
	guint body_obj_len;

	body_obj_len = obj_length - OBJ_HDR_LEN;

	if (obj_length < OBJ_HDR_LEN+XRO_OBJ_MIN_LEN) {
		proto_tree_add_text(pcep_object_tree, tvb, offset2, obj_length,
		    "Bad XRO object length %u, should be >= %u", obj_length,
		    OBJ_HDR_LEN+XRO_OBJ_MIN_LEN);
		return;
	}

	reserved = tvb_get_ntohs(tvb, offset2);
	proto_tree_add_text(pcep_object_tree, tvb, offset2, 2, "Reserved: 0x%04x", reserved);

	flags = tvb_get_ntohs(tvb, offset2+2);
	ti =  proto_tree_add_text(pcep_object_tree, tvb, offset2+2, 2, "Flags: 0x%04x ", flags);
	pcep_xro_flags_obj = proto_item_add_subtree(ti, ett_pcep_obj_xro);
	proto_tree_add_boolean(pcep_xro_flags_obj, pcep_xro_flags_f, tvb, offset2 + 2, 2, flags);

	offset2 += XRO_OBJ_MIN_LEN;
	body_obj_len -= XRO_OBJ_MIN_LEN;

	while(body_obj_len >= 2){
		if (body_obj_len < 2) {
			proto_tree_add_text(pcep_object_tree, tvb, offset2, 0,
			    "Bad XRO object: subobject goes past end of object");
			break;
		}

		x_type = tvb_get_guint8(tvb, offset2);
		length = tvb_get_guint8(tvb, offset2+1);

		if (length < 2) {
			proto_tree_add_text(pcep_object_tree, tvb, offset2, 0,
			    "Bad XRO object: object length %u < 2", length);
			break;
		}

		type_xro = (x_type & Mask_Type);

		if (body_obj_len <length) {
			proto_tree_add_text(pcep_object_tree, tvb, offset2, length,
			    "Bad XRO object: object length %u > remaining length %u",
			        length, body_obj_len);
			break;
		}

		switch(type_xro) {

		case PCEP_SUB_IPv4:
			dissect_subobj_ipv4(pcep_object_tree, tvb, offset2, obj_class, ett_pcep_obj_xro, x_type, length);
			break;
		case PCEP_SUB_IPv6:
			dissect_subobj_ipv6(pcep_object_tree, tvb, offset2, obj_class, ett_pcep_obj_xro, x_type, length);
			break;
		case PCEP_SUB_UNNUMB_INTERFACE_ID_XRO:
			dissect_subobj_unnumb_interfaceID(pcep_object_tree, tvb, offset2, obj_class, ett_pcep_obj_xro, x_type, length);
			break;
		case PCEP_SUB_AUTONOMOUS_SYS_NUM_XRO:
			dissect_subobj_autonomous_sys_num(pcep_object_tree, tvb, offset2, obj_class, ett_pcep_obj_xro, x_type, length);
			break;
		case PCEP_SUB_SRLG:
			dissect_subobj_srlg(pcep_object_tree, tvb, offset2, ett_pcep_obj_xro, x_type, length);
			break;
		default:
			proto_tree_add_text(pcep_object_tree, tvb, offset2-4, length, "Non defined subobject (%d)", type_xro);
			break;
		}
		offset2 += length;
		body_obj_len -= length;
	}
}

/*------------------------------------------------------------------------------*/	
/* Dissect in Objects */
/*------------------------------------------------------------------------------*/
static void
dissect_pcep_obj_tree(proto_tree *pcep_tree, tvbuff_t *tvb, int len, int offset, int msg_length)  
{  
  guint8 obj_class;
  guint8 ot_res_p_i;
  guint16 obj_length;
  int type;
  proto_tree *pcep_object_tree;
  proto_item *pcep_object_item;
  proto_tree *pcep_header_obj_flags;
  proto_item *ti;

  while (len < msg_length) {
	obj_class = tvb_get_guint8(tvb, offset);
	switch (obj_class) {

	case PCEP_OPEN_OBJ:
		pcep_object_item = proto_tree_add_item(pcep_tree, pcep_filter[PCEPF_OBJ_OPEN], tvb, offset, -1, FALSE);
		pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_open);
		break;

	case PCEP_RP_OBJ:
		pcep_object_item = proto_tree_add_item(pcep_tree, pcep_filter[PCEPF_OBJ_RP], tvb, offset, -1, FALSE);
		pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_request_parameters);
		break;

	case PCEP_NO_PATH_OBJ:
		pcep_object_item = proto_tree_add_item(pcep_tree, pcep_filter[PCEPF_OBJ_NO_PATH], tvb, offset, -1, FALSE);
		pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_no_path);
		break;

	case PCEP_END_POINT_OBJ:
		pcep_object_item = proto_tree_add_item(pcep_tree, pcep_filter[PCEPF_OBJ_END_POINT], tvb, offset, -1, FALSE);
		pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_end_point);
		break;

	case PCEP_BANDWIDTH_OBJ:
		pcep_object_item = proto_tree_add_item(pcep_tree, pcep_filter[PCEPF_OBJ_BANDWIDTH], tvb, offset, -1, FALSE);
		pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_bandwidth);
		break;

	case PCEP_METRIC_OBJ:
		pcep_object_item = proto_tree_add_item(pcep_tree, pcep_filter[PCEPF_OBJ_METRIC], tvb, offset, -1, FALSE);
		pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_metric);
		break;

	case PCEP_EXPLICIT_ROUTE_OBJ:
		pcep_object_item = proto_tree_add_item(pcep_tree, pcep_filter[PCEPF_OBJ_EXPLICIT_ROUTE], tvb, offset, -1, FALSE);
		pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_explicit_route);
		break;

	case PCEP_RECORD_ROUTE_OBJ:
		pcep_object_item = proto_tree_add_item(pcep_tree, pcep_filter[PCEPF_OBJ_RECORD_ROUTE], tvb, offset, -1, FALSE);
		pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_record_route);
		break;

	case PCEP_LSPA_OBJ:
		pcep_object_item = proto_tree_add_item(pcep_tree, pcep_filter[PCEPF_OBJ_LSPA], tvb, offset, -1, FALSE);
		pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_lspa);
		break;

	case PCEP_IRO_OBJ:
		pcep_object_item = proto_tree_add_item(pcep_tree, pcep_filter[PCEPF_OBJ_IRO], tvb, offset, -1, FALSE);
		pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_iro);
		break;

	case PCEP_SVEC_OBJ:
		pcep_object_item = proto_tree_add_item(pcep_tree, pcep_filter[PCEPF_OBJ_SVEC], tvb, offset, -1, FALSE);
		pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_svec);
		break;

	case PCEP_NOTIFICATION_OBJ:
		pcep_object_item = proto_tree_add_item(pcep_tree, pcep_filter[PCEPF_OBJ_NOTIFICATION], tvb, offset, -1, FALSE);
		pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_notification);
		break;

	case PCEP_PCEP_ERROR_OBJ:
		pcep_object_item = proto_tree_add_item(pcep_tree, pcep_filter[PCEPF_OBJ_PCEP_ERROR], tvb, offset, -1, FALSE);
		pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_error);
		break;

	case PCEP_LOAD_BALANCING_OBJ:
		pcep_object_item = proto_tree_add_item(pcep_tree, pcep_filter[PCEPF_OBJ_LOAD_BALANCING], tvb, offset, -1, FALSE);
		pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_load_balancing);
		break;

	case PCEP_CLOSE_OBJ:
		pcep_object_item = proto_tree_add_item(pcep_tree, pcep_filter[PCEPF_OBJ_CLOSE], tvb, offset, -1, FALSE);
		pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_close);
		break;

	case PCEP_XRO_OBJ:
		pcep_object_item = proto_tree_add_item(pcep_tree, pcep_filter[PCEPF_OBJ_XRO], tvb, offset, -1, FALSE);
		pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_xro);
		break;

	default:
		pcep_object_item = proto_tree_add_text(pcep_tree, tvb, offset, -1, "Unknown object (%u)", obj_class);
		pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_unknown);
		break;
	}

	proto_tree_add_uint(pcep_object_tree, pcep_filter[PCEPF_OBJECT_CLASS], tvb, offset, 1, obj_class);

	ot_res_p_i = tvb_get_guint8(tvb, offset+1);
	type = (ot_res_p_i & MASK_OBJ_TYPE)>>4;
	proto_tree_add_text(pcep_object_tree, tvb, offset+1, 1, "Object Type: %u", type);

	ti = proto_tree_add_text(pcep_object_tree, tvb, offset+1, 1, "Flags");
	pcep_header_obj_flags = proto_item_add_subtree(ti, ett_pcep_hdr);
	proto_tree_add_boolean(pcep_header_obj_flags, pcep_hdr_obj_flags_reserved, tvb, offset+1, 1, ot_res_p_i);
	proto_tree_add_boolean(pcep_header_obj_flags, pcep_hdr_obj_flags_p, tvb, offset+1, 1, ot_res_p_i);
	proto_tree_add_boolean(pcep_header_obj_flags, pcep_hdr_obj_flags_i, tvb, offset+1, 1, ot_res_p_i);

	obj_length = tvb_get_ntohs(tvb, offset+2);
	proto_item_set_len(pcep_object_item, obj_length);
	if (obj_length < 4) {
	    proto_tree_add_text(pcep_object_tree, tvb, offset+2, 2, "Object Length: %u (bogus, must be >= 4)", obj_length);
	    break;
	}
	proto_tree_add_text(pcep_object_tree, tvb, offset+2, 2, "Object Length: %u", obj_length);

	switch(obj_class) {

	case PCEP_OPEN_OBJ:
	    dissect_pcep_open_obj(pcep_object_tree, tvb, offset+4, obj_length);
	    break;

	case PCEP_RP_OBJ:
	    dissect_pcep_rp_obj(pcep_object_tree, tvb, offset+4, obj_length);
	    break;

	case PCEP_NO_PATH_OBJ:
	    dissect_pcep_no_path_obj(pcep_object_tree, tvb, offset+4, obj_length);
	    break;

	case PCEP_END_POINT_OBJ:
	    dissect_pcep_end_point_obj(pcep_object_tree, tvb, offset+4, obj_length, type);
	    break;

	case PCEP_BANDWIDTH_OBJ:
	    dissect_pcep_bandwidth_obj(pcep_object_tree, tvb, offset+4, obj_length);
	    break;

	case PCEP_METRIC_OBJ:
	    dissect_pcep_metric_obj(pcep_object_tree, tvb, offset+4, obj_length);
	    break;

	case PCEP_EXPLICIT_ROUTE_OBJ:
	    dissect_pcep_explicit_route_obj(pcep_object_tree, tvb, offset+4, obj_length, obj_class);
	    break;

	case PCEP_RECORD_ROUTE_OBJ:
	    dissect_pcep_record_route_obj(pcep_object_tree, tvb, offset+4, obj_length, obj_class);
	    break;

	case PCEP_LSPA_OBJ:
	    dissect_pcep_lspa_obj(pcep_object_tree, tvb, offset+4, obj_length);
	    break;

	case PCEP_IRO_OBJ:
	    dissect_pcep_iro_obj(pcep_object_tree, tvb, offset+4, obj_length, obj_class);
	    break;

	case PCEP_SVEC_OBJ:
	    dissect_pcep_svec_obj(pcep_object_tree, tvb, offset+4, obj_length);
	    break;

	case PCEP_NOTIFICATION_OBJ:
	    dissect_pcep_notification_obj(pcep_object_tree, tvb, offset+4, obj_length);
	    break;

	case PCEP_PCEP_ERROR_OBJ:
	    dissect_pcep_error_obj(pcep_object_tree, tvb, offset+4, obj_length);
	    break;

	case PCEP_LOAD_BALANCING_OBJ:
	    dissect_pcep_balancing_obj(pcep_object_tree, tvb, offset+4, obj_length);
	    break;

	case PCEP_CLOSE_OBJ:
	    dissect_pcep_close_obj(pcep_object_tree, tvb, offset+4, obj_length);
	    break;

	case PCEP_XRO_OBJ:
	    dissect_pcep_xro_obj(pcep_object_tree, tvb, offset+4, obj_length, obj_class);
	    break;

	default:
	    proto_tree_add_text(pcep_object_tree, tvb, offset+4, obj_length-OBJ_HDR_LEN, "PCEP Object BODY non defined (%u)", type);
	    break;
	}

	offset += obj_length;
	len += obj_length;
    }	
}


/*------------------------------------------------------------------------------
 * Dissect a single PCEP message in a tree
 *------------------------------------------------------------------------------*/
static void
dissect_pcep_msg_tree(tvbuff_t *tvb, proto_tree *tree, guint tree_mode, packet_info *pinfo)
{
    proto_tree *pcep_tree = NULL;
    proto_tree *pcep_header_tree;
    proto_tree *ti;
    proto_tree *pcep_header_msg_flags;
    proto_item *hidden_item;

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

    ti = proto_tree_add_item(tree, proto_pcep, tvb, offset, msg_length, FALSE);
    pcep_tree = proto_item_add_subtree(ti, tree_mode);

    ti = proto_tree_add_text(pcep_tree, tvb, offset, 4, "%s Header", val_to_str(message_type, message_type_vals, "Unknown Message (%u). "));

    pcep_header_tree = proto_item_add_subtree(ti, ett_pcep_hdr);

    proto_tree_add_text(pcep_header_tree, tvb, offset, 1, "PCEP Version: %x", (ver_flags & 0x20)>>5);

    ti = proto_tree_add_text(pcep_header_tree, tvb, offset, 1, "Flags: 0x%02x", ver_flags & 0x1f);
    pcep_header_msg_flags = proto_item_add_subtree(ti, ett_pcep_hdr);
    proto_tree_add_boolean(pcep_header_msg_flags, pcep_hdr_msg_flags_reserved, tvb, offset, 1, (ver_flags & 0x1f));
    proto_tree_add_uint(pcep_header_tree, pcep_filter[PCEPF_MSG], tvb, offset+1, 1, message_type);
    proto_tree_add_text(pcep_header_tree, tvb, offset+2, 2, "Message length: %u", msg_length);

    switch (PCEPF_MSG + message_type) {

    case PCEPF_OPEN:
    case PCEPF_KEEPALIVE:
    case PCEPF_PATH_COMPUTATION_REQUEST:
    case PCEPF_PATH_COMPUTATION_REPLY:
    case PCEPF_NOTIFICATION:
    case PCEPF_ERROR:
    case PCEPF_CLOSE:
	hidden_item = proto_tree_add_boolean(pcep_header_tree, pcep_filter[PCEPF_MSG + message_type], tvb, offset+1, 1, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);
	break;

    default:
	proto_tree_add_protocol_format(pcep_header_tree, proto_malformed, tvb, offset+1, 1, "Invalid message type: %u", message_type);
	return;
    }

    offset = 4;
    len = 4;

    dissect_pcep_obj_tree(pcep_tree, tvb, len, offset, msg_length);
}


static guint
get_pcep_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
    guint16 plen;

    /* Get the length of the PCEP packet.*/
    plen = tvb_get_ntohs(tvb, offset+2);

    return plen;
}

static void
dissect_pcep_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "PCEP");

	/* Clear out stuff in the info column */
	if (check_col(pinfo->cinfo,COL_INFO))
		col_clear(pinfo->cinfo,COL_INFO);

	dissect_pcep_msg_tree(tvb, tree, ett_pcep, pinfo);
}

static void
dissect_pcep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 4, get_pcep_message_len,
	dissect_pcep_pdu);
}

/*Register the protocol with wireshark*/
void
proto_register_pcep(void){

/*Register the protocol name and description*/
	proto_pcep = proto_register_protocol (
			"Path Computation Element communication Protocol",	/* name*/
			"PCEP",		/* short name */
			"pcep"		/* abbrev*/);

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_pcep, pcepf_info, array_length(pcepf_info));
	proto_register_subtree_array(ett, array_length(ett));
}

/*Dissector Handoff*/
void
proto_reg_handoff_pcep(void)
{
	dissector_handle_t pcep_handle;

	pcep_handle = create_dissector_handle(dissect_pcep, proto_pcep);
	dissector_add("tcp.port", TCP_PORT_PCEP, pcep_handle);
}
