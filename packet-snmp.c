/* packet-snmp.c
 * Routines for SNMP (simple network management protocol)
 * D.Jorand (c) 1998
 *
 * $Id: packet-snmp.c,v 1.4 1999/07/07 22:51:54 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
 * Copyright 1998 Didier Jorand
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


#if defined(HAVE_UCD_SNMP_SNMP_H)
  #define WITH_SNMP_UCD 1
#elif defined(HAVE_SNMP_SNMP_H)
  #define WITH_SNMP_CMU 1
#endif

#if defined(WITH_SNMP_CMU) || defined(WITH_SNMP_UCD)

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>
#include "packet.h"

#define in_addr_t u_int

#ifdef WITH_SNMP_UCD
/* should be defined only if supported in ucd-snmp */
#define OPAQUE_SPECIAL_TYPES 1
#include <ucd-snmp/asn1.h>
#include <ucd-snmp/snmp.h>
#include <ucd-snmp/snmp_api.h>
#include <ucd-snmp/snmp_impl.h>
#include <ucd-snmp/mib.h>

typedef long SNMP_INT;
typedef unsigned  long SNMP_UINT;
#define OID_FORMAT_STRING "%ld"
#define OID_FORMAT_STRING1 ".%ld"

#endif
#ifdef WITH_SNMP_CMU
#include <snmp/snmp.h>
#include <snmp/snmp_impl.h>


#ifndef MAX_NAME_LEN
#define MAX_NAME_LEN SNMP_MAX_LEN
#endif

#define SNMP_MSG_GET GET_REQ_MSG
#define SNMP_MSG_GETNEXT GETNEXT_REQ_MSG
#define SNMP_MSG_RESPONSE GET_RSP_MSG
#define SNMP_MSG_SET SET_REQ_MSG   
#define SNMP_MSG_TRAP TRP_REQ_MSG

#ifdef GETBULK_REQ_MSG
#define SNMP_MSG_GETBULK GETBULK_REQ_MSG
#else
#define SNMP_MSG_GETBULK SNMP_PDU_GETBULK
#endif

#ifdef INFORM_REQ_MSG
#define SNMP_MSG_INFORM INFORM_REQ_MSG
#else
#define SNMP_MSG_INFORM SNMP_PDU_INFORM
#endif

#ifdef TRP2_REQ_MSG
#define SNMP_MSG_TRAP2 TRP2_REQ_MSG
#else
#define SNMP_MSG_TRAP2 SNMP_PDU_V2TRAP
#endif

#ifdef REPORT_MSG
#define SNMP_MSG_REPORT REPORT_MSG
#else
#define SNMP_MSG_REPORT SNMP_PDU_REPORT
#endif


#ifndef SNMP_VERSION_2c
#define SNMP_VERSION_2c 1
#endif
#ifndef SNMP_VERSION_2u
#define SNMP_VERSION_2u 2
#endif
#ifndef SNMP_VERSION_3
#define SNMP_VERSION_3 3
#endif

#ifdef SNMP_TRAP_AUTHENTICATIONFAILURE
#define SNMP_TRAP_AUTHFAIL SNMP_TRAP_AUTHENTICATIONFAILURE
#endif

#ifndef COMMUNITY_MAX_LEN
#define COMMUNITY_MAX_LEN 256
#endif

#ifndef ASN_INTEGER
#define ASN_INTEGER SMI_INTEGER
#endif
#ifndef ASN_OCTET_STR
#define ASN_OCTET_STR SMI_STRING
#endif
#ifndef ASN_OBJECT_ID
#define ASN_OBJECT_ID SMI_OBJID
#endif
#ifndef ASN_NULL
#define ASN_NULL SMI_NULLOBJ
#endif

#ifndef ASN_IPADDRESS
	#ifdef IPADDRESS
	#define ASN_IPADDRESS IPADDRESS
	#else
	#define ASN_IPADDRESS SMI_IPADDRESS
	#endif
#endif

#ifndef ASN_COUNTER
	#ifdef COUNTER
	#define ASN_COUNTER COUNTER
	#else
	#define ASN_COUNTER SMI_COUNTER32
	#endif
#endif

#ifndef ASN_GAUGE
	#ifdef GAUGE
	#define ASN_GAUGE GAUGE
	#else
	#define ASN_GAUGE SMI_GAUGE32
	#endif
#endif

#ifndef ASN_TIMETICKS
	#ifdef TIMETICKS
	#define ASN_TIMETICKS TIMETICKS
	#else
	#define ASN_TIMETICKS SMI_TIMETICKS
	#endif
#endif

#ifndef ASN_OPAQUE
	#ifdef OPAQUE
	#define ASN_OPAQUE OPAQUE
	#else
	#define ASN_OPAQUE SMI_OPAQUE
	#endif
#endif

#ifndef ASN_COUNTER64
	#ifdef COUNTER64
	#define ASN_COUNTER64 COUNTER64
	#else
	#define ASN_COUNTER64 SMI_COUNTER64
	#endif
#endif

#ifndef ASN_UINTEGER
/* historic: should not be used! */
#define ASN_UINTEGER (ASN_APPLICATION | 7)
#endif
#ifndef ASN_NSAP
/* historic: should not be used! */
#define ASN_NSAP (ASN_APPLICATION | 5)
#endif
#ifndef SNMP_NOSUCHOBJECT
#define SNMP_NOSUCHOBJECT SMI_NOSUCHOBJECT
#endif
#ifndef SNMP_NOSUCHINSTANCE
#define SNMP_NOSUCHINSTANCE SMI_NOSUCHINSTANCE
#endif
#ifndef SNMP_ENDOFMIBVIEW
#define SNMP_ENDOFMIBVIEW SMI_ENDOFMIBVIEW
#endif


typedef int SNMP_INT;
typedef unsigned int SNMP_UINT;
#define OID_FORMAT_STRING "%d"
#define OID_FORMAT_STRING1 ".%d"

#endif

static const value_string versions[] = {
	{ SNMP_VERSION_1,	"VERSION 1" },
	{ SNMP_VERSION_2c,	"VERSION 2C" },
	{ SNMP_VERSION_2u,	"VERSION 2U" },
	{ SNMP_VERSION_3,	"VERSION 3" },
	{ 0,			NULL },
};

static const value_string pdu_types[] = {
	{ SNMP_MSG_GET,		"GET" },
	{ SNMP_MSG_GETNEXT,	"GET-NEXT" },
	{ SNMP_MSG_SET,		"SET" },
	{ SNMP_MSG_RESPONSE,	"RESPONSE" },
	{ SNMP_MSG_TRAP, 	"TRAP-V1" },
	{ SNMP_MSG_GETBULK, 	"GETBULK" },
	{ SNMP_MSG_INFORM, 	"INFORM" },
	{ SNMP_MSG_TRAP2, 	"TRAP-V2" },
	{ SNMP_MSG_REPORT,	"REPORT" },
	{ 0,			NULL }
};

static const value_string error_statuses[] = {
	{ SNMP_ERR_NOERROR,		"NO ERROR" },
	{ SNMP_ERR_TOOBIG,		"ERROR: TOOBIG" },
	{ SNMP_ERR_NOSUCHNAME,		"ERROR: NO SUCH NAME" },
	{ SNMP_ERR_BADVALUE,		"ERROR: BAD VALUE" },
	{ SNMP_ERR_READONLY,		"ERROR: READ ONLY" },
	{ SNMP_ERR_GENERR,		"ERROR: GENERIC ERROR" },
	{ SNMP_ERR_NOACCESS,		"ERROR: NO ACCESS" },
	{ SNMP_ERR_WRONGTYPE,		"ERROR: WRONG TYPE" },
	{ SNMP_ERR_WRONGLENGTH,		"ERROR: WRONG LENGTH" },
	{ SNMP_ERR_WRONGENCODING,	"ERROR: WRONG ENCODING" },
	{ SNMP_ERR_WRONGVALUE,		"ERROR: WRONG VALUE" },
	{ SNMP_ERR_NOCREATION,		"ERROR: NO CREATION" },
	{ SNMP_ERR_INCONSISTENTVALUE,	"ERROR: INCONSISTENT VALUE" },
	{ SNMP_ERR_RESOURCEUNAVAILABLE,	"ERROR: RESOURCE UNAVAILABLE" },
	{ SNMP_ERR_COMMITFAILED,	"ERROR: COMMIT FAILED" },
	{ SNMP_ERR_UNDOFAILED,		"ERROR: UNDO FAILED" },
	{ SNMP_ERR_AUTHORIZATIONERROR,	"ERROR: AUTHORIZATION ERROR" },
	{ SNMP_ERR_NOTWRITABLE,		"ERROR: NOT WRITABLE" },
	{ SNMP_ERR_INCONSISTENTNAME,	"ERROR: INCONSISTENT NAME" },
	{ 0,				NULL }
};

static const value_string trap_types[] = {
	{ SNMP_TRAP_COLDSTART,		"COLD START" },
	{ SNMP_TRAP_WARMSTART,		"WARM START" },
	{ SNMP_TRAP_LINKDOWN,		"LINK DOWN" },
	{ SNMP_TRAP_LINKUP,		"LINK UP" },
	{ SNMP_TRAP_AUTHFAIL,		"AUTHENTICATION FAILED" },
	{ SNMP_TRAP_EGPNEIGHBORLOSS,	"EGP NEIGHBORLOSS" },
	{ SNMP_TRAP_ENTERPRISESPECIFIC,	"ENTERPRISE SPECIFIC" },
	{ 0,				NULL }
};

static void
dissect_snmp_error(const u_char *pd, int offset, frame_data *fd,
		   proto_tree *tree, const char *message)
{
	if (check_col(fd, COL_INFO))
		col_add_str(fd, COL_INFO, message);

	dissect_data(pd, offset, fd, tree);
}

void
dissect_snmp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) 
{
	int length=fd->pkt_len-offset;
	u_char *data, *tmp_data;

	int all_length, header_length;
	u_char type, pdu_type;
	int pdu_type_length;
	SNMP_INT request_id, error_status, error_index;
	int request_id_length, error_status_length, error_index_length;
	
	SNMP_INT version;
	u_char community[COMMUNITY_MAX_LEN];
	int community_length = COMMUNITY_MAX_LEN;

	oid enterprise[MAX_NAME_LEN];
	int enterprise_length;
	SNMP_INT trap_type, specific_type;
	SNMP_UINT timestamp;
	
	int tmp_length;
	oid vb_name[MAX_NAME_LEN];
	int vb_name_length;
	int vb_index;
	u_char vb_type;
	char vb_string[MAX_NAME_LEN*6]; /* TBC */
	char vb_string2[2048]; /* TBC */
	char tmp_string[12];
	SNMP_INT vb_integer_value;
	SNMP_UINT vb_unsigned_value;
#ifdef WITH_SNMP_UCD	
	struct counter64 vb_counter64_value;
#endif	
	oid vb_oid_value[MAX_NAME_LEN];
	int vb_oid_value_length;
	unsigned char vb_string_value[128];
	int vb_string_value_length;
#ifdef WITH_SNMP_UCD	
	float vb_float_value;
	double vb_double_value;
#endif
	
	int i;

	char *pdu_type_string;

	proto_tree *snmp_tree=NULL;
	proto_item *item=NULL;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "SNMP");

	/* NOTE: we have to parse the message piece by piece, since the
	 * capture length may be less than the message length: a 'global'
	 * parsing is likely to fail.
	 */
	
#ifdef WITH_SNMP_UCD	
	/* parse the SNMP header */
	if(NULL == asn_parse_header( &pd[offset], &length, &type)) {
		dissect_snmp_error(pd, offset, fd, tree,
			"Couldn't parse SNMP header");
		return;
	}
	
	if (type != (ASN_SEQUENCE | ASN_CONSTRUCTOR)) {
		dissect_snmp_error(pd, offset, fd, tree, "Not an SNMP PDU");
		return;
	}
	
	/* authenticates message */
	length=fd->pkt_len-offset;
	header_length=length;
	data = snmp_comstr_parse(&pd[offset], &length, community, &community_length,&version);
	if(NULL == data) {
		dissect_snmp_error(pd, offset, fd, tree,
		    "Couldn't parse authentication");
		return;
	}
#endif
#ifdef WITH_SNMP_CMU
	/* initialize length variables */
	/* length=fd->pkt_len-offset; */
	header_length=length;	

	/* parse the SNMP header */
	data = asn_parse_header( &pd[offset], &length, &type);
	if(NULL == data) {
		dissect_snmp_error(pd, offset, fd, tree,
			"Couldn't parse SNMP header");
		return;
	}
	
	if (type != (ASN_SEQUENCE | ASN_CONSTRUCTOR)) {
		dissect_snmp_error(pd, offset, fd, tree, "Not an SNMP PDU");
		return;
	}

	data = asn_parse_int(data, &length, &type, &version, sizeof(SNMP_INT));
	if(NULL == data) {
		dissect_snmp_error(pd, offset, fd, tree,
		    "Couldn't parse SNMP version number");
		return;
	}
	data = asn_parse_string(data, &length, &type, community, &community_length);
	if(NULL == data) {
		dissect_snmp_error(pd, offset, fd, tree,
		    "Couldn't parse SNMP community");
		return;
	}
	community[community_length] = '\0';	
#endif 

	header_length-=length;
	/* printf("Community is %s, version is %d (header length is %d)\n", community, version, header_length); */
	if(version != SNMP_VERSION_1) {
		dissect_snmp_error(pd, offset, fd, tree,
		    "Non-version-1 SNMP PDU");
		return;
	}

	pdu_type_length=length;
	data = asn_parse_header(data, &length, &pdu_type);
	if (data == NULL) {
		dissect_snmp_error(pd, offset, fd, tree,
		    "Couldn't parse PDU type");
		return;
	}
	pdu_type_length-=length;
	/* printf("pdu type is %#x (length is %d)\n", type, pdu_type_length); */
	
	/* get the fields in the PDU preceeding the variable-bindings sequence */
	if (pdu_type != SNMP_MSG_TRAP) {

	/* request id */
		request_id_length=length;
		data = asn_parse_int(data, &length, &type, &request_id, sizeof(request_id));
		if (data == NULL) {
			dissect_snmp_error(pd, offset, fd, tree,
				"Couldn't parse request ID");
			return;
		}
		request_id_length-=length;
		/* printf("request id is %#lx (length is %d)\n", request_id, request_id_length); */
		
	/* error status (getbulk non-repeaters) */
		error_status_length=length;
		data = asn_parse_int(data, &length, &type, &error_status, sizeof(error_status));
		if (data == NULL) {
			dissect_snmp_error(pd, offset, fd, tree,
				"Couldn't parse error status");
			return;
		}
		error_status_length-=length;

	/* error index (getbulk max-repetitions) */
		error_index_length=length;
		data = asn_parse_int(data, &length, &type, &error_index, sizeof(error_index));
		if (data == NULL) {
			dissect_snmp_error(pd, offset, fd, tree,
				"Couldn't parse error index");
			return;
		}
		error_index_length-=length;

		pdu_type_string = val_to_str(pdu_type, pdu_types,
		    "Unknown PDU type %#x");
		if (check_col(fd, COL_INFO))
			col_add_str(fd, COL_INFO, pdu_type_string);
		if(tree) {
			/* all_length=header_length+pdu_type_length+request_id_length+error_status_length+error_index_length; */
			all_length=fd->pkt_len-offset;
			item = proto_tree_add_text(tree, offset, all_length, "Simple Network Management Protocol");
			snmp_tree = proto_item_add_subtree(item, ETT_SNMP);
			proto_tree_add_text(snmp_tree, offset, header_length, "Community: \"%s\", Version: %s", community, val_to_str(version, versions, "Unknown version %#x"));
			offset+=header_length;
			proto_tree_add_text(snmp_tree, offset, pdu_type_length, "%s", pdu_type_string);
			offset+=pdu_type_length;
			proto_tree_add_text(snmp_tree, offset, request_id_length, "Request Id.: %#x", (unsigned int)request_id);
			offset+=request_id_length;
			proto_tree_add_text(snmp_tree, offset, error_status_length, "Error Status: %s", val_to_str(error_status, error_statuses, "Unknown (%d)"));
			offset+=error_status_length;
			proto_tree_add_text(snmp_tree, offset, error_index_length, "Error Index: %d", (int)error_index);
			offset+=error_index_length;
		} else {
			offset+=header_length;
			offset+=pdu_type_length;
			offset+=request_id_length;
			offset+=error_status_length;
			offset+=error_index_length;		
		}
		
	} else {
		/* an SNMPv1 trap PDU */
		pdu_type_string = val_to_str(pdu_type, pdu_types,
		    "Unknown PDU type %#x");
		if (check_col(fd, COL_INFO))
			col_add_str(fd, COL_INFO, pdu_type_string);
		if(tree) {
			all_length=fd->pkt_len-offset;
			item = proto_tree_add_text(tree, offset, all_length, "Simple Network Management Protocol");
			snmp_tree = proto_item_add_subtree(item, ETT_SNMP);
			proto_tree_add_text(snmp_tree, offset, header_length, "Community: \"%s\", Version: %s", community, val_to_str(version, versions, "Unknown version %#x"));
			offset+=header_length;
			proto_tree_add_text(snmp_tree, offset, pdu_type_length, "Pdu type: %s", pdu_type_string);
			offset+=pdu_type_length;
		} else {
			offset+=header_length;
			offset+=pdu_type_length;
		}
		
	/* enterprise */
		enterprise_length = MAX_NAME_LEN;
		tmp_length=length;
		data = asn_parse_objid(data, &length, &type, enterprise,  &enterprise_length);
		if (data == NULL) {
			dissect_snmp_error(pd, offset, fd, tree,
				"Couldn't parse enterprise OID");
			return;
		}
		tmp_length-=length;

		sprintf(vb_string, OID_FORMAT_STRING, enterprise[0]);
		for(i=1; i<enterprise_length;i++) {
			sprintf(tmp_string, OID_FORMAT_STRING1, enterprise[i]);
			strcat(vb_string,tmp_string);
		}
		if(tree) {
			proto_tree_add_text(snmp_tree, offset, tmp_length, "Enterprise: %s", vb_string);
		}
		offset+=tmp_length;

	/* agent address */
		vb_string_value_length = 4;
		tmp_length=length;
		data = asn_parse_string(data, &length, &type, vb_string_value, &vb_string_value_length);
		if (data == NULL) {
			dissect_snmp_error(pd, offset, fd, tree,
				"Couldn't parse agent address");
			return;
		}
		tmp_length-=length;
		if(tree) {
			proto_tree_add_text(snmp_tree, offset, tmp_length, "Agent address: %d.%d.%d.%d",
							 vb_string_value[0],vb_string_value[1],vb_string_value[2],vb_string_value[3]);
		}
		offset+=tmp_length;
		
        /* generic trap */
		tmp_length=length;
		data = asn_parse_int(data, &length, &type, &trap_type, sizeof(trap_type));
		if (data == NULL) {
			dissect_snmp_error(pd, offset, fd, tree,
				"Couldn't parse trap type");
			return;
		}
		tmp_length-=length;
		if(tree) {
			proto_tree_add_text(snmp_tree, offset, tmp_length, "Trap type: %s", val_to_str(trap_type, trap_types, "Unknown (%d)"));
		}		
		offset+=tmp_length;
		
        /* specific trap */
		tmp_length=length;
		data = asn_parse_int(data, &length, &type, &specific_type, sizeof(specific_type));
		if (data == NULL) {
			dissect_snmp_error(pd, offset, fd, tree,
				"Couldn't parse specific trap type");
			return;
		}
		tmp_length-=length;
		if(tree) {
			proto_tree_add_text(snmp_tree, offset, tmp_length, "Specific trap type: %ld (%#lx)", (long)specific_type, (long)specific_type);
		}		
		offset+=tmp_length;
		
        /* timestamp  */
		tmp_length=length;
		data = asn_parse_unsigned_int(data, &length, &type, &timestamp, sizeof(timestamp));
		if (data == NULL) {
			dissect_snmp_error(pd, offset, fd, tree,
				"Couldn't parse time stamp");
			return;
		}
		tmp_length-=length;
		if(tree) {
			proto_tree_add_text(snmp_tree, offset, tmp_length, "Timestamp: %lu", (unsigned long)timestamp);
		}		
		offset+=tmp_length;
	}
	
	/* variable bindings */
    /* get header for variable-bindings sequence */
	tmp_length=length;
	data = asn_parse_header(data, &length, &type);
	if (data == NULL) {
		dissect_snmp_error(pd, offset, fd, tree,
			"Couldn't variable-bindings header");
		return;
	}
	tmp_length-=length;
	if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR)) {
		dissect_snmp_error(pd, offset, fd, tree,
			"Bad type for variable-bindings header");
		return;
	}
	offset+=tmp_length;
	/* printf("VB header: offset is %d; length is %d.\n", offset, tmp_length); */

	/* loop on variable bindings */
	vb_index=0;
	while(length>0) {
		vb_index++;
		/* printf("VB index is %d (offset=%d; length=%d).\n", vb_index, offset, length); */
		/* parse type */
		tmp_length=length;
		tmp_data=data;
		data = asn_parse_header(data, &tmp_length, &type);
		if (data == NULL) {
			dissect_snmp_error(pd, offset, fd, tree,
				"Couldn't parse variable-binding header");
			return;
		}
		if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR)) {
			dissect_snmp_error(pd, offset, fd, tree,
				"Bad type for variable-binding header");
			return;
		}
		tmp_length=(int)(data-tmp_data);
		length-=tmp_length;
		offset+=tmp_length;
		
		/* parse object identifier */
		vb_name_length=MAX_NAME_LEN;
		tmp_length=length;
		data = asn_parse_objid(data, &length, &type, vb_name, &vb_name_length);
		if (data == NULL) {
			dissect_snmp_error(pd, offset, fd, tree,
				"No object-identifier for variable-binding");
			return;
		}

		if (type != (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID)) {
			dissect_snmp_error(pd, offset, fd, tree,
				"Bad type for variable-binding");
			return;
		}
		tmp_length-=length;

		if(tree) {
			sprintf(vb_string, OID_FORMAT_STRING, vb_name[0]);
			for(i=1; i<vb_name_length;i++) {
				sprintf(tmp_string, OID_FORMAT_STRING1, vb_name[i]);
				strcat(vb_string,tmp_string);
			}
			
			sprint_objid(vb_string2, vb_name, vb_name_length);
			
			proto_tree_add_text(snmp_tree, offset, tmp_length, "Object identifier %d: %s (%s)", vb_index, vb_string, vb_string2);
		}
		offset+=tmp_length;
				
		/* parse the type of the object */
		tmp_length=length;
		if (NULL == asn_parse_header(data, &tmp_length, &vb_type)){
			dissect_snmp_error(pd, offset, fd, tree,
				"Bad type for variable-binding value");
			return;
		}

		/* parse the value */
		switch(vb_type) {
		case ASN_NULL:
			tmp_length=length;
			data=asn_parse_null(data, &length, &type);
			tmp_length-=length;
			if (data == NULL){
				dissect_snmp_error(pd, offset, fd, tree,
					"Couldn't parse null value");
				return;
			}
			if(tree) {
				proto_tree_add_text(snmp_tree, offset, tmp_length, "Value: NULL");
			}
			offset+=tmp_length;
			break;
			
		case ASN_INTEGER:
			tmp_length=length;
			data=asn_parse_int(data,  &length, &type, &vb_integer_value, sizeof(vb_integer_value));
			tmp_length-=length;
			if (data == NULL){
				dissect_snmp_error(pd, offset, fd, tree,
					"Couldn't parse integer value");
				return;
			}
			if(tree) {
				proto_tree_add_text(snmp_tree, offset, tmp_length, "Value: <i> %ld (%#lx)", (long)vb_integer_value, (long)vb_integer_value);
			}
			offset+=tmp_length;
			break;

		case ASN_COUNTER:
		case ASN_GAUGE:
		case ASN_TIMETICKS:
		case ASN_UINTEGER:
			tmp_length=length;
			data=asn_parse_unsigned_int(data, &length, &type, &vb_unsigned_value, sizeof(vb_unsigned_value));
			tmp_length-=length;
			if (data == NULL){
				dissect_snmp_error(pd, offset, fd, tree,
					"Couldn't parse unsigned value");
				return;
			}
			if(tree) {
				proto_tree_add_text(snmp_tree, offset, tmp_length, "Value: <u> %lu (%#lx)", (unsigned long)vb_unsigned_value, (unsigned long)vb_unsigned_value);
			}
			offset+=tmp_length;
			break;

#ifdef WITH_SNMP_UCD
			/* only ucd support 64bits types */
		case ASN_COUNTER64:
#ifdef OPAQUE_SPECIAL_TYPES
		case ASN_OPAQUE_COUNTER64:
		case ASN_OPAQUE_U64:
#endif /* OPAQUE_SPECIAL_TYPES */
			tmp_length=length;
			data=asn_parse_unsigned_int64(data, &length, &type, &vb_counter64_value, sizeof(vb_counter64_value));
			tmp_length-=length;
			if (data == NULL){
				dissect_snmp_error(pd, offset, fd, tree,
					"Couldn't parse counter64 value");
				return;
			}
			if(tree) {
				proto_tree_add_text(snmp_tree, offset, tmp_length, "Value: <i64> %lu:%lu (%#lx:%lx)",
								 vb_counter64_value.high,
								 vb_counter64_value.low,
								 vb_counter64_value.high,
								 vb_counter64_value.low);
			}
			offset+=tmp_length;
			break;
#endif /* WITH_SNMP_UCD */
			
		case ASN_OBJECT_ID:
			vb_oid_value_length = MAX_NAME_LEN;
			tmp_length=length;
			data=asn_parse_objid(data, &length, &type, vb_oid_value, &vb_oid_value_length);
			tmp_length-=length;
			if (data == NULL){
				dissect_snmp_error(pd, offset, fd, tree,
					"Couldn't parse OID value");
				return;
			}
			if(tree) {
				sprintf(vb_string, OID_FORMAT_STRING, vb_oid_value[0]);
				for(i=1; i<vb_oid_value_length;i++) {
					sprintf(tmp_string, OID_FORMAT_STRING1, vb_oid_value[i]);
					strcat(vb_string,tmp_string);
				}
				proto_tree_add_text(snmp_tree, offset, tmp_length, "Value: <oid> %s", vb_string);
			}			
			offset+=tmp_length;
			break;
		case ASN_OCTET_STR:
		case ASN_IPADDRESS:
		case ASN_OPAQUE:
		case ASN_NSAP:
			vb_string_value_length=128;
			tmp_length=length;
			data=asn_parse_string(data, &length, &type, vb_string_value, &vb_string_value_length);
			tmp_length-=length;
			if (data == NULL){
				dissect_snmp_error(pd, offset, fd, tree,
					"Couldn't parse octet string value");
				return;
			}
			if(tree) {
				vb_string_value[vb_string_value_length]=0;
				/* if some characters are not printable, display the string as
				 * bytes */
				for(i=0; i<vb_string_value_length; i++) {
					if(!(isprint(vb_string_value[i]) || isspace(vb_string_value[i]))) break;
				}
				if(i<vb_string_value_length) {
					sprintf(vb_string, "%03d", (int)vb_string_value[0]);
					for(i=1; i<vb_string_value_length; i++) {
						sprintf(tmp_string, ".%03d", (int)vb_string_value[i]);
						strcat(vb_string,tmp_string);
					}
					proto_tree_add_text(snmp_tree, offset, tmp_length, "Value: <str> %s", vb_string);
				}else {
					proto_tree_add_text(snmp_tree, offset, tmp_length, "Value: <str> %s", vb_string_value);
				}
			}
			offset+=tmp_length;
			break;			

#ifdef OPAQUE_SPECIAL_TYPES
		case ASN_OPAQUE_I64:
			tmp_length=length;
			data=asn_parse_signed_int64(data, &length, &type, &vb_counter64_value, sizeof(vb_counter64_value));
			tmp_length-=length;
			if (data == NULL){
				dissect_snmp_error(pd, offset, fd, tree,
					"Couldn't parse integer64 value");
				return;
			}
			if(tree) {
				proto_tree_add_text(snmp_tree, offset, tmp_length, "Value: <i64> %ld:%lu (%#lx:%lx)",
								 vb_counter64_value.high,
								 vb_counter64_value.low,
								 vb_counter64_value.high,
								 vb_counter64_value.low);
			}
			offset+=tmp_length;
			break;
			break;

		case ASN_OPAQUE_FLOAT:
			tmp_length=length;
			data=asn_parse_float(data, &length, &type,&vb_float_value, sizeof(vb_float_value));
			tmp_length-=length;
			if (data == NULL){
				dissect_snmp_error(pd, offset, fd, tree,
					"Couldn't parse float value");
				return;
			}
			if(tree) {
				proto_tree_add_text(snmp_tree, offset, tmp_length, "Value: <f> %f", (double)vb_float_value);
			}
			offset+=tmp_length;
			break;
			
		case ASN_OPAQUE_DOUBLE:
			tmp_length=length;
			data=asn_parse_double(data, &length, &type,&vb_double_value, sizeof(vb_double_value));
			tmp_length-=length;
			if (data == NULL){
				dissect_snmp_error(pd, offset, fd, tree,
					"Couldn't parse double value");
				return;
			}
			if(tree) {
				proto_tree_add_text(snmp_tree, offset, tmp_length, "Value: <d> %f", vb_double_value);
			}
			offset+=tmp_length;
			break;
#endif /* OPAQUE_SPECIAL_TYPES */
			
		case SNMP_NOSUCHOBJECT:
			if(tree) {
				proto_tree_add_text(snmp_tree, offset, tmp_length, "Value: <err> no such object");
			}			
			break;
		case SNMP_NOSUCHINSTANCE:
			if(tree) {
				proto_tree_add_text(snmp_tree, offset, tmp_length, "Value: <err> no such instance");
			}			
			break;
		case SNMP_ENDOFMIBVIEW:
			if(tree) {
				proto_tree_add_text(snmp_tree, offset, tmp_length, "Value: <err> end of mib view");
			}			
			break;
			
		default:
			dissect_snmp_error(pd, offset, fd, tree,
				"Unsupported type for variable-binding value");
			return;
		}			
	}
}

#endif /* WITH_SNMP: CMU or UCD */
