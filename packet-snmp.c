/* packet-snmp.c
 * Routines for SNMP (simple network management protocol)
 * D.Jorand (c) 1998
 *
 * $Id: packet-snmp.c,v 1.2 1999/05/16 04:13:29 gram Exp $
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

static const char *get_version(int version)
{
	switch(version) {
	 case SNMP_VERSION_1:
		return "VERSION 1";
		break;
	 case SNMP_VERSION_2c:
		return "VERSION 2C";
		break;
	 case SNMP_VERSION_2u:
		return "VERSION 2U";
		break;	   
	 case SNMP_VERSION_3:
		return "VERSION 3";
		break;		
	 default:
		return "UNKNOWN";
		break;
	}
	return "";
}
	
static const char *get_pdu_type(u_char pdu_type)
{
	switch(pdu_type) {
	 case SNMP_MSG_GET:
		return "GET";
		break;
	 case SNMP_MSG_GETNEXT:
		return "GET-NEXT";
		break;
	 case SNMP_MSG_SET:
		return "SET";
		break;
	 case SNMP_MSG_RESPONSE:
		return "RESPONSE";
		break;
	 case SNMP_MSG_TRAP:
		return "TRAP-V1";
		break;
	 case SNMP_MSG_GETBULK:
		return "GETBULK";
		break;
	 case SNMP_MSG_INFORM:
		return "INFORM";
		break;
	 case SNMP_MSG_TRAP2:
		return "TRAP-V2";
		break;
	 case SNMP_MSG_REPORT:
		return "REPORT";
		break;
	 default:
		return "UNKNOWN";
		break;
	}
	return "";
}

static const char *get_error_status(long status)
{
	switch(status) {
	 case SNMP_ERR_NOERROR:
		return "NO ERROR";
		break;
	 case SNMP_ERR_TOOBIG:
		return "ERROR: TOOBIG";
		break;
	 case SNMP_ERR_NOSUCHNAME:
		return "ERROR: NO SUCH NAME";
		break;
	 case SNMP_ERR_BADVALUE:
		return "ERROR: BAD VALUE";
		break;
	 case SNMP_ERR_READONLY:
		return "ERROR: READ ONLY";
		break;
	 case SNMP_ERR_GENERR:
		return "ERROR: GENERIC ERROR";
		break;
	 case SNMP_ERR_NOACCESS:
		return "ERROR: NO ACCESS";
		break;
	 case SNMP_ERR_WRONGTYPE:
		return "ERROR: WRONG TYPE";
		break;
	 case SNMP_ERR_WRONGLENGTH:
		return "ERROR: WRONG LENGTH";
		break;
	 case SNMP_ERR_WRONGENCODING:
		return "ERROR: WRONG ENCODING";
		break;
	 case SNMP_ERR_WRONGVALUE:
		return "ERROR: WRONG VALUE";
		break;
	 case SNMP_ERR_NOCREATION:
		return "ERROR: NO CREATION";
		break;
	 case SNMP_ERR_INCONSISTENTVALUE:
		return "ERROR: INCONSISTENT VALUE";
		break;
	 case SNMP_ERR_RESOURCEUNAVAILABLE:
		return "ERROR: RESOURCE UNAVAILABLE";
		break;
	 case SNMP_ERR_COMMITFAILED:
		return "ERROR: COMMIT FAILED";
		break;
	 case SNMP_ERR_UNDOFAILED:
		return "ERROR: UNDO FAILED";
		break;
	 case SNMP_ERR_AUTHORIZATIONERROR:
		return "ERROR: AUTHORIZATION ERROR";
		break;
	 case SNMP_ERR_NOTWRITABLE:
		return "ERROR: NOT WRITABLE";
		break;
	 case SNMP_ERR_INCONSISTENTNAME:
		return "ERROR: INCONSISTENT NAME";
		break;
	 default:
		return "ERROR: UNKNOWN";
		break;
	}
	return "";
}

static const char *get_trap_type(long trap_type)
{
	switch(trap_type) {
	 case SNMP_TRAP_COLDSTART:
		return "COLD START";
		break;
	 case SNMP_TRAP_WARMSTART:
		return "WARM START";
		break;
	 case SNMP_TRAP_LINKDOWN:
		return "LINK DOWN";
		break;
	 case SNMP_TRAP_LINKUP:
		return "LINK UP";
		break;
	 case SNMP_TRAP_AUTHFAIL:
		return "AUTHENTICATION FAILED";
		break;
	 case SNMP_TRAP_EGPNEIGHBORLOSS:
		return "EGP NEIGHBORLOSS";
		break;
	 case SNMP_TRAP_ENTERPRISESPECIFIC:
		return "ENTERPRISE SPECIFIC";
		break;
	 default:
		return "UNKNOWN";
		break;
	}
	return "";
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
	
	proto_tree *snmp_tree=NULL;
	proto_item *item=NULL;

	/* NOTE: we have to parse the message piece by piece, since the
	 * capture length may be less than the message length: a 'global'
	 * parsing is likely to fail.
	 */
	
#ifdef WITH_SNMP_UCD	
	/* parse the SNMP header */
	  if(NULL == asn_parse_header( &pd[offset], &length, &type)) {
		fprintf(stderr, "<1> asn_parse_header failed\n");
		dissect_data(pd, offset, fd, tree);
		return;
	}
	
	if (type != (ASN_SEQUENCE | ASN_CONSTRUCTOR)) {
		fprintf(stderr, "<2> not a snmp pdu\n");
		dissect_data(pd, offset, fd, tree);
		return;
	}
	
	/* authenticates message */
	length=fd->pkt_len-offset;
	header_length=length;
	data = snmp_comstr_parse(&pd[offset], &length, community, &community_length,&version);
	if(NULL == data) {
		fprintf(stderr, "<3> authentication failed\n");
		dissect_data(pd, offset, fd, tree);
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
		fprintf(stderr, "<1> asn_parse_header failed\n");
		dissect_data(pd, offset, fd, tree);
		return;
	}
	
	if (type != (ASN_SEQUENCE | ASN_CONSTRUCTOR)) {
		fprintf(stderr, "<2> not a snmp pdu\n");
		dissect_data(pd, offset, fd, tree);
		return;
	}

	data = asn_parse_int(data, &length, &type, &version, sizeof(SNMP_INT));
	if(NULL == data) {
		fprintf(stderr, "<2.1> parse snmp version failed\n");
		dissect_data(pd, offset, fd, tree);
		return;
	}
	data = asn_parse_string(data, &length, &type, community, &community_length);
	if(NULL == data) {
		fprintf(stderr, "<2.1> parse snmp community failed\n");
		dissect_data(pd, offset, fd, tree);
		return;
	}
	community[community_length] = '\0';	
#endif	  

	header_length-=length;
	/* printf("Community is %s, version is %d (header length is %d)\n", community, version, header_length); */
	if(version != SNMP_VERSION_1) {
		fprintf(stderr, "<4> only SNMP V1 is supported\n");
		dissect_data(pd, offset, fd, tree);
		return;
	}

	pdu_type_length=length;
    data = asn_parse_header(data, &length, &pdu_type);
    if (data == NULL) {
		fprintf(stderr, "<5> parsing of pdu type failed\n");
		dissect_data(pd, offset, fd, tree);
		return;
	}
	pdu_type_length-=length;
	/* printf("pdu type is %#x (length is %d)\n", type, pdu_type_length); */
	
	/* get the fields in the PDU preceeding the variable-bindings sequence */
    if (pdu_type != SNMP_MSG_TRAP){

        /* request id */
		request_id_length=length;
		data = asn_parse_int(data, &length, &type, &request_id, sizeof(request_id));
		if (data == NULL) {
			fprintf(stderr, "<6> parsing of request-id failed\n");
			dissect_data(pd, offset, fd, tree);
			return;
		}
		request_id_length-=length;
		/* printf("request id is %#lx (length is %d)\n", request_id, request_id_length); */
		
        /* error status (getbulk non-repeaters) */
		error_status_length=length;
		data = asn_parse_int(data, &length, &type, &error_status, sizeof(error_status));
		if (data == NULL) {
			fprintf(stderr, "<7> parsing of error-status failed\n");
			dissect_data(pd, offset, fd, tree);
			return;
		}
		error_status_length-=length;

        /* error index (getbulk max-repetitions) */
		error_index_length=length;
		data = asn_parse_int(data, &length, &type, &error_index, sizeof(error_index));
		if (data == NULL) {
			fprintf(stderr, "<8> parsing of error-index failed\n");
			dissect_data(pd, offset, fd, tree);
			return;
		}
		error_index_length-=length;

		if(tree) {
			/* all_length=header_length+pdu_type_length+request_id_length+error_status_length+error_index_length; */
			all_length=fd->pkt_len-offset;
			item = proto_tree_add_item(tree, offset, all_length, "Simple Network Management Protocol");
			snmp_tree = proto_tree_new();
			proto_item_add_subtree(item, snmp_tree, ETT_SNMP);
			proto_tree_add_item(snmp_tree, offset, header_length, "Community: \"%s\", Version: %s", community, get_version(version));
			offset+=header_length;
			proto_tree_add_item(snmp_tree, offset, pdu_type_length, "Pdu type: %s (%#x)", get_pdu_type(pdu_type), pdu_type);
			offset+=pdu_type_length;
			proto_tree_add_item(snmp_tree, offset, request_id_length, "Request Id.: %#x", (unsigned int)request_id);
			offset+=request_id_length;
			proto_tree_add_item(snmp_tree, offset, error_status_length, "Error Status: %s (%d)", get_error_status(error_status), (int)error_status);
			offset+=error_status_length;
			proto_tree_add_item(snmp_tree, offset, error_index_length, "Error Index: %d", (int)error_index);
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
		if(tree) {
			all_length=fd->pkt_len-offset;
			item = proto_tree_add_item(tree, offset, all_length, "Simple Network Management Protocol");
			snmp_tree = proto_tree_new();
			proto_item_add_subtree(item, snmp_tree, ETT_SNMP);
			proto_tree_add_item(snmp_tree, offset, header_length, "Community: \"%s\", Version: %s", community, get_version(version));
			offset+=header_length;
			proto_tree_add_item(snmp_tree, offset, pdu_type_length, "Pdu type: %s (%#x)", get_pdu_type(pdu_type), pdu_type);
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
			fprintf(stderr, "<9> parsing of enterprise oid failed\n");
			dissect_data(pd, offset, fd, tree);
			return;
		}
		tmp_length-=length;

		sprintf(vb_string, OID_FORMAT_STRING, enterprise[0]);
		for(i=1; i<enterprise_length;i++) {
			sprintf(tmp_string, OID_FORMAT_STRING1, enterprise[i]);
			strcat(vb_string,tmp_string);
		}
		if(tree) {
			proto_tree_add_item(snmp_tree, offset, tmp_length, "Enterprise: %s", vb_string);
		}
		offset+=tmp_length;

        /* agent address */
		vb_string_value_length = 4;
		tmp_length=length;
		data = asn_parse_string(data, &length, &type, vb_string_value, &vb_string_value_length);
		if (data == NULL) {
			fprintf(stderr, "<10> parsing of agent address failed\n");
			dissect_data(pd, offset, fd, tree);
			return;
		}
		tmp_length-=length;
		if(tree) {
			proto_tree_add_item(snmp_tree, offset, tmp_length, "Agent address: %d.%d.%d.%d",
							 vb_string_value[0],vb_string_value[1],vb_string_value[2],vb_string_value[3]);
		}
		offset+=tmp_length;
		
        /* generic trap */
		tmp_length=length;
		data = asn_parse_int(data, &length, &type, &trap_type, sizeof(trap_type));
		if (data == NULL) {
			fprintf(stderr, "<11> parsing of trap type failed\n");
			dissect_data(pd, offset, fd, tree);
			return;
		}
		tmp_length-=length;
		if(tree) {
			proto_tree_add_item(snmp_tree, offset, tmp_length, "Trap type: %s (%ld)", get_trap_type(trap_type), (long)trap_type);
		}		
		offset+=tmp_length;
		
        /* specific trap */
		tmp_length=length;
		data = asn_parse_int(data, &length, &type, &specific_type, sizeof(specific_type));
		if (data == NULL) {
			fprintf(stderr, "<12> parsing of specific trap type failed\n");
			dissect_data(pd, offset, fd, tree);
			return;
		}
		tmp_length-=length;
		if(tree) {
			proto_tree_add_item(snmp_tree, offset, tmp_length, "Specific trap type: %ld (%#lx)", (long)specific_type, (long)specific_type);
		}		
		offset+=tmp_length;
		
        /* timestamp  */
		tmp_length=length;
		data = asn_parse_unsigned_int(data, &length, &type, &timestamp, sizeof(timestamp));
		if (data == NULL) {
			fprintf(stderr, "<13> parsing of timestamp failed\n");
			dissect_data(pd, offset, fd, tree);
			return;
		}
		tmp_length-=length;
		if(tree) {
			proto_tree_add_item(snmp_tree, offset, tmp_length, "Timestamp: %lu", (unsigned long)timestamp);
		}		
		offset+=tmp_length;
    }
	
	/* variable bindings */
    /* get header for variable-bindings sequence */
	tmp_length=length;
    data = asn_parse_header(data, &length, &type);
    if (data == NULL) {
		fprintf(stderr, "<+> parsing of variable-bindings header failed\n");
		dissect_data(pd, offset, fd, tree);
		return;
	}
	tmp_length-=length;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR)) {
		fprintf(stderr, "<+> bad type for variable-bindings header\n");
		dissect_data(pd, offset, fd, tree);
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
			fprintf(stderr, "<20> parsing of variable-binding header failed\n");
			dissect_data(pd, offset, fd, tree);
			return;
		}
		if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR)) {
			fprintf(stderr, "<21> bad type for variable-binding header (%#x)\n", type);
			dissect_data(pd, offset, fd, tree);
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
			fprintf(stderr, "<22> no object-identifier for variable-binding\n");
			dissect_data(pd, offset, fd, tree);
			return;
		}

		if (type != (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID)) {
			fprintf(stderr, "<23> bad type for variable-binding (%#x)\n", type);
			dissect_data(pd, offset, fd, tree);
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
			
			proto_tree_add_item(snmp_tree, offset, tmp_length, "Object identifier %d: %s (%s)", vb_index, vb_string, vb_string2);
		}
		offset+=tmp_length;
				
		/* parse the type of the object */
		tmp_length=length;
		if (NULL == asn_parse_header(data, &tmp_length, &vb_type)){
			fprintf(stderr, "<24> no type for variable-binding value\n");
			dissect_data(pd, offset, fd, tree);
			return;
		}

		/* parse the value */
		switch(vb_type) {
		 case ASN_NULL:
			tmp_length=length;
			data=asn_parse_null(data, &length, &type);
			tmp_length-=length;
			if (data == NULL){
				fprintf(stderr, "<25> parsing failed for null value\n");
				dissect_data(pd, offset, fd, tree);
				return;
			}
			if(tree) {
				proto_tree_add_item(snmp_tree, offset, tmp_length, "Value: NULL");
			}
			offset+=tmp_length;
			break;
			
		 case ASN_INTEGER:
			tmp_length=length;
			data=asn_parse_int(data,  &length, &type, &vb_integer_value, sizeof(vb_integer_value));
			tmp_length-=length;
			if (data == NULL){
				fprintf(stderr, "<26> parsing failed for integer value\n");
				dissect_data(pd, offset, fd, tree);
				return;
			}
			if(tree) {
				proto_tree_add_item(snmp_tree, offset, tmp_length, "Value: <i> %ld (%#lx)", (long)vb_integer_value, (long)vb_integer_value);
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
				fprintf(stderr, "<27> parsing failed for unsigned value\n");
				dissect_data(pd, offset, fd, tree);
				return;
			}
			if(tree) {
				proto_tree_add_item(snmp_tree, offset, tmp_length, "Value: <u> %lu (%#lx)", (unsigned long)vb_unsigned_value, (unsigned long)vb_unsigned_value);
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
				fprintf(stderr, "<28> parsing failed for counter64 value\n");
				dissect_data(pd, offset, fd, tree);
				return;
			}
			if(tree) {
				proto_tree_add_item(snmp_tree, offset, tmp_length, "Value: <i64> %lu:%lu (%#lx:%lx)",
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
				fprintf(stderr, "<29> parsing failed for oid value\n");
				dissect_data(pd, offset, fd, tree);
				return;
			}
			if(tree) {
				sprintf(vb_string, OID_FORMAT_STRING, vb_oid_value[0]);
				for(i=1; i<vb_oid_value_length;i++) {
					sprintf(tmp_string, OID_FORMAT_STRING1, vb_oid_value[i]);
					strcat(vb_string,tmp_string);
				}
				proto_tree_add_item(snmp_tree, offset, tmp_length, "Value: <oid> %s", vb_string);
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
				fprintf(stderr, "<30> parsing failed for octet string value\n");
				dissect_data(pd, offset, fd, tree);
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
					proto_tree_add_item(snmp_tree, offset, tmp_length, "Value: <str> %s", vb_string);
				}else {
					proto_tree_add_item(snmp_tree, offset, tmp_length, "Value: <str> %s", vb_string_value);
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
				fprintf(stderr, "<31> parsing failed for integer64 value\n");
				dissect_data(pd, offset, fd, tree);
				return;
			}
			if(tree) {
				proto_tree_add_item(snmp_tree, offset, tmp_length, "Value: <i64> %ld:%lu (%#lx:%lx)",
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
				fprintf(stderr, "<32> parsing failed for float value\n");
				dissect_data(pd, offset, fd, tree);
				return;
			}
			if(tree) {
				proto_tree_add_item(snmp_tree, offset, tmp_length, "Value: <f> %f", (double)vb_float_value);
			}
			offset+=tmp_length;
			break;
			
	    case ASN_OPAQUE_DOUBLE:
			tmp_length=length;
			data=asn_parse_double(data, &length, &type,&vb_double_value, sizeof(vb_double_value));
			tmp_length-=length;
			if (data == NULL){
				fprintf(stderr, "<32> parsing failed for double value\n");
				dissect_data(pd, offset, fd, tree);
				return;
			}
			if(tree) {
				proto_tree_add_item(snmp_tree, offset, tmp_length, "Value: <d> %f", vb_double_value);
			}
			offset+=tmp_length;
			break;
#endif /* OPAQUE_SPECIAL_TYPES */
			
		 case SNMP_NOSUCHOBJECT:
			if(tree) {
				proto_tree_add_item(snmp_tree, offset, tmp_length, "Value: <err> no such object");
			}			
			break;
		 case SNMP_NOSUCHINSTANCE:
			if(tree) {
				proto_tree_add_item(snmp_tree, offset, tmp_length, "Value: <err> no such instance");
			}			
			break;
		 case SNMP_ENDOFMIBVIEW:
			if(tree) {
				proto_tree_add_item(snmp_tree, offset, tmp_length, "Value: <err> end of mib view");
			}			
			break;
			
		 default:
			fprintf(stderr, "<=> unsupported type for variable-binding value: %#x\n", vb_type);
			dissect_data(pd, offset, fd, tree);
			return;
		}			
	}
}

#endif /* WITH_SNMP: CMU or UCD */
