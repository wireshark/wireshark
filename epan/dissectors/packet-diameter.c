/* packet-diameter.c
 * Routines for Diameter packet disassembly
 *
 * $Id$
 *
 * Copyright (c) 2001 by David Frascone <dave@frascone.com>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * References:
 * 2004-03-11
 * http://www.ietf.org/rfc/rfc3588.txt
 * http://www.iana.org/assignments/radius-types
 * http://www.ietf.org/internet-drafts/draft-ietf-aaa-diameter-cc-03.txt
 * http://www.ietf.org/internet-drafts/draft-ietf-aaa-diameter-nasreq-14.txt
 * http://www.ietf.org/internet-drafts/draft-ietf-aaa-diameter-mobileip-16.txt
 * http://www.ietf.org/internet-drafts/draft-ietf-aaa-diameter-sip-app-01.txt
 * http://www.ietf.org/html.charters/aaa-charter.html
 * http://www.iana.org/assignments/address-family-numbers
 * http://www.iana.org/assignments/enterprise-numbers
 * http://www.iana.org/assignments/aaa-parameters
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <glib.h>
#include <epan/filesystem.h>
#include <epan/xmlstub.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/report_err.h>
#include <epan/prefs.h>
#include <epan/sminmpec.h>
#include <epan/emem.h>
#include "packet-tcp.h"
#include "packet-sip.h"

/* This must be defined before we include packet-diameter-defs.h */

/* Valid data types */
typedef enum {
  /* Base Types */
  DIAMETER_OCTET_STRING = 1,
  DIAMETER_INTEGER32,
  DIAMETER_INTEGER64,
  DIAMETER_UNSIGNED32,
  DIAMETER_UNSIGNED32ENUM,
  DIAMETER_UNSIGNED64,
  DIAMETER_FLOAT32,
  DIAMETER_FLOAT64,
  DIAMETER_FLOAT128,
  DIAMETER_GROUPED,

  /* Derived Types */
  DIAMETER_IP_ADDRESS,         /* OctetString */
  DIAMETER_TIME,               /* Integer 32 */
  DIAMETER_UTF8STRING,         /* OctetString */
  DIAMETER_IDENTITY,           /* OctetString */
  DIAMETER_ENUMERATED,         /* Integer 32 */
  DIAMETER_IP_FILTER_RULE,     /* OctetString */
  DIAMETER_QOS_FILTER_RULE,    /* OctetString */
  DIAMETER_MIP_REG_REQ,        /* OctetString */
  DIAMETER_VENDOR_ID,          /* Integer32  */
  DIAMETER_APPLICATION_ID,     /* Integer32  */
  DIAMETER_URI,                /* OctetString */
  DIAMETER_SESSION_ID,          /* OctetString */
  DIAMETER_PUBLIC_ID,			/* OctetString */
  DIAMETER_PRIVATE_ID			/* OctetString */	
} diameterDataType;


static const value_string TypeValues[]={
  {  DIAMETER_OCTET_STRING,    "OctetString" },
  {  DIAMETER_INTEGER32,       "Integer32" },
  {  DIAMETER_INTEGER64,       "Integer64" },
  {  DIAMETER_UNSIGNED32,      "Unsigned32" },
  {  DIAMETER_UNSIGNED32ENUM,	"Unsigned32" }, /* This is needed to get value translation for Uint32:s with a value*/
  {  DIAMETER_UNSIGNED64,      "Unsigned64" },
  {  DIAMETER_FLOAT32,         "Float32" },
  {  DIAMETER_FLOAT64,         "Float64" },
  {  DIAMETER_FLOAT128,        "Float128" },
  {  DIAMETER_GROUPED,         "Grouped" },
  {  DIAMETER_IP_ADDRESS,      "IpAddress" },
  {  DIAMETER_TIME,            "Time" },
  {  DIAMETER_UTF8STRING,      "UTF8String" },
  {  DIAMETER_IDENTITY,        "DiameterIdentity" },
  {  DIAMETER_ENUMERATED,      "Enumerated" },
  {  DIAMETER_IP_FILTER_RULE,  "IPFilterRule" },
  {  DIAMETER_QOS_FILTER_RULE, "QOSFilterRule" },
  {  DIAMETER_MIP_REG_REQ,     "MIPRegistrationRequest"},
  {  DIAMETER_VENDOR_ID,       "VendorId"},
  {  DIAMETER_APPLICATION_ID,  "AppId"},
  {  DIAMETER_URI,             "DiameterURI"},
  {  DIAMETER_SESSION_ID,      "Session-Id"},
  {	 DIAMETER_PUBLIC_ID,		"Public-Id"},
  {	 DIAMETER_PRIVATE_ID,		"Private-Id"},
	
  {0, (char *)NULL}
};

typedef struct value_name {
  guint32            value;
  gchar             *name;
  struct value_name *next;
} ValueName;

typedef struct old_avp_info {
  guint32           code;
  const gchar      *name;
  diameterDataType  type;
  const value_string *values;
} oldAvpInfo;

typedef struct avp_info {
  guint32           code;
  gchar            *name;
  gchar            *vendorName;
  diameterDataType  type;
  ValueName        *values;
  struct avp_info  *next;
} avpInfo;

typedef struct command_code {
  guint32              code;
  gchar               *name;
  gchar               *vendorName;
  struct command_code *next;
} CommandCode;

typedef struct vendor_id {
  guint32              id;
  gchar               *name;
  gchar               *longName;
  struct vendor_id    *next;
} VendorId;

typedef struct application_id {
  guint32              id;
  gchar               *name;
  struct application_id    *next;
} ApplicationId;

static avpInfo         *avpListHead=NULL;
static VendorId        *vendorListHead=NULL;
static CommandCode     *commandListHead=NULL;
static ApplicationId   *ApplicationIdHead=NULL;


#include "packet-diameter-defs.h"

#define  NTP_TIME_DIFF                   (2208988800UL)

#define TCP_PORT_DIAMETER	3868
#define SCTP_PORT_DIAMETER	3868

static const true_false_string reserved_set = {
  "*** Error! Reserved Bit is Set",
  "Ok"
};

static int proto_diameter = -1;
static int hf_diameter_length = -1;
static int hf_diameter_code = -1;
static int hf_diameter_hopbyhopid =-1;
static int hf_diameter_endtoendid =-1;
static int hf_diameter_version = -1;
static int hf_diameter_vendor_id = -1;
static int hf_diameter_application_id = -1;
static int hf_diameter_flags = -1;
static int hf_diameter_flags_request = -1;
static int hf_diameter_flags_proxyable = -1;
static int hf_diameter_flags_error = -1;
static int hf_diameter_flags_T		= -1;
static int hf_diameter_flags_reserved4 = -1;
static int hf_diameter_flags_reserved5 = -1;
static int hf_diameter_flags_reserved6 = -1;
static int hf_diameter_flags_reserved7 = -1;

static int hf_diameter_avp_code = -1;
static int hf_diameter_avp_length = -1;
static int hf_diameter_avp_flags = -1;
static int hf_diameter_avp_flags_vendor_specific = -1;
static int hf_diameter_avp_flags_mandatory = -1;
static int hf_diameter_avp_flags_protected = -1;
static int hf_diameter_avp_flags_reserved3 = -1;
static int hf_diameter_avp_flags_reserved4 = -1;
static int hf_diameter_avp_flags_reserved5 = -1;
static int hf_diameter_avp_flags_reserved6 = -1;
static int hf_diameter_avp_flags_reserved7 = -1;
static int hf_diameter_avp_vendor_id = -1;


static int hf_diameter_avp_data_uint32 = -1;
static int hf_diameter_avp_data_int32 = -1;
static int hf_diameter_avp_data_uint64 = -1;
static int hf_diameter_avp_data_int64 = -1;
static int hf_diameter_avp_data_bytes = -1;
static int hf_diameter_avp_data_string = -1;
static int hf_diameter_avp_data_addrfamily = -1;
static int hf_diameter_avp_data_v4addr		= -1;
static int hf_diameter_avp_data_v6addr		= -1;
static int hf_diameter_avp_data_time		= -1;
static int hf_diameter_avp_diameter_uri		= -1;
static int hf_diameter_avp_session_id		= -1;
static int hf_diameter_avp_public_id		= -1;
static int hf_diameter_avp_private_id		= -1;

static gint ett_diameter = -1;
static gint ett_diameter_flags = -1;
static gint ett_diameter_avp = -1;
static gint ett_diameter_avp_flags = -1;
static gint ett_diameter_avpinfo = -1;

static guint gbl_diameterTcpPort=TCP_PORT_DIAMETER;
static guint gbl_diameterSctpPort=SCTP_PORT_DIAMETER;

/* desegmentation of Diameter over TCP */
static gboolean gbl_diameter_desegment = TRUE;

/* Allow zero as a valid application ID */
static gboolean allow_zero_as_app_id = TRUE;

/* Suppress console output at unknown AVP:s,Flags etc */
static gboolean suppress_console_output = TRUE;

static gboolean gbl_use_xml_dictionary = TRUE;
#define DICT_FN  "diameter/dictionary.xml"
static const gchar *gbl_diameterDictionary;

typedef struct _e_diameterhdr_v16 {
  guint32  versionLength;
  guint32  flagsCmdCode;
  guint32  vendorId;
  guint32  hopByHopId;
  guint32  endToEndId;
} e_diameterhdr_v16;

typedef struct _e_diameterhdr_rfc {
  guint32  versionLength;
  guint32  flagsCmdCode;
  guint32  applicationId;
  guint32  hopByHopId;
  guint32  endToEndId;
} e_diameterhdr_rfc;

typedef struct _e_avphdr {
  guint32 avp_code;
  guint32 avp_flagsLength;
  guint32 avp_vendorId;           /* optional */
} e_avphdr;

/* Diameter Header Flags */
/*                                      RPrrrrrrCCCCCCCCCCCCCCCCCCCCCCCC  */
#define DIAM_FLAGS_R 0x80
#define DIAM_FLAGS_P 0x40
#define DIAM_FLAGS_E 0x20
#define DIAM_FLAGS_T 0x10
#define DIAM_FLAGS_RESERVED4 0x08
#define DIAM_FLAGS_RESERVED5 0x04
#define DIAM_FLAGS_RESERVED6 0x02
#define DIAM_FLAGS_RESERVED7 0x01
#define DIAM_FLAGS_RESERVED  0x0f

#define DIAM_LENGTH_MASK  0x00ffffffl
#define DIAM_COMMAND_MASK DIAM_LENGTH_MASK
#define DIAM_GET_FLAGS(dh)                ((dh.flagsCmdCode & ~DIAM_COMMAND_MASK) >> 24)
#define DIAM_GET_VERSION(dh)              ((dh.versionLength & (~DIAM_LENGTH_MASK)) >> 24)
#define DIAM_GET_COMMAND(dh)              (dh.flagsCmdCode & DIAM_COMMAND_MASK)
#define DIAM_GET_LENGTH(dh)               (dh.versionLength & DIAM_LENGTH_MASK)

/* Diameter AVP Flags */
#define AVP_FLAGS_P 0x20
#define AVP_FLAGS_V 0x80
#define AVP_FLAGS_M 0x40
#define AVP_FLAGS_RESERVED3 0x10
#define AVP_FLAGS_RESERVED4 0x08
#define AVP_FLAGS_RESERVED5 0x04
#define AVP_FLAGS_RESERVED6 0x02
#define AVP_FLAGS_RESERVED7 0x01
#define AVP_FLAGS_RESERVED 0x1f          /* 00011111  -- V M P X X X X X */

#define MIN_AVP_SIZE (sizeof(e_avphdr) - sizeof(guint32))
#define MIN_DIAMETER_SIZE (sizeof(e_diameterhdr_rfc))

static Version_Type gbl_version = DIAMETER_RFC;

static void dissect_avps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static gchar *diameter_vendor_to_str(guint32 vendorId, gboolean longName);

/*
 * This routine will do a push-parse of the passed in
 * filename.  This was taken almost verbatum from
 * the xmlsoft examples.
 */
static xmlDocPtr
xmlParseFilePush( const char *filename, int checkValid
#ifndef ETHEREAL_XML_DO_VALIDITY_CHECKING
                 _U_
#endif
) {
  FILE *f;
  xmlDocPtr doc=NULL;
#ifdef ETHEREAL_XML_DO_VALIDITY_CHECKING
  int valid=0;
#endif
  int res, size = 1024;
  char chars[1024];
  xmlParserCtxtPtr ctxt;

#ifdef ETHEREAL_XML_DO_VALIDITY_CHECKING
  /* I wonder what kind of a performance hit this is? */
  *XmlStub.xmlDoValidityCheckingDefaultValue = checkValid;
#endif

  f = fopen(filename, "r");
  if (f == NULL) {
	report_open_failure(filename, errno, FALSE);
	return NULL;
  }

  res = fread(chars, 1, 4, f);
  if (res > 0) {
	ctxt = XmlStub.xmlCreatePushParserCtxt(NULL, NULL,
										   chars, res, filename);
	while ((res = fread(chars, 1, size-1, f)) > 0) {
	  XmlStub.xmlParseChunk(ctxt, chars, res, 0);
	}
	XmlStub.xmlParseChunk(ctxt, chars, 0, 1);
	doc = ctxt->myDoc;
#ifdef ETHEREAL_XML_DO_VALIDITY_CHECKING
  valid=ctxt->valid;
#endif
	XmlStub.xmlFreeParserCtxt(ctxt);
  }
  fclose(f);

#ifdef ETHEREAL_XML_DO_VALIDITY_CHECKING
  /* Check valid */
  if (!valid) {
	report_failure( "Error!  Invalid xml in %s!  Failed DTD check!",
			   filename);
	return NULL;
  }
#endif

  return doc;
} /* xmlParseFilePush */

/*
 * This routine will add a static avp to the avp list.  It is
 * only called when the XML dictionary fails to load properly.
 */
static int
addStaticAVP(int code, const gchar *name, diameterDataType type, const value_string *values)
{
  avpInfo *entry;
  ValueName *vEntry=NULL;
  int i;

  /* Parse our values array, if we have one */
  if (values) {
	for (i=0; values[i].strptr != NULL; i++) {
	  ValueName *ve = NULL;

	  ve = g_malloc(sizeof(ValueName));
	  ve->name = strdup(values[i].strptr);
	  ve->value = values[i].value;
	  ve->next = vEntry;
	  vEntry = ve;
	}
  } /* if values */

	/* And, create the entry */
  entry = (avpInfo *)g_malloc(sizeof(avpInfo));
  entry->name = g_strdup(name);
  entry->code = code;
  entry->vendorName = NULL;
  entry->type = type;
  entry->values = vEntry;
  /* Unsigned32 might have values to ( Result-code 268 ) */
  if (vEntry){
		switch(type){
		case DIAMETER_UNSIGNED32:
			entry->type = DIAMETER_UNSIGNED32ENUM;
			break;
		case DIAMETER_VENDOR_ID:
			/* Ignore data from the xml file, use sminmpec.h vals */
			break;
		default:
			entry->type = DIAMETER_ENUMERATED;
	}
  }


  /* And, add it to the list */
  entry->next = avpListHead;
  avpListHead = entry;

  return (0);

} /* addStaticAVP */
/*
 * This routine will add a Vendor avp to the avp list.  It is
 * only called when the XML dictionary fails to load properly.
 */
static int
addVendorAVP(int code, const gchar *name, diameterDataType type, const value_string *values,int vendorId)
{
  avpInfo *entry;
  ValueName *vEntry=NULL;
  gchar *vendorName;
  int i;

  /* Parse our values array, if we have one */
  if (values) {
	for (i=0; values[i].strptr != NULL; i++) {
	  ValueName *ve = NULL;

	  ve = g_malloc(sizeof(ValueName));
	  ve->name = strdup(values[i].strptr);
	  ve->value = values[i].value;
	  ve->next = vEntry;
	  vEntry = ve;
	}
  } /* if values */

	/* And, create the entry */
  entry = (avpInfo *)g_malloc(sizeof(avpInfo));
  entry->name = g_strdup(name);
  entry->code = code;

  vendorName = diameter_vendor_to_str(vendorId, FALSE);
	
  if (vendorName)
	entry->vendorName = g_strdup(vendorName);
  else
	entry->vendorName = NULL;  
  entry->type = type;
  entry->values = vEntry;

  /* Unsigned32 might have values to ( Result-code 268 ) */
  if (vEntry){
		switch(type){
		case DIAMETER_UNSIGNED32:
			entry->type = DIAMETER_UNSIGNED32ENUM;
			break;
		case DIAMETER_VENDOR_ID:
			/* Ignore data from the xml file, use sminmpec.h vals */
			break;
		default:
			entry->type = DIAMETER_ENUMERATED;
	}
  }

  /* And, add it to the list */
  entry->next = avpListHead;
  avpListHead = entry;

  return (0);

} /* addStaticAVP */
/*
 * This routine will parse an XML avp entry, and add it to our
 * avp list.  If any values are present in the avp, it will
 * add them too.
 */
static int
xmlParseAVP(xmlNodePtr cur)
{
  char *name=NULL, *description=NULL, *code=NULL, *mayEncrypt=NULL,
	*mandatory=NULL, *protected=NULL, *vendorBit=NULL, *vendorName = NULL,
	*constrained=NULL;
  char *type=NULL;
  avpInfo *entry;
  guint32 avpType=0;
  ValueName *vEntry=NULL;
  int i;

  /* First, get our properties */
  name = XmlStub.xmlGetProp(cur, "name");
  description = XmlStub.xmlGetProp(cur, "description");
  code = XmlStub.xmlGetProp(cur, "code");
  mayEncrypt = XmlStub.xmlGetProp(cur, "may-encrypt");
  mandatory = XmlStub.xmlGetProp(cur, "mandatory");
  protected = XmlStub.xmlGetProp(cur, "protected");
  vendorBit = XmlStub.xmlGetProp(cur, "vendor-bit");
  vendorName = XmlStub.xmlGetProp(cur, "vendor-id");
  constrained = XmlStub.xmlGetProp(cur, "constrained");

  cur = cur->xmlChildrenNode;

  while (cur != NULL ) {
	if (strcasecmp((const char *)cur->name, "type") == 0) {
	  type = XmlStub.xmlGetProp(cur, "type-name");
	} else if (strcasecmp((const char *)cur->name, "enum") == 0) {
	  char *valueName=NULL, *valueCode=NULL;
	  ValueName *ve = NULL;
	  valueName = XmlStub.xmlGetProp(cur, "name");
	  valueCode = XmlStub.xmlGetProp(cur, "code");

	  if (!valueName || !valueCode) {
		report_failure( "Error, bad value on avp %s", name);
		return (-1);
	  }

	  ve = g_malloc(sizeof(ValueName));
	  ve->name = strdup(valueName);
	  ve->value = atol(valueCode);

	  ve->next = vEntry;
	  vEntry = ve;
	} else if (strcasecmp((const char *)cur->name, "grouped") == 0) {
	  /* WORK Recurse here for grouped AVPs */
	  type = "grouped";
	}
	cur=cur->next;
  } /* while */

	/*
	 * Check for the AVP Type.
	 */
  if (type) {
	for (i = 0; TypeValues[i].strptr; i++) {
	  if (!strcasecmp(type, TypeValues[i].strptr)) {
		avpType = TypeValues[i].value;
		break;
	  }
	}

	if (TypeValues[i].strptr == NULL) {
	  report_failure( "Invalid Type field in dictionary! avp %s (%s)",  name, type);
	  return (-1);
	}
  } else if (!vEntry) {
	report_failure("Missing type/enum field in dictionary avpName=%s",
			  name);
	return (-1);
  }

  /* WORK - Handle flags  -- for validation later */


  /* And, create the entry */
  entry = (avpInfo *)g_malloc(sizeof(avpInfo));
  entry->name = g_strdup(name);
  entry->code = atol(code);
  if (vendorName)
	entry->vendorName = g_strdup(vendorName);
  else
	entry->vendorName = NULL;
  entry->type = avpType;
  entry->values = vEntry;
  /* Unsigned32 might have values to ( Result-code 268 ) */
    if (vEntry)
		switch(avpType){
		case DIAMETER_UNSIGNED32:
			entry->type = DIAMETER_UNSIGNED32ENUM;
			break;
		case DIAMETER_VENDOR_ID:
			/* Ignore data from the xml file, use sminmpec.h vals */
			break;
		default:
			entry->type = DIAMETER_ENUMERATED;
	}

	/* And, add it to the list */
  entry->next = avpListHead;
  avpListHead = entry;

  return (0);
} /* xmlParseAVP */

/*
 * This routine will add a command to the list of commands.
 */
static int
addCommand(int code, const char *name, char *vendorId)
{
  CommandCode *entry;

  /*
   * Allocate the memory required for the dictionary.
   */
  entry = (CommandCode *) g_malloc(sizeof (CommandCode));

  if (entry == NULL) {
	report_failure("Unable to allocate memory");
	return (-1);
  }

  /*
   * Allocate memory for the AVPName and copy the name to the
   * structure
   */
  entry->name = g_strdup(name);
  entry->code = code;
  if (vendorId)
	entry->vendorName = g_strdup(vendorId);
  else
	entry->vendorName = "None";

  /* Add the entry to the list */
  entry->next = commandListHead;
  commandListHead = entry;

  return 0;
} /* addCommand */

/*
 * This routine will parse the XML command, and add it to our
 * list of commands.
 */
static int
xmlParseCommand(xmlNodePtr cur)
{
  char *name, *code, *vendorIdString;

  /*
   * Get the Attributes
   */
  name = XmlStub.xmlGetProp(cur, "name");
  code = XmlStub.xmlGetProp(cur, "code");
  /*
  g_warning("xmlParseCommand Name: %s code %s",name,code);
  */
  if (!name || !code) {
	report_failure("Invalid command.  Name or code missing!");
	return -1;
  }
  vendorIdString = XmlStub.xmlGetProp(cur, "vendor-id");

  if (!vendorIdString || !strcasecmp(vendorIdString, "None")) {
	vendorIdString = NULL;
  }

  return (addCommand(atoi(code), name, vendorIdString));
} /* xmlParseCommand */

/* This routine adds an application to the name<-> id table */
static int
dictionaryAddApplication(char *name, guint32 id)
{
  ApplicationId *entry;

  if (!name || (id == 0 && !allow_zero_as_app_id)) {
	report_failure( "Diameter Error: Invalid application (name=%s, id=%d)",
			   name, id);
	return (-1);
  } /* Sanity Checks */

  entry = g_malloc(sizeof(ApplicationId));
  if (!entry) {
	report_failure( "Unable to allocate memory");
	return (-1);
  }

  entry->name = g_strdup(name);
  entry->id = id;

  /* Add it to the list */
  entry->next = ApplicationIdHead;
  ApplicationIdHead = entry;

  return 0;
} /* dictionaryAddApplication */

/*
 * This routine will add a vendor to the vendors list
 */
static int
addVendor(int id, const gchar *name, const gchar *longName)
{
  VendorId *vendor;

  /* add entry */
  vendor=g_malloc(sizeof(VendorId));
  if (!vendor) {
	return (-1);
  }

  vendor->id = id;
  vendor->name = g_strdup(name);
  vendor->longName = g_strdup(longName);
  vendor->next = vendorListHead;
  vendorListHead = vendor;

  return 0;
} /* addVendor */

/*
 * This routine will pars in a XML vendor entry.
 */
static int
xmlParseVendor(xmlNodePtr cur)
{
  char *name=NULL, *code=NULL, *id=NULL;

  /* First, get our properties */
  id = XmlStub.xmlGetProp(cur, "vendor-id");
  name = XmlStub.xmlGetProp(cur, "name");
  code = XmlStub.xmlGetProp(cur, "code");

  if (!id || !name || !code) {
	report_failure( "Invalid vendor section.  vendor-id, name, and code must be specified");
	return -1;
  }

  return (addVendor(atoi(code), id, name));

} /* addVendor */

/*
 * This routine will either parse in the base protocol, or an application.
 */
static int
xmlDictionaryParseSegment(xmlNodePtr cur, int base)
{
  if (!base) {
	char *name;
	char *id;

	/* Add our application */
	id = XmlStub.xmlGetProp(cur, "id");
	name = XmlStub.xmlGetProp(cur, "name");

	if (!name || !id) {
	  /* ERROR!!! */
	  report_failure("Diameter: Invalid application!: name=\"%s\", id=\"%s\"",
				name?name:"NULL", id?id:"NULL");
	  return -1;
	}
	/* Add the application */
	if (dictionaryAddApplication(name, (guint32)atol(id)) != 0) {
	  /* ERROR! */
	  return -1;
	}
  }


  /*
   * Get segment values
   */
  cur = cur->xmlChildrenNode;
  while (cur != NULL) {
	if (strcasecmp((const char *)cur->name, "avp") == 0) {
	  /* we have an avp!!! */
	  xmlParseAVP(cur);
	} else if (strcasecmp((const char *)cur->name, "vendor") == 0) {
	  /* we have a vendor */
	  xmlParseVendor(cur);
	  /* For now, ignore typedefn and text */
	} else if (strcasecmp((const char *)cur->name, "command") == 0) {
	  /* Found a command */
	  xmlParseCommand(cur);
	} else if (strcasecmp((const char *)cur->name, "text") == 0) {
	} else if (strcasecmp((const char *)cur->name, "comment") == 0) {
	} else if (strcasecmp((const char *)cur->name, "typedefn") == 0) {
	  /* WORK -- parse in valid types . . . */
	} else {
	  /* IF we got here, we're an error */
	  report_failure("Error!  expecting an avp or a typedefn (got \"%s\")",
				cur->name);
	  return (-1);
	}
	cur = cur->next;
  } /* while */
  return 0;
} /* xmlDictionaryParseSegment */

/*
 * The main xml parse routine.  This will walk through an XML
 * dictionary that has been parsed by libxml.
 */
static int
xmlDictionaryParse(xmlNodePtr cur)
{
  /* We should expect a base protocol, followed by multiple applications */
  while (cur != NULL) {
	if (strcasecmp((const char *)cur->name, "base") == 0) {
	  /* Base protocol.  Descend and parse */
	  xmlDictionaryParseSegment(cur, 1);
	} else if (strcasecmp((const char *)cur->name, "application") == 0) {
	  /* Application.  Descend and parse */
	  xmlDictionaryParseSegment(cur, 0);
	} else if (strcasecmp((const char *)cur->name, "text") == 0) {
	  /* Ignore text */
	} else if (strcasecmp((const char *)cur->name, "comment") == 0) {
	  /* Ignore text */
	} else {
	  report_failure( "Diameter: XML Expecting a base or an application  (got \"%s\")",
				 cur->name);
	  return (-1);
	}
	cur = cur->next;
  }

  return 0;

} /* xmlDictionaryParse */

/*
 * This routine will call libxml to parse in the dictionary.
 */
static int
loadXMLDictionary(void)
{
  xmlDocPtr doc;
  xmlNodePtr cur;

  /*
   * build an XML tree from the file;
   */
  XmlStub.xmlKeepBlanksDefault(0);                    /* Strip leading and trailing blanks */
  XmlStub.xmlSubstituteEntitiesDefault(1);            /* Substitute entities automagically */
  doc = xmlParseFilePush(gbl_diameterDictionary, 1);  /* Parse the XML (do validity checks)*/

  /* Check for invalid xml.
     Note that xmlParseFilePush reports details of problems found,
     and it should be obvious from the default filename that the error relates
     to Diameter.
  */
  if (doc == NULL) {
	return -1;
  }

  /*
   * Check the document is of the right kind
   */
  cur = XmlStub.xmlDocGetRootElement(doc);
  if (cur == NULL) {
	report_failure("Diameter: Error: \"%s\": empty document",
			  gbl_diameterDictionary);
	XmlStub.xmlFreeDoc(doc);
	return -1;
  }
  if (XmlStub.xmlStrcmp(cur->name, (const xmlChar *) "dictionary")) {
	report_failure("Diameter: Error: \"%s\": document of the wrong type, root node != dictionary",
			  gbl_diameterDictionary);
	XmlStub.xmlFreeDoc(doc);
	return -1;
  }

  /*
   * Ok, the dictionary has been parsed by libxml, and is valid.
   * All we have to do now is read in our information.
   */
  if (xmlDictionaryParse(cur->xmlChildrenNode) != 0) {
	/* Error has already been printed */
	return -1;
  }

  /* Once we're done parsing, free up the xml memory */
  XmlStub.xmlFreeDoc(doc);

  return 0;

} /* loadXMLDictionary */

/*
 * Fallback routine.  In the event of ANY error when loading the XML
 * dictionary, this routine will populate the new avp list structures
 * with the old static data from packet-diameter-defs.h
 */
static void
initializeDictionaryDefaults(void)
{
  int i;

  /* Add static vendors to list */
  for(i=0; sminmpec_values[i].strptr; i++) {
	addVendor(sminmpec_values[i].value,
			  sminmpec_values[i].strptr,
			  sminmpec_values[i].strptr);

  }
  /* Add static commands to list. */
  for(i=0; diameter_command_code_vals[i].strptr; i++) {
	addCommand(diameter_command_code_vals[i].value,
			   diameter_command_code_vals[i].strptr, NULL);
  }

  /* Add static AVPs to list */
  for (i=0; old_diameter_avps[i].name; i++) {
	addStaticAVP(old_diameter_avps[i].code,
				 old_diameter_avps[i].name,
				 old_diameter_avps[i].type,
				 old_diameter_avps[i].values);
  }
  /* Add 3GPP AVPs to list */
  for (i=0; ThreeGPP_vendor_diameter_avps[i].name; i++) {
	addVendorAVP(ThreeGPP_vendor_diameter_avps[i].code,
				 ThreeGPP_vendor_diameter_avps[i].name,
				 ThreeGPP_vendor_diameter_avps[i].type,
				 ThreeGPP_vendor_diameter_avps[i].values,
				 VENDOR_THE3GPP);
  }

} /* initializeDictionaryDefaults */

/*
 * This routine will attempt to load the XML dictionary if configured to.
 * Otherwise, or if load fails, it will call initializeDictionaryDefaults
 * to load in our static dictionary instead.
 */
static void
initializeDictionary(void)
{
  /*
   * First, empty the dictionary of any previous contents
   */

  ApplicationId *tmpApplicationId = ApplicationIdHead;
  VendorId      *tmpVendorId = vendorListHead;
  CommandCode   *tmpCommandCode = commandListHead;
  avpInfo       *tmpAvpInfo = avpListHead;

  /* ApplicationId list */
  while (tmpApplicationId != NULL) {
    g_free(tmpApplicationId->name);
    tmpApplicationId = tmpApplicationId->next;
  }
  ApplicationIdHead = NULL;

  /* VendorId list */
  while (tmpVendorId != NULL) {
    g_free(tmpVendorId->name);
    g_free(tmpVendorId->longName);
    tmpVendorId = tmpVendorId->next;
  }
  vendorListHead = NULL;

  /* CommandCode list */
  while (tmpCommandCode != NULL) {
    g_free(tmpCommandCode->name);
    g_free(tmpCommandCode->vendorName);
    tmpCommandCode = tmpCommandCode->next;
  }
  commandListHead = NULL;

  /* avpInfo list */
  while (tmpAvpInfo != NULL) {
    ValueName *valueNamePtr = tmpAvpInfo->values;
    g_free(tmpAvpInfo->name);
    g_free(tmpAvpInfo->vendorName);
    while (valueNamePtr) {
      g_free(valueNamePtr->name);
      valueNamePtr = valueNamePtr->next;
    }
    tmpAvpInfo = tmpAvpInfo->next;
  }
  avpListHead = NULL;


  /*
   * Using ugly ordering here.  If loadLibXML succeeds, then
   * loadXMLDictionary will be called.  This is one of the few times when
   * I think this is prettier than the nested if alternative.
   */
   if (gbl_use_xml_dictionary) {
      if (loadLibXML() || (loadXMLDictionary() != 0)) {
	     /* Something failed.  Use the static dictionary */
	     report_failure("Diameter: Using static dictionary! (Unable to use XML)");
	     initializeDictionaryDefaults();
      }
   }
   else {
      initializeDictionaryDefaults();
   }

} /* initializeDictionary */



/*
 * These routines manipulate the diameter structures.
 */

/* return vendor string, based on the id */
static gchar *
diameter_vendor_to_str(guint32 vendorId, gboolean longName) {
  VendorId *probe;
  gchar *buffer;

  for (probe=vendorListHead; probe; probe=probe->next) {
	if (vendorId == probe->id) {
	  if (longName)
		return probe->longName;
	  else
		return probe->name;
	}
  }

  buffer=ep_alloc(64);
  g_snprintf(buffer, 64, "Vendor 0x%08x", vendorId);
  return buffer;
} /*diameter_vendor_to_str */

/* return command string, based on the code */
static gchar *
diameter_command_to_str(guint32 commandCode, guint32 vendorId)
{
  CommandCode *probe;
  gchar *buffer=NULL;
  gchar *vendorName=NULL;

  switch(gbl_version) {
    case DIAMETER_V16:
      /* In draft-v16 version, command code is depending on vendorID */
  if (vendorId)
	vendorName = diameter_vendor_to_str(vendorId, FALSE);

  for (probe=commandListHead; probe; probe=probe->next) {
	if (commandCode == probe->code) {
	  if (vendorId) {
/* 		g_warning("Command: Comparing \"%s\" to \"%s\"", */
/* 				  vendorName?vendorName:"(null)", */
/* 				  probe->vendorName?probe->vendorName:"(null)"); */
		/* Now check the vendor name */
		if (!strcmp(vendorName, probe->vendorName))
		  /* We found it */
		  return probe->name;
	  } else {
		/* With no vendor id, the Command's entry should be "None" */
		if (!strcmp(probe->vendorName, "None")) {
		  /* We found it */
		  return probe->name;
		}
	  }
	}
  }

  if ( suppress_console_output == FALSE )
	  g_warning("Diameter: Unable to find name for command code 0x%08x, Vendor \"%u\"!",
			commandCode, vendorId);
  buffer=ep_alloc(64);
  g_snprintf(buffer, 64,
		   "Cmd-0x%08x", commandCode);
    break;
    case DIAMETER_RFC:
      /* In RFC3588 version, command code is independant on vendorID */
      for (probe=commandListHead; probe; probe=probe->next) {
        if (commandCode == probe->code) {
          /* We found it */
          return probe->name;
        }
      }
  
    if ( suppress_console_output == FALSE )
          g_warning("Diameter: Unable to find name for command code 0x%08x!",
                        commandCode);
    buffer=ep_alloc(64);
    g_snprintf(buffer, 64,
                   "Cmd-0x%08x", commandCode);
    break;
  }
  return buffer;
}/*diameter_command_to_str */

/* return application string, based on the id */
static gchar *
diameter_app_to_str(guint32 appId) {
  ApplicationId *probe;
  gchar *buffer;

  for (probe=ApplicationIdHead; probe; probe=probe->next) {
    if (appId == probe->id) {
      return probe->name;
    }
  }

  buffer=ep_alloc(64);
  g_snprintf(buffer, 64, "Unknown");
  return buffer;
} /*diameter_app_to_str */

/* return an avp type, based on the code */
static diameterDataType
diameter_avp_get_type(guint32 avpCode, guint32 vendorId){
  avpInfo *probe;
  gchar *vendorName=NULL;

  if (vendorId)
	vendorName = diameter_vendor_to_str(vendorId, FALSE);

  for (probe=avpListHead; probe; probe=probe->next) {
	if (avpCode == probe->code) {

	  if (vendorId) {
/* 		g_warning("AvpType: Comparing \"%s\" to \"%s\"", */
/* 				  vendorName?vendorName:"(null)", */
/* 				  probe->vendorName?probe->vendorName:"(null)"); */
		/* Now check the vendor name */
		if (probe->vendorName && (!strcmp(vendorName, probe->vendorName)))
		  /* We found it! */
		  return probe->type;
	  } else {
		/* No Vendor ID -- vendorName should be null */
		if (!probe->vendorName)
		  /* We found it! */
		  return probe->type;
	  }
	}
  }

  /* If we don't find it, assume it's data */
  if ( suppress_console_output == FALSE )
	  g_warning("Diameter: Unable to find type for avpCode %u, Vendor %u!", avpCode,
			vendorId);
  return DIAMETER_OCTET_STRING;
} /* diameter_avp_get_type */

/* return an avp name from the code */
static gchar *
diameter_avp_get_name(guint32 avpCode, guint32 vendorId)
{
  gchar *buffer;
  avpInfo *probe;
  gchar *vendorName=NULL;

  if (vendorId)
	vendorName = diameter_vendor_to_str(vendorId, FALSE);

  for (probe=avpListHead; probe; probe=probe->next) {
	if (avpCode == probe->code) {
	  if (vendorId) {
/* 		g_warning("AvpName: Comparing \"%s\" to \"%s\"", */
/* 				  vendorName?vendorName:"(null)", */
/* 				  probe->vendorName?probe->vendorName:"(null)"); */
		/* Now check the vendor name */
		if (probe->vendorName && (!strcmp(vendorName, probe->vendorName)))
		  /* We found it! */
		  return probe->name;
	  } else {
		/* No Vendor ID -- vendorName should be null */
		if (!probe->vendorName)
		  /* We found it! */
		  return probe->name;
	  }
	}
  }
  if ( suppress_console_output == FALSE )
	  g_warning("Diameter: Unable to find name for AVP 0x%08x, Vendor %u!",
			avpCode, vendorId);

  /* If we don't find it, build a name string */
  buffer=ep_alloc(64);
  g_snprintf(buffer, 64, "Unknown AVP:0x%08x", avpCode);
  return buffer;
} /* diameter_avp_get_name */
static const gchar *
diameter_avp_get_value(guint32 avpCode, guint32 vendorId, guint32 avpValue)
{
  avpInfo *probe;
  gchar *vendorName=NULL;

  if (vendorId)
	vendorName = diameter_vendor_to_str(vendorId, FALSE);

  for (probe=avpListHead; probe; probe=probe->next) {
	if (avpCode == probe->code) {
	  if (vendorId) {
/* 		g_warning("AvpValue: Comparing \"%s\" to \"%s\"", */
/* 				  vendorName?vendorName:"(null)", */
/* 				  probe->vendorName?probe->vendorName:"(null)"); */
		/* Now check the vendor name */
		if (probe->vendorName && (!strcmp(vendorName, probe->vendorName))) {
		  ValueName *vprobe;
		  for(vprobe=probe->values; vprobe; vprobe=vprobe->next) {
			if (avpValue == vprobe->value) {
			  return vprobe->name;
			}
		  }
		  return "(Unknown value)";
		}
	  } else {
		if (!probe->vendorName) {
		  ValueName *vprobe;
		  for(vprobe=probe->values; vprobe; vprobe=vprobe->next) {
			if (avpValue == vprobe->value) {
			  return vprobe->name;
			}
		  }
		  return "(Unknown value)";
		}
	  }
	}
  }
  /* We didn't find the avp */
  return "(Unknown AVP)";
} /* diameter_avp_get_value */


/* Code to actually dissect the packets */

static gboolean
check_diameter(tvbuff_t *tvb)
{
  if (!tvb_bytes_exist(tvb, 0, 1))
	return FALSE;	/* not enough bytes to check the version */
  if (tvb_get_guint8(tvb, 0) != 1)
	return FALSE;	/* not version 1 */

  /* XXX - fetch length and make sure it's at least MIN_DIAMETER_SIZE?
     Fetch flags and check that none of the DIAM_FLAGS_RESERVED bits
     are set? */
  return TRUE;
}

/*
 * Main dissector
 */
static void
dissect_diameter_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item      *ti;
  proto_item      *tf;
  proto_tree      *flags_tree;
  tvbuff_t        *avp_tvb;
  proto_tree      *diameter_tree;
  e_diameterhdr_v16   dh;
  e_diameterhdr_rfc   dh2;
  int              offset=0;
  size_t           avplength=0;
  proto_tree      *avp_tree;
  proto_item      *avptf;
  int              BadPacket = FALSE;
  guint32          commandCode=0, pktLength=0;
  guint8           version=0, flags=0;
  gchar            *flagstr="<None>";
  const gchar     *fstr[] = {"RSVD7", "RSVD6", "RSVD5", "RSVD4", "RSVD3", "Error", "Proxyable", "Request" };
  gchar            *commandString=NULL, *vendorName=NULL, *applicationName=NULL, *commandStringType=NULL;
  gint        i;
  guint      bpos;
  static  int initialized=FALSE;

  /* Keep track of preference settings affecting dictionary source */
  static  gboolean previous_use_xml_dictionary=FALSE;
  #define MAX_DICT_NAME_SIZE 256
  static  gchar    previous_diameterDictionary[MAX_DICT_NAME_SIZE];

  /*
   * Only parse in dictionary if there are diameter packets to
   * dissect.
   * Keeps track of preference settings and frees/reinitializes the
   * dictionary when appropriate.
   */
  if (!initialized ||
      (gbl_use_xml_dictionary != previous_use_xml_dictionary) ||
      (strncmp(gbl_diameterDictionary,
               previous_diameterDictionary,
               MAX_DICT_NAME_SIZE) != 0)) {
      /* Populate dictionary according to preferences */
      initializeDictionary();
      initialized=TRUE;

      /* Record current preference settings */
      previous_use_xml_dictionary = gbl_use_xml_dictionary;
      strncpy(previous_diameterDictionary, gbl_diameterDictionary, MAX_DICT_NAME_SIZE);
  }

  /* Make entries in Protocol column and Info column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Diameter");
  if (check_col(pinfo->cinfo, COL_INFO))
	col_clear(pinfo->cinfo, COL_INFO);

  /* Copy our header */
  switch(gbl_version) {
    case DIAMETER_V16:
  tvb_memcpy(tvb, (guint8*) &dh, offset, sizeof(dh));
  /* Fix byte ordering in our static structure */
  dh.versionLength = g_ntohl(dh.versionLength);
  dh.flagsCmdCode = g_ntohl(dh.flagsCmdCode);
  dh.vendorId = g_ntohl(dh.vendorId);
  dh.hopByHopId = g_ntohl(dh.hopByHopId);
  dh.endToEndId = g_ntohl(dh.endToEndId);
  if (dh.vendorId) {
	vendorName=diameter_vendor_to_str(dh.vendorId, TRUE);
  } else {
	vendorName="None";
  }
  /* Do the bit twiddling */
  version = DIAM_GET_VERSION(dh);
  pktLength = DIAM_GET_LENGTH(dh);
  flags = DIAM_GET_FLAGS(dh);
  commandCode = DIAM_GET_COMMAND(dh);
    break;
    case DIAMETER_RFC:
      tvb_memcpy(tvb, (guint8*) &dh2, offset, sizeof(dh2));
      /* Fix byte ordering in our static structure */
      dh2.versionLength = g_ntohl(dh2.versionLength);
      dh2.flagsCmdCode = g_ntohl(dh2.flagsCmdCode);
      dh2.applicationId = g_ntohl(dh2.applicationId);
      dh2.hopByHopId = g_ntohl(dh2.hopByHopId);
      dh2.endToEndId = g_ntohl(dh2.endToEndId);
      if (dh2.applicationId) {
        applicationName=diameter_app_to_str(dh2.applicationId);
        /* If not found, it might be a vendor ID? */
        if (strcmp(applicationName, "Unknown") == 0){
          applicationName=diameter_vendor_to_str(dh2.applicationId,FALSE);
        }
      } else {
        applicationName="None";
      }
      /* Do the bit twiddling */
      version = DIAM_GET_VERSION(dh2);
      pktLength = DIAM_GET_LENGTH(dh2);
      flags = DIAM_GET_FLAGS(dh2);
      commandCode = DIAM_GET_COMMAND(dh2);
    break;
  }


  /* Set up our flags */
  if (check_col(pinfo->cinfo, COL_INFO) || tree) {
	int fslen;

#define FLAG_STR_LEN 64
	flagstr=ep_alloc(FLAG_STR_LEN);
	flagstr[0]=0;
	fslen=0;
	for (i = 0; i < 8; i++) {
	  bpos = 1 << i;
	  if (flags & bpos) {
		if (flagstr[0]) {
		  fslen+=MIN(FLAG_STR_LEN-fslen,
			     g_snprintf(flagstr+fslen, FLAG_STR_LEN-fslen, ", "));
		}
		fslen+=MIN(FLAG_STR_LEN-fslen,
			   g_snprintf(flagstr+fslen, FLAG_STR_LEN-fslen, "%s", fstr[i]));
	  }
	}
	if (flagstr[0] == 0) {
	  flagstr="<None>";
	}
  }

  /* Set up our commandString */
  switch(gbl_version) {
    case DIAMETER_V16:
      commandString=diameter_command_to_str(commandCode, dh.vendorId);
    break;
    case DIAMETER_RFC:
      /* FIXME: in RFC, is applicationID needed to decode the command code?  */
      commandString=diameter_command_to_str(commandCode, dh2.applicationId);
    break;
  }

  if (flags & DIAM_FLAGS_R)
	commandStringType="Request";
  else
	commandStringType="Answer";

  /* Short packet.  Should have at LEAST one avp */
  if (pktLength < MIN_DIAMETER_SIZE) {
	  if ( suppress_console_output == FALSE )
		  g_warning("Diameter: Packet too short: %u bytes less than min size (%lu bytes))",
			  pktLength, (unsigned long)MIN_DIAMETER_SIZE);
	  BadPacket = TRUE;
  }

  /* And, check our reserved flags/version */
  if ((flags & DIAM_FLAGS_RESERVED) ||
	  (version != 1)) {
	  if ( suppress_console_output == FALSE )
		  g_warning("Diameter: Bad packet: Bad Flags(0x%x) or Version(%u)",
			  flags, version);
	  BadPacket = TRUE;
  }

  if (check_col(pinfo->cinfo, COL_INFO)) {
    switch(gbl_version) {
      case DIAMETER_V16:
        col_add_fstr(pinfo->cinfo, COL_INFO,
                     "%s%s%s%s%s-%s vendor=%s (hop-id=%u) (end-id=%u) RPE=%d%d%d",
                     (BadPacket)?"***** Bad Packet!: ":"",
                     (flags & DIAM_FLAGS_P)?"Proxyable ":"",
                     (flags & DIAM_FLAGS_E)?" Error":"",
                     ((BadPacket ||
                       (flags & (DIAM_FLAGS_P|DIAM_FLAGS_E))) ?
                       ": " : ""),
                     commandString, commandStringType, vendorName,
                     dh.hopByHopId, dh.endToEndId,
                     (flags & DIAM_FLAGS_R)?1:0,
                     (flags & DIAM_FLAGS_P)?1:0,
                     (flags & DIAM_FLAGS_E)?1:0);
      break;
      case DIAMETER_RFC:
        col_add_fstr(pinfo->cinfo, COL_INFO,
                     "%s%s%s%s%s-%s app=%s (hop-id=%u) (end-id=%u) RPE=%d%d%d",
                     (BadPacket)?"***** Bad Packet!: ":"",
                     (flags & DIAM_FLAGS_P)?"Proxyable ":"",
                     (flags & DIAM_FLAGS_E)?" Error":"",
                     ((BadPacket ||
                       (flags & (DIAM_FLAGS_P|DIAM_FLAGS_E))) ?
                       ": " : ""),
                     commandString, commandStringType, applicationName,
                     dh2.hopByHopId, dh2.endToEndId,
                     (flags & DIAM_FLAGS_R)?1:0,
                     (flags & DIAM_FLAGS_P)?1:0,
                     (flags & DIAM_FLAGS_E)?1:0);
      break;
    }
  }


  /* In the interest of speed, if "tree" is NULL, don't do any work not
	 necessary to generate protocol tree items. */
  if (tree) {

	/* create display subtree for the protocol */
	ti = proto_tree_add_item(tree, proto_diameter, tvb, offset,
							 MAX(pktLength,MIN_DIAMETER_SIZE), FALSE);
	diameter_tree = proto_item_add_subtree(ti, ett_diameter);

	/* Version */
	proto_tree_add_uint(diameter_tree,
						hf_diameter_version,
						tvb, offset, 1,
						version);

	offset+=1;

	/* Length */
	proto_tree_add_uint(diameter_tree,
						hf_diameter_length, tvb,
						offset, 3, pktLength);
	offset += 3;

	/* Flags */
	tf = proto_tree_add_uint_format_value(diameter_tree, hf_diameter_flags, tvb,
					      offset, 1, flags, "0x%02x (%s)", flags,
					      flagstr);
	flags_tree = proto_item_add_subtree(tf, ett_diameter_avp_flags);
	proto_tree_add_boolean(flags_tree, hf_diameter_flags_request, tvb, offset, 1, flags);
	proto_tree_add_boolean(flags_tree, hf_diameter_flags_proxyable, tvb, offset, 1, flags);
	proto_tree_add_boolean(flags_tree, hf_diameter_flags_error, tvb, offset, 1, flags);
	proto_tree_add_boolean(flags_tree, hf_diameter_flags_T, tvb, offset, 1, flags);
	proto_tree_add_boolean(flags_tree, hf_diameter_flags_reserved4, tvb, offset, 1, flags);
	proto_tree_add_boolean(flags_tree, hf_diameter_flags_reserved5, tvb, offset, 1, flags);
	proto_tree_add_boolean(flags_tree, hf_diameter_flags_reserved6, tvb, offset, 1, flags);
	proto_tree_add_boolean(flags_tree, hf_diameter_flags_reserved7, tvb, offset, 1, flags);

	offset += 1;

	/* Command Code */
	proto_tree_add_uint_format_value(diameter_tree, hf_diameter_code,
	                                 tvb, offset, 3, commandCode, "%s-%s (%d)",
	                                 commandString, commandStringType, commandCode);
	offset += 3;

        switch(gbl_version) {
          case DIAMETER_V16:

			/* Vendor Id */
			proto_tree_add_item(diameter_tree, hf_diameter_vendor_id, tvb, offset, 4, FALSE);
			offset += 4;
			/* Hop-by-hop Identifier */
			proto_tree_add_uint(diameter_tree, hf_diameter_hopbyhopid,
						tvb, offset, 4, dh.hopByHopId);
			offset += 4;
			/* End-to-end Identifier */
			proto_tree_add_uint(diameter_tree, hf_diameter_endtoendid,
						tvb, offset, 4, dh.endToEndId);
			offset += 4;
			break;
          case DIAMETER_RFC:
		    /* Application Id */
			proto_tree_add_item(diameter_tree, hf_diameter_application_id, tvb, offset, 4, FALSE);
		    offset += 4;
		    /* Hop-by-hop Identifier */
		    proto_tree_add_uint(diameter_tree, hf_diameter_hopbyhopid,
						tvb, offset, 4, dh2.hopByHopId);
		    offset += 4;
		    /* End-to-end Identifier */
		    proto_tree_add_uint(diameter_tree, hf_diameter_endtoendid,
						tvb, offset, 4, dh2.endToEndId);
		    offset += 4;
	          break;
        }


	/* If we have a bad packet, don't bother trying to parse the AVPs */
	if (BadPacket) {
	  return;
	}

	/* Start looking at the AVPS */
	/* Make the next tvbuff */

	/* Update the lengths */
        switch(gbl_version) {
          case DIAMETER_V16:
	    avplength= pktLength - sizeof(e_diameterhdr_v16);
	  break;
	  case DIAMETER_RFC:
	    avplength= pktLength - sizeof(e_diameterhdr_rfc);
	  break;
	}

	avp_tvb = tvb_new_subset(tvb, offset, avplength, avplength);
	avptf = proto_tree_add_text(diameter_tree,
								tvb, offset, avplength,
								"Attribute Value Pairs");

	avp_tree = proto_item_add_subtree(avptf,
									  ett_diameter_avp);
	if (avp_tree != NULL) {
	  dissect_avps( avp_tvb, pinfo, avp_tree);
	}
	return;
  }
} /* dissect_diameter_common */


static guint
get_diameter_pdu_len(tvbuff_t *tvb, int offset)
{
  /* Get the length of the Diameter packet. */
  return tvb_get_ntoh24(tvb, offset + 1);
}

static int
dissect_diameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  if (!check_diameter(tvb))
	return 0;
  dissect_diameter_common(tvb, pinfo, tree);
  return tvb_length(tvb);
}

static void
dissect_diameter_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tcp_dissect_pdus(tvb, pinfo, tree, gbl_diameter_desegment, 4,
	get_diameter_pdu_len, dissect_diameter_common);
} /* dissect_diameter_tcp */

/*
 * Call the mip_dissector, after saving our pinfo variables
 * so it doesn't write to our column display.
 */
static void
safe_dissect_mip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
				 size_t offset, size_t length)
{
  static dissector_handle_t mip_handle;
  static int mipInitialized=FALSE;
  tvbuff_t *mip_tvb;
  address save_dl_src;
  address save_dl_dst;
  address save_net_src;
  address save_net_dst;
  address save_src;
  address save_dst;
  gboolean save_in_error_pkt;

  if (!mipInitialized) {
	mip_handle = find_dissector("mip");
	mipInitialized=TRUE;
  }

  mip_tvb = tvb_new_subset(tvb, offset,
						   MIN(length, tvb_length(tvb)-offset),
						   length);

  /* The contained packet is a MIP registration request;
	 dissect it with the MIP dissector. */
  col_set_writable(pinfo->cinfo, FALSE);

  /* Also, save the current values of the addresses, and restore
	 them when we're finished dissecting the contained packet, so
	 that the address columns in the summary don't reflect the
	 contained packet, but reflect this packet instead. */
  save_dl_src = pinfo->dl_src;
  save_dl_dst = pinfo->dl_dst;
  save_net_src = pinfo->net_src;
  save_net_dst = pinfo->net_dst;
  save_src = pinfo->src;
  save_dst = pinfo->dst;
  save_in_error_pkt = pinfo->in_error_pkt;

  call_dissector(mip_handle, mip_tvb, pinfo, tree);

  /* Restore the "we're inside an error packet" flag. */
  pinfo->in_error_pkt = save_in_error_pkt;
  pinfo->dl_src = save_dl_src;
  pinfo->dl_dst = save_dl_dst;
  pinfo->net_src = save_net_src;
  pinfo->net_dst = save_net_dst;
  pinfo->src = save_src;
  pinfo->dst = save_dst;


} /* safe_dissect_mip */

/*
 * This function will dissect the AVPs in a diameter packet.  It handles
 * all normal types, and even recursively calls itself for grouped AVPs
 */
static void dissect_avps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *avp_tree)
{
  /* adds the attribute value pairs to the tree */
  e_avphdr avph;
  const gchar *avpTypeString;
  const gchar *avpNameString;
  const gchar *valstr;
  guint32 vendorId=0;
  gchar    *vendorName;
  int hdrLength;
  int fixAmt;
  proto_tree *avpi_tree;
  size_t offset = 0;
  tvbuff_t        *group_tvb;
  proto_tree *group_tree;
  proto_item *grouptf;
  proto_item *avptf;
  char *buffer;
  int BadPacket = FALSE;
  guint32 avpLength;
  guint8 flags;
  proto_item      *tf;
  proto_tree      *flags_tree;

  gint32 packetLength;
  size_t avpDataLength;
  int avpType;
  gchar *flagstr="<None>";
  const gchar *fstr[] = {"RSVD7", "RSVD6", "RSVD5", "RSVD4", "RSVD3", "Protected", "Mandatory", "Vendor-Specific" };
  gint        i;
  guint      bpos;

  packetLength = tvb_length(tvb);

  /* Check for invalid packet lengths */
  if (packetLength <= 0) {
	proto_tree_add_text(avp_tree, tvb, offset, tvb_length(tvb),
						"No Attribute Value Pairs Found");
	return;
  }

  /* Spin around until we run out of packet */
  while (packetLength > 0 ) {

	/* Check for short packet */
	if (packetLength < (long)MIN_AVP_SIZE) {
		if ( suppress_console_output == FALSE )
			g_warning("Diameter: AVP Payload too short: %d bytes less than min size (%ld bytes))",
				packetLength, (long)MIN_AVP_SIZE);
		BadPacket = TRUE;
	  /* Don't even bother trying to parse a short packet. */
	  return;
	}

	/* Copy our header */
	tvb_memcpy(tvb, (guint8*) &avph, offset, MIN((long)sizeof(avph),packetLength));

	/* Fix the byte ordering */
	avph.avp_code = g_ntohl(avph.avp_code);
	avph.avp_flagsLength = g_ntohl(avph.avp_flagsLength);

	flags = (avph.avp_flagsLength & 0xff000000) >> 24;
	avpLength = avph.avp_flagsLength & 0x00ffffff;

	/* Set up our flags string */
	if (check_col(pinfo->cinfo, COL_INFO) || avp_tree) {
	  int fslen;

#define FLAG_STR_LEN 64
	  flagstr=ep_alloc(FLAG_STR_LEN);
	  flagstr[0]=0;
	  fslen=0;
	  for (i = 0; i < 8; i++) {
		bpos = 1 << i;
		if (flags & bpos) {
		  if (flagstr[0]) {
			fslen+=MIN(FLAG_STR_LEN-fslen,
				   g_snprintf(flagstr+fslen, FLAG_STR_LEN-fslen, ", "));
		  }
		  fslen+=MIN(FLAG_STR_LEN-fslen,
			     g_snprintf(flagstr+fslen, FLAG_STR_LEN-fslen, "%s", fstr[i]));
		}
	  }
	  if (flagstr[0] == 0) {
		flagstr="<None>";
	  }
	}

	/* Dissect our vendor id if it exists  and set hdr length */
	if (flags & AVP_FLAGS_V) {
	  vendorId = g_ntohl(avph.avp_vendorId);
	  /* Vendor id */
	  hdrLength = sizeof(e_avphdr);
	} else {
	  /* No vendor */
	  hdrLength = sizeof(e_avphdr) -
		sizeof(guint32);
	  vendorId = 0;
	}

	if (vendorId) {
	  vendorName=diameter_vendor_to_str(vendorId, TRUE);
	} else {
	  vendorName="";
	}

	/* Check for bad length */
	if (avpLength < MIN_AVP_SIZE ||
		((long)avpLength > packetLength)) {
		if ( suppress_console_output == FALSE )
			g_warning("Diameter: AVP payload size invalid: avp_length: %ld bytes,  "
				"min: %ld bytes,    packetLen: %d",
				(long)avpLength, (long)MIN_AVP_SIZE,
				packetLength);
		BadPacket = TRUE;
	}

	/* Check for bad flags */
	if (flags & AVP_FLAGS_RESERVED) {
		if ( suppress_console_output == FALSE )
			g_warning("Diameter: Invalid AVP: Reserved bit set.  flags = 0x%x,"
				" resFl=0x%x",
				flags, AVP_FLAGS_RESERVED);
	  /* For now, don't set bad packet, since I'm accidentally setting a wrong bit 
	   BadPacket = TRUE; 
	   */
	}

	/*
	 * Compute amount of byte-alignment fix (Diameter AVPs are sent on 4 byte
	 * boundries)
	 */
	fixAmt = 4 - (avpLength % 4);
	if (fixAmt == 4) fixAmt = 0;

	/* shrink our packetLength */
	packetLength = packetLength - (avpLength + fixAmt);

	/* Check for out of bounds */
	if (packetLength < 0) {
		if ( suppress_console_output == FALSE )
			g_warning("Diameter: Bad AVP: Bad new length (%d bytes) ",
				packetLength);
		BadPacket = TRUE;
	}

	/* Make avp Name & type */
	avpTypeString=val_to_str(diameter_avp_get_type(avph.avp_code,vendorId),
									 TypeValues,
									 "Unknown-Type: 0x%08x");
	avpNameString=diameter_avp_get_name(avph.avp_code, vendorId);

	avptf = proto_tree_add_text(avp_tree, tvb,
								offset, avpLength + fixAmt,
								"%s (%s) l:0x%x (%d bytes) (%d padded bytes)",
								avpNameString, avpTypeString, avpLength,
								avpLength, avpLength+fixAmt);
	avpi_tree = proto_item_add_subtree(avptf,
									   ett_diameter_avpinfo);

	if (avpi_tree !=NULL) {
	  /* Command Code */
	  proto_tree_add_uint_format_value(avpi_tree, hf_diameter_avp_code,
					   tvb, offset, 4, avph.avp_code, "%s (%u)", avpNameString,avph.avp_code);
	  offset += 4;

	  tf = proto_tree_add_uint_format_value(avpi_tree, hf_diameter_avp_flags, tvb,
						offset, 1, flags, "0x%02x (%s)", flags,
						flagstr);
	  flags_tree = proto_item_add_subtree(tf, ett_diameter_avp_flags);
	  proto_tree_add_boolean(flags_tree, hf_diameter_avp_flags_vendor_specific, tvb, offset, 1, flags);
	  proto_tree_add_boolean(flags_tree, hf_diameter_avp_flags_mandatory, tvb, offset, 1, flags);
	  proto_tree_add_boolean(flags_tree, hf_diameter_avp_flags_protected, tvb, offset, 1, flags);
	  proto_tree_add_boolean(flags_tree, hf_diameter_avp_flags_reserved3,  tvb, offset, 1, flags);
	  proto_tree_add_boolean(flags_tree, hf_diameter_avp_flags_reserved4,  tvb, offset, 1, flags);
	  proto_tree_add_boolean(flags_tree, hf_diameter_avp_flags_reserved5,  tvb, offset, 1, flags);
	  proto_tree_add_boolean(flags_tree, hf_diameter_avp_flags_reserved6,  tvb, offset, 1, flags);
	  proto_tree_add_boolean(flags_tree, hf_diameter_avp_flags_reserved7,  tvb, offset, 1, flags);
	  offset += 1;

	  proto_tree_add_uint(avpi_tree, hf_diameter_avp_length,
						  tvb, offset, 3, avpLength);
	  offset += 3;

	  if (flags & AVP_FLAGS_V) {
		proto_tree_add_uint_format_value(avpi_tree, hf_diameter_avp_vendor_id,
						 tvb, offset, 4, vendorId, "%s", vendorName);
		offset += 4;
	  }

	  avpDataLength = avpLength - hdrLength;

	  /*
	   * If we've got a bad packet, just highlight the data.  Don't try
	   * to parse it, and, don't move to next AVP.
	   */
	  if (BadPacket) {
		offset -= hdrLength;
		proto_tree_add_bytes_format(avpi_tree, hf_diameter_avp_data_bytes,
					tvb, offset, tvb_length(tvb) - offset,
					tvb_get_ptr(tvb, offset, tvb_length(tvb) - offset),
					"Bad AVP (Suspect Data Not Dissected)");
		return;
	  }

	  avpType=diameter_avp_get_type(avph.avp_code,vendorId);

	  switch(avpType) {
	  case DIAMETER_GROUPED:
		buffer=ep_alloc(256);
		g_snprintf(buffer, 256, "%s Grouped AVPs", avpNameString);
		/* Recursively call ourselves */
		grouptf = proto_tree_add_text(avpi_tree,
									  tvb, offset, tvb_length(tvb),
									  buffer);

		group_tree = proto_item_add_subtree(grouptf,
											ett_diameter_avp);

		group_tvb = tvb_new_subset(tvb, offset,
								   MIN(avpDataLength, tvb_length(tvb)-offset), avpDataLength);
		if (group_tree != NULL) {
		  dissect_avps( group_tvb, pinfo, group_tree);
		}
		break;

	  case DIAMETER_IDENTITY:
		{
		  const guint8 *data;

		  data = tvb_get_ptr(tvb, offset, avpDataLength);
		  proto_tree_add_string_format(avpi_tree, hf_diameter_avp_data_string,
				               tvb, offset, avpDataLength, data,
					       "Identity: %*.*s",
					       (int)avpDataLength,
					       (int)avpDataLength, data);
		}
		break;
	  case DIAMETER_UTF8STRING:
		{
		  const guint8 *data;

		  data = tvb_get_ptr(tvb, offset, avpDataLength);
		  proto_tree_add_string_format(avpi_tree, hf_diameter_avp_data_string,
					       tvb, offset, avpDataLength, data,
					       "UTF8String: %*.*s",
					       (int)avpDataLength,
					       (int)avpDataLength, data);
		}
		break;
	  case DIAMETER_IP_ADDRESS:
    {
      switch(gbl_version) {
        case DIAMETER_V16:
		if (avpDataLength == 4) {
		  proto_tree_add_item(avpi_tree, hf_diameter_avp_data_v4addr,
				      tvb, offset, avpDataLength, FALSE);
		} else if (avpDataLength == 16) {
		  proto_tree_add_item(avpi_tree, hf_diameter_avp_data_v6addr,
				      tvb, offset, avpDataLength, FALSE);
		} else {
		  proto_tree_add_bytes_format(avpi_tree, hf_diameter_avp_data_bytes,
					      tvb, offset, avpDataLength,
					      tvb_get_ptr(tvb, offset, avpDataLength),
                  "Error! Bad Address Length (Address in RFC3588 format?)");
          }
          break;
        case DIAMETER_RFC:
          /* Indicate the address family */
          proto_tree_add_item(avpi_tree, hf_diameter_avp_data_addrfamily,
              tvb, offset, 2, FALSE);
          if (tvb_get_ntohs(tvb, offset) == 0x0001) {
            proto_tree_add_item(avpi_tree, hf_diameter_avp_data_v4addr,
                    tvb, offset+2, avpDataLength-2, FALSE);
          } else if (tvb_get_ntohs(tvb, offset) == 0x0002) {
            proto_tree_add_item(avpi_tree, hf_diameter_avp_data_v6addr,
                    tvb, offset+2, avpDataLength-2, FALSE);
          } else {
            proto_tree_add_bytes_format(avpi_tree, hf_diameter_avp_data_bytes,
                    tvb, offset, avpDataLength,
                    tvb_get_ptr(tvb, offset, avpDataLength),
                    "Error! Can't Parse Address Family %d (Address in draft v16 format?)",
                    (int)tvb_get_ntohs(tvb, offset));
          }
          break;
      }
		}
		break;

	  case DIAMETER_INTEGER32:
		if (avpDataLength == 4) {
		  proto_tree_add_item(avpi_tree, hf_diameter_avp_data_int32,
				      tvb, offset, avpDataLength, FALSE);
		} else {
		  proto_tree_add_bytes_format(avpi_tree, hf_diameter_avp_data_bytes,
					      tvb, offset, avpDataLength,
					      tvb_get_ptr(tvb, offset, avpDataLength),
					      "Error!  Bad Integer32 Length");
		}
		break;

	  case DIAMETER_UNSIGNED32:
		if (avpDataLength == 4) {
		  guint32 data;

		  data = tvb_get_ntohl(tvb, offset);
		  proto_tree_add_uint_format(avpi_tree, hf_diameter_avp_data_uint32,
					     tvb, offset, avpDataLength, data,
					     "Value: 0x%08x (%u)", data, data);
		} else {
		  proto_tree_add_bytes_format(avpi_tree, hf_diameter_avp_data_bytes,
					      tvb, offset, avpDataLength,
					      tvb_get_ptr(tvb, offset, avpDataLength),
					      "Error!  Bad Unsigned32 Length");
		}
		break;

	  case DIAMETER_UNSIGNED32ENUM:
		if (avpDataLength == 4) {
		  guint32 data;

		  data = tvb_get_ntohl(tvb, offset);
		  valstr = diameter_avp_get_value(avph.avp_code, vendorId, data);
		  proto_tree_add_uint_format(avpi_tree, hf_diameter_avp_data_uint32,
					     tvb, offset, avpDataLength, data,
					     "Value: 0x%08x (%u): %s", data,
					     data, valstr);
		} else {
		  proto_tree_add_bytes_format(avpi_tree, hf_diameter_avp_data_bytes,
					      tvb, offset, avpDataLength,
					      tvb_get_ptr(tvb, offset, avpDataLength),
					      "Error!  Bad Enumerated Length");
		}
		break;

	  case DIAMETER_INTEGER64:
		if (avpDataLength == 8) {
		  proto_tree_add_item(avpi_tree, hf_diameter_avp_data_int64,
				      tvb, offset, 8, FALSE);
		} else {
		  proto_tree_add_bytes_format(avpi_tree, hf_diameter_avp_data_bytes,
					      tvb, offset, avpDataLength,
					      tvb_get_ptr(tvb, offset, avpDataLength),
					      "Error!  Bad Integer64 Length");
		}
		break;

	  case DIAMETER_UNSIGNED64:
		if (avpDataLength == 8) {
		  proto_tree_add_item(avpi_tree, hf_diameter_avp_data_uint64,
				      tvb, offset, 8, FALSE);
		} else {
		  proto_tree_add_bytes_format(avpi_tree, hf_diameter_avp_data_bytes,
					      tvb, offset, avpDataLength,
					      tvb_get_ptr(tvb, offset, avpDataLength),
					      "Error!  Bad Unsigned64 Length");
		}
		break;

	  case DIAMETER_TIME:
		if (avpDataLength == 4) {
		  nstime_t data;
		  struct tm *gmtp;

		  data.secs = tvb_get_ntohl(tvb, offset);
		  /* Present the time as UTC, Time before 00:00:00 UTC, January 1, 1970 can't be presented correctly  */
			if ( data.secs >= NTP_TIME_DIFF){
				data.secs -= NTP_TIME_DIFF;
				data.nsecs = 0;

				gmtp = gmtime(&data.secs);
				buffer=ep_alloc(64);
				strftime(buffer, 64,
				"%a, %d %b %Y %H:%M:%S UTC", gmtp);

				proto_tree_add_time_format(avpi_tree, hf_diameter_avp_data_time,
						tvb, offset, avpDataLength, &data,
						"Time: %s", buffer);
			}else{
				proto_tree_add_bytes_format(avpi_tree, hf_diameter_avp_data_bytes,
						tvb, offset, avpDataLength,
						tvb_get_ptr(tvb, offset, avpDataLength),
						"Error!  Time before 00:00:00 UTC, January 1, 1970");
			}
		} else {
		  proto_tree_add_bytes_format(avpi_tree, hf_diameter_avp_data_bytes,
					      tvb, offset, avpDataLength,
					      tvb_get_ptr(tvb, offset, avpDataLength),
					      "Error!  Bad Time Length");
		}
		break;

	  case DIAMETER_ENUMERATED:
		if (avpDataLength == 4) {
		  guint32 data;

		  data = tvb_get_ntohl(tvb, offset);
		  valstr = diameter_avp_get_value(avph.avp_code, vendorId, data);
		  proto_tree_add_uint_format(avpi_tree, hf_diameter_avp_data_uint32,
					     tvb, offset, avpDataLength, data,
					     "Value: 0x%08x (%u): %s", data,
					     data, valstr);
		} else {
		  proto_tree_add_bytes_format(avpi_tree, hf_diameter_avp_data_bytes,
					      tvb, offset, avpDataLength,
					      tvb_get_ptr(tvb, offset, avpDataLength),
					      "Error!  Bad Enumerated Length");
		}
		break;

	  case DIAMETER_VENDOR_ID:
		if (avpDataLength == 4) {
		  proto_tree_add_item(avpi_tree, hf_diameter_vendor_id, tvb, offset, avpDataLength, FALSE);
		} else {
		  proto_tree_add_bytes_format(avpi_tree, hf_diameter_avp_data_bytes,
					      tvb, offset, avpDataLength,
					      tvb_get_ptr(tvb, offset, avpDataLength),
					      "Error!  Bad Vendor ID Length");
		}
		break;

	  case DIAMETER_APPLICATION_ID:
		if (avpDataLength == 4) {
		  guint32 data;

		  data = tvb_get_ntohl(tvb, offset);
		  valstr = diameter_app_to_str(data);
		  proto_tree_add_uint_format(avpi_tree, hf_diameter_avp_data_uint32,
					     tvb, offset, avpDataLength, data,
					     "Application ID: %s %d (0x%08x)",
					     valstr, data, data);
		} else {
		  proto_tree_add_bytes_format(avpi_tree, hf_diameter_avp_data_bytes,
					      tvb, offset, avpDataLength,
					      tvb_get_ptr(tvb, offset, avpDataLength),
					      "Error!  Bad Application ID Length");
		}
		break;

	  case DIAMETER_MIP_REG_REQ:
		safe_dissect_mip(tvb, pinfo, avpi_tree, offset, avpDataLength);
		break;

	  case DIAMETER_URI:
		proto_tree_add_item(avpi_tree, hf_diameter_avp_diameter_uri,
				    tvb, offset, avpDataLength, FALSE);
		  break;

	  case DIAMETER_SESSION_ID:
		proto_tree_add_item(avpi_tree, hf_diameter_avp_session_id,
				    tvb, offset, avpDataLength, FALSE);
		break;

	  case DIAMETER_PUBLIC_ID:
		  {
		proto_tree_add_item(avpi_tree, hf_diameter_avp_public_id,
				    tvb, offset, avpDataLength, FALSE);
		  /* This is a SIP address, to be able to filter the SIP messages
		   * belonging to this Diameter session add this to the SIP filter.
		   */
		dfilter_store_sip_from_addr(tvb, avpi_tree, offset, avpDataLength);
		  }
		break;
	  case DIAMETER_PRIVATE_ID:
		  {
		proto_tree_add_item(avpi_tree, hf_diameter_avp_private_id,
				    tvb, offset, avpDataLength, FALSE);
		  }

	  default:
	  case DIAMETER_OCTET_STRING:
		proto_tree_add_bytes_format(avpi_tree, hf_diameter_avp_data_bytes,
					    tvb, offset, avpDataLength,
					    tvb_get_ptr(tvb, offset, avpDataLength),
					   "Hex Data Highlighted Below");
		break;

	  } /* switch type */
	} /* avpi_tree != null */
	offset += (avpLength - hdrLength);
	offset += fixAmt; /* fix byte alignment */
  } /* loop */
} /* dissect_avps */



void
proto_reg_handoff_diameter(void)
{
  static int Initialized=FALSE;
  static int TcpPort=0;
  static int SctpPort=0;
  static dissector_handle_t diameter_tcp_handle;
  static dissector_handle_t diameter_handle;

  if (!Initialized) {
	diameter_tcp_handle = create_dissector_handle(dissect_diameter_tcp,
	    proto_diameter);
	diameter_handle = new_create_dissector_handle(dissect_diameter,
	    proto_diameter);
	Initialized=TRUE;
  } else {
	dissector_delete("tcp.port", TcpPort, diameter_tcp_handle);
	dissector_delete("sctp.port", SctpPort, diameter_handle);
  }

  /* set port for future deletes */
  TcpPort=gbl_diameterTcpPort;
  SctpPort=gbl_diameterSctpPort;

  /* g_warning ("Diameter: Adding tcp dissector to port %d",
	 gbl_diameterTcpPort); */
  dissector_add("tcp.port", gbl_diameterTcpPort, diameter_tcp_handle);
  dissector_add("sctp.port", gbl_diameterSctpPort, diameter_handle);
}

/* registration with the filtering engine */
void
proto_register_diameter(void)
{
	static hf_register_info hf[] = {
		{ &hf_diameter_version,
		  { "Version", "diameter.version", FT_UINT8, BASE_HEX, NULL, 0x00,
		    "", HFILL }},
		{ &hf_diameter_length,
		  { "Length","diameter.length", FT_UINT24, BASE_DEC, NULL, 0x0,
		    "", HFILL }},

		{ &hf_diameter_flags,
		  { "Flags", "diameter.flags", FT_UINT8, BASE_HEX, NULL, 0x0,
		    "", HFILL }},
		{ &hf_diameter_flags_request,
		  { "Request", "diameter.flags.request", FT_BOOLEAN, 8, TFS(&flags_set_truth), DIAM_FLAGS_R,
			"", HFILL }},
		{ &hf_diameter_flags_proxyable,
		  { "Proxyable", "diameter.flags.proxyable", FT_BOOLEAN, 8, TFS(&flags_set_truth), DIAM_FLAGS_P,
			"", HFILL }},
		{ &hf_diameter_flags_error,
		  { "Error","diameter.flags.error", FT_BOOLEAN, 8, TFS(&flags_set_truth), DIAM_FLAGS_E,
			"", HFILL }},
		{ &hf_diameter_flags_T,
		  { "T(Potentially re-transmitted message)","diameter.flags.T", FT_BOOLEAN, 8, TFS(&flags_set_truth),DIAM_FLAGS_T,
			"", HFILL }},
		{ &hf_diameter_flags_reserved4,
		  { "Reserved","diameter.flags.reserved4", FT_BOOLEAN, 8, TFS(&reserved_set),
			DIAM_FLAGS_RESERVED4, "", HFILL }},
		{ &hf_diameter_flags_reserved5,
		  { "Reserved","diameter.flags.reserved5", FT_BOOLEAN, 8, TFS(&reserved_set),
			DIAM_FLAGS_RESERVED5, "", HFILL }},
		{ &hf_diameter_flags_reserved6,
		  { "Reserved","diameter.flags.reserved6", FT_BOOLEAN, 8, TFS(&reserved_set),
			DIAM_FLAGS_RESERVED6, "", HFILL }},
		{ &hf_diameter_flags_reserved7,
		  { "Reserved","diameter.flags.reserved7", FT_BOOLEAN, 8, TFS(&reserved_set),
			DIAM_FLAGS_RESERVED7, "", HFILL }},

		{ &hf_diameter_code,
		  { "Command Code","diameter.code", FT_UINT24, BASE_DEC,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_vendor_id,
		  { "VendorId",	"diameter.vendorId", FT_UINT32, BASE_DEC, VALS(sminmpec_values),
			0x0,"", HFILL }},
		{ &hf_diameter_application_id,
		  { "ApplicationId",	"diameter.applicationId", FT_UINT32, BASE_DEC, VALS(diameter_application_id_vals),
			0x0,"", HFILL }},
		{ &hf_diameter_hopbyhopid,
		  { "Hop-by-Hop Identifier", "diameter.hopbyhopid", FT_UINT32,
		    BASE_HEX, NULL, 0x0, "", HFILL }},
		{ &hf_diameter_endtoendid,
		  { "End-to-End Identifier", "diameter.endtoendid", FT_UINT32,
		    BASE_HEX, NULL, 0x0, "", HFILL }},

		{ &hf_diameter_avp_code,
		  { "AVP Code","diameter.avp.code", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_length,
		  { "AVP Length","diameter.avp.length", FT_UINT24, BASE_DEC,
		    NULL, 0x0, "", HFILL }},


		{ &hf_diameter_avp_flags,
		  { "AVP Flags","diameter.avp.flags", FT_UINT8, BASE_HEX,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_flags_vendor_specific,
		  { "Vendor-Specific", "diameter.flags.vendorspecific", FT_BOOLEAN, 8, TFS(&flags_set_truth), AVP_FLAGS_V,
			"", HFILL }},
		{ &hf_diameter_avp_flags_mandatory,
		  { "Mandatory", "diameter.flags.mandatory", FT_BOOLEAN, 8, TFS(&flags_set_truth), AVP_FLAGS_M,
			"", HFILL }},
		{ &hf_diameter_avp_flags_protected,
		  { "Protected","diameter.avp.flags.protected", FT_BOOLEAN, 8, TFS(&flags_set_truth), AVP_FLAGS_P,
			"", HFILL }},
		{ &hf_diameter_avp_flags_reserved3,
		  { "Reserved","diameter.avp.flags.reserved3", FT_BOOLEAN, 8, TFS(&reserved_set),
			AVP_FLAGS_RESERVED3,	"", HFILL }},
		{ &hf_diameter_avp_flags_reserved4,
		  { "Reserved","diameter.avp.flags.reserved4", FT_BOOLEAN, 8, TFS(&reserved_set),
			AVP_FLAGS_RESERVED4,	"", HFILL }},
		{ &hf_diameter_avp_flags_reserved5,
		  { "Reserved","diameter.avp.flags.reserved5", FT_BOOLEAN, 8, TFS(&reserved_set),
			AVP_FLAGS_RESERVED5,	"", HFILL }},
		{ &hf_diameter_avp_flags_reserved6,
		  { "Reserved","diameter.avp.flags.reserved6", FT_BOOLEAN, 8, TFS(&reserved_set),
			AVP_FLAGS_RESERVED6,	"", HFILL }},
		{ &hf_diameter_avp_flags_reserved7,
		  { "Reserved","diameter.avp.flags.reserved7", FT_BOOLEAN, 8, TFS(&reserved_set),
			AVP_FLAGS_RESERVED7,	"", HFILL }},
		{ &hf_diameter_avp_vendor_id,
		  { "AVP Vendor Id","diameter.avp.vendorId", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_data_uint64,
		  { "Value","diameter.avp.data.uint64", FT_UINT64, BASE_DEC,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_data_int64,
		  { "Value","diameter.avp.data.int64", FT_INT64, BASE_DEC,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_data_uint32,
		  { "Value","diameter.avp.data.uint32", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_data_int32,
		  { "Value","diameter.avp.data.int32", FT_INT32, BASE_DEC,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_data_bytes,
		  { "Value","diameter.avp.data.bytes", FT_BYTES, BASE_NONE,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_data_string,
		  { "Value","diameter.avp.data.string", FT_STRING, BASE_NONE,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_data_addrfamily,
		  { "Address Family","diameter.avp.data.addrfamily", FT_UINT16, BASE_DEC,
		    VALS(diameter_avp_data_addrfamily_vals), 0x0, "", HFILL }},
		{ &hf_diameter_avp_data_v4addr,
		  { "IPv4 Address","diameter.avp.data.v4addr", FT_IPv4, BASE_NONE,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_data_v6addr,
		  { "IPv6 Address","diameter.avp.data.v6addr", FT_IPv6, BASE_NONE,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_data_time,
		  { "Time","diameter.avp.data.time", FT_ABSOLUTE_TIME, BASE_NONE,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_diameter_uri,
		  { "Diameter URI","diameter.avp.diameter_uri", FT_STRING, BASE_NONE,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_session_id,
		  { "Session ID","diameter.avp.session_id", FT_STRING, BASE_NONE,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_public_id,
		  { "Public ID","diameter.avp.public_id", FT_STRING, BASE_NONE,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_private_id,
		  { "Private ID","diameter.avp.private_id", FT_STRING, BASE_NONE,
		    NULL, 0x0, "", HFILL }},

	};
	static gint *ett[] = {
		&ett_diameter,
		&ett_diameter_flags,
		&ett_diameter_avp,
		&ett_diameter_avp_flags,
		&ett_diameter_avpinfo
	};
	module_t *diameter_module;
	gchar *default_diameterDictionary;

	proto_diameter = proto_register_protocol ("Diameter Protocol", "DIAMETER", "diameter");
	proto_register_field_array(proto_diameter, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register a configuration option for port */
	diameter_module = prefs_register_protocol(proto_diameter,
											  proto_reg_handoff_diameter);
	/* Register a configuration option for Diameter version */
	prefs_register_enum_preference(diameter_module, "version", "Diameter version", "Standard version used for decoding", (gint *)&gbl_version, options, FALSE);

	prefs_register_uint_preference(diameter_module, "tcp.port",
								   "Diameter TCP Port",
								   "Set the TCP port for Diameter messages",
								   10,
								   &gbl_diameterTcpPort);
	prefs_register_uint_preference(diameter_module, "sctp.port",
								   "Diameter SCTP Port",
								   "Set the SCTP port for Diameter messages",
								   10,
								   &gbl_diameterSctpPort);
	/*
	 * Build our default dictionary filename
	 */
	default_diameterDictionary = get_datafile_path(DICT_FN);

	/*
	 * Now register the dictionary filename as a preference,
	 * so it can be changed.
	 */
	gbl_diameterDictionary = default_diameterDictionary;
	prefs_register_string_preference(diameter_module, "dictionary.name",
									 "Diameter XML Dictionary",
									 "Set the dictionary used for Diameter messages",
									 &gbl_diameterDictionary);

	/*
	 * We don't need the default dictionary, so free it (a copy was made
	 * of it in "gbl_diameterDictionary" by
	 * "prefs_register_string_preference()").
	 */
	g_free(default_diameterDictionary);

	/*
	 * Make use of the dictionary optional.  Avoids error popups if xml library
	 * or dictionary file aren't available.
	 */
	prefs_register_bool_preference(diameter_module, "dictionary.use",
	                               "Attempt to load/use Diameter XML Dictionary",
	                               "Only attempt to load and use the Diameter XML "
	                               "Dictionary when this option is selected",
	                               &gbl_use_xml_dictionary);

	/* Desegmentation */
	prefs_register_bool_preference(diameter_module, "desegment",
                                   "Reassemble Diameter messages\nspanning multiple TCP segments",
								   "Whether the Diameter dissector should reassemble messages spanning multiple TCP segments."
								   " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
								   &gbl_diameter_desegment);
	/* Allow zero as valid application ID */
	prefs_register_bool_preference(diameter_module, "allow_zero_as_app_id",
			"Allow 0 as valid application ID",
			"If set, the value 0 (zero) can be used as a valid "
			"application ID. This is used in experimental cases.",
			&allow_zero_as_app_id);
	/* Register some preferences we no longer support, so we can report
	   them as obsolete rather than just illegal. */
	/* Suppress console output or not */
	prefs_register_bool_preference(diameter_module, "suppress_console_output",
			"Suppress console output for unknown AVP:s Flags etc.",
			"If console output for errors should be suppressed or not",
			&suppress_console_output);
	/* Register some preferences we no longer support, so we can report
	   them as obsolete rather than just illegal. */
	prefs_register_obsolete_preference(diameter_module, "udp.port");
	prefs_register_obsolete_preference(diameter_module, "command_in_header");
} /* proto_register_diameter */
