/* packet-diameter.c
 * Routines for Diameter packet disassembly
 *
 * $Id: packet-diameter.c,v 1.38 2002/01/07 20:05:20 guy Exp $
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
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <glib.h>
#include <filesystem.h>
#include "xmlstub.h"
#include "packet.h"
#include "resolv.h"
#include "prefs.h"

/* This must be defined before we include packet-diameter-defs.h */

/* Valid data types */
typedef enum {
  /* Base Types */
  DIAMETER_OCTET_STRING = 1,
  DIAMETER_INTEGER32,
  DIAMETER_INTEGER64,
  DIAMETER_UNSIGNED32,
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
  DIAMETER_VENDOR_ID,           /* Integer32  */
  DIAMETER_APPLICATION_ID
  
} diameterDataType;


static value_string TypeValues[]={
  {  DIAMETER_OCTET_STRING,    "OctetString" },
  {  DIAMETER_INTEGER32,       "Integer32" },
  {  DIAMETER_INTEGER64,       "Integer64" },
  {  DIAMETER_UNSIGNED32,      "Unsigned32" },
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
  {0, (char *)NULL}
};

typedef struct value_name {
  guint32            value;
  gchar             *name;
  struct value_name *next;
} ValueName;

typedef struct old_avp_info {
  guint32           code;
  gchar            *name;
  diameterDataType  type;
  value_string     *values;
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

#define TCP_PORT_DIAMETER	1812
#define SCTP_PORT_DIAMETER	1812

static const true_false_string flags_set_truth = {
  "Set",
  "Not set"
};

static const true_false_string reserved_set = {
  "*** Error! Reserved Bit is Set",
  "Ok"
};
static int proto_diameter = -1;
static int hf_diameter_length = -1;
static int hf_diameter_code = -1;
static int hf_diameter_hopbyhopid =-1;
static int hf_diameter_endtoendid =-1;
static int hf_diameter_reserved = -1;
static int hf_diameter_version = -1;
static int hf_diameter_vendor_id = -1;
static int hf_diameter_flags = -1;
static int hf_diameter_flags_request = -1;
static int hf_diameter_flags_proxyable = -1;
static int hf_diameter_flags_error = -1;
static int hf_diameter_flags_reserved3 = -1;
static int hf_diameter_flags_reserved4 = -1;
static int hf_diameter_flags_reserved5 = -1;
static int hf_diameter_flags_reserved6 = -1;
static int hf_diameter_flags_reserved7 = -1;

static int hf_diameter_avp_code = -1;
static int hf_diameter_avp_length = -1;
static int hf_diameter_avp_reserved = -1;
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
static int hf_diameter_avp_data_v4addr = -1;
static int hf_diameter_avp_data_v6addr = -1;
static int hf_diameter_avp_data_time = -1;

static gint ett_diameter = -1;
static gint ett_diameter_flags = -1;
static gint ett_diameter_avp = -1;
static gint ett_diameter_avp_flags = -1;
static gint ett_diameter_avpinfo = -1;

static char gbl_diameterString[200];
static int gbl_diameterTcpPort=TCP_PORT_DIAMETER;
static int gbl_diameterSctpPort=SCTP_PORT_DIAMETER;

/* desegmentation of Diameter over TCP */
static gboolean gbl_diameter_desegment = TRUE;

#define DIAMETER_DIR "diameter"
#define DICT_FN "dictionary.xml"
static gchar *gbl_diameterDictionary = NULL;

typedef struct _e_diameterhdr {
  guint32  versionLength;
  guint32  flagsCmdCode;
  guint32  vendorId;
  guint32  hopByHopId;
  guint32  endToEndId;
} e_diameterhdr;

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
#define DIAM_FLAGS_RESERVED3 0x10
#define DIAM_FLAGS_RESERVED4 0x08
#define DIAM_FLAGS_RESERVED5 0x04
#define DIAM_FLAGS_RESERVED6 0x02
#define DIAM_FLAGS_RESERVED7 0x01
#define DIAM_FLAGS_RESERVED  0x1f

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
#define MIN_DIAMETER_SIZE (sizeof(e_diameterhdr))

static void dissect_avps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);


/*
 * This routine will do a push-parse of the passed in
 * filename.  This was taken almost verbatum from
 * the xmlsoft examples.
 */
static xmlDocPtr
xmlParseFilePush( char *filename, int checkValid) {
  FILE *f;
  xmlDocPtr doc=NULL;
  int valid=0;
  int res, size = 1024;
  char chars[1024];
  xmlParserCtxtPtr ctxt;
	
  /* I wonder what kind of a performance hit this is? */
  *XmlStub.xmlDoValidityCheckingDefaultValue = checkValid;
  
  f = fopen(filename, "r");
  if (f == NULL) {
	g_warning("Diameter: Unable to open %s", filename);
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
	valid=ctxt->valid;
	XmlStub.xmlFreeParserCtxt(ctxt);
  }
  fclose(f); 

  /* Check valid */
  if (!valid) {
	g_warning( "Error!  Invalid xml in %s!  Failed DTD check!",
			   filename);
	return NULL;
  }
  return doc;
} /* xmlParseFilePush */

/*
 * This routine will add a static avp to the avp list.  It is
 * only called when the XML dictionary fails to load properly.
 */
static int
addStaticAVP(int code, gchar *name, diameterDataType type, value_string *values)
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
  if (vEntry)
	entry->type = DIAMETER_INTEGER32;

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
xmlParseAVP(xmlDocPtr doc, xmlNodePtr cur)
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
	if (!strcasecmp((char *)cur->name, "type")) {
	  type = XmlStub.xmlGetProp(cur, "type-name");
	}
	if (!strcasecmp((char *)cur->name, "enum")) {
	  char *valueName=NULL, *valueCode=NULL;
	  ValueName *ve = NULL;
	  valueName = XmlStub.xmlGetProp(cur, "name");
	  valueCode = XmlStub.xmlGetProp(cur, "code");
			
	  if (!valueName || !valueCode) {
		g_warning( "Error, bad value on avp %s", name);
		return (-1);
	  }
			
	  ve = g_malloc(sizeof(ValueName));
	  ve->name = strdup(valueName);
	  ve->value = atol(valueCode);

	  ve->next = vEntry;
	  vEntry = ve;
	}
	if (!strcasecmp((char *)cur->name, "grouped")) {
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
	  g_warning( "Invalid Type field in dictionary! avp %s (%s)",  name, type);
	  return (-1);
	}
  } else if (!vEntry) {
	g_warning("Missing type/enum field in dictionary avpName=%s",
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
  if (vEntry)
	entry->type = DIAMETER_INTEGER32;

  /* And, add it to the list */
  entry->next = avpListHead;
  avpListHead = entry;

  return (0);
} /* xmlParseAVP */

/*
 * This routine will add a command to the list of commands.
 */
static int
addCommand(int code, char *name, char *vendorId)
{
  CommandCode *entry;

  /*
   * Allocate the memory required for the dictionary.
   */
  entry = (CommandCode *) g_malloc(sizeof (CommandCode));

  if (entry == NULL) {
	g_warning("Unable to allocate memory");
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
xmlParseCommand(xmlDocPtr doc, xmlNodePtr cur)
{
  char *name, *code, *vendorIdString;

  /*
   * Get the Attributes
   */
  name = XmlStub.xmlGetProp(cur, "name");
  code = XmlStub.xmlGetProp(cur, "code");
  if (!name || !code) {
	g_warning("Invalid command.  Name or code missing!");
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
dictionaryAddApplication(char *name, int id)
{
  ApplicationId *entry;

  if (!name || (id <= 0)) {
	g_warning( "Diameter Error: Inavlid application (name=%p, id=%d)",
			   name, id);
	return (-1);
  } /* Sanity Checks */

  entry = g_malloc(sizeof(ApplicationId));
  if (!entry) {
	g_warning( "Unable to allocate memory");
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
addVendor(int id, gchar *name, gchar *longName)
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
xmlParseVendor(xmlDocPtr doc, xmlNodePtr cur)
{
  char *name=NULL, *code=NULL, *id=NULL;

  /* First, get our properties */
  id = XmlStub.xmlGetProp(cur, "vendor-id");
  name = XmlStub.xmlGetProp(cur, "name");
  code = XmlStub.xmlGetProp(cur, "code");

  if (!id || !name || !code) {
	g_warning( "Invalid vendor section.  vendor-id, name, and code must be specified");
	return -1;
  }

  return (addVendor(atoi(code), id, name));
} /* addVendor */

/*
 * This routine will either parse in the base protocol, or an application.
 */
static int
xmlDictionaryParseSegment(xmlDocPtr doc, xmlNodePtr cur, int base)
{
  if (!base) {
	char *name;
	char *id;
		
	/* Add our application */
	id = XmlStub.xmlGetProp(cur, "id");
	name = XmlStub.xmlGetProp(cur, "name");
		
	if (!name || !id) {
	  /* ERROR!!! */
	  g_warning("Diameter: Invalid application!: name=\"%s\", id=\"%s\"",
				name?name:"NULL", id?id:"NULL");
	  return -1;
	}
		
	/* Add the application */
	if (dictionaryAddApplication(name, atol(id)) != 0) {
	  /* ERROR! */
	  return -1;
	}
  }

	
  /*
   * Get segment values
   */
  cur = cur->xmlChildrenNode;
  while (cur != NULL) {
	if (!strcasecmp((char *)cur->name, "avp")) {
	  /* we have an avp!!! */
	  xmlParseAVP(doc, cur);
	} else if (!strcasecmp((char *)cur->name, "vendor")) {
	  /* we have a vendor */
	  xmlParseVendor(doc, cur);
	  /* For now, ignore typedefn and text */
	} else if (!strcasecmp((char *)cur->name, "command")) {
	  /* Found a command */
	  xmlParseCommand(doc,cur);
	} else if (!strcasecmp((char *)cur->name, "text")) {
	} else if (!strcasecmp((char *)cur->name, "comment")) {
	} else if (!strcasecmp((char *)cur->name, "typedefn")) {
	  /* WORK -- parse in valid types . . . */
	} else {
	  /* IF we got here, we're an error */
	  g_warning("Error!  expecting an avp or a typedefn (got \"%s\")",
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
xmlDictionaryParse(xmlDocPtr doc, xmlNodePtr cur)
{
  /* We should expect a base protocol, followed by multiple applicaitons */
  while (cur != NULL) {
	if (!strcasecmp((char *)cur->name, "base")) {
	  /* Base protocol.  Descend and parse */
	  xmlDictionaryParseSegment(doc, cur, 1);
	} else if (!strcasecmp((char *)cur->name, "application")) {
	  /* Application.  Descend and parse */
	  xmlDictionaryParseSegment(doc, cur, 0);
	} else if (!strcasecmp((char *)cur->name, "text")) {
	  /* Ignore text */
	} else {
	  g_warning( "Diameter: XML Expecting a base or an application  (got \"%s\")",
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
loadXMLDictionary()
{
  xmlDocPtr doc;
  xmlNodePtr cur;

  /*
   * build an XML tree from a the file;
   */
  XmlStub.xmlKeepBlanksDefault(0);                    /* Strip leading and trailing blanks */
  XmlStub.xmlSubstituteEntitiesDefault(1);            /* Substitute entities automagically */
  doc = xmlParseFilePush(gbl_diameterDictionary, 1);  /* Parse the XML (do validity checks)*/

  /* Check for invalid xml */
  if (doc == NULL) {
	g_warning("Diameter: Unable to parse xmldictionary %s",
			  gbl_diameterDictionary);
	return -1;
  }
	
  /*
   * Check the document is of the right kind
   */
  cur = XmlStub.xmlDocGetRootElement(doc);
  if (cur == NULL) {
	g_warning("Diameter: Error: \"%s\": empty document",
			  gbl_diameterDictionary);
	XmlStub.xmlFreeDoc(doc);
	return -1;
  }
  if (XmlStub.xmlStrcmp(cur->name, (const xmlChar *) "dictionary")) {
	g_warning("Diameter: Error: \"%s\": document of the wrong type, root node != dictionary",
			  gbl_diameterDictionary);
	XmlStub.xmlFreeDoc(doc);
	return -1;
  }
	
  /*
   * Ok, the dictionary has been parsed by libxml, and is valid.
   * All we have to do now is read in our information.
   */
  if (xmlDictionaryParse(doc, cur->xmlChildrenNode) != 0) {
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
initializeDictionaryDefaults()
{
  int i;

  /* Add static vendors to list */
  for(i=0; diameter_vendor_specific_vendors[i].strptr; i++) {
	addVendor(diameter_vendor_specific_vendors[i].value,
			  diameter_vendor_specific_vendors[i].strptr,
			  diameter_vendor_specific_vendors[i].strptr);
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

} /* initializeDictionaryDefaults */

/* 
 * This routine will attempt to load the XML dictionary, and on 
 * failure, will call initializeDictionaryDefaults to load in
 * our static dictionary.
 */
static void
initializeDictionary()
{
  /*
   * Using ugly ordering here.  If loadLibXML succeeds, then 
   * loadXMLDictionary will be called.  This is one of the few times when
   * I think this is prettier than the nested if alternative.
   */
  if (loadLibXML() ||
	  (loadXMLDictionary() != 0)) {
	/* Something failed.  Use the static dictionary */
	g_warning("Diameter: Using static dictionary! (Unable to use XML)");
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
  static gchar buffer[64];

  for (probe=vendorListHead; probe; probe=probe->next) {
	if (vendorId == probe->id) {
	  if (longName)
		return probe->longName;
	  else
		return probe->name;
	}
  }

  snprintf(buffer, sizeof(buffer),
		   "Vendor 0x%08x", vendorId);
  return buffer;
} /*diameter_vendor_to_str */

/* return command string, based on the code */
static gchar *
diameter_command_to_str(guint32 commandCode, guint32 vendorId)
{
  CommandCode *probe;
  static gchar buffer[64];
  gchar *vendorName=NULL;

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
  
  g_warning("Diameter: Unable to find name for command code 0x%08x, Vendor \"%d\"!", 
			commandCode, vendorId);
  snprintf(buffer, sizeof(buffer),
		   "Cmd-0x%08x", commandCode);
  return buffer;
}/*diameter_command_to_str */

/* return application string, based on the id */
static gchar *
diameter_app_to_str(guint32 vendorId) {
  ApplicationId *probe;
  static gchar buffer[64];

  for (probe=ApplicationIdHead; probe; probe=probe->next) {
	if (vendorId == probe->id) {
	  return probe->name;
	}
  }

  snprintf(buffer, sizeof(buffer),
		   "AppId 0x%08x", vendorId);
  return buffer;
} /*diameter_app_to_str */

/* return an avp type, based on the code */
diameterDataType
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
  g_warning("Diameter: Unable to find type for avpCode %d, Vendor %d!", avpCode,
			vendorId);
  return DIAMETER_OCTET_STRING;
} /* diameter_avp_get_type */

/* return an avp name from the code */
static gchar *
diameter_avp_get_name(guint32 avpCode, guint32 vendorId)
{
  static gchar buffer[64];
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

  g_warning("Diameter: Unable to find name for AVP 0x%08x, Vendor %d!", 
			avpCode, vendorId);

  /* If we don't find it, build a name string */
  sprintf(buffer, "Unknown AVP:0x%08x", avpCode);
  return buffer;
} /* diameter_avp_get_name */
static gchar *
diameter_avp_get_value(guint32 avpCode, guint32 vendorId, guint32 avpValue)
{
  static gchar buffer[64];

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
		  sprintf(buffer, "Unknown Value: 0x%08x", avpValue);
		  return buffer;
		}
	  } else {
		if (!probe->vendorName) {
		  ValueName *vprobe;
		  for(vprobe=probe->values; vprobe; vprobe=vprobe->next) {
			if (avpValue == vprobe->value) {
			  return vprobe->name;
			}
		  }
		  sprintf(buffer, "Unknown Value: 0x%08x", avpValue);
		  return buffer;
		}
	  }
	}
  }
  /* If we don't find the avp, build a value string */
  sprintf(buffer, "Unknown AVP! Value: 0x%08x", avpValue);
  return buffer;
} /* diameter_avp_get_value */

static gchar *
diameter_time_to_string(gchar *timeValue)
{
  static gchar buffer[64];
  int intval;
  struct tm lt;

  intval=pntohl(*((guint32*)timeValue));
  intval -= NTP_TIME_DIFF;
  lt=*localtime((time_t *)&intval);
  strftime(buffer, 1024, 
		   "%a, %d %b %Y %H:%M:%S %z",&lt);
  return buffer;
} /* diameter_time_to_string */


/* Code to actually dissect the packets */

/*
 * Main dissector
 */
static guint32 dissect_diameter_common(tvbuff_t *tvb, size_t start, packet_info *pinfo,
									   proto_tree *tree)
{

  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item      *ti;
  proto_item      *tf;
  proto_tree      *flags_tree;
  tvbuff_t        *avp_tvb;
  proto_tree      *diameter_tree;
  e_diameterhdr    dh;
  size_t           offset=0;
  size_t           avplength;
  proto_tree      *avp_tree;
  proto_item      *avptf;
  int              BadPacket = FALSE;
  guint32          commandCode, pktLength;
  guint8           version, flags;
  gchar            flagstr[64] = "<None>";
  gchar           *fstr[] = {"RSVD7", "RSVD6", "RSVD5", "RSVD4", "RSVD3", "Error", "Proxyable", "Request" };
  gchar            commandString[64], vendorName[64];
  gint        i;
  guint      bpos;
  static  int initialized=FALSE;

  /* set our offset */
  offset=start;

  /*
   * Only parse in dictionary if there are diameter packets to
   * dissect.
   */
  if (!initialized) {
	  /* Read in our dictionary, if it exists. */
	  initializeDictionary();
	  initialized=TRUE;
  }
	
  /* Make entries in Protocol column and Info column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
	col_add_str(pinfo->cinfo, COL_PROTOCOL, "Diameter");
  if (check_col(pinfo->cinfo, COL_INFO)) 
	col_clear(pinfo->cinfo, COL_INFO);
	
  /* Copy our header */
  tvb_memcpy(tvb, (guint8*) &dh, offset, sizeof(dh));
	
  /* Fix byte ordering in our static structure */
  dh.versionLength = ntohl(dh.versionLength);
  dh.flagsCmdCode = ntohl(dh.flagsCmdCode);
  dh.vendorId = ntohl(dh.vendorId);
  dh.hopByHopId = ntohl(dh.hopByHopId);
  dh.endToEndId = ntohl(dh.endToEndId);

  if (dh.vendorId) {
	strcpy(vendorName, 
		   diameter_vendor_to_str(dh.vendorId, TRUE));
  } else {
	strcpy(vendorName, "None");
  }


  /* Do the bit twiddling */
  version = DIAM_GET_VERSION(dh);
  pktLength = DIAM_GET_LENGTH(dh);
  flags = DIAM_GET_FLAGS(dh);
  commandCode = DIAM_GET_COMMAND(dh);

  /* Set up our flags */
  if (check_col(pinfo->cinfo, COL_INFO) || tree) {  
	flagstr[0]=0;
	for (i = 0; i < 8; i++) {
	  bpos = 1 << i;
	  if (flags & bpos) {
		if (flagstr[0]) {
		  strcat(flagstr, ", ");
		}
		strcat(flagstr, fstr[i]);
	  }
	}
	if (strlen(flagstr) == 0) {
	  strcpy(flagstr,"<None>");
	}
  }
  
  /* Set up our commandString */
  strcpy(commandString, diameter_command_to_str(commandCode, dh.vendorId));
  if (flags & DIAM_FLAGS_R) 
	strcat(commandString, "-Request");
  else
	strcat(commandString, "-Answer");

  /* Short packet.  Should have at LEAST one avp */
  if (pktLength < MIN_DIAMETER_SIZE) {
	g_warning("Diameter: Packet too short: %d bytes less than min size (%d bytes))",
			  pktLength, MIN_DIAMETER_SIZE);
	BadPacket = TRUE;
  }

  /* And, check our reserved flags/version */
  if ((flags & DIAM_FLAGS_RESERVED) ||
	  (version != 1)) {
	g_warning("Diameter: Bad packet: Bad Flags(0x%x) or Version(%u)",
			  flags, version);
	BadPacket = TRUE;
  }

  if (check_col(pinfo->cinfo, COL_INFO)) {
	col_add_fstr(pinfo->cinfo, COL_INFO,
				 "%s%s%s%s%s vendor=%s (hop-id=%d) (end-id=%d) RPE=%d%d%d",
				 (BadPacket)?"***** Bad Packet!: ":"",
				 (flags & DIAM_FLAGS_P)?"Proxyable ":"",
				 (flags & DIAM_FLAGS_E)?" Error":"",
				 ((BadPacket ||
				   (flags & (DIAM_FLAGS_P|DIAM_FLAGS_E))) ?
				   ": " : ""),
				 commandString, vendorName,
				 dh.hopByHopId, dh.endToEndId,
				 (flags & DIAM_FLAGS_R)?1:0,
				 (flags & DIAM_FLAGS_P)?1:0,
				 (flags & DIAM_FLAGS_E)?1:0);
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
	tf = proto_tree_add_uint_format(diameter_tree, hf_diameter_flags, tvb,
									offset , 1, flags, "Flags: 0x%02x (%s)", flags,
									flagstr);
	flags_tree = proto_item_add_subtree(tf, ett_diameter_avp_flags);
	proto_tree_add_boolean(flags_tree, hf_diameter_flags_request, tvb, offset, 1, flags);
	proto_tree_add_boolean(flags_tree, hf_diameter_flags_proxyable, tvb, offset, 1, flags);
	proto_tree_add_boolean(flags_tree, hf_diameter_flags_error, tvb, offset, 1, flags);
	proto_tree_add_boolean(flags_tree, hf_diameter_flags_reserved3, tvb, offset, 1, flags);
	proto_tree_add_boolean(flags_tree, hf_diameter_flags_reserved4, tvb, offset, 1, flags);
	proto_tree_add_boolean(flags_tree, hf_diameter_flags_reserved5, tvb, offset, 1, flags);
	proto_tree_add_boolean(flags_tree, hf_diameter_flags_reserved6, tvb, offset, 1, flags);
	proto_tree_add_boolean(flags_tree, hf_diameter_flags_reserved7, tvb, offset, 1, flags);

	offset += 1;

	/* Command Code */
	proto_tree_add_uint_format(diameter_tree, hf_diameter_code,
							   tvb, offset, 3, commandCode, "Command Code: %s", commandString);
	offset += 3;

	/* Vendor Id */
	proto_tree_add_uint_format(diameter_tree,hf_diameter_vendor_id,
							   tvb, offset, 4,	dh.vendorId, "Vendor-Id: %s", vendorName);
	offset += 4;

	/* Hop-by-hop Identifier */
	proto_tree_add_uint(diameter_tree, hf_diameter_hopbyhopid,
						tvb, offset, 4, dh.hopByHopId);
	offset += 4;

	/* End-to-end Identifier */
	proto_tree_add_uint(diameter_tree, hf_diameter_endtoendid,
						tvb, offset, 4, dh.endToEndId);
	offset += 4;

	/* If we have a bad packet, don't bother trying to parse the AVPs */
	if (BadPacket) {
	  return (offset + MAX(pktLength,MIN_DIAMETER_SIZE));
	}

	/* Start looking at the AVPS */
	/* Make the next tvbuff */

	/* Update the lengths */
	avplength= pktLength - sizeof(e_diameterhdr);
    
	avp_tvb = tvb_new_subset(tvb, offset, avplength, avplength);
	avptf = proto_tree_add_text(diameter_tree,
								tvb, offset, avplength,
								"Attribute Value Pairs");
		
	avp_tree = proto_item_add_subtree(avptf,
									  ett_diameter_avp);
	if (avp_tree != NULL) {
	  dissect_avps( avp_tvb, pinfo, avp_tree);
	}
	return MAX((offset + avplength), MIN_DIAMETER_SIZE);
  }
  return (offset + MAX(pktLength, MIN_DIAMETER_SIZE));

} /* dissect_diameter_common */

static void
dissect_diameter_sctp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_diameter_common(tvb, 0, pinfo, tree);
}

static void
dissect_diameter_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	size_t offset = 0;
	guint32 plen;
	guint32 available_bytes;
/* 	guint32 noffset; */
	
	/* Loop through the packet, dissecting multiple diameter messages */
	do {
		available_bytes = tvb_length_remaining(tvb, offset);
		if (available_bytes < 4) {
			g_warning("Diameter:  Bailing because only %d bytes of packet are available",
					  available_bytes);
			return; /* Bail.  We can't even get our length */
		}

		/* get our packet length */
		plen = tvb_get_ntohl(tvb, offset);
		plen &= 0x00ffffff; /* get rid of the flags */

		/*Desegmentation */
		if (gbl_diameter_desegment) {
			if (pinfo->can_desegment
				&& plen > available_bytes) {
				pinfo->desegment_offset = offset;
				pinfo->desegment_len = plen - available_bytes;
/* 				g_warning("Diameter: Bailing for deseg because plen(%d) > available(%d)", */
/* 						  plen, available_bytes); */
				return;
			}
		}
	
		/* Otherwise, dissect our packet */
		offset = dissect_diameter_common(tvb, offset, pinfo, tree);

/* 		g_warning("dissected from %d to %d bytes out of %d (available was %d plen was %d)", */
/* 				  offset, noffset, tvb_length(tvb), available_bytes, plen); */
/* 		offset=noffset; */
	} while (offset < tvb_reported_length(tvb));

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
  gchar avpTypeString[64];
  gchar avpNameString[64];
  gchar *valstr;
  guint32 vendorId=0;
  gchar    vendorName[64];
  int hdrLength;
  int fixAmt;
  proto_tree *avpi_tree;
  size_t offset = 0 ;
  char dataBuffer[4096];
  tvbuff_t        *group_tvb;
  proto_tree *group_tree;
  proto_item *grouptf;
  proto_item *avptf;
  char buffer[1024];
  int BadPacket = FALSE;
  guint32 avpLength;
  guint8 flags;
  proto_item      *tf;
  proto_tree      *flags_tree;
	
  gint32 packetLength;
  size_t avpDataLength;
  int avpType;
  gchar flagstr[64] = "<None>";
  gchar *fstr[] = {"RSVD7", "RSVD6", "RSVD5", "RSVD4", "RSVD3", "Protected", "Mandatory", "Vendor-Specific" };
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
	  g_warning("Diameter: AVP Payload too short: %d bytes less than min size (%d bytes))",
				packetLength, MIN_AVP_SIZE);
	  BadPacket = TRUE;
	  /* Don't even bother trying to parse a short packet. */
	  return;
	}
	
	/* Copy our header */
	tvb_memcpy(tvb, (guint8*) &avph, offset, MIN((long)sizeof(avph),packetLength));
	
	/* Fix the byte ordering */
	avph.avp_code = ntohl(avph.avp_code);
	avph.avp_flagsLength = ntohl(avph.avp_flagsLength);
	
	flags = (avph.avp_flagsLength & 0xff000000) >> 24;
	avpLength = avph.avp_flagsLength & 0x00ffffff;
	
	/* Set up our flags string */
	if (check_col(pinfo->cinfo, COL_INFO) || avp_tree) {  
	  flagstr[0]=0;
	  for (i = 0; i < 8; i++) {
		bpos = 1 << i;
		if (flags & bpos) {
		  if (flagstr[0]) {
			strcat(flagstr, ", ");
		  }
		  strcat(flagstr, fstr[i]);
		}
	  }
	  if (strlen(flagstr) == 0) {
		strcpy(flagstr,"<None>");
	  }
	}

	/* Dissect our vendor id if it exists  and set hdr length */
	if (flags & AVP_FLAGS_V) {
	  vendorId = ntohl(avph.avp_vendorId);
	  /* Vendor id */
	  hdrLength = sizeof(e_avphdr);
	} else {
	  /* No vendor */
	  hdrLength = sizeof(e_avphdr) - 
		sizeof(guint32);
	  vendorId = 0;
	}

	if (vendorId) {
	  strcpy(vendorName, 
			 diameter_vendor_to_str(vendorId, TRUE));
	} else {
	  vendorName[0]='\0';
	}

	/* Check for bad length */
	if (avpLength < MIN_AVP_SIZE || 
		((long)avpLength > packetLength)) {
	  g_warning("Diameter: AVP payload size invalid: avp_length: %d bytes,  "
				"min: %d bytes,    packetLen: %d",
				avpLength, MIN_AVP_SIZE, packetLength);
	  BadPacket = TRUE;
	}

	/* Check for bad flags */
	if (flags & AVP_FLAGS_RESERVED) {
	  g_warning("Diameter: Invalid AVP: Reserved bit set.  flags = 0x%x,"
				" resFl=0x%x",
				flags, AVP_FLAGS_RESERVED);
	  /* For now, don't set bad packet, since I'm accidentally setting a wrong bit */
	  /* BadPacket = TRUE; */
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
	  g_warning("Diameter: Bad AVP: Bad new length (%d bytes) ",
				packetLength);
	  BadPacket = TRUE;
	}

	/* Make avp Name & type */
	strcpy(avpTypeString, val_to_str(diameter_avp_get_type(avph.avp_code,vendorId),
									 TypeValues, 
									 "Unknown-Type: 0x%08x"));
	strcpy(avpNameString, diameter_avp_get_name(avph.avp_code, vendorId));

	avptf = proto_tree_add_text(avp_tree, tvb,
								offset, avpLength + fixAmt,
								"%s (%s) l:0x%x (%d bytes) (%d padded bytes)",
								avpNameString, avpTypeString, avpLength,
								avpLength, avpLength+fixAmt);
	avpi_tree = proto_item_add_subtree(avptf,
									   ett_diameter_avpinfo);

	if (avpi_tree !=NULL) {
	  /* Command Code */
	  proto_tree_add_uint_format(avpi_tree, hf_diameter_avp_code,
								 tvb, offset, 4, avph.avp_code, "AVP Code: %s", avpNameString);
	  offset += 4;
		
	  tf = proto_tree_add_uint_format(avpi_tree, hf_diameter_avp_flags, tvb,
									  offset , 1, flags, "Flags: 0x%02x (%s)", flags,
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
		proto_tree_add_uint_format(avpi_tree, hf_diameter_avp_vendor_id,
								   tvb, offset, 4, vendorId, vendorName);
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
									tvb, offset, tvb_length(tvb) - offset, dataBuffer,
									"Bad AVP (Suspect Data Not Dissected)");
		return;
	  }

	  avpType=diameter_avp_get_type(avph.avp_code,vendorId);
	  tvb_memcpy(tvb, (guint8*) dataBuffer, offset, MIN(4095,avpDataLength));
	
	  
	  switch(avpType) {
	  case DIAMETER_GROUPED:
		sprintf(buffer, "%s Grouped AVPs", avpNameString);
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
		proto_tree_add_string_format(avpi_tree, hf_diameter_avp_data_string,
									 tvb, offset, avpDataLength, dataBuffer,
									 "Identity: %*.*s", (int)avpDataLength, (int)avpDataLength,
									 dataBuffer);
		break;
	  case DIAMETER_UTF8STRING:
		proto_tree_add_string_format(avpi_tree, hf_diameter_avp_data_string,
									 tvb, offset, avpDataLength, dataBuffer,
									 "UTF8String: %*.*s", (int)avpDataLength, (int)avpDataLength,
									 dataBuffer);
		break;
	  case DIAMETER_IP_ADDRESS:
		if (avpDataLength == 4) {
		  guint32 ipv4Address = ntohl((*(guint32*)dataBuffer));
		  proto_tree_add_ipv4_format(avpi_tree, hf_diameter_avp_data_v4addr,
									 tvb, offset, avpDataLength, ipv4Address,
									 "IPv4 Address: %u.%u.%u.%u",
									 (ipv4Address&0xff000000)>>24,
									 (ipv4Address&0xff0000)>>16,
									 (ipv4Address&0xff00)>>8,
									 (ipv4Address&0xff));
		} else if (avpDataLength == 16) {
		  proto_tree_add_ipv6_format(avpi_tree, hf_diameter_avp_data_v6addr,
									 tvb, offset, avpDataLength, dataBuffer, 
									 "IPv6 Address: %04x:%04x:%04x:%04x",
									 *((guint32*)dataBuffer),
									 *((guint32*)&dataBuffer[4]),
									 *((guint32*)&dataBuffer[8]),
									 *((guint32*)&dataBuffer[12]));
		} else {
		  proto_tree_add_bytes_format(avpi_tree, hf_diameter_avp_data_bytes,
									  tvb, offset, avpDataLength, dataBuffer,
									  "Error!  Bad Address Length");
		}
		break;

	  case DIAMETER_INTEGER32:
		{
		  gint32 data;
		  memcpy(&data, dataBuffer, 4);
		  data = ntohl(data);
		  proto_tree_add_int_format(avpi_tree, hf_diameter_avp_data_int32,
									tvb, offset, avpDataLength, data,
									"Value: %d", data );
		}
		break;

	  case DIAMETER_UNSIGNED32:
		{
		  guint32 data;

		  memcpy(&data, dataBuffer, 4);
		  data=ntohl(data);
		  proto_tree_add_uint_format(avpi_tree, hf_diameter_avp_data_uint32,
									 tvb, offset, avpDataLength, data,
									 "Value: 0x%08x (%u)", data,
									 data );
		}
		break;

	  case DIAMETER_INTEGER64:
		proto_tree_add_item(avpi_tree, hf_diameter_avp_data_int64, tvb, offset, 8, FALSE);
		break;

	  case DIAMETER_UNSIGNED64:
		proto_tree_add_item(avpi_tree, hf_diameter_avp_data_uint64, tvb, offset, 8, FALSE);
		break;

	  case DIAMETER_TIME:
		valstr=diameter_time_to_string(dataBuffer);

		proto_tree_add_bytes_format(avpi_tree, hf_diameter_avp_data_bytes,
									tvb, offset, avpDataLength, dataBuffer, "Time: %s", valstr);
		break;

	  case DIAMETER_ENUMERATED:
		{
		  guint32 data;
		  
		  memcpy(&data, dataBuffer, 4);
		  data = ntohl(data);
		  valstr = diameter_avp_get_value(avph.avp_code, vendorId, data);
		  proto_tree_add_uint_format(avpi_tree, hf_diameter_avp_data_uint32,
									 tvb, offset, avpDataLength, data,
									 "Value: 0x%08x (%u): %s", data, data, valstr);
		}
		break;
	  case DIAMETER_VENDOR_ID:
		{
		  guint32 data;
		  
		  memcpy(&data, dataBuffer, 4);
		  data = ntohl(data);
		  valstr = diameter_vendor_to_str(data, TRUE);
		  proto_tree_add_uint_format(avpi_tree, hf_diameter_avp_data_uint32,
									 tvb, offset, avpDataLength, data,
									 "%s (0x%08x)", valstr, data);
		}
		break;
	  case DIAMETER_APPLICATION_ID:
		{
		  guint32 data;
		  
		  memcpy(&data, dataBuffer, 4);
		  data = ntohl(data);
		  valstr = diameter_app_to_str(data);
		  proto_tree_add_uint_format(avpi_tree, hf_diameter_avp_data_uint32,
									 tvb, offset, avpDataLength, data,
									 "%s (0x%08x)", valstr, data);
		}
		break;
	  case DIAMETER_MIP_REG_REQ:
		safe_dissect_mip(tvb, pinfo, avpi_tree, offset, avpDataLength);
		break;

	  default:
	  case DIAMETER_OCTET_STRING:
		proto_tree_add_bytes_format(avpi_tree, hf_diameter_avp_data_bytes,
									tvb, offset, avpDataLength, dataBuffer,
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
  static dissector_handle_t diameter_sctp_handle;

  if (!Initialized) {
	diameter_tcp_handle = create_dissector_handle(dissect_diameter_tcp,
	    proto_diameter);
	diameter_sctp_handle = create_dissector_handle(dissect_diameter_sctp,
	    proto_diameter);
	Initialized=TRUE;
  } else {
	dissector_delete("tcp.port", TcpPort, diameter_tcp_handle);
	dissector_delete("sctp.port", SctpPort, diameter_sctp_handle);
  }

  /* set port for future deletes */
  TcpPort=gbl_diameterTcpPort;
  SctpPort=gbl_diameterSctpPort;

  strcpy(gbl_diameterString, "Diameter Protocol");

  /* g_warning ("Diameter: Adding tcp dissector to port %d",
	 gbl_diameterTcpPort); */
  dissector_add("tcp.port", gbl_diameterTcpPort, diameter_tcp_handle);
  dissector_add("sctp.port", gbl_diameterSctpPort, diameter_sctp_handle);
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
		{ &hf_diameter_flags_reserved3,
		  { "Reserved","diameter.flags.reserved3", FT_BOOLEAN, 8, TFS(&reserved_set),
			DIAM_FLAGS_RESERVED3, "", HFILL }},
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
		  { "VendorId",	"diameter.vendorId", FT_UINT32, BASE_DEC, NULL,
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
		  { "AVP Data","diameter.avp.data.uint64", FT_UINT64, BASE_DEC,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_data_int64,
		  { "AVP Data","diameter.avp.data.int64", FT_INT64, BASE_DEC,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_data_uint32,
		  { "AVP Data","diameter.avp.data.uint32", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_data_int32,
		  { "AVP Data","diameter.avp.data.int32", FT_INT32, BASE_DEC,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_data_bytes,
		  { "AVP Data","diameter.avp.data.bytes", FT_BYTES, BASE_NONE,
		    NULL, 0x0, "", HFILL }},
		
		{ &hf_diameter_avp_data_string,
		  { "AVP Data","diameter.avp.data.string", FT_STRING, BASE_NONE,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_data_v4addr,
		  { "AVP Data","diameter.avp.data.v4addr", FT_IPv4, BASE_NONE,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_data_v6addr,
		  { "AVP Data","diameter.avp.data.v6addr", FT_IPv6, BASE_NONE,
		    NULL, 0x0, "", HFILL }},
		{ &hf_diameter_avp_data_time,
		  { "AVP Data","diameter.avp.data.time", FT_ABSOLUTE_TIME, BASE_NONE,
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

	proto_diameter = proto_register_protocol (gbl_diameterString,
											  "Diameter", "diameter");
	proto_register_field_array(proto_diameter, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register a configuration option for port */
	diameter_module = prefs_register_protocol(proto_diameter,
											  proto_reg_handoff_diameter);
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
	if (! gbl_diameterDictionary) {
		gbl_diameterDictionary = (gchar *) g_malloc(strlen(get_datafile_dir()) +
													1 + strlen(DICT_FN) + 1); /* slash + fn + null */
		sprintf(gbl_diameterDictionary, "%s" G_DIR_SEPARATOR_S "%s",
				get_datafile_dir(), DICT_FN );
	}
	/* Now register its preferences so it can be changed. */
	prefs_register_string_preference(diameter_module, "dictionary.name",
									 "Diameter XML Dictionary",
									 "Set the dictionary used for Diameter messages",
									 &gbl_diameterDictionary);

	/* Desegmentation */
	prefs_register_bool_preference(diameter_module, "diameter.desegment",
								   "Desegment all Diameter messages spanning multiple TCP segments",
								   "Whether the Diameter dissector should desegment all messages spanning multiple TCP segments",
								   &gbl_diameter_desegment);

	/* Register some preferences we no longer support, so we can report
	   them as obsolete rather than just illegal. */
	prefs_register_obsolete_preference(diameter_module, "udp.port");
	prefs_register_obsolete_preference(diameter_module, "command_in_header");
} /* proto_register_diameter */
