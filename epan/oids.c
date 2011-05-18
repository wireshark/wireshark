/* oids.c
 * Object IDentifier Support
 *
 * (c) 2007, Luis E. Garcia Ontanon <luis@ontanon.org>
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
# include "config.h"
#endif

#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "emem.h"
#include "uat.h"
#include "prefs.h"
#include "proto.h"
#include "packet.h"
#include "report_err.h"
#include "filesystem.h"
#include "dissectors/packet-ber.h"

#ifdef HAVE_LIBSMI
#include <smi.h>

static gboolean oids_init_done = FALSE;
#endif

#define D(level,args) do if (debuglevel >= level) { printf args; printf("\n"); fflush(stdout); } while(0)

#include "oids.h"

static int debuglevel = 0;

/*
 * From SNMPv2-SMI and X.690
 *
 * Counter32  ::= [APPLICATION 1] IMPLICIT INTEGER (0..4294967295)
 * Gauge32    ::= [APPLICATION 2] IMPLICIT INTEGER (0..4294967295)
 * Unsigned32 ::= [APPLICATION 2] IMPLICIT INTEGER (0..4294967295) (alias of Gauge32)
 * TimeTicks  ::= [APPLICATION 3] IMPLICIT INTEGER (0..4294967295)
 *
 * If the BER encoding should not have the top bit set as to not become a negative number
 * the BER encoding may take 5 octets to encode.
 */

static const oid_value_type_t integer_type =    { FT_INT32,  BASE_DEC,  BER_CLASS_UNI, BER_UNI_TAG_INTEGER,     1,   4, OID_KEY_TYPE_INTEGER, 1};
static const oid_value_type_t bytes_type =      { FT_BYTES,  BASE_NONE, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, 0,  -1, OID_KEY_TYPE_BYTES,   0};
static const oid_value_type_t oid_type =        { FT_OID,    BASE_NONE, BER_CLASS_UNI, BER_UNI_TAG_OID,         1,  -1, OID_KEY_TYPE_OID,     0};
static const oid_value_type_t ipv4_type =       { FT_IPv4,   BASE_NONE, BER_CLASS_APP, 0,                       4,   4, OID_KEY_TYPE_IPADDR,  4};
static const oid_value_type_t counter32_type =  { FT_UINT64, BASE_DEC,  BER_CLASS_APP, 1,                       1,   5, OID_KEY_TYPE_INTEGER, 1};
static const oid_value_type_t unsigned32_type = { FT_UINT64, BASE_DEC,  BER_CLASS_APP, 2,                       1,   5, OID_KEY_TYPE_INTEGER, 1};
static const oid_value_type_t timeticks_type =  { FT_UINT64, BASE_DEC,  BER_CLASS_APP, 3,                       1,   5, OID_KEY_TYPE_INTEGER, 1};
static const oid_value_type_t opaque_type =     { FT_BYTES,  BASE_NONE, BER_CLASS_APP, 4,                       1,   4, OID_KEY_TYPE_BYTES,   0};
static const oid_value_type_t nsap_type =       { FT_BYTES,  BASE_NONE, BER_CLASS_APP, 5,                       0,  -1, OID_KEY_TYPE_NSAP,    0};
static const oid_value_type_t counter64_type =  { FT_UINT64, BASE_DEC,  BER_CLASS_APP, 6,                       1,   8, OID_KEY_TYPE_INTEGER, 1};
static const oid_value_type_t ipv6_type =       { FT_IPv6,   BASE_NONE, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, 16, 16, OID_KEY_TYPE_BYTES,   16};
static const oid_value_type_t float_type =      { FT_FLOAT,  BASE_DEC,  BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, 4,   4, OID_KEY_TYPE_WRONG,   0};
static const oid_value_type_t double_type =     { FT_DOUBLE, BASE_DEC,  BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, 8,   8, OID_KEY_TYPE_WRONG,   0};
static const oid_value_type_t ether_type =      { FT_ETHER,  BASE_NONE, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, 6,   6, OID_KEY_TYPE_ETHER,   6};
static const oid_value_type_t string_type =     { FT_STRING, BASE_NONE, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, 0,  -1, OID_KEY_TYPE_STRING,  0};
static const oid_value_type_t unknown_type =    { FT_BYTES,  BASE_NONE, BER_CLASS_ANY, BER_TAG_ANY,             0,  -1, OID_KEY_TYPE_WRONG,   0};

static oid_info_t oid_root = { 0, NULL, OID_KIND_UNKNOWN, NULL, &unknown_type, -2, NULL, NULL, NULL};

static oid_info_t* add_oid(const char* name, oid_kind_t kind, const oid_value_type_t* type, oid_key_t* key, guint oid_len, guint32 *subids) {
	guint i = 0;
	oid_info_t* c = &oid_root;

	if (!oid_root.children) {
		char* debug_env = getenv("WIRESHARK_DEBUG_MIBS");
		guint32 subid;

		debuglevel = debug_env ? strtoul(debug_env,NULL,10) : 0;

		oid_root.children = pe_tree_create(EMEM_TREE_TYPE_RED_BLACK,"oid_root");

		/*
		 * make sure we got strings at least in the three root-children oids
		 * that way oid_resolved() will always have a string to print
		 */
		subid = 0; oid_add("itu-t",1,&subid);
		subid = 1; oid_add("iso",1,&subid);
		subid = 2; oid_add("joint-iso-itu-t",1,&subid);
	}

	oid_len--;

	do {
		oid_info_t* n = emem_tree_lookup32(c->children,subids[i]);

		if(n) {
			if (i == oid_len) {
				if (n->name) {
					if (!g_str_equal(n->name,name)) {
						D(2,("Renaming Oid from: %s -> %s, this means the same oid is registered more than once",n->name,name));
					}
					/* XXX - Don't free n->name here. It may be part of an hf_register_info
                                         * struct that has been appended to the hfa GArray. */
				}

				n->name = g_strdup(name);

				if (! n->value_type) {
					n->value_type = type;
				}

				return n;
			}
		} else {
			n = g_malloc(sizeof(oid_info_t));
			n->subid = subids[i];
			n->kind = kind;
			n->children = pe_tree_create(EMEM_TREE_TYPE_RED_BLACK,"oid_children");
			n->value_hfid = -2;
			n->key = key;
			n->parent = c;
			n->bits = NULL;

			emem_tree_insert32(c->children,n->subid,n);

			if (i == oid_len) {
				n->name = g_strdup(name);
				n->value_type = type;
				n->kind = kind;
				return n;
			} else {
				n->name = NULL;
				n->value_type = NULL;
				n->kind = OID_KIND_UNKNOWN;
			}
		}
		c = n;
	} while(++i);

	g_assert_not_reached();
	return NULL;
}

void oid_add(const char* name, guint oid_len, guint32 *subids) {
	g_assert(subids && *subids <= 2);
	if (oid_len) {
		D(3,("\tOid (from subids): %s %s ",name?name:"NULL", oid_subid2string(subids,oid_len)));
		add_oid(name,OID_KIND_UNKNOWN,NULL,NULL,oid_len,subids);
	} else {
		D(1,("Failed to add Oid: %s (from subids)",name?name:"NULL"));
	}
}

void oid_add_from_string(const char* name, const gchar *oid_str) {
	guint32* subids;
	guint oid_len = oid_string2subid(oid_str, &subids);

	if (oid_len) {
		D(3,("\tOid (from string): %s %s ",name?name:"NULL", oid_subid2string(subids,oid_len)));
		add_oid(name,OID_KIND_UNKNOWN,NULL,NULL,oid_len,subids);
	} else {
		D(1,("Failed to add Oid: %s %s ",name?name:"NULL", oid_str?oid_str:NULL));
	}
}

extern void oid_add_from_encoded(const char* name, const guint8 *oid, gint oid_len) {
	guint32* subids;
	guint subids_len = oid_encoded2subid(oid, oid_len, &subids);

	if (subids_len) {
		D(3,("\tOid (from encoded): %s %s ",name, oid_subid2string(subids,subids_len)));
		add_oid(name,OID_KIND_UNKNOWN,NULL,NULL,subids_len,subids);
	} else {
		D(1,("Failed to add Oid: %s [%d]%s ",name?name:"NULL", oid_len,bytestring_to_str(oid, oid_len, ':')));
	}
}

#ifdef HAVE_LIBSMI
/* de-allocate storage mallocated by libsmi                            */
/*                                                                     */
/* XXX: libsmi provides access to smiFree as of libsmi v 0.4.8.        */
/*      On Windows: Wireshark 1.01 and later is built and distributed  */
/*      with libsmi 0.4.8 (or newer).                                  */
/*      On non-Windows systems, free() should be OK for libsmi         */
/*       versions older than 0.4.8.                                    */

static void smi_free(void *ptr) {

#if (SMI_VERSION_MAJOR >= 0) && (SMI_VERSION_MINOR >= 4) && (SMI_VERSION_PATCHLEVEL >= 8)
       smiFree(ptr);
#else
 #ifdef _WIN32
 #error Invalid Windows libsmi version ?? !!
 #endif
#define xx_free free  /* hack so checkAPIs.pl doesn't complain */
       xx_free(ptr);
#endif
}


typedef struct smi_module_t {
	char* name;
} smi_module_t;

static smi_module_t* smi_paths = NULL;
static guint num_smi_paths = 0;
static uat_t* smi_paths_uat = NULL;

static smi_module_t* smi_modules = NULL;
static guint num_smi_modules = 0;
static uat_t* smi_modules_uat = NULL;

static GString* smi_errors;

UAT_CSTRING_CB_DEF(smi_mod,name,smi_module_t)

static void smi_error_handler(char *path, int line, int severity, char *msg, char *tag) {
		g_string_append_printf(smi_errors,"%s:%d %d %s %s\n",
						  path ? path : "-",
						  line, severity,
						  tag ? tag : "-",
						  msg ? msg : "");
}


static void* smi_mod_copy_cb(void* dest, const void* orig, size_t len _U_) {
	const smi_module_t* m = orig;
	smi_module_t* d = dest;

	d->name = g_strdup(m->name);

	return d;
}

static void smi_mod_free_cb(void* p) {
	smi_module_t* m = p;
	g_free(m->name);
}


static char* alnumerize(const char* name) {
	char* s = g_strdup(name);
	char* r = s;
	char* w = r;
	char c;

	for (;(c = *r); r++) {
		if (isalnum(c) || c == '_' || c == '-' || c == '.') {
			*(w++) = c;
		} else if (c == ':' && r[1] == ':') {
			*(w++) = '.';
		}
	}

	*w = '\0';

	return s;
}

static const oid_value_type_t* get_typedata(SmiType* smiType) {
	/*
	 * There has to be a better way to know if a given
	 * OCTETSTRING type is actually human readable text,
	 * an address of some type or some moe specific FT_
	 * Until that is found, this is the mappping between
	 * SNMP Types and our FT_s
	 */
	static const struct _type_mapping_t {
		char* name;
		SmiBasetype base;
		const oid_value_type_t* type;
	} types[] =  {
		{"IpAddress", SMI_BASETYPE_UNKNOWN, &ipv4_type},
		{"InetAddressIPv4",SMI_BASETYPE_UNKNOWN,&ipv4_type},
		{"InetAddressIPv6",SMI_BASETYPE_UNKNOWN,&ipv6_type},
		{"NetworkAddress",SMI_BASETYPE_UNKNOWN,&ipv4_type},
		{"MacAddress",SMI_BASETYPE_UNKNOWN,&ether_type},
		{"TimeTicks",SMI_BASETYPE_UNKNOWN,&timeticks_type},
		{"Ipv6Address",SMI_BASETYPE_UNKNOWN,&ipv6_type},
		{"TimeStamp",SMI_BASETYPE_UNKNOWN,&timeticks_type},
		{"DisplayString",SMI_BASETYPE_UNKNOWN,&string_type},
		{"SnmpAdminString",SMI_BASETYPE_UNKNOWN,&string_type},
		{"DateAndTime",SMI_BASETYPE_UNKNOWN,&string_type},
		{"Counter",SMI_BASETYPE_UNKNOWN,&counter32_type},
		{"Counter32",SMI_BASETYPE_UNKNOWN,&counter32_type},
		{"Unsigned32",SMI_BASETYPE_UNKNOWN,&unsigned32_type},
		{"Gauge",SMI_BASETYPE_UNKNOWN,&unsigned32_type},
		{"Gauge32",SMI_BASETYPE_UNKNOWN,&unsigned32_type},
		{"NsapAddress",SMI_BASETYPE_UNKNOWN,&nsap_type},
		{"i32",SMI_BASETYPE_INTEGER32,&integer_type},
		{"octets",SMI_BASETYPE_OCTETSTRING,&bytes_type},
		{"oid",SMI_BASETYPE_OBJECTIDENTIFIER,&oid_type},
		{"u32",SMI_BASETYPE_UNSIGNED32,&unsigned32_type},
		{"u64",SMI_BASETYPE_UNSIGNED64,&counter64_type},
		{"f32",SMI_BASETYPE_FLOAT32,&float_type},
		{"f64",SMI_BASETYPE_FLOAT64,&double_type},
		{"f128",SMI_BASETYPE_FLOAT128,&bytes_type},
		{"enum",SMI_BASETYPE_ENUM,&integer_type},
		{"bits",SMI_BASETYPE_BITS,&bytes_type},
		{"unk",SMI_BASETYPE_UNKNOWN,&unknown_type},
		{NULL,0,NULL}
	};
	const struct _type_mapping_t* t;
	SmiType* sT = smiType;

	if (!smiType) return NULL;

	do {
		for (t = types; t->type ; t++ ) {
			char* name = smiRenderType(sT, SMI_RENDER_NAME);
			if (name && t->name && g_str_equal(name, t->name )) {
				smi_free(name);
				return t->type;
			}
			if (name) {
				smi_free (name);
			}
		}
	} while(( sT  = smiGetParentType(sT) ));

	for (t = types; t->type ; t++ ) {
		if(smiType->basetype == t->base) {
			return t->type;
		}
	}

	return &unknown_type;
}

static guint get_non_implicit_size(SmiType* sT) {
	SmiRange *sR;
	guint size = 0xffffffff;

	switch (sT->basetype) {
		case SMI_BASETYPE_OCTETSTRING:
		case SMI_BASETYPE_OBJECTIDENTIFIER:
			break;
		default:
			return 0;
	}

	for ( ; sT; sT = smiGetParentType(sT) ) {
		for (sR = smiGetFirstRange(sT); sR ; sR = smiGetNextRange(sR)) {
			if (size == 0xffffffff) {
				if (sR->minValue.value.unsigned32 == sR->maxValue.value.unsigned32) {
					size = sR->minValue.value.unsigned32;
				} else {
					return 0;
				}
			} else {
				if (sR->minValue.value.unsigned32 != size || sR->maxValue.value.unsigned32 != size) {
					return 0;
				}
			}
		}
	}

	return size == 0xffffffff ? 0 : size;
}


static inline oid_kind_t smikind(SmiNode* sN, oid_key_t** key_p) {
	*key_p = NULL;

	switch(sN->nodekind) {
		case SMI_NODEKIND_ROW: {
			SmiElement* sE;
			oid_key_t* kl = NULL;
			const oid_value_type_t* typedata = NULL;
			gboolean implied;

			switch (sN->indexkind) {
				case SMI_INDEX_INDEX:
					break;
				case SMI_INDEX_AUGMENT:
				case SMI_INDEX_REORDER:
				case SMI_INDEX_SPARSE:
				case SMI_INDEX_EXPAND:
					sN = smiGetRelatedNode(sN);
					break;
				case SMI_INDEX_UNKNOWN:
					return OID_KIND_UNKNOWN;
			};

			implied = sN->implied;

			for (sE = smiGetFirstElement(sN); sE; sE = smiGetNextElement(sE)) {
				SmiNode* elNode =  smiGetElementNode(sE) ;
				SmiType* elType = smiGetNodeType(elNode);
				oid_key_t* k;
				guint non_implicit_size = 0;
				char *oid1, *oid2;

				if (elType) {
					non_implicit_size = get_non_implicit_size(elType);
				}

				typedata =  get_typedata(elType);

				k = g_malloc(sizeof(oid_key_t));

				oid1 = smiRenderOID(sN->oidlen, sN->oid, SMI_RENDER_QUALIFIED);
				oid2 = smiRenderOID(elNode->oidlen, elNode->oid, SMI_RENDER_NAME);
				k->name = g_strdup_printf("%s.%s", oid1, oid2);
				smi_free (oid1);
				smi_free (oid2);

				k->hfid = -2;
				k->ft_type = typedata ? typedata->ft_type : FT_BYTES;
				k->display = typedata ? typedata->display : BASE_NONE;
				k->next = NULL;


				if (typedata) {
					k->key_type = typedata->keytype;
					k->num_subids = typedata->keysize;
				} else {
					if (elType) {
						switch (elType->basetype) {
							case SMI_BASETYPE_BITS:
							case SMI_BASETYPE_OCTETSTRING: {
								k->key_type = OID_KEY_TYPE_BYTES;
								k->num_subids = non_implicit_size;
								break;
							}
							case SMI_BASETYPE_ENUM:
							case SMI_BASETYPE_OBJECTIDENTIFIER:
							case SMI_BASETYPE_INTEGER32:
							case SMI_BASETYPE_UNSIGNED32:
							case SMI_BASETYPE_INTEGER64:
							case SMI_BASETYPE_UNSIGNED64:
								k->key_type = OID_KEY_TYPE_INTEGER;
								k->num_subids = 1;
								break;
							default:
								k->key_type = OID_KEY_TYPE_WRONG;
								k->num_subids = 0;
								break;
						}
					} else {
						k->key_type = OID_KEY_TYPE_WRONG;
						k->num_subids = 0;
						break;
					}
				}

				if (!*key_p) *key_p = k;
				if (kl) kl->next = k;

				kl = k;
			}

			if (implied && kl) {
				switch (kl->key_type) {
					case OID_KEY_TYPE_BYTES:  kl->key_type = OID_KEY_TYPE_IMPLIED_BYTES; break;
					case OID_KEY_TYPE_STRING: kl->key_type = OID_KEY_TYPE_IMPLIED_STRING; break;
					case OID_KEY_TYPE_OID:    kl->key_type = OID_KEY_TYPE_IMPLIED_OID; break;
					default: break;
				}
			}

			return OID_KIND_ROW;
		}
		case SMI_NODEKIND_NODE: return OID_KIND_NODE;
		case SMI_NODEKIND_SCALAR: return OID_KIND_SCALAR;
		case SMI_NODEKIND_TABLE: return OID_KIND_TABLE;
		case SMI_NODEKIND_COLUMN: return OID_KIND_COLUMN;
		case SMI_NODEKIND_NOTIFICATION: return OID_KIND_NOTIFICATION;
		case SMI_NODEKIND_GROUP: return OID_KIND_GROUP;
		case SMI_NODEKIND_COMPLIANCE: return OID_KIND_COMPLIANCE;
		case SMI_NODEKIND_CAPABILITIES: return OID_KIND_CAPABILITIES;
		default: return OID_KIND_UNKNOWN;
	}
}

#define IS_ENUMABLE(ft) ( (ft == FT_UINT8) || (ft == FT_UINT16) || (ft == FT_UINT24) || (ft == FT_UINT32) \
						   || (ft == FT_INT8) || (ft == FT_INT16) || (ft == FT_INT24) || (ft == FT_INT32) \
						   || (ft == FT_UINT64) || (ft == FT_INT64) )

static void unregister_mibs(void) {
	/* TODO: Unregister "MIBs" proto and clean up field array and subtree array.
	 * Wireshark does not support that yet. :-( */

	/* smiExit(); */
}

static void restart_needed_warning(void) {
	if (oids_init_done)
		report_failure("Wireshark needs to be restarted for these changes to take effect");
}

static void register_mibs(void) {
	SmiModule *smiModule;
	SmiNode *smiNode;
	guint i;
	int proto_mibs = -1;
	GArray* hfa = g_array_new(FALSE,TRUE,sizeof(hf_register_info));
	GArray* etta = g_array_new(FALSE,TRUE,sizeof(gint*));
	static uat_field_t smi_fields[] = {
		UAT_FLD_CSTRING(smi_mod,name,"Module name","The module's name"),
		UAT_END_FIELDS
	};
	static uat_field_t smi_paths_fields[] = {
		UAT_FLD_PATHNAME(smi_mod,name,"Directory path","The directory name"),
		UAT_END_FIELDS
	};
	char* smi_load_error = NULL;
	gchar* path_str;

	smi_modules_uat = uat_new("SMI Modules",
							  sizeof(smi_module_t),
							  "smi_modules",
							  FALSE,
							  (void*)&smi_modules,
							  &num_smi_modules,
							  UAT_CAT_GENERAL,
							  "ChSNMPSMIModules",
							  smi_mod_copy_cb,
							  NULL,
							  smi_mod_free_cb,
							  restart_needed_warning,
							  smi_fields);

	smi_paths_uat = uat_new("SMI Paths",
							  sizeof(smi_module_t),
							  "smi_paths",
							  FALSE,
							  (void*)&smi_paths,
							  &num_smi_paths,
							  UAT_CAT_GENERAL,
							  "ChSNMPSMIPaths",
							  smi_mod_copy_cb,
							  NULL,
							  smi_mod_free_cb,
							  restart_needed_warning,
							  smi_paths_fields);


	uat_load(smi_modules_uat, &smi_load_error);

	if (smi_load_error) {
		report_failure("Error Loading SMI Modules Table: %s",smi_load_error);
		return;
	}

	uat_load(smi_paths_uat, &smi_load_error);

	if (smi_load_error) {
		report_failure("Error Loading SMI Paths Table: %s",smi_load_error);
		return;
	}

	if (!prefs.load_smi_modules) {
		D(1,("OID resolution not enabled"));
		return;
	}

	/* TODO: Remove this workaround when unregistration of "MIBs" proto is solved.
	 * Wireshark does not support that yet. :-( */
	if (oids_init_done) {
		D(1,("Exiting register_mibs() to avoid double registration of MIBs proto."));
		return;
	} else {
		oids_init_done = TRUE;
	}

	smiInit(NULL);

	smi_errors = g_string_new("");
	smiSetErrorHandler(smi_error_handler);

	path_str = oid_get_default_mib_path();
	D(1,("SMI Path: '%s'",path_str));

	smiSetPath(path_str);

	for(i=0;i<num_smi_modules;i++) {
		if (!smi_modules[i].name) continue;

		if (smiIsLoaded(smi_modules[i].name)) {
			continue;
		} else {
			char* mod_name =  smiLoadModule(smi_modules[i].name);
			if (mod_name)
				D(2,("Loaded: '%s'[%d] as %s",smi_modules[i].name,i,mod_name ));
			else
				D(1,("Failed to load: '%s'[%d]",smi_modules[i].name,i));
		}
	}

	if (smi_errors->len) {
		if (!prefs.suppress_smi_errors) {
			report_failure("The following errors were found while loading the MIBS:\n%s\n\n"
					   "The Current Path is: %s\n\nYou can avoid this error message "
					   "by removing the missing MIB modules at Edit -> Preferences"
					   " -> Name Resolution -> SMI (MIB and PIB) modules or by "
					   "installing them.\n" , smi_errors->str , path_str);
		}
		D(1,("Errors while loading:\n%s\n",smi_errors->str));
	}

	g_free(path_str);
	g_string_free(smi_errors,TRUE);

	for (smiModule = smiGetFirstModule();
		 smiModule;
		 smiModule = smiGetNextModule(smiModule)) {

		D(3,("\tModule: %s", smiModule->name));

		/* TODO: Check libsmi version at compile time and disable this
		 * workaround for libsmi versions where this problem is fixed.
		 * Currently there is no such version. :-(
		 */
		if (smiModule->conformance == 1) {
			if (!prefs.suppress_smi_errors) {
				report_failure("Stopped processing module %s due to "
					"error(s) to prevent potential crash in libsmi.\n"
					"Module's conformance level: %d.\n"
					"See details at: http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=560325\n",
					 smiModule->name, smiModule->conformance);
			}
			continue;
		}
		for (smiNode = smiGetFirstNode(smiModule, SMI_NODEKIND_ANY);
			 smiNode;
			 smiNode = smiGetNextNode(smiNode, SMI_NODEKIND_ANY)) {

			SmiType* smiType =  smiGetNodeType(smiNode);
			const oid_value_type_t* typedata =  get_typedata(smiType);
			oid_key_t* key;
			oid_kind_t kind = smikind(smiNode,&key);
			char *oid = smiRenderOID(smiNode->oidlen, smiNode->oid, SMI_RENDER_QUALIFIED);
			oid_info_t* oid_data = add_oid(oid,
						       kind,
						       typedata,
						       key,
						       smiNode->oidlen,
						       smiNode->oid);
			smi_free (oid);

			D(4,("\t\tNode: kind=%d oid=%s name=%s ",
				 oid_data->kind, oid_subid2string(smiNode->oid, smiNode->oidlen), oid_data->name ));

			if ( typedata && oid_data->value_hfid == -2 ) {
				SmiNamedNumber* smiEnum;
				hf_register_info hf = { &(oid_data->value_hfid), {
					oid_data->name,
					alnumerize(oid_data->name),
					typedata->ft_type,
					typedata->display,
					NULL,
					0,
					smiRenderOID(smiNode->oidlen, smiNode->oid, SMI_RENDER_ALL),
					HFILL }};

				/* Don't allow duplicate blurb/name */
				if (strcmp(hf.hfinfo.blurb, hf.hfinfo.name) == 0) {
					smi_free((void *) hf.hfinfo.blurb);
					hf.hfinfo.blurb = NULL;
				}

				oid_data->value_hfid = -1;

				if ( IS_ENUMABLE(hf.hfinfo.type) && (smiEnum = smiGetFirstNamedNumber(smiType))) {
					GArray* vals = g_array_new(TRUE,TRUE,sizeof(value_string));

					for(;smiEnum; smiEnum = smiGetNextNamedNumber(smiEnum)) {
						if (smiEnum->name) {
							value_string val = {smiEnum->value.value.integer32,g_strdup(smiEnum->name)};
							g_array_append_val(vals,val);
						}
					}

					hf.hfinfo.strings = vals->data;
					g_array_free(vals,FALSE);
				}
#if 0 /* packet-snmp does not handle bits yet */
			} else if (smiType->basetype == SMI_BASETYPE_BITS && ( smiEnum = smiGetFirstNamedNumber(smiType) )) {
				guint n = 0;
				oid_bits_info_t* bits = g_malloc(sizeof(oid_bits_info_t));
				gint* ettp = &(bits->ett);

				bits->num = 0;
				bits->ett = -1;

				g_array_append_val(etta,ettp);

				for(;smiEnum; smiEnum = smiGetNextNamedNumber(smiEnum), bits->num++);

				bits->data = g_malloc(sizeof(struct _oid_bit_t)*bits->num);

				for(smiEnum = smiGetFirstNamedNumber(smiType),n=0;
					smiEnum;
					smiEnum = smiGetNextNamedNumber(smiEnum),n++) {
					guint mask = 1 << (smiEnum->value.value.integer32 % 8);
					char* base = alnumerize(oid_data->name);
					char* ext = alnumerize(smiEnum->name);
					hf_register_info hf2 = { &(bits->data[n].hfid), { NULL, NULL, FT_UINT8, BASE_HEX, NULL, mask, NULL, HFILL }};

					bits->data[n].hfid = -1;
					bits->data[n].offset = smiEnum->value.value.integer32 / 8;

					hf2.hfinfo.name = g_strdup_printf("%s:%s",oid_data->name,smiEnum->name);
					hf2.hfinfo.abbrev = g_strdup_printf("%s.%s",base,ext);

					g_free(base);
					g_free(ext);
					g_array_append_val(hfa,hf2);
				}
#endif /* packet-snmp does not use this yet */
				g_array_append_val(hfa,hf);
			}

			if ((key = oid_data->key)) {
				for(; key; key = key->next) {
					hf_register_info hf = { &(key->hfid), {
						key->name,
						alnumerize(key->name),
						key->ft_type,
						key->display,
						NULL,
						0,
						NULL,
						HFILL }};

					D(5,("\t\t\tIndex: name=%s subids=%d key_type=%d",
						 key->name, key->num_subids, key->key_type ));

					if (key->hfid == -2) {
						g_array_append_val(hfa,hf);
						key->hfid = -1;
					} else {
						g_free((void*)hf.hfinfo.abbrev);
					}
				}
			}
		}
	}

	proto_mibs = proto_register_protocol("MIBs", "MIBS", "mibs");

	proto_register_field_array(proto_mibs, (hf_register_info*)(void*)hfa->data, hfa->len);

	proto_register_subtree_array((gint**)(void*)etta->data, etta->len);


	g_array_free(etta,TRUE);
	g_array_free(hfa,FALSE);
}
#endif


void oids_init(void) {
#ifdef HAVE_LIBSMI
	register_mibs();
#else
	D(1,("libsmi disabled oid resolution not enabled"));
#endif
}

void oids_cleanup(void) {
#ifdef HAVE_LIBSMI
	unregister_mibs();
#else
	D(1,("libsmi disabled oid resolution not enabled"));
#endif
}

const char* oid_subid2string(guint32* subids, guint len) {
	char* s = ep_alloc0(((len)*11)+1);
	char* w = s;

	if(!subids)
		return "*** Empty OID ***";

	do {
		w += g_snprintf(w,12,"%u.",*subids++);
	} while(--len);

	if (w!=s) *(w-1) = '\0'; else *(s) = '\0';

	return s;
}

static guint check_num_oid(const char* str) {
	const char* r = str;
	char c = '\0';
	guint n = 0;

	D(8,("check_num_oid: '%s'",str));
	if (!r || *r == '.' || *r == '\0') return 0;

	do {
		D(9,("\tcheck_num_oid: '%c' %d",*r,n));
		switch(*r) {
			case '.':
				n++;
				if (c == '.') return 0;
			case '1' : case '2' : case '3' : case '4' : case '5' :
			case '6' : case '7' : case '8' : case '9' : case '0' :
				continue;
			case '\0':
				n++;
				break;
			default:
				return 0;
		}
	} while((c = *r++));

	if (c == '.') return 0;

	return n;
}

guint oid_string2subid(const char* str, guint32** subids_p) {
	const char* r = str;
	guint32* subids;
	guint32* subids_overflow;
	guint n = check_num_oid(str);
	/*
	 * we cannot handle sub-ids greater than 32bytes
	 * keep a pilot subid of 64 bytes to check the limit
	 */
	guint64 subid = 0;

	D(6,("oid_string2subid: str='%s'",str));

	if (!n) {
		*subids_p = NULL;
		return 0;
	}

	*subids_p = subids = ep_alloc0(sizeof(guint32)*n);
	subids_overflow = subids + n;
	do switch(*r) {
		case '.':
			subid = 0;
			subids++;
			continue;
		case '1' : case '2' : case '3' : case '4' : case '5' :
		case '6' : case '7' : case '8' : case '9' : case '0' :
			subid *= 10;
			subid += *r - '0';

			if( subids >= subids_overflow ||  subid > 0xffffffff) {
				*subids_p=NULL;
				return 0;
			}

			*(subids) *= 10;
			*(subids) += *r - '0';
			continue;
		case '\0':
			break;
		default:
			return 0;
	} while(*r++);

	return n;
}


guint oid_encoded2subid(const guint8 *oid_bytes, gint oid_len, guint32** subids_p) {
	gint i;
	guint n = 1;
	gboolean is_first = TRUE;
	guint32* subids;
	guint32* subid_overflow;
	/*
	 * we cannot handle sub-ids greater than 32bytes
	 * have the subid in 64 bytes to be able to check the limit
	 */
	guint64 subid = 0;

	for (i=0; i<oid_len; i++) { if (! (oid_bytes[i] & 0x80 )) n++; }

	*subids_p = subids = ep_alloc(sizeof(guint32)*n);
	subid_overflow = subids+n;

	for (i=0; i<oid_len; i++){
		guint8 byte = oid_bytes[i];

		subid <<= 7;
		subid |= byte & 0x7F;

		if (byte & 0x80) {
			continue;
		}

		if (is_first) {
			guint32 subid0 = 0;

			if (subid >= 40) { subid0++; subid-=40; }
			if (subid >= 40) { subid0++; subid-=40; }

			*subids++ = subid0;

			is_first = FALSE;
		}

		if( subids >= subid_overflow || subid > 0xffffffff) {
			*subids_p=NULL;
			return 0;
		}

		*subids++ = (guint32)subid;
		subid = 0;
	}

	return n;
}

oid_info_t* oid_get(guint len, guint32* subids, guint* matched, guint* left) {
	oid_info_t* curr_oid = &oid_root;
	guint i;

	if(!(subids && *subids <= 2)) {
		*matched = 0;
		*left = len;
		return curr_oid;
	}

	for( i=0; i < len; i++) {
		oid_info_t* next_oid = emem_tree_lookup32(curr_oid->children,subids[i]);
		if (next_oid) {
			curr_oid = next_oid;
		} else {
			goto done;
		}
	}
done:
	*matched = i;
	*left = len - i;
	return curr_oid;
}


oid_info_t* oid_get_from_encoded(const guint8 *bytes, gint byteslen, guint32** subids_p, guint* matched_p, guint* left_p) {
	guint subids_len = oid_encoded2subid(bytes, byteslen, subids_p);
	return oid_get(subids_len, *subids_p, matched_p, left_p);
}

oid_info_t* oid_get_from_string(const gchar *oid_str, guint32** subids_p, guint* matched, guint* left) {
	guint subids_len = oid_string2subid(oid_str, subids_p);
	return oid_get(subids_len, *subids_p, matched, left);
}

const gchar *oid_resolved_from_encoded(const guint8 *oid, gint oid_len) {
	guint32 *subid_oid;
	guint subid_oid_length = oid_encoded2subid(oid, oid_len, &subid_oid);

	return oid_resolved(subid_oid_length, subid_oid);
}


guint oid_subid2encoded(guint subids_len, guint32* subids, guint8** bytes_p) {
	guint bytelen = 0;
	guint i;
	guint32 subid;
	guint8* b;

	if ( !subids || subids_len <= 0) {
		*bytes_p = NULL;
		return 0;
	}

	subid = (subids[0] * 40) + subids[1];
	i = 2;

	do {
		if (subid <= 0x0000007F) {
			bytelen += 1;
		} else if (subid <= 0x00003FFF ) {
			bytelen += 2;
		} else if (subid <= 0x001FFFFF ) {
			bytelen += 3;
		} else if (subid <= 0x0FFFFFFF ) {
			bytelen += 4;
		} else {
			bytelen += 5;
		}

			subid = subids[i];
	} while ( i++ < subids_len );

	*bytes_p = b = ep_alloc(bytelen);

	subid = (subids[0] * 40) + subids[1];
	i = 2;

	do {
		guint len;

		if ((subid <= 0x0000007F )) len = 1;
		else if ((subid <= 0x00003FFF )) len = 2;
		else if ((subid <= 0x001FFFFF )) len = 3;
		else if ((subid <= 0x0FFFFFFF )) len = 4;
		else len = 5;

		switch(len) {
			default: *bytes_p=NULL; return 0;
			case 5: *(b++) = ((subid & 0xF0000000) >> 28) | 0x80;
			case 4: *(b++) = ((subid & 0x0FE00000) >> 21) | 0x80;
			case 3: *(b++) = ((subid & 0x001FC000) >> 14) | 0x80;
			case 2: *(b++) = ((subid & 0x00003F10) >> 7)  | 0x80;
			case 1: *(b++) =   subid & 0x0000007F ; break;
		}

		subid = subids[i];
	} while ( i++ < subids_len);

	return bytelen;
}

const gchar* oid_encoded2string(const guint8* encoded, guint len) {
	guint32* subids;
	guint subids_len = oid_encoded2subid(encoded, len, &subids);

	if (subids_len) {
		return oid_subid2string(subids,subids_len);
	} else {
		return "";
	}
}



guint oid_string2encoded(const char *oid_str, guint8 **bytes) {
	guint32* subids;
	guint32 subids_len;
	guint byteslen;

		if ( ( subids_len = oid_string2subid(oid_str, &subids) )
			 &&
			 ( byteslen = oid_subid2encoded(subids_len, subids, bytes) )  ) {
			return byteslen;
		}
	return 0;
}

const gchar *oid_resolved_from_string(const gchar *oid_str) {
	guint32 *subid_oid;
	guint subid_oid_length = oid_string2subid(oid_str, &subid_oid);

	return oid_resolved(subid_oid_length, subid_oid);
}

const gchar *oid_resolved(guint32 num_subids, guint32* subids) {
	guint matched;
	guint left;
	oid_info_t* oid;

	if(! (subids && *subids <= 2 ))
		return "*** Malformed OID ***";

	oid = oid_get(num_subids, subids, &matched, &left);

	while (! oid->name ) {
		if (!(oid = oid->parent)) {
			return oid_subid2string(subids,num_subids);
		}
		left++;
		matched--;
	}

	if (left) {
		return ep_strdup_printf("%s.%s",
					oid->name ? oid->name : oid_subid2string(subids,matched),
					oid_subid2string(&(subids[matched]),left));
	} else {
		return oid->name ? oid->name : oid_subid2string(subids,matched);
	}
}

extern void oid_both(guint oid_len, guint32 *subids, char** resolved_p, char** numeric_p) {
	*resolved_p = (void*)oid_resolved(oid_len,subids);
	*numeric_p = (void*)oid_subid2string(subids,oid_len);
}

extern void oid_both_from_encoded(const guint8 *oid, gint oid_len, char** resolved_p, char** numeric_p) {
	guint32* subids;
	guint subids_len = oid_encoded2subid(oid, oid_len, &subids);
	*resolved_p = (void*)oid_resolved(subids_len,subids);
	*numeric_p = (void*)oid_subid2string(subids,subids_len);
}

extern void oid_both_from_string(const gchar *oid_str, char** resolved_p, char** numeric_p) {
	guint32* subids;
	guint subids_len = oid_string2subid(oid_str, &subids);
	*resolved_p = (void*)oid_resolved(subids_len,subids);
	*numeric_p = (void*)oid_subid2string(subids,subids_len);
}

/**
 * Fetch the default OID path.
 */
extern gchar *
oid_get_default_mib_path(void) {
#ifdef HAVE_LIBSMI
	GString* path_str;
	gchar *path_ret;
	char *path;
	guint i;

	path_str = g_string_new("");
	
	if (!prefs.load_smi_modules) {
		D(1,("OID resolution not enabled"));
		return path_str->str;
	}
#ifdef _WIN32
#define PATH_SEPARATOR ";"
	path = get_datafile_path("snmp\\mibs");
	g_string_append_printf(path_str, "%s;", path);
	g_free (path);

	path = get_persconffile_path("snmp\\mibs", FALSE, FALSE);
	g_string_append_printf(path_str, "%s", path);
	g_free (path);
#else
#define PATH_SEPARATOR ":"
	path = smiGetPath();
	g_string_append(path_str, "/usr/share/snmp/mibs");
	if (strlen(path) > 0 ) {
		g_string_append(path_str, PATH_SEPARATOR);
	}
	g_string_append_printf(path_str, "%s", path);
	free (path);
#endif

	for(i=0;i<num_smi_paths;i++) {
		if (!( smi_paths[i].name && *smi_paths[i].name))
			continue;

		g_string_append_printf(path_str,PATH_SEPARATOR "%s",smi_paths[i].name);
	}

	path_ret = path_str->str;
	g_string_free(path_str, FALSE);
	return path_ret;
#else /* HAVE_LIBSMI */
        return g_strdup("");
#endif
}

#ifdef DEBUG_OIDS
char* oid_test_a2b(guint32 num_subids, guint32* subids) {
	guint8* sub2enc;
	guint8* str2enc;
	guint32* enc2sub;
	guint32* str2sub;
	const char* sub2str = oid_subid2string(subids, num_subids);
	guint sub2enc_len = oid_subid2encoded(num_subids, subids,&sub2enc);
	guint enc2sub_len = oid_encoded2subid(sub2enc, sub2enc_len, &enc2sub);
	const char* enc2str = oid_encoded2string(sub2enc, sub2enc_len);
	guint str2enc_len = oid_string2encoded(sub2str,&str2enc);
	guint str2sub_len = oid_string2subid(sub2str,&str2sub);

	return ep_strdup_printf(
							"oid_subid2string=%s \n"
							"oid_subid2encoded=[%d]%s \n"
							"oid_encoded2subid=%s \n "
							"oid_encoded2string=%s \n"
							"oid_string2encoded=[%d]%s \n"
							"oid_string2subid=%s \n "
							,sub2str
							,sub2enc_len,bytestring_to_str(sub2enc, sub2enc_len, ':')
							,enc2sub ? oid_subid2string(enc2sub,enc2sub_len) : "-"
							,enc2str
							,str2enc_len,bytestring_to_str(str2enc, str2enc_len, ':')
							,str2sub ? oid_subid2string(str2sub,str2sub_len) : "-"
							);
}

void add_oid_debug_subtree(oid_info_t* oid_info, proto_tree *tree) {
	static const char* oid_kinds[] = { "Unknown", "Node", "Scalar", "Table", "Row", "Column", "Notification", "Group", "Compliance", "Capabilities"};
	static const char* key_types[] = {"OID_KEY_TYPE_WRONG","OID_KEY_TYPE_INTEGER",
										"OID_KEY_TYPE_FIXED_STRING","OID_KEY_TYPE_FIXED_BYTES","OID_KEY_TYPE_STRING",
										"OID_KEY_TYPE_BYTES","OID_KEY_TYPE_NSAP","OID_KEY_TYPE_OID","OID_KEY_TYPE_IPADDR"};
	proto_item* pi = proto_tree_add_text(tree,NULL,0,0,
	"OidInfo: Name='%s' sub-id=%u  kind=%s  hfid=%d",
	oid_info->name ? oid_info->name : "",
	oid_info->subid,
	oid_info->kind <= OID_KIND_CAPABILITIES ? oid_kinds[oid_info->kind] : "BROKEN",
	oid_info->value_hfid);
	proto_tree* pt = proto_item_add_subtree(pi,0);
	oid_key_t* key;

	for(key = oid_info->key; key; key = key->next) {
		proto_tree_add_text(pt,NULL,0,0,
		"Key: name='%s' num_subids=%d type=%s",
		key->name,
		key->key_type <= OID_KEY_TYPE_IPADDR ? key_types[key->key_type] : "BROKEN"
		);
	};

	if (oid_info->parent) {
		pi = proto_tree_add_text(pt,NULL,0,0,"Parent:");
		pt = proto_item_add_subtree(pi,0);
		add_oid_debug_subtree(oid_info->parent, pt);
	}
}
#endif

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * ex: set shiftwidth=8 tabstop=8 noexpandtab
 * :indentSize=8:tabSize=8:noTabs=false:
 */

