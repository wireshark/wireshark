/* packet-acse.c
*
* Routine to dissect OSI ACSE Protocol packets
*
* $Id: packet-acse.c,v 1.1 2004/01/23 10:15:37 guy Exp $
*
* Yuriy Sidelnikov <YSidelnikov@hotmail.com>
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
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <stdio.h>
#include <string.h>

#include "packet-acse.h"
#include "packet-frame.h"
#include "prefs.h"

#include <epan/strutil.h>

#include "asn1.h"
#include "format-oid.h"

#include "packet-ses.h"
extern const value_string ses_vals[];

/* acse header fields             */
static int proto_acse          = -1;
/*   type of session envelop */
static struct SESSION_DATA_STRUCTURE* session = NULL;
/* acse fields defining a sub tree */
static gint ett_acse           = -1;
static gint ett_acse_param     = -1;
static gint ett_acse_rc           = -1;
static gint ett_acse_ms           = -1;
static gint ett_acse_itm           = -1;

/*
----------------------------------------------------------------------------------------------------------*/
static dissector_handle_t ftam_handle = NULL;
static dissector_handle_t cmip_handle = NULL;
static dissector_handle_t app_handle = NULL;
static int hf_acse_type        = -1;
static int hf_cp_type_message_length = -1;
static int hf_protocol_version       = -1;

static  int  type_of_application = 0;


static const value_string acse_vals[] =
{
  {ACSE_AARQ,  "A-associate request" },
  {ACSE_AARE,  "A-associate response" },
  {ACSE_RLRQ,  "A-reliase request" },
  {ACSE_RLRE,  "A-reliase response" },
  {ACSE_ABRT,  "A-abort" },
  {0,             NULL           }
};

static const value_string cr_vals[] =
{
  {MODE_SELECTOR, "Mode Selector"},
  {SEQUENCE_TOP, "Sequence"},
  {SET_TOP, "Set"},
  {0, NULL}
};

static const value_string request_sequence_top_vals[] =
{
  {PROTOCOL_VERSION, "Protocol version"},
  {APPLICATION_CONTEXT_NAME, "Application context name"},
  {CALLED_AP_TITLE, "Called AP title"},
  {CALLED_AE_QUALIFIER, "Called AE qualifier"},
  {CALLED_AP_INVOKATION_ID, "Called AP invokation id"},
  {CALLED_AE_INVOKATION_ID, "Called AE invokation id"},
  {CALLING_AP_TITLE, "Calling AP title"},
  {CALLING_AE_QUALIFIER, "Calling AE qualifier"},
  {CALLING_AP_INVOKATION_ID, "Calling AP invokation id"},
  {CALLING_AE_INVOKATION_ID, "Calling AE invokation id"},
  {IMPLEMENTATION_INFORMATION,"Implementation information"},
  {USER_INFORMATION,"User information"},
  {0, NULL}
};
static const value_string response_sequence_top_vals[] =
{
  {PROTOCOL_VERSION, "Protocol version"},
  {APPLICATION_CONTEXT_NAME, "Application context name"},
  {ACSE_RESULT, "Result"},
  {ACSE_RESULT_SOURCE_DIAGNOSTIC, "Result source diagnostic"},
  {RESPONDING_AP_TITLE, "Responding AP title"},
  {RESPONDING_AE_QUALIFIER, "Responding AE qualifier"},
  {RESPONDING_AP_INVOKATION_ID, "Responding AP invokation id"},
  {RESPONDING_AE_INVOKATION_ID, "Responding AE invokation id"},
  {IMPLEMENTATION_INFORMATION,"Implementation information"},
  {USER_INFORMATION,"User information"},
  {0, NULL}
};
static const value_string associate_result_values_vals[] =
{
  {PRESENTATION_RESULT_ACCEPTANCE,"Accepted"},
  {PRESENTATION_RESULT_USER_REJECTION,"Rejected permanent"},
  {PRESENTATION_RESULT_PROVIDER_REJECTION,"Rejected transient"},
  {0, NULL}
};

static const value_string acse_associate_source_diagnostic_vals[] =
{
  {ACSE_SERVICE_USER,"Acse service user"},
  {ACSE_SERVICE_PROVIDER,"Acse service provider"},
  {0, NULL}
};
static const value_string acse_service_user_values_vals[] =
{
  {ACSE_NULL,"null"},
  {ACSE_NO_REASON_GIVEN,"No reason given"},
  {ACSE_APPLICATION_CONTEXT_NAME_NOT_SUPPORTED,"Application context name not 
supported"},
  {ACSE_CALLING_AP_TITLE_NOT_RECOGNIZED,"Calling AP title not recognized"},
  {ACSE_CALLING_AP_INVOKATION_IDENTIFIER_NOT_RECOGNIZED,"Calling AP 
invokation identifier not recognized"},
  {ACSE_CALLING_AE_QUALIFIER_NOT_RECOGNIZED,"Calling AE qualifier not 
recognized"},
  {ACSE_CALLING_AE_INVOKATION_IDENTIFIER_NOT_RECOGNIZED,"Calling AE 
invokation identifier not recognized"},
  {ACSE_CALLED_AP_TITLE_NOT_RECOGNIZED,"Called AP title not recognized"},
  {ACSE_CALLED_AP_INVOKATION_IDENTIFIER_NOT_RECOGNIZED,"Called AP invokation 
identifier not recognized"},
  {ACSE_CALLED_AE_QUALIFIER_NOT_RECOGNIZED,"Called AE qualifier not 
recognized"},
  {ACSE_CALLED_AE_INVOKATION_IDENTIFIER_NOT_RECOGNIZED,"Called AE invokation 
identifier not recognized"},
  {0, NULL}
};
static const value_string acse_service_provider_values_vals[] =
{
  {ACSE_NULL,"Null"},
  {ACSE_NO_REASON_GIVEN,"No reason given"},
  {ACSE_NO_COMMON_ACSE_VERSION,"no_common_acse_version"},
  {0, NULL}
};

static const value_string acse_user_information_vals[] =
{
  {ACSE_EXTERNAL_USER,"External"},
  {0, NULL}
};
static const value_string sequence_list_vals[] =
{
  {PRESENTATION_CONTEXT_IDENTIFIER,"Presentation context identifier"},
  {ABSTRACT_SYNTAX_NAME,"Abstract syntax name"},
  {TRANSFER_SYNTAX_NAMES,"Transfer syntax names"},
  {0, NULL}
};
static const value_string presentation_context_definition_vals[] =
{
  {SEQUENCE, "Sequence"},
  {0, NULL}
};
static const value_string user_data_values_vals[] =
{
  {SIMPLY_ENCODED_DATA,"Simply encoded data"},
  {FULLY_ENCODED_DATA,"Fully encoded data "},
  {0, NULL}
};
static const value_string presentation_data_values[] =
{
  {PRESENTATION_CONTEXT_IDENTIFIER,"Presentation context identifier"},
  {SINGLE_ASN1_TYPE,"Single ASN.1 type"},
  {OCTET_ALIGNED,"Octet aligned"},
  {ARBITRARY,"Arbitrary"},
  {ABSTRACT_SYNTAX_NAME,"Abstract syntax name"},
  {0, NULL}
};
static const value_string release_request_reason[] =
{
  {RRR_NORMAL,"Normal"},
  {RRR_URGENT,"Urgent"},
  {RRR_USER_DEFINED,"User defined"},
  {0, NULL}
};
static const value_string release_response_reason[] =
{
  {RRPR_NORMAL,"Normal"},
  {RRPR_URGENT,"Not finished"},
  {RRPR_USER_DEFINED,"User defined"},
  {0, NULL}
};

static const value_string abort_reason[] =
{
  {ABRT_ACSE_SERVICE_USER,"Acse service user"},
  {ABRT_ACSE_SERVICE_PROVIDER,"Acse service provider"},
  {0, NULL}
};

static const value_string type_app[] =
{
	{0,""},             /*   for unknown dissector   */
	{FTAM_APP,"FTAM"},
	{CMIP_APP,"CMIP"},
	{0, NULL}
};

/*      pointers for acse dissector  */
static proto_tree *global_tree  = NULL;
static packet_info *global_pinfo = NULL;
/* dissector for data */
static dissector_handle_t data_handle;
static void
call_app_dissector(tvbuff_t *tvb, int offset, guint16 param_len,
    packet_info *pinfo, proto_tree *tree, proto_tree *param_tree)
{
	char* name_of_app_dissect;
	name_of_app_dissect = val_to_str(type_of_application, type_app,"Unknown 
type of application dissector (0x%02x)");
	/* do we have OSI app packet dissector ? */
	if(!app_handle || !type_of_application)
	{

		/* No - display as data */
		if (tree)
		{
			proto_tree_add_text(param_tree, tvb, offset, param_len,
			    "%s dissector is not available",name_of_app_dissect);
		}
	}
	else
	{
			/* Yes - call application dissector */
			tvbuff_t *next_tvb;

			next_tvb = tvb_new_subset(tvb, offset, param_len,
			    param_len);
			TRY
			{
				call_dissector(app_handle, next_tvb, pinfo,
				    tree);
			}
			CATCH_ALL
			{
				show_exception(tvb, pinfo, tree, EXCEPT_CODE);
			}
			ENDTRY;
	}
}
static char*
string_to_hex(unsigned char * in,char * out,int len)
{
	char ascii[MAXSTRING];
	int  i;
	memset(&ascii,0x00,sizeof(ascii));
for(i=0;i<len;i++)
			{
	unsigned char o_out = *(in+i);
    sprintf(out+(i<<1),"%.2x",*  (in+i));
	if(  ( (o_out) >= 'a') & ( (o_out) <='z')  ||
		 ( (o_out) >= 'A') & ( (o_out) <='Z')  ||
		 ( (o_out) >= '0') & ( (o_out) <='9')
	   )
					{
					ascii[i] = o_out;
					}
				else
					{
					ascii[i] = '.';
					}

			}
		strcat(out," ");
		strcat(out,ascii);
    return out;
}

static int read_length(ASN1_SCK *a, proto_tree *tree, int hf_id, guint *len)
{
  guint length = 0;
  gboolean def = FALSE;
  int start = a->offset;
  int ret;

  ret = asn1_length_decode(a, &def, &length);
  if (ret != ASN1_ERR_NOERROR)
  {
    if (tree)
	{
      proto_tree_add_text(tree, a->tvb, start, 0,
        "%s: ERROR: Couldn't parse length: %s",
        proto_registrar_get_name(hf_id), asn1_err_to_str(ret));
    }
    return ret;
  }

  if (len)
    *len = length;

  if (tree && hf_id)
    proto_tree_add_uint(tree, hf_id, a->tvb, start, a->offset-start,
length);

  return ASN1_ERR_NOERROR;
}
static int read_integer_value(ASN1_SCK *a, proto_tree *tree, int hf_id,
	proto_item **new_item, guint *i, int start, guint length)
{
  guint integer = 0;
  proto_item *temp_item = NULL;
  int ret;

  ret = asn1_uint32_value_decode(a, length, &integer);
  if (ret != ASN1_ERR_NOERROR)
  {
    if (tree)
	{
      proto_tree_add_text(tree, a->tvb, start, 0,
       "%s: ERROR: Couldn't parse value: %s",
        proto_registrar_get_name(hf_id), asn1_err_to_str(ret));
    }
    return ret;
  }

  if (i)
    *i = integer;

  if (tree && hf_id)
    temp_item = proto_tree_add_uint(tree, hf_id, a->tvb, start,
a->offset-start, integer);

  if (new_item)
    *new_item = temp_item;

  return ASN1_ERR_NOERROR;
}

static int read_integer(ASN1_SCK *a, proto_tree *tree, int hf_id,
	proto_item **new_item, guint *i)
{
  guint cls, con, tag;
  gboolean def;
  guint length;
  int start = a->offset;
  int ret;

  ret = asn1_header_decode(a, &cls, &con, &tag, &def, &length);
  if (ret != ASN1_ERR_NOERROR)
  {
    if (tree)
	{
      proto_tree_add_text(tree, a->tvb, start, 0,
        "%s: ERROR: Couldn't parse header: %s",
        (hf_id != -1) ? proto_registrar_get_name(hf_id) : "LDAP message",
        asn1_err_to_str(ret));
    }
    return ret;
  }

  return read_integer_value(a, tree, hf_id, new_item, i, start, length);
}
/*   display asn.1 Integer type */
static void
show_integer(ASN1_SCK *asn,proto_tree *acse_tree,tvbuff_t *tvb,int
*offset,int item_len)
{
	  proto_tree *acse_tree_itm = NULL;
	  proto_item *itm;
	  int       ret;
	  int		save_len = item_len;
	  int		off      = *offset;
	  itm = proto_tree_add_text(acse_tree, tvb, *offset, item_len,
										"Integer");
	  acse_tree_itm = proto_item_add_subtree(itm, ett_acse_itm);
	  ret = read_integer(asn,acse_tree_itm,0,NULL,&item_len);
	  if (ret == ASN1_ERR_NOERROR )
			{
				*offset = asn->offset;
				itm = proto_tree_add_text(acse_tree_itm, tvb, (*offset)-item_len,
											item_len,
											"Integer value: %u",item_len);
			}
	  else
			{
		  /* can't dissect item. Skip it. */
		  *offset = off+ save_len;
			}

}
static void
show_protocol_version(ASN1_SCK *asn,proto_tree *acse_tree,tvbuff_t *tvb,int
*offset,int item_len,int tag)
{
	  proto_tree *acse_tree_itm = NULL;
	  proto_item *itm;
	  guint16       flags;
	  gint length;
/* do we have enough bytes to dissect this item ? */
			if( ( length = tvb_reported_length_remaining(tvb, *offset))  <
										(asn->offset -*offset)+ item_len )
			{
					proto_tree_add_text(acse_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					return;
			}

	  itm = proto_tree_add_text(acse_tree, tvb, *offset,(asn->offset -*offset)+
								item_len,
								val_to_str(tag, request_sequence_top_vals,"Unknown item (0x%02x)"));
	  acse_tree_itm = proto_item_add_subtree(itm, ett_acse_itm);
	  *offset = asn->offset;
	  flags = tvb_get_ntohs(tvb, *offset);
	  proto_tree_add_boolean(acse_tree_itm,hf_protocol_version, tvb, *offset,
							2, flags);
	  *offset = *offset + item_len;
	  asn->offset = *offset;
}
static void
print_oid_value(ASN1_SCK *asn,proto_tree *acse_tree,tvbuff_t *tvb,int
*offset,int item_len)
{
	guint		ret;
	subid_t		*oid;
	guint		len;
	gchar		*display_string;
	guint		length;
	guint		start=*offset;

		ret = asn1_oid_value_decode (asn, item_len, &oid, &len);
		if (ret != ASN1_ERR_NOERROR)
		{
			return ;
		}
		length = asn->offset - start;
		display_string = format_oid(oid, len);
		proto_tree_add_text(acse_tree, tvb, *offset,length,"Value:%s",
							display_string);
		g_free(display_string);
		(*offset)=start+item_len;
		asn->offset = (*offset);
}
static void
print_oid(ASN1_SCK *asn,proto_tree *acse_tree,tvbuff_t *tvb,int *offset,int
item_len,gchar* d_s)
{
	guint		ret;
	subid_t		*oid;
	guint		len;
	guint		nbytes;
	gchar		*display_string;
	guint		length;
	guint		start=*offset;

		ret = asn1_oid_decode ( asn, &oid, &len, &nbytes);

		if (ret != ASN1_ERR_NOERROR)
		{
			return ;
		}
		length = asn->offset - start;
		display_string = format_oid(oid, len);
		proto_tree_add_text(acse_tree, tvb, *offset,length,"Value:%s",
							display_string);
		if(d_s)
		{
			/*   copy OID   */
			strcpy(d_s,display_string);
		}
		g_free(display_string);
		(*offset)=start+item_len;
		asn->offset = (*offset);
}

static void
print_value(proto_tree *acse_tree,tvbuff_t *tvb,int
*offset,int item_len)
{
	  char    tmp[MAXSTRING];
		string_to_hex((char*)tvb_get_ptr(tvb,*offset,item_len),tmp,item_len);
		proto_tree_add_text(acse_tree, tvb, *offset, item_len, tmp);
}
static int
get_integer_value(ASN1_SCK *asn,int length,int *offset)
{
	int off = *offset;
	int asn_off = asn->offset;
	int item_len = -1;
	int ret;
	/* align   pointers */
	*offset=asn->offset;
	ret = asn1_uint32_value_decode(asn, length, &item_len);
	/* return to present position */
	*offset = off;
	asn->offset = asn_off;

    if (ret != ASN1_ERR_NOERROR )
	{
		return -1;
	}
	else
	{
		return item_len;
	}

}
static void
show_fully_encoded_seq(ASN1_SCK *asn,proto_tree *acse_tree,tvbuff_t *tvb,int
*offset,int item_len)
{
	  proto_tree *acse_tree_ms = NULL;
	  guint length;
	  guint   type;
	  proto_item *ms;
	  guint   new_item_len;
	  guint   start = *offset;
	  guint   header_len;
	  guint   acse = 0;      /*   no acse   id   */
	  int		old_offset;
			/*  print seq */
			while ( item_len > 0 && tvb_reported_length_remaining(tvb, *offset) > 0 )
			{
				old_offset = *offset ;
			/*  get item type  */
			type = tvb_get_guint8(tvb, *offset);
			/* skip type */
			(*offset)++;
			asn->offset = *offset;
			/* get length  */
				if (read_length(asn, acse_tree, 0, &new_item_len) != ASN1_ERR_NOERROR)
				{
					(*offset)=start+item_len;
					asn->offset = (*offset);
					return  ;
				}
			/* do we have enough bytes to dissect ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  <
														new_item_len )
			{
					proto_tree_add_text(acse_tree, tvb, *offset, new_item_len,
							"Wrong item.Need %u bytes but have %u", new_item_len,length);
					(*offset)=start+item_len;
					asn->offset = (*offset);
				    return ;
			}
				header_len = asn->offset - (*offset) +1;
					ms = proto_tree_add_text(acse_tree, tvb, *offset-1,
										new_item_len+(asn->offset-*offset)+1,
										val_to_str(type, presentation_data_values,
										"Unknown item (0x%02x)"));
				acse_tree_ms = proto_item_add_subtree(ms, ett_acse_ms);
				*offset = asn->offset;


			switch(type)
				{
			case PRESENTATION_CONTEXT_IDENTIFIER:
				{
				acse	=	get_integer_value(asn,new_item_len,offset);
				print_value(acse_tree_ms,tvb,offset,new_item_len);
				}
					break;
			case ABSTRACT_SYNTAX_NAME:
				print_oid_value(asn,acse_tree_ms,tvb,offset,new_item_len);
					break;

			case OCTET_ALIGNED:
				break;
			case SINGLE_ASN1_TYPE:
				{
						proto_item *acse_ms;
					/*  yes, we have to call ACSE dissector    */
				acse_ms = proto_tree_add_text(acse_tree_ms, tvb, *offset,
										new_item_len+(asn->offset-*offset),
										"user data");
					/*  call acse dissector  */
				call_app_dissector(tvb,*offset,new_item_len,global_pinfo,global_tree,acse_tree_ms);
				}
					break;
			case ARBITRARY:
				print_value(acse_tree_ms,tvb,offset,new_item_len);
					break;
			default:
					proto_tree_add_text(acse_tree, tvb, *offset,
										new_item_len+(asn->offset-*offset),
					"Unknown asn.1 parameter: (0x%02x)", type);
				}
				*offset = old_offset+new_item_len+header_len;
				item_len-=new_item_len+header_len;
			}
			/*   align the pointer */
			(*offset)=start+item_len;
			asn->offset = (*offset);

}

static void
show_acse_user_information(ASN1_SCK *asn,proto_tree
*acse_tree,tvbuff_t *tvb,int *offset,int item_len)
{
	  proto_tree *acse_tree_ms = NULL;
	  proto_tree *acse_tree_ab = NULL;
	  guint length;
	  guint   type;
	  proto_item *ms;
	  proto_item *ab;
	  guint   new_item_len;
	  guint   code_item_len;
	  guint   start = *offset;
	  guint   header_len;
			/*  get item type  */
			type = tvb_get_guint8(tvb, *offset) & 0x1f;
			/* skip type */
			(*offset)++;
			asn->offset = *offset;
			/* get length  */
				if (read_length(asn, acse_tree, 0, &new_item_len) != ASN1_ERR_NOERROR)
				{
					(*offset)=start+item_len;
					asn->offset = (*offset);
					return  ;
				}

			/* do we have enough bytes to dissect ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  <
														new_item_len )
			{
					proto_tree_add_text(acse_tree, tvb, *offset, new_item_len,
							"Wrong item.Need %u bytes but have %u", new_item_len,length);
					(*offset)=start+item_len;
					asn->offset = (*offset);
				    return ;
			}
				header_len = asn->offset - (*offset) +1;
				ms = proto_tree_add_text(acse_tree, tvb, *offset-1,
										new_item_len+(asn->offset-*offset)+1,
										val_to_str(type,response_sequence_top_vals,
										"Unknown item (0x%02x)"));
				acse_tree_ms = proto_item_add_subtree(ms, ett_acse_ms);
				*offset = asn->offset;
				/*  get item type  */
				type = tvb_get_guint8(tvb, *offset) & 0x1f;
				/* do we have user or provider abort ?  */
				ab = proto_tree_add_text(acse_tree_ms, tvb, *offset,
										new_item_len+(asn->offset-*offset),
										val_to_str(type,acse_user_information_vals,
										"Unknown item (0x%02x)"));
				acse_tree_ab = proto_item_add_subtree(ab, ett_acse_ms);

				if(type!= ACSE_EXTERNAL)
				{
					(*offset)=start+item_len;
					asn->offset = (*offset);
					return  ;
				}

				/*  skip type of item*/
				(*offset)++;
				asn->offset = *offset;
				/* get length  */
				if (read_length(asn, acse_tree_ab, 0, &code_item_len) != 
ASN1_ERR_NOERROR)
				{
					(*offset)=start+item_len;
					asn->offset = (*offset);
					return  ;
				}
				/* do we have enough bytes to dissect ? */
				if( ( length =tvb_reported_length_remaining(tvb, *offset))  <
														code_item_len )
				{
					proto_tree_add_text(acse_tree_ab, tvb, *offset, code_item_len,
							"Wrong item.Need %u bytes but have %u", code_item_len,length);
					(*offset)=start+item_len;
					asn->offset = (*offset);
				    return ;
				}
				*offset = asn->offset;

				show_fully_encoded_seq(asn,acse_tree_ab,tvb,offset,code_item_len);
			/*   align the pointer */
			(*offset)=start+item_len;
			asn->offset = (*offset);
}

static void
show_acse_result_source_diagnostic(ASN1_SCK *asn,proto_tree
*acse_tree,tvbuff_t *tvb,int *offset,int item_len)
{
	  proto_tree *acse_tree_ms = NULL;
	  proto_tree *acse_tree_ab = NULL;
	  guint length;
	  guint   type;
	  proto_item *ms;
	  proto_item *ab;
	  guint   new_item_len;
	  guint   code_item_len;
	  guint   start = *offset;
	  guint   header_len;
	  proto_tree *acse_tree_pr = NULL;
	  proto_item *pr;
	  int	value;
			/*  get item type  */
			type = tvb_get_guint8(tvb, *offset) & 0x1f;
			/* skip type */
			(*offset)++;
			asn->offset = *offset;
			/* get length  */
				if (read_length(asn, acse_tree, 0, &new_item_len) != ASN1_ERR_NOERROR)
				{
					(*offset)=start+item_len;
					asn->offset = (*offset);
					return  ;
				}

			/* do we have enough bytes to dissect ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  <
														new_item_len )
			{
					proto_tree_add_text(acse_tree, tvb, *offset, new_item_len,
							"Wrong item.Need %u bytes but have %u", new_item_len,length);
					(*offset)=start+item_len;
					asn->offset = (*offset);
				    return ;
			}
				header_len = asn->offset - (*offset) +1;
				ms = proto_tree_add_text(acse_tree, tvb, *offset-1,
										new_item_len+(asn->offset-*offset)+1,
										val_to_str(type,response_sequence_top_vals,
										"Unknown item (0x%02x)"));
				acse_tree_ms = proto_item_add_subtree(ms, ett_acse_ms);
				*offset = asn->offset;
			/*  get item type  */
			type = tvb_get_guint8(tvb, *offset) & 0x1f;
			/* do we have user or provider abort ?  */
				ab = proto_tree_add_text(acse_tree_ms, tvb, *offset,
										new_item_len+(asn->offset-*offset),
										val_to_str(type,acse_associate_source_diagnostic_vals,
										"Unknown item (0x%02x)"));
				acse_tree_ab = proto_item_add_subtree(ab, ett_acse_ms);

				/*  skip type of abort*/
				(*offset)++;
				asn->offset = *offset;
				/* get length  */
				if (read_length(asn, acse_tree, 0, &code_item_len) != ASN1_ERR_NOERROR)
				{
					(*offset)=start+item_len;
					asn->offset = (*offset);
					return  ;
				}
				*offset = asn->offset;
				/* do we have enough bytes to dissect ? */
				if( ( length =tvb_reported_length_remaining(tvb, *offset))  <
														code_item_len )
				{
					proto_tree_add_text(acse_tree, tvb, *offset, code_item_len,
							"Wrong item.Need %u bytes but have %u", code_item_len,length);
					(*offset)=start+item_len;
					asn->offset = (*offset);
				    return ;
				}

				/*  skip type of constant*/
				(*offset)++;
				asn->offset = *offset;
				/* get length  */
				if (read_length(asn, acse_tree_ab, 0, &code_item_len) != 
ASN1_ERR_NOERROR)
				{
					(*offset)=start+item_len;
					asn->offset = (*offset);
					return  ;
				}
				/* do we have enough bytes to dissect ? */
				if( ( length =tvb_reported_length_remaining(tvb, *offset))  <
														code_item_len )
				{
					proto_tree_add_text(acse_tree_ab, tvb, *offset, code_item_len,
							"Wrong item.Need %u bytes but have %u", code_item_len,length);
					(*offset)=start+item_len;
					asn->offset = (*offset);
				    return ;
				}
				*offset = asn->offset;
			    value	=	get_integer_value(asn,code_item_len,offset);
				if(type == ACSE_SERVICE_USER )
				{
				pr = proto_tree_add_text(acse_tree_ab, tvb, *offset,
								code_item_len+(asn->offset-*offset),
								val_to_str(value , acse_service_user_values_vals,
								"Unknown item (0x%02x)"));
				}
				else
				{
				pr = proto_tree_add_text(acse_tree_ab, tvb, *offset,
								code_item_len+(asn->offset-*offset),
								val_to_str(value , acse_service_provider_values_vals,
								"Unknown item (0x%02x)"));
				}

				acse_tree_pr = proto_item_add_subtree(pr, ett_acse_ms);
				print_value(acse_tree_pr,tvb,offset,code_item_len);

				*offset = start+new_item_len+header_len;
				item_len-=new_item_len+header_len;
			/*   align the pointer */
			(*offset)=start+item_len;
			asn->offset = (*offset);

}
static void
show_acse_result(ASN1_SCK *asn,proto_tree
*acse_tree,tvbuff_t *tvb,int *offset,int item_len)
{
	  proto_tree *acse_tree_ms = NULL;
	  guint length;
	  guint   type;
	  proto_item *ms;
	  guint   new_item_len;
	  guint   code_item_len;
	  guint   start = *offset;
	  guint   header_len;
	  proto_tree *acse_tree_pr = NULL;
	  proto_item *pr;
	  int	value;
			/*  get item type  */
			type = tvb_get_guint8(tvb, *offset) & 0x1f;
			/* skip type */
			(*offset)++;
			asn->offset = *offset;
			/* get length  */
				if (read_length(asn, acse_tree, 0, &new_item_len) != ASN1_ERR_NOERROR)
				{
					(*offset)=start+item_len;
					asn->offset = (*offset);
					return  ;
				}

			/* do we have enough bytes to dissect ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  <
														new_item_len )
			{
					proto_tree_add_text(acse_tree, tvb, *offset, new_item_len,
							"Wrong item.Need %u bytes but have %u", new_item_len,length);
					(*offset)=start+item_len;
					asn->offset = (*offset);
				    return ;
			}
				header_len = asn->offset - (*offset) +1;
				ms = proto_tree_add_text(acse_tree, tvb, *offset-1,
										new_item_len+(asn->offset-*offset)+1,
										val_to_str(type,response_sequence_top_vals,
										"Unknown item (0x%02x)"));
				acse_tree_ms = proto_item_add_subtree(ms, ett_acse_ms);
				*offset = asn->offset;
				/*  skip type */
				(*offset)++;
				asn->offset = *offset;
				/* get length  */
				if (read_length(asn, acse_tree, 0, &code_item_len) != ASN1_ERR_NOERROR)
				{
					(*offset)=start+item_len;
					asn->offset = (*offset);
					return  ;
				}
				/* do we have enough bytes to dissect ? */
				if( ( length =tvb_reported_length_remaining(tvb, *offset))  <
														code_item_len )
				{
					proto_tree_add_text(acse_tree, tvb, *offset, code_item_len,
							"Wrong item.Need %u bytes but have %u", code_item_len,length);
					(*offset)=start+item_len;
					asn->offset = (*offset);
				    return ;
				}
				*offset = asn->offset;
			    value	=	get_integer_value(asn,code_item_len,offset);
				pr = proto_tree_add_text(acse_tree_ms, tvb, *offset,
								code_item_len+(asn->offset-*offset),
								val_to_str(value , associate_result_values_vals,
								"Unknown item (0x%02x)"));
				acse_tree_pr = proto_item_add_subtree(pr, ett_acse_ms);
				print_value(acse_tree_pr,tvb,offset,code_item_len);

				*offset = start+new_item_len+header_len;
				item_len-=new_item_len+header_len;
			/*   align the pointer */
			(*offset)=start+item_len;
			asn->offset = (*offset);
}

static void
show_oid(ASN1_SCK *asn,proto_tree
*acse_tree,tvbuff_t *tvb,int *offset,int item_len,const value_string* 
v_s,gchar* oid)
{
	  proto_tree *acse_tree_ms = NULL;
	  guint length;
	  guint   type;
	  proto_item *ms;
	  guint   new_item_len;
	  guint   start = *offset;
	  guint   header_len;
	  int		old_offset;
				old_offset = *offset ;
			/*  get item type  */
			type = tvb_get_guint8(tvb, *offset) & 0x1f;
			/* skip type */
			(*offset)++;
			asn->offset = *offset;
			/* get length  */
				if (read_length(asn, acse_tree, 0, &new_item_len) != ASN1_ERR_NOERROR)
				{
					(*offset)=start+item_len;
					asn->offset = (*offset);
					return  ;
				}

			/* do we have enough bytes to dissect ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  <
														new_item_len )
			{
					proto_tree_add_text(acse_tree, tvb, *offset, new_item_len,
							"Wrong item.Need %u bytes but have %u", new_item_len,length);
					(*offset)=start+item_len;
					asn->offset = (*offset);
				    return ;
			}
				header_len = asn->offset - (*offset) +1;
				ms = proto_tree_add_text(acse_tree, tvb, *offset-1,
										new_item_len+(asn->offset-*offset)+1,
										val_to_str(type, v_s,
										"Unknown item (0x%02x)"));
				acse_tree_ms = proto_item_add_subtree(ms, ett_acse_ms);
				*offset = asn->offset;
				print_oid(asn,acse_tree_ms,tvb,offset,new_item_len,oid);
				*offset = old_offset+new_item_len+header_len;
				item_len-=new_item_len+header_len;
			/*   align the pointer */
			(*offset)=start+item_len;
			asn->offset = (*offset);
}
static void
show_fully_encoded_data(ASN1_SCK *asn,proto_tree *acse_tree,tvbuff_t
*tvb,int *offset,int item_len)
{
	  proto_tree *acse_tree_ms = NULL;
	  proto_tree *acse_tree_pc = NULL;
	  gint    length;
	  guint   type;
	  guint   header_len;
	  proto_item *ms;
	  gint   new_item_len;
	  guint   start = asn->offset;
	  guint	  item_length = item_len;
	  acse_tree_pc = acse_tree;

/* do we have enough bytes to dissect ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < item_len )
			{
					proto_tree_add_text(acse_tree_pc, tvb, *offset, item_len,
							"Wrong item.Need %u bytes but have %u", item_len,length);
					/*   align the pointer */
					(*offset)=start+item_length;
					asn->offset = (*offset);
					return ;
			}
			*offset =asn->offset;
			start = *offset;
			/*  read the rest */
			while ( item_len > 0 && tvb_reported_length_remaining(tvb, *offset) > 0 )
			{
				int old_offset = *offset;
			/*  get item type  */
			type = tvb_get_guint8(tvb, *offset);
			/* skip type */
			(*offset)++;
			asn->offset = *offset;
			/* get length  */
				if (read_length(asn, acse_tree_pc, 0, &new_item_len) !=
								ASN1_ERR_NOERROR)
				{
					/*   align the pointer */
					(*offset)=start+item_length;
					asn->offset = (*offset);
					return  ;
				}
				header_len = asn->offset - (*offset) +1;
			/* do we have enough bytes to dissect ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  <
														new_item_len )
			{
					proto_tree_add_text(acse_tree_pc, tvb, *offset, new_item_len,
							"Wrong item.Need %u bytes but have %u", new_item_len,length);
					/*   align the pointer */
					(*offset)=start+item_length;
					asn->offset = (*offset);
					return ;
			}
				ms = proto_tree_add_text(acse_tree_pc, tvb, *offset-1,
										new_item_len+(asn->offset-*offset)+1,
										val_to_str(type, presentation_context_definition_vals,
										"Unknown item (0x%02x)"));
				acse_tree_ms = proto_item_add_subtree(ms, ett_acse_ms);
				*offset = asn->offset;


			switch(type)
				{

			case SEQUENCE:
			show_fully_encoded_seq(asn,acse_tree_ms,tvb,offset,new_item_len);
			*offset = old_offset+(new_item_len+header_len);
					break;

			default:
					proto_tree_add_text(acse_tree_ms, tvb, *offset,
										new_item_len+(asn->offset-*offset),
					"Unknown asn.1 parameter: (0x%02x)", type);
					*offset = old_offset+(new_item_len+header_len);
				}
				item_len = item_len -  (new_item_len+header_len);

			}


					/*   align the pointer */
					(*offset)=start+item_length;
					asn->offset = (*offset);
}
static void
show_abort_reason(ASN1_SCK *asn,proto_tree *acse_tree,tvbuff_t
*tvb,int *offset,int item_len)
{
	gint		length;
	gint		value;
    proto_tree	*acse_tree_pc = NULL;
	proto_item	*itu;
	gint		new_item_len;
	guint		start = *offset;
	int			save_len = item_len;
/* do we have enough bytes to dissect this item ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < item_len )
			{
					proto_tree_add_text(acse_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
							*offset = asn->offset;
							return;
			}

			if(item_len <= 0)
			{
					proto_tree_add_text(acse_tree, tvb, *offset, item_len,
							"Reason not specified");
							*offset = asn->offset;
							return;
			}
			itu = proto_tree_add_text(acse_tree, tvb, *offset,ABORT_REASON_LEN,
					"Reason");
			acse_tree_pc = proto_item_add_subtree(itu, ett_acse_ms);
			(*offset)++; /* skip type  */
			asn->offset =  *offset;
			item_len--;
			/* get length  */
				if (read_length(asn, acse_tree_pc, 0, &new_item_len) !=
								ASN1_ERR_NOERROR)
				{
							*offset = asn->offset;
							return;
				}
			/*  try to get reason  */
			value	=	get_integer_value(asn,new_item_len,offset);

			proto_tree_add_text(acse_tree_pc, tvb, *offset+1,new_item_len,
					val_to_str(value,abort_reason,"Unknown item (0x%02x)"));
			item_len-=(asn->offset-*offset)+new_item_len;
			*offset = asn->offset+new_item_len;
			asn->offset = *offset;
			/*  do we have User information field  ?  */
			if(item_len > 0)
			{
				show_acse_user_information(asn,acse_tree,tvb,offset,item_len);
			}
			/*   align the pointer */
			(*offset)=start+save_len;
			asn->offset = (*offset);
}

static void
show_disconnect_pdu(ASN1_SCK *asn,proto_tree *acse_tree,tvbuff_t
*tvb,int *offset,int item_len)
{
	gint		length;
	gint		value;
    proto_tree	*acse_tree_pc = NULL;
	proto_item	*itu;
	gint		new_item_len;
	guint		start = *offset;
	int			save_len = item_len;
/* do we have enough bytes to dissect this item ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < item_len )
			{
					proto_tree_add_text(acse_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
							*offset = asn->offset;
							return;
			}

			if(item_len <= 0)
			{
					proto_tree_add_text(acse_tree, tvb, *offset, item_len,
							"Reason not specified");
							*offset = asn->offset;
							return;
			}
			itu = proto_tree_add_text(acse_tree, tvb, *offset,ABORT_REASON_LEN,
					"Reason");
			acse_tree_pc = proto_item_add_subtree(itu, ett_acse_ms);
			(*offset)++; /* skip type  */
			asn->offset =  *offset;
			item_len--;
			/* get length  */
				if (read_length(asn, acse_tree_pc, 0, &new_item_len) !=
								ASN1_ERR_NOERROR)
				{
							*offset = asn->offset;
							return;
				}
			/*  try to get reason  */
			value	=	get_integer_value(asn,new_item_len,offset);

			proto_tree_add_text(acse_tree_pc, tvb, *offset+1,new_item_len,
					val_to_str(value,release_response_reason,"Unknown item (0x%02x)"));
			item_len-=(asn->offset-*offset)+new_item_len;
			*offset = asn->offset+new_item_len;
			asn->offset = *offset;
			/*  do we have User information field  ?  */
			if(item_len > 0)
			{
				show_acse_user_information(asn,acse_tree,tvb,offset,item_len);
			}
			/*   align the pointer */
			(*offset)=start+save_len;
			asn->offset = (*offset);
}

static void
show_finish_pdu(ASN1_SCK *asn,proto_tree *acse_tree,tvbuff_t
*tvb,int *offset,int item_len)
{
	gint		length;
	gint		value;
    proto_tree	*acse_tree_pc = NULL;
	proto_item	*itu;
	gint		new_item_len;
	guint		start = *offset;
	int			save_len = item_len;
/* do we have enough bytes to dissect this item ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < item_len )
			{
					proto_tree_add_text(acse_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
							*offset = asn->offset;
							return;
			}

			if(item_len <= 0)
			{
					proto_tree_add_text(acse_tree, tvb, *offset, item_len,
							"Reason not specified");
							*offset = asn->offset;
							return;
			}
			itu = proto_tree_add_text(acse_tree, tvb, *offset,ABORT_REASON_LEN,
					"Reason");
			acse_tree_pc = proto_item_add_subtree(itu, ett_acse_ms);
			(*offset)++; /* skip type  */
			asn->offset =  *offset;
			item_len--;
			/* get length  */
				if (read_length(asn, acse_tree_pc, 0, &new_item_len) !=
								ASN1_ERR_NOERROR)
				{
							*offset = asn->offset;
							return;
				}
			/*  try to get reason  */
			value	=	get_integer_value(asn,new_item_len,offset);

			proto_tree_add_text(acse_tree_pc, tvb, *offset+1,new_item_len,
					val_to_str(value,release_request_reason,"Unknown item (0x%02x)"));
			item_len-=(asn->offset-*offset)+new_item_len;
			*offset = asn->offset+new_item_len;
			asn->offset = *offset;
			/*  do we have User information field  ?  */
			if(item_len > 0)
			{
				show_acse_user_information(asn,acse_tree,tvb,offset,item_len);
			}
			/*   align the pointer */
			(*offset)=start+save_len;
			asn->offset = (*offset);
}
static void
show_user_data(ASN1_SCK *asn,proto_tree *acse_tree,tvbuff_t *tvb,int
*offset,int item_len,int tag)
{
	  proto_tree *acse_tree_ud = NULL;
	  proto_tree *acse_tree_pc = NULL;
	  proto_item *itm;
	  proto_item *itu;
	  guint   start = asn->offset;
	  guint	  item_length = item_len;

			itm = proto_tree_add_text(acse_tree, tvb, *offset,(asn->offset -*offset)+
									item_len,	"User data");
			acse_tree_ud = proto_item_add_subtree(itm, ett_acse_ms);
			itu = proto_tree_add_text(acse_tree_ud, tvb,
										*offset,item_len+(asn->offset-*offset),
					val_to_str(tag, user_data_values_vals,"Unknown item (0x%02x)"));
			acse_tree_pc = proto_item_add_subtree(itu, ett_acse_ms);
			switch(tag)
			{
			case SIMPLY_ENCODED_DATA:
				break;
			case FULLY_ENCODED_DATA:
				show_fully_encoded_data(asn,acse_tree_pc,tvb,offset,item_len);
				break;
			default:
				break;
			}


			/*   align the pointer */
			(*offset)=start+item_length;
			asn->offset = (*offset);

}

/* if we can't dissect */
static void
dissect_parse_error(tvbuff_t *tvb, int offset, packet_info *pinfo,
		    proto_tree *tree, const char *field_name, int ret)
{
	char *errstr;
	errstr = asn1_err_to_str(ret);

	if (tree != NULL)
	{
		proto_tree_add_text(tree, tvb, offset, 0,
		    "ERROR: Couldn't parse %s: %s", field_name, errstr);
		call_dissector(data_handle,
		    tvb_new_subset(tvb, offset, -1, -1), pinfo, tree);
	}
}

/* display request top sequence  */
static void
show_request_sequence_top(ASN1_SCK *asn,proto_tree *acse_tree,tvbuff_t
*tvb,packet_info *pinfo,int *offset,int item_len)
{
	int ret;
	guint cls, con, tag,len1;
	gint  type;
	gboolean def;
	proto_item *itm;
	gint length;
	unsigned char ftam_oid[] = "1.0.8571.1.1";
	unsigned char cmip_oid[] ="2.9.0.0.2";

	while(item_len > 0 )
	{
			int offset_save = *offset;
/* do we have enough bytes to dissect this item ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < item_len )
			{
					proto_tree_add_text(acse_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					break;
			}
		/*   get  tag     */
			type = tvb_get_guint8(tvb, *offset);
		/* decode header  */
			ret = asn1_header_decode(asn, &cls, &con, &tag, &def, &len1);

			if (ret != ASN1_ERR_NOERROR)
			{
							dissect_parse_error(tvb, *offset, pinfo, acse_tree,
									"sequence error", ret);
				break;
			}
			/* add header  */
			item_len = item_len - (asn->offset - *offset);
			offset_save += (asn->offset - *offset);
						/*
						* [APPLICATION <tag>]
						*/
						switch (tag)
							{
								case USER_INFORMATION:
									show_acse_user_information(asn,acse_tree,tvb,offset,len1);
									break;
								case CALLED_AE_QUALIFIER:
								case CALLING_AE_QUALIFIER:
									{
									proto_tree *acse_tree_pr = NULL;
									proto_item *pr;
									pr = proto_tree_add_text(acse_tree,tvb,*offset,
									len1+(asn->offset-*offset),
									val_to_str(tag ,request_sequence_top_vals,
									"Unknown item (0x%02x)"));
									acse_tree_pr = proto_item_add_subtree(pr, ett_acse_ms);
									show_integer(asn,acse_tree_pr,tvb,offset,len1);
									}
									break;
								case APPLICATION_CONTEXT_NAME:
								case CALLED_AP_TITLE:
								case CALLING_AP_TITLE:
								case CALLED_AP_INVOKATION_ID:
								case CALLED_AE_INVOKATION_ID:
								case CALLING_AP_INVOKATION_ID:
								case CALLING_AE_INVOKATION_ID:
								{
									gchar oid_string[MAXSTRING];
									show_oid(asn,acse_tree,tvb,offset,len1,(const 
value_string*)&request_sequence_top_vals,
												(gchar*)&oid_string);
									if(tag == APPLICATION_CONTEXT_NAME )
									{
										if( !strcmp(oid_string,cmip_oid)  )
										{
											/* it is CMIP   */
											type_of_application = CMIP_APP;
											app_handle = cmip_handle;
										}
										else
										if( !strcmp(oid_string,ftam_oid) )
										{
											/* it is CMIP   */
											type_of_application = FTAM_APP;
											app_handle = ftam_handle;
										}
										else
										{
											proto_tree_add_text(acse_tree,tvb,*offset,len1,"Unknown OID");
										}
									}
								}
									break;
								case PROTOCOL_VERSION:
									show_protocol_version(asn,acse_tree,tvb,offset,len1,tag);
									break;
								default:
									itm = proto_tree_add_text(acse_tree, tvb, *offset,(asn->offset
																-*offset)+ len1,
											"Unknown tag: %x",tag);
							}
		item_len-=len1;
		*offset = asn->offset = offset_save+len1;;
	}
}
/* display response top sequence  */
static void
show_response_sequence_top(ASN1_SCK *asn,proto_tree *acse_tree,tvbuff_t
*tvb,packet_info *pinfo,int *offset,int item_len)
{
	int ret;
	guint cls, con, tag,len1;
	gint  type;
	gboolean def;
	proto_item *itm;
	gint length;

	while(item_len > 0 )
	{
			int offset_save = *offset;
/* do we have enough bytes to dissect this item ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < item_len )
			{
					proto_tree_add_text(acse_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					break;
			}
		/*   get  tag     */
			type = tvb_get_guint8(tvb, *offset);
		/* decode header  */
			ret = asn1_header_decode(asn, &cls, &con, &tag, &def, &len1);

			if (ret != ASN1_ERR_NOERROR)
			{
							dissect_parse_error(tvb, *offset, pinfo, acse_tree,
									"sequence error", ret);
				break;
			}
			/* add header  */
			item_len = item_len - (asn->offset - *offset);
			offset_save += (asn->offset - *offset);
						/*
						* [APPLICATION <tag>]
						*/
						switch (tag)
							{
								case ACSE_RESULT:
									show_acse_result(asn,acse_tree,tvb,offset,len1);
									break;
								case ACSE_RESULT_SOURCE_DIAGNOSTIC:
									show_acse_result_source_diagnostic(asn,acse_tree,tvb,offset,len1);
									break;
								case USER_INFORMATION:
									show_acse_user_information(asn,acse_tree,tvb,offset,len1);
									break;

								case RESPONDING_AE_QUALIFIER:
									{
									proto_tree *acse_tree_pr = NULL;
									proto_item *pr;
									pr = proto_tree_add_text(acse_tree,tvb,*offset,
									len1+(asn->offset-*offset),
									val_to_str(tag ,response_sequence_top_vals,
									"Unknown item (0x%02x)"));
									acse_tree_pr = proto_item_add_subtree(pr, ett_acse_ms);
									show_integer(asn,acse_tree_pr,tvb,offset,len1);
									}
									break;
								case APPLICATION_CONTEXT_NAME:
								case RESPONDING_AP_TITLE:
								case RESPONDING_AP_INVOKATION_ID:
								case RESPONDING_AE_INVOKATION_ID:
									show_oid(asn,acse_tree,tvb,offset,len1,(const 
value_string*)&response_sequence_top_vals,NULL);
									break;
								case PROTOCOL_VERSION:
									show_protocol_version(asn,acse_tree,tvb,offset,len1,tag);
									break;
								default:
									itm = proto_tree_add_text(acse_tree, tvb, *offset,(asn->offset
																-*offset)+ len1,
											"Unknown tag: %x",tag);
							}
		item_len-=len1;
		*offset = asn->offset = offset_save+len1;
	}
}

/*
* Dissect a pdu.
*/
static int
dissect_pdu(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree
			*tree)
{
  proto_item *ti;
  proto_tree *acse_tree = NULL;
  guint length;
  guint       rest_len;
  guint  s_type;
  ASN1_SCK asn;
  guint cp_type_len;
/* get type of tag      */
	s_type = tvb_get_guint8(tvb, offset);
		/*  set up type of pdu */
  	if (check_col(pinfo->cinfo, COL_INFO))
					col_add_str(pinfo->cinfo, COL_INFO,
						val_to_str(session->spdu_type, ses_vals, "Unknown pdu type 
(0x%02x)"));
  if (tree)
	{
		ti = proto_tree_add_item(tree, proto_acse, tvb, offset, -1,
		    FALSE);
		acse_tree = proto_item_add_subtree(ti, ett_acse);
	}
	offset++;
/*    open asn.1 stream    */
	asn1_open(&asn, tvb, offset);

	switch(session->spdu_type)
	{
		case SES_REFUSE:
		case SES_CONNECTION_REQUEST:
		case SES_CONNECTION_ACCEPT:
			proto_tree_add_uint(acse_tree, hf_acse_type, tvb, offset-1, 1, s_type);

			if (read_length(&asn, acse_tree, hf_cp_type_message_length, &cp_type_len)
							!= ASN1_ERR_NOERROR)
					{
					return  FALSE;
					}
			/* skip length   */
			offset = asn.offset;
			/* do we have enough bytes to dissect ? */
			if( ( length =tvb_reported_length_remaining(tvb, offset))  < cp_type_len
					)
			{
				if(tree)
				{
					proto_tree_add_text(acse_tree, tvb, offset, -1,
							"Wrong pdu.Need %u bytes but have %u", cp_type_len,length);
				}
			return FALSE;
			}
			if(tree)
			{
				if(session->spdu_type == SES_CONNECTION_REQUEST)
				{
				show_request_sequence_top(&asn,acse_tree,tvb,pinfo,&offset,cp_type_len);
				}
				else
				{
				show_response_sequence_top(&asn,acse_tree,tvb,pinfo,&offset,cp_type_len);
				}

			}
				break;
		case SES_FINISH:
			proto_tree_add_uint(acse_tree, hf_acse_type, tvb, offset-1, 1, s_type);
	  			/* get length  */
				if (read_length(&asn, acse_tree, 0, &rest_len) != ASN1_ERR_NOERROR)
						{
					return  FALSE;
						}
				/* skip length   */
				offset = asn.offset;
				/* do we have enough bytes to dissect ? */
				if( ( length =tvb_reported_length_remaining(tvb, offset))  < rest_len )
				{
					if(tree)
					{
					proto_tree_add_text(acse_tree, tvb, offset, -1,
							"Wrong pdu.Need %u bytes but have %u", rest_len,length);
					}
				return FALSE;
				}
				show_finish_pdu(&asn,acse_tree,tvb,&offset,rest_len);
				break;
		case SES_DISCONNECT:
			proto_tree_add_uint(acse_tree, hf_acse_type, tvb, offset-1, 1, s_type);
	  			/* get length  */
				if (read_length(&asn, acse_tree, 0, &rest_len) != ASN1_ERR_NOERROR)
						{
					return  FALSE;
						}
				/* skip length   */
				offset = asn.offset;
				/* do we have enough bytes to dissect ? */
				if( ( length =tvb_reported_length_remaining(tvb, offset))  < rest_len )
				{
					if(tree)
					{
					proto_tree_add_text(acse_tree, tvb, offset, -1,
							"Wrong pdu.Need %u bytes but have %u", rest_len,length);
					}
				return FALSE;
				}
				show_disconnect_pdu(&asn,acse_tree,tvb,&offset,rest_len);
				break;
		case SES_ABORT:
			proto_tree_add_uint(acse_tree, hf_acse_type, tvb, offset-1, 1, s_type);
	  			/* get length  */
				if (read_length(&asn, acse_tree, 0, &rest_len) != ASN1_ERR_NOERROR)
						{
					return  FALSE;
						}
				/* skip length   */
				offset = asn.offset;
				/* do we have enough bytes to dissect ? */
				if( ( length =tvb_reported_length_remaining(tvb, offset))  < rest_len )
				{
					if(tree)
					{
					proto_tree_add_text(acse_tree, tvb, offset, -1,
							"Wrong pdu.Need %u bytes but have %u", rest_len,length);
					}
				return FALSE;
				}
				show_abort_reason(&asn,acse_tree,tvb,&offset,rest_len);
				break;
		default:
			{
				proto_item *ms;
				proto_tree *acse_tree_ms = NULL;
				/* back to length  */
				  offset--;
	  			/* get length  */
				if (read_length(&asn, acse_tree, 0, &rest_len) != ASN1_ERR_NOERROR)
						{
					return  FALSE;
						}
				ms = proto_tree_add_text(acse_tree, tvb, offset, rest_len,
										val_to_str(session->spdu_type, ses_vals, "Unknown pdu type 
(0x%02x)"));
				acse_tree_ms = proto_item_add_subtree(ms, ett_acse_ms);
				show_user_data(&asn,acse_tree_ms,tvb,&offset,rest_len,s_type);
			}
	}
/*    close asn.1 stream    */
	  asn1_close(&asn, &offset);

	return offset;
}

/*
* Dissect ACSE PDUs inside a PPDU.
*/
static void
dissect_acse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
/* first, try to check length   */
/* do we have at least 2 bytes  */
	if (!tvb_bytes_exist(tvb, 0, 2))
	{
	proto_tree_add_text(tree, tvb, offset, 
tvb_reported_length_remaining(tvb,offset),
								"User data");
			return;  /* no, it isn't a ACSE PDU */
	}
/* do we have spdu type from the session dissector?  */
	if( !pinfo->private_data )
				{
				if(tree)
						{
					proto_tree_add_text(tree, tvb, offset, -1,
							"Internal error:can't get spdu type from session dissector.");
					return  ;
						}
				}
	else
				{
					session  = ( (struct SESSION_DATA_STRUCTURE*)(pinfo->private_data) );
					if(session->spdu_type == 0 )
					{
						if(tree)
						{
					proto_tree_add_text(tree, tvb, offset, -1,
							"Internal error:wrong spdu type %x from session 
dissector.",session->spdu_type);
					return  ;
						}
					}
				}
/*  ACSE has only AARQ,AARE,RLRQ,RLRE,ABRT type of pdu */
/*  reject everything else                              */
/*  data pdu is not ACSE pdu and has to go directly to app dissector */
			switch(session->spdu_type)
			{
		case SES_REFUSE:					/*   RLRE   */
		case SES_CONNECTION_REQUEST:		/*   AARQ   */
		case SES_CONNECTION_ACCEPT:			/*   AARE   */
		case SES_DISCONNECT:				/*   RLRQ   */
		case SES_FINISH:					/*   RLRE   */
		case SES_ABORT:						/*   ABRT   */
			break;
		case SES_DATA_TRANSFER:
			call_app_dissector(tvb,offset,tvb_reported_length_remaining(tvb, offset) 
,pinfo,tree,tree);
			return;
		default:
			return;
			}

	/*  we can't make any additional checking here   */
	/*  postpone it before dissector will have more information */

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "ACSE");
  	if (check_col(pinfo->cinfo, COL_INFO))
  		col_clear(pinfo->cinfo, COL_INFO);
	/* save pointers for calling the app dissector  */
	global_tree = tree;
	global_pinfo = pinfo;

	while (tvb_reported_length_remaining(tvb, offset) > 0)
			{
		offset = dissect_pdu(tvb, offset, pinfo, tree);
		if(offset == FALSE )
							{
									proto_tree_add_text(tree, tvb, offset, -1,"Internal error");
									offset = tvb_length(tvb);
									break;
							}
			}
}

void
proto_register_acse(void)
{
	static hf_register_info hf[] =
	{
		{
			&hf_acse_type,
			{
				"PDU Type",
				"acse.type",
				FT_UINT8,
				BASE_DEC,
				VALS(acse_vals),
				0x0,
				"", HFILL
			}
		},
		{
			&hf_cp_type_message_length,
			{
				"Message Length",
				"cp_type.message_length",
				FT_UINT32,
				BASE_DEC,
				NULL,
				0x0,
				"CP type Message Length",
				HFILL
			}
		},
		{
			&hf_protocol_version,
			{
				"Protocol version 1",
				"acse.protocol.version",
				FT_BOOLEAN, 16,
				NULL,
				ACSE_PROTOCOL_VERGION,
				"Protocol version 1",
				HFILL
			}
		},
	};

	static gint *ett[] =
	{
		&ett_acse,
		&ett_acse_param,
		&ett_acse_rc,
		&ett_acse_ms,
		&ett_acse_itm,
	};
	module_t *acse_module;


	proto_acse = proto_register_protocol(PROTO_STRING_ACSE, "ACSE", "acse");
	proto_register_field_array(proto_acse, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	acse_module = prefs_register_protocol(proto_acse, NULL);

	/*
	 * Register the dissector by name, so other dissectors can
	 * grab it by name rather than just referring to it directly
	 */
	register_dissector("acse", dissect_acse, proto_acse);
}

void
proto_reg_handoff_acse(void)
{
	/*   find data dissector  */
	data_handle = find_dissector("data");
	/* define ftam sub dissector */
	ftam_handle = find_dissector("ftam");
	/* define cmip sub dissector */
	cmip_handle = find_dissector("cmip");

}


