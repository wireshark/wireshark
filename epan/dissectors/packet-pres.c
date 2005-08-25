/* packet-pres.c
*
* Routine to dissect ISO 8823 OSI Presentation Protocol packets
*
* $Id$
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

#include "packet-pres.h"
#include "packet-frame.h"
#include <epan/prefs.h>

#include <epan/strutil.h>

#include <epan/asn1.h>
#include "format-oid.h"

#include "packet-ses.h"
extern const value_string ses_vals[];

/* pres header fields             */
static int proto_pres          = -1;
/*   type of session envelop */
static struct SESSION_DATA_STRUCTURE* session = NULL;
static int hf_pres_rc_type			= -1;
static int hf_pres_ms_type			= -1;
static int hf_pres_seq_type			= -1;
static int hf_pres_protocol_version =-1;
/* pres fields defining a sub tree */
static gint ett_pres           = -1;
static gint ett_pres_param     = -1;
static gint ett_pres_rc           = -1;
static gint ett_pres_ms           = -1;
static gint ett_pres_itm           = -1;

/*
----------------------------------------------------------------------------------------------------------*/
static dissector_handle_t acse_handle = NULL;

static int hf_pres_type        = -1;
static int hf_pres_length      = -1;
static int hf_value			   = -1;


static int hf_cp_type_message_length = -1;

static int hf_protocol_version       = -1;
static int hf_context_management       = -1;
static int hf_restoration       = -1;


static const value_string pres_vals[] =
{
  {PRES_CONNECTION_REQUEST_CONFIRM,  "Connection request/confirm PDU" },
  {PRES_CONNECTION_REFUSE,    "Connection refuse PDU"   },
  {0,             NULL           }
};

static const value_string cr_vals[] =
{
  {MODE_SELECTOR, "Mode Selector"},
  {SEQUENCE_TOP, "Sequence"},
  {SET_TOP, "Set"},
  {0, NULL}
};

static const value_string sequence_top_vals[] =
{
  {CALLED_PRESENTATION_SELECTOR, "Called presentation selector"},
  {CALLING_PRESENTATION_SELECTOR, "Calling presentation selector"},
  {PRESENTATION_CONTEXT_DEFINITION_LIST, "Presentation context definition list"},
  {RESPONDING_PRESENTATION_SELECTOR, "Responding presentation selector"},
  {PROTOCOL_VERSION, "Protocol version"},
  {PRESENTATION_CONTEXT_DEFINITION_RESULT_LIST, "Presentation context definition result list"},
  {PRESENTATION_REQUIREMENTS,"Presentation requirements"},
  {DEFAULT_CONTEXT_NAME,"Default context name"},
  {USER_SESSION_REQUIREMENTS,"User session requirements"},
  {DEFAULT_CONTEXT_RESULT,"Default context result"},
  {PROVIDER_REASON,"Provider reason"},
  {0, NULL}
};
static const value_string sequence_list_vals[] =
{
  {PRESENTATION_CONTEXT_IDENTIFIER,"Presentation context identifier"},
  {ABSTRACT_SYNTAX_NAME,"Abstract syntax name"},
  {TRANSFER_SYNTAX_NAMES,"Transfer syntax names"},
  {0, NULL}
};
static const value_string sequence_list_result_vals[] =
{
  {PRESENTATION_RESULT,"Result"},
  {PRESENTATION_RESULT_INTEGER,"Integer"},
  {PRESENTATION_RESULT_TRANSFER_SYNTAX_NAME,"Transfer syntax name"},
  {0, NULL}
};
static const value_string presentation_context_definition_vals[] =
{
  {SEQUENCE, "Sequence"},
  {0, NULL}
};
static const value_string sequence_list_result_values_vals[] =
{
  {PRESENTATION_RESULT_ACCEPTANCE,"Acceptance"},
  {PRESENTATION_RESULT_USER_REJECTION,"User rejection"},
  {PRESENTATION_RESULT_PROVIDER_REJECTION,"Provider rejection"},
  {0, NULL}
};
static const value_string provider_reason_values_vals[] =
{
  {REASON_NOT_SPECIFIED,"Reason not specified"},
  {TEMPORARY_CONGESTION,"Temporary congestion"},
  {LOCAL_LIMIT_EXCEEDED,"Local limit exceeded"},
  {CALLED_PRESENTATION_ADDRESS_UNKNOWN,"Called presentation address unknown"},
  {PROTOCOL_VERSION_NOT_SUPPORTED,"Protocol version not supported"},
  {DEFAULT_CONTEXT_NOT_SUPPORTED,"Default context not supported"},
  {USER_DATA_NOT_READABLE,"User data not readable"},
  {NO_PSAP_AVAILABLE,"No PSAP available"},
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
  {DATA_BLOCK,"Data block"},
  {0, NULL}
};
static const value_string provider_abort_values_vals[] =
{
  {PR_REASON_NOT_SPECIFIED,"Reason not specified"},
  {UNRECOGNIZED_PDU,"Unrecognized ppdu"},
  {UNEXPECTED_PDU,"Unexpected ppdu"},
  {UNEXPECTED_SESSION_SERVICE_PRIMITIVE,"Unexpected session service primitive"},
  {UNRECOGNIZED_PPDU_PARAMETER,"Unrecognized ppdu parameter"},
  {UNEXPECTED_PPDU_PARAMETER,"Unexpected ppdu parameter"},
  {INVALID_PPDU_PARAMETER_VALUE,"Invalid ppdu parameter value"},
  {0, NULL}
};
static const value_string event_identifier_values_vals[] =
{
  {REASON_CP_PPDU,"cp PPDU"},
  {REASON_CPA_PPDU,"cpa PPDU"},
  {REASON_CPR_PPDU,"cpr PPDU"},
  {REASON_ARU_PPDU,"aru PPDU"},
  {REASON_ARP_PPDU,"arp PPDU"},
  {REASON_AC_PPDU,"ac PPDU"},
  {REASON_ACA_PPDU,"aca PPDU"},
  {REASON_TD_PPDU,"td PPDU"},
  {REASON_TTD_PPDU,"td PPDU"},
  {REASON_TE_PPDU,"te PPDU"},
  {REASON_TC_PPDU,"tc PPDU"},
  {REASON_TCC_PPDU,"tcc PPDU"},
  {REASON_RS_PPDU,"rs PPDU"},
  {REASON_RSA_PPDU,"rsa PPDU"},
  {S_RELEASE_INDICATION,"s release indication"},
  {S_RELEASE_CONFIRM,"s release confirm"},
  {S_TOKEN_GIVE_INDICATION,"s token give indication"},
  {S_TOKEN_PLEASE_INDICATION,"s token please indication"},
  {S_CONTROL_GIVE_INDICATION,"s control give indication"},
  {S_SYNC_MINOR_INDICATION,"s sync minor indication"},
  {S_SYNC_MINOR_CONFIRM,"s sync minor confirm"},
  {S_SYNC_MAJOR_INDICATION,"s sync major indication"},
  {S_SYNC_MAJOR_CONFIRM,"s sync major confirm"},
  {S_P_EXCEPTION_REPORT_INDICATION,"s p exception report indication"},
  {S_U_EXCEPTION_REPORT_INDICATION,"s u exception report indication"},
  {S_ACTIVITY_START_INDICATION,"s activity start indication"},
  {S_ACTIVITY_RESUME_INDICATION,"s activity resume indication"},
  {S_ACTIVITY_INTERRUPT_INDICATION,"s activity interrupt indication"},
  {S_ACTIVITY_INTERRUPT_CONFIRM,"s activity interrupt confirm"},
  {S_ACTIVITY_DISCARD_INDICATION,"s activity discard indication"},
  {S_ACTIVITY_DISCARD_CONFIRM,"s activity discard confirm"},
  {S_ACTIVITY_END_INDICATION,"s activity end indication"},
  {S_ACTIVITY_END_CONFIRM,"s activity end confirm"},
  {0, NULL}
};
/*      pointers for acse dissector  */
proto_tree *global_tree  = NULL;
packet_info *global_pinfo = NULL;
/* dissector for data */
static dissector_handle_t data_handle;

static void
call_acse_dissector(tvbuff_t *tvb, gint offset, gint param_len,
    packet_info *pinfo, proto_tree *tree, proto_tree *param_tree)
{
	/* do we have OSI acse/rose packet dissector ? */
	if(!acse_handle)
	{
		/* No - display as data */
		if (tree)
		{
			proto_tree_add_text(param_tree, tvb, offset, param_len,
			    "No ACSE dissector available");
		}
	}
	else
	{
		/* Yes - call app dissector */
		tvbuff_t *next_tvb;

		next_tvb = tvb_new_subset(tvb, offset, param_len, param_len);
		TRY
		{
			call_dissector(acse_handle, next_tvb, pinfo, tree);
		}
		CATCH_ALL
		{
			show_exception(tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
		}
		ENDTRY;
	}
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

  if (hf_id)
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

  if (hf_id)
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
show_integer(ASN1_SCK *asn,proto_tree *pres_tree,tvbuff_t *tvb,int 
*offset,int item_len)
{
	  proto_tree *pres_tree_itm = NULL;
	  proto_item *itm;
	  int       ret;
	  int		save_len = item_len;
	  int		off      = *offset;
	  itm = proto_tree_add_text(pres_tree, tvb, *offset, item_len,
										"Integer");
	  pres_tree_itm = proto_item_add_subtree(itm, ett_pres_itm);
	  ret = read_integer(asn,pres_tree_itm,0,NULL,&item_len);
	  if (ret == ASN1_ERR_NOERROR )
			{
				*offset = asn->offset;
				itm = proto_tree_add_text(pres_tree_itm, tvb, (*offset)-item_len, 
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
show_presentation_requirements(ASN1_SCK *asn,proto_tree *pres_tree,tvbuff_t 
*tvb,int *offset,int item_len,int tag)
{
	  proto_tree *pres_tree_itm = NULL;
	  proto_item *itm;
	  guint16       flags;
	  gint length;
/* do we have enough bytes to dissect this item ? */
			if( ( length = tvb_reported_length_remaining(tvb, *offset))  < 
(asn->offset -*offset)+ item_len )
			{
					proto_tree_add_text(pres_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					return;
			}

	  itm = proto_tree_add_text(pres_tree, tvb, *offset,(asn->offset -*offset)+ 
item_len,
											val_to_str(tag, sequence_top_vals,"Unknown item (0x%02x)"));
	  pres_tree_itm = proto_item_add_subtree(itm, ett_pres_itm);
	  *offset = asn->offset;
	  flags = tvb_get_ntohs(tvb, *offset);
	  proto_tree_add_boolean(pres_tree_itm,hf_context_management, tvb, *offset, 
2, flags);
	  proto_tree_add_boolean(pres_tree_itm,hf_restoration, tvb, *offset, 2, 
flags);
	  *offset = *offset + item_len;
	  asn->offset = *offset;
}

static void
show_protocol_version(ASN1_SCK *asn,proto_tree *pres_tree,tvbuff_t *tvb,int 
*offset,int item_len,int tag)
{
	  proto_tree *pres_tree_itm = NULL;
	  proto_item *itm;
	  guint16       flags;
	  gint length;
/* do we have enough bytes to dissect this item ? */
			if( ( length = tvb_reported_length_remaining(tvb, *offset))  < 
(asn->offset -*offset)+ item_len )
			{
					proto_tree_add_text(pres_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					return;
			}

	  itm = proto_tree_add_text(pres_tree, tvb, *offset,(asn->offset -*offset)+ 
item_len,
											val_to_str(tag, sequence_top_vals,"Unknown item (0x%02x)"));
	  pres_tree_itm = proto_item_add_subtree(itm, ett_pres_itm);
	  *offset = asn->offset;
	  flags = tvb_get_ntohs(tvb, *offset);
	  proto_tree_add_boolean(pres_tree_itm,hf_protocol_version, tvb, *offset, 
2, flags);
	  *offset = *offset + item_len;
	  asn->offset = *offset;
}
static void
print_oid_value(ASN1_SCK *asn,proto_tree *pres_tree,tvbuff_t *tvb,int 
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
		proto_tree_add_text(pres_tree, tvb, *offset,length,"Value:%s", 
display_string);
		(*offset)=start+item_len;
		asn->offset = (*offset);
}
static void
print_oid(ASN1_SCK *asn,proto_tree *pres_tree,tvbuff_t *tvb,int *offset,int 
item_len)
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
		proto_tree_add_text(pres_tree, tvb, *offset,length,"Value:%s", 
display_string);
		(*offset)=start+item_len;
		asn->offset = (*offset);
}

static void
print_value(ASN1_SCK *asn,proto_tree *pres_tree, tvbuff_t *tvb, int *offset, int item_len)
{
    gint    start = *offset;
    gchar  *tmp;

    *offset = asn->offset;  /* align to data*/
    tmp = tvb_bytes_to_str(tvb, *offset, item_len);
    proto_tree_add_text(pres_tree, tvb, *offset, item_len, tmp);
    (*offset) = start+item_len;
    asn->offset = (*offset);
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
show_presentation_context_definition_result_seq(ASN1_SCK *asn,proto_tree 
*pres_tree,tvbuff_t *tvb,int *offset,int item_len)
{
	  proto_tree *pres_tree_ms = NULL;
	  guint length;
	  guint   type;
	  proto_item *ms;
	  guint   new_item_len;
	  guint   start = *offset;
	  guint   header_len;
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
				if (read_length(asn, pres_tree, 0, &new_item_len) != ASN1_ERR_NOERROR)
				{
					(*offset)=start+item_len;
					asn->offset = (*offset);
					return  ;
				}

			/* do we have enough bytes to dissect ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < 
new_item_len )
			{
					proto_tree_add_text(pres_tree, tvb, *offset, new_item_len,
							"Wrong item.Need %u bytes but have %u", new_item_len,length);
					(*offset)=start+item_len;
					asn->offset = (*offset);
				    return ;
			}
				header_len = asn->offset - (*offset) +1;
				ms = proto_tree_add_text(pres_tree, tvb, *offset-1, 
new_item_len+(asn->offset-*offset)+1,
										val_to_str(type, sequence_list_result_vals,
										"Unknown item (0x%02x)"));
				pres_tree_ms = proto_item_add_subtree(ms, ett_pres_ms);
				*offset = asn->offset;


			switch(type)
				{
			case PRESENTATION_RESULT:
				{
					proto_tree *pres_tree_pr = NULL;
					proto_item *pr;
					int        value	=	get_integer_value(asn,new_item_len,offset);
				pr = proto_tree_add_text(pres_tree_ms, tvb, *offset, 
new_item_len+(asn->offset-*offset),
								val_to_str(value ,sequence_list_result_values_vals,
								"Unknown item (0x%02x)"));
				pres_tree_pr = proto_item_add_subtree(pr, ett_pres_ms);

				print_value(asn,pres_tree_pr,tvb,offset,new_item_len);
				}
					break;
			case PRESENTATION_RESULT_INTEGER:
				print_value(asn,pres_tree_ms,tvb,offset,new_item_len);
					break;
			case PRESENTATION_RESULT_TRANSFER_SYNTAX_NAME:
				print_oid_value(asn,pres_tree_ms,tvb,offset,new_item_len);
					break;

			default:
					proto_tree_add_text(pres_tree, tvb, *offset, 
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
show_presentation_context_definition_seq(ASN1_SCK *asn,proto_tree 
*pres_tree,tvbuff_t *tvb,int *offset,int item_len)
{
	  proto_tree *pres_tree_ms = NULL;
	  guint length;
	  guint   type;
	  proto_item *ms;
	  guint   new_item_len;
	  guint   start = *offset;
	  guint   header_len;
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
				if (read_length(asn, pres_tree, 0, &new_item_len) != ASN1_ERR_NOERROR)
				{
					(*offset)=start+item_len;
					asn->offset = (*offset);
					return  ;
				}

			/* do we have enough bytes to dissect ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < 
new_item_len )
			{
					proto_tree_add_text(pres_tree, tvb, *offset, new_item_len,
							"Wrong item.Need %u bytes but have %u", new_item_len,length);
					(*offset)=start+item_len;
					asn->offset = (*offset);
				    return ;
			}
				header_len = asn->offset - (*offset) +1;
				ms = proto_tree_add_text(pres_tree, tvb, *offset-1, 
new_item_len+(asn->offset-*offset)+1,
										val_to_str(type, sequence_list_vals,
										"Unknown item (0x%02x)"));
				pres_tree_ms = proto_item_add_subtree(ms, ett_pres_ms);
				*offset = asn->offset;


			switch(type)
				{
			case PRESENTATION_CONTEXT_IDENTIFIER:
				print_value(asn,pres_tree_ms,tvb,offset,new_item_len);
					break;
			case ABSTRACT_SYNTAX_NAME:
				print_oid_value(asn,pres_tree_ms,tvb,offset,new_item_len);
					break;
			case TRANSFER_SYNTAX_NAMES:
				print_oid(asn,pres_tree_ms,tvb,offset,new_item_len);
					break;
			default:
					proto_tree_add_text(pres_tree, tvb, *offset, 
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
show_fully_encoded_seq(ASN1_SCK *asn,proto_tree *pres_tree,tvbuff_t *tvb,int 
*offset,int item_len)
{
	  proto_tree *pres_tree_ms = NULL;
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
				if (read_length(asn, pres_tree, 0, &new_item_len) != ASN1_ERR_NOERROR)
				{
					(*offset)=start+item_len;
					asn->offset = (*offset);
					return  ;
				}
			/* do we have enough bytes to dissect ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < 
new_item_len )
			{
					proto_tree_add_text(pres_tree, tvb, *offset, new_item_len,
							"Wrong item.Need %u bytes but have %u", new_item_len,length);
					(*offset)=start+item_len;
					asn->offset = (*offset);
				    return ;
			}
			if(!new_item_len && length>2)
			{
					new_item_len = length-1;  /* can't get length from asn1 tag. Use rest of the pdu len. */
			}
				header_len = asn->offset - (*offset) +1;
				ms = proto_tree_add_text(pres_tree, tvb, *offset-1, 
new_item_len+(asn->offset-*offset)+1,
										val_to_str(type, presentation_data_values,
										"Unknown item (0x%02x)"));
				pres_tree_ms = proto_item_add_subtree(ms, ett_pres_ms);
				*offset = asn->offset;


			switch(type)
				{
			case PRESENTATION_CONTEXT_IDENTIFIER:
				{
				acse	=	get_integer_value(asn,new_item_len,offset);
				print_value(asn,pres_tree_ms,tvb,offset,new_item_len);
				if(session){
					session->pres_ctx_id=acse;
				}
				}
					break;
			case OCTET_ALIGNED:
			case DATA_BLOCK:
				{
						proto_item *acse_ms;
					/*  yes, we have to call ACSE dissector    */
				acse_ms = proto_tree_add_text(pres_tree_ms, tvb, *offset,new_item_len+(asn->offset-*offset),
										"User data");

				session->abort_type = DATA_BLOCK;
					/*  call acse dissector  */
				call_acse_dissector(tvb,*offset,new_item_len,global_pinfo,global_tree,pres_tree_ms);
				}
					break;
			case SINGLE_ASN1_TYPE:

				{
						proto_item *acse_ms;
					/*  yes, we have to call ACSE dissector    */
				acse_ms = proto_tree_add_text(pres_tree_ms, tvb, *offset, 
new_item_len+(asn->offset-*offset),
										"User data");
					/*  call acse dissector  */
				call_acse_dissector(tvb,*offset,new_item_len,global_pinfo,global_tree,pres_tree_ms);
				acse = 0;
				}
					break;
			case ARBITRARY:
				print_value(asn,pres_tree_ms,tvb,offset,new_item_len);
					break;
			default:
					proto_tree_add_text(pres_tree, tvb, *offset, 
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
show_fully_encoded_data(ASN1_SCK *asn,proto_tree *pres_tree,tvbuff_t 
*tvb,int *offset,int item_len)
{
	  proto_tree *pres_tree_ms = NULL;
	  proto_tree *pres_tree_pc = NULL;
	  gint    length;
	  guint   type;
	  guint   header_len;
	  proto_item *ms;
	  gint   new_item_len;
	  guint   start = asn->offset;
	  guint	  item_length = item_len;
	  pres_tree_pc = pres_tree;

/* do we have enough bytes to dissect ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < item_len )
			{
					proto_tree_add_text(pres_tree_pc, tvb, *offset, item_len,
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
				if (read_length(asn, pres_tree_pc, 0, &new_item_len) != 
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
					proto_tree_add_text(pres_tree_pc, tvb, *offset, new_item_len,
							"Wrong item.Need %u bytes but have %u", new_item_len,length);
					/*   align the pointer */
					(*offset)=start+item_length;
					asn->offset = (*offset);
					return ;
			}
			if(!new_item_len && length>2)
			{
				/* check if really do have what to dissect */
				new_item_len = length-1;
			}
				ms = proto_tree_add_text(pres_tree_pc, tvb, *offset-1, 
new_item_len+(asn->offset-*offset)+1,
										val_to_str(type, presentation_context_definition_vals,
										"Unknown item (0x%02x)"));
				pres_tree_ms = proto_item_add_subtree(ms, ett_pres_ms);
				*offset = asn->offset;


			switch(type)
				{

			case SEQUENCE:
			show_fully_encoded_seq(asn,pres_tree_ms,tvb,offset,new_item_len);
			*offset = old_offset+(new_item_len+header_len);
					break;

			default:
					proto_tree_add_text(pres_tree_ms, tvb, *offset, 
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
show_session_provider_abort(ASN1_SCK *asn,proto_tree *pres_tree,tvbuff_t 
*tvb,int *offset,int item_len)
{
	gint length;
	gint		value;
    proto_tree *pres_tree_pc = NULL;
    proto_tree *pres_tree_pp = NULL;
	proto_item *itu;
	gint   new_item_len;


/* do we have enough bytes to dissect this item ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < item_len )
			{
					proto_tree_add_text(pres_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
							*offset = asn->offset;
							return;
			}
			itu = proto_tree_add_text(pres_tree, tvb, *offset,item_len,
					"Provider abort");
			pres_tree_pp = proto_item_add_subtree(itu, ett_pres_ms);

			if(item_len <= 0)
			{
					proto_tree_add_text(pres_tree_pc, tvb, *offset, item_len,
							"Provider reason not specified");
							*offset = asn->offset;
							return;
			}
			itu = proto_tree_add_text(pres_tree_pp, tvb, *offset,ABORT_REASON_LEN,
					"Abort reason");
			pres_tree_pc = proto_item_add_subtree(itu, ett_pres_ms);
			(*offset)++; /* skip type  */
			asn->offset =  *offset;
			item_len--;
			/* get length  */
				if (read_length(asn, pres_tree_pc, 0, &new_item_len) != 
ASN1_ERR_NOERROR)
				{
							*offset = asn->offset;
							return;
				}
			/*  try to get Abort reason  */
			value	=	get_integer_value(asn,new_item_len,offset);


			proto_tree_add_text(pres_tree_pc, tvb, *offset+1,new_item_len,
					val_to_str(value, provider_abort_values_vals,"Unknown item (0x%02x)"));
			item_len-=(asn->offset-*offset)+new_item_len;
			*offset = asn->offset+new_item_len;
			asn->offset = *offset;
			/*  do we have Event identifier  ?  */
			if(item_len > 0)
			{
			itu = proto_tree_add_text(pres_tree_pp, tvb, *offset,item_len,
					"Event identifier");
			pres_tree_pc = proto_item_add_subtree(itu, ett_pres_ms);

			(*offset)++; /* skip type  */
			asn->offset = *offset;
			item_len--;
			/* get length  */
				if (read_length(asn, pres_tree_pc, 0, &new_item_len) != 
ASN1_ERR_NOERROR)
				{
							*offset = asn->offset;
							return;
				}
			/*  try to get Event identifier  */
			value	=	get_integer_value(asn,new_item_len,offset);

			proto_tree_add_text(pres_tree_pc, tvb, *offset+1,new_item_len,
					val_to_str(value, event_identifier_values_vals,"Unknown item (0x%02x)"));
			item_len-=(asn->offset-*offset)+new_item_len;
			*offset = asn->offset+new_item_len;
						asn->offset = *offset;
			}
}
static void
show_user_data(ASN1_SCK *asn,proto_tree *pres_tree,tvbuff_t *tvb,int 
*offset,int item_len,int tag)
{
	  proto_tree *pres_tree_ud = NULL;
	  proto_tree *pres_tree_pc = NULL;
	  proto_item *itm;
	  proto_item *itu;
	  guint   start = asn->offset;
	  guint	  item_length = item_len;

			itm = proto_tree_add_text(pres_tree, tvb, *offset,(asn->offset -*offset)+ 
item_len,	"User data");
			pres_tree_ud = proto_item_add_subtree(itm, ett_pres_ms);
			itu = proto_tree_add_text(pres_tree_ud, tvb, 
*offset,item_len+(asn->offset-*offset),
					val_to_str(tag, user_data_values_vals,"Unknown item (0x%02x)"));
			pres_tree_pc = proto_item_add_subtree(itu, ett_pres_ms);
			switch(tag)
			{
			case SIMPLY_ENCODED_DATA:
				break;
			case FULLY_ENCODED_DATA:
				show_fully_encoded_data(asn,pres_tree_pc,tvb,offset,item_len);
				break;
			default:
				break;
			}


			/*   align the pointer */
			(*offset)=start+item_length;
			asn->offset = (*offset);

}

static void
show_presentation_context_definition(ASN1_SCK *asn,proto_tree 
*pres_tree,tvbuff_t *tvb,int *offset,int item_len,int tag)
{
	  proto_tree *pres_tree_ms = NULL;
	  proto_tree *pres_tree_pc = NULL;
	  proto_item *itm;
	  gint    length;
	  guint   type;
	  guint   header_len;
	  proto_item *ms;
	  gint   new_item_len;
	  guint   start = asn->offset;
	  guint	  item_length = item_len;

			itm = proto_tree_add_text(pres_tree, tvb, 
*offset,item_len+(asn->offset-*offset),
					val_to_str(tag, sequence_top_vals,"Unknown item (0x%02x)"));
			pres_tree_pc = proto_item_add_subtree(itm, ett_pres_ms);

/* do we have enough bytes to dissect ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < item_len )
			{
					proto_tree_add_text(pres_tree_pc, tvb, *offset, item_len,
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
				if (read_length(asn, pres_tree_pc, 0, &new_item_len) != 
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
					proto_tree_add_text(pres_tree_pc, tvb, *offset, new_item_len,
							"Wrong item.Need %u bytes but have %u", new_item_len,length);
					/*   align the pointer */
					(*offset)=start+item_length;
					asn->offset = (*offset);
					return ;
			}
				ms = proto_tree_add_text(pres_tree_pc, tvb, *offset-1, 
new_item_len+(asn->offset-*offset)+1,
										val_to_str(type, presentation_context_definition_vals,
										"Unknown item (0x%02x)"));
				pres_tree_ms = proto_item_add_subtree(ms, ett_pres_ms);
				*offset = asn->offset;


			switch(type)
				{

			case SEQUENCE:
				if(tag == PRESENTATION_CONTEXT_DEFINITION_RESULT_LIST
					|| tag == DEFAULT_CONTEXT_RESULT)
				{
			show_presentation_context_definition_result_seq(asn,pres_tree_ms,tvb,offset,new_item_len);
				}
				else
				{
			show_presentation_context_definition_seq(asn,pres_tree_ms,tvb,offset,new_item_len);
				}
			*offset = old_offset+(new_item_len+header_len);
					break;

			default:
					proto_tree_add_text(pres_tree_ms, tvb, *offset, 
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
/* if we can't dissect */
static void
dissect_parse_error(tvbuff_t *tvb, int offset, packet_info *pinfo,
		    proto_tree *tree, const char *field_name, int ret)
{
	const char *errstr;
	errstr = asn1_err_to_str(ret);

	if (tree != NULL)
	{
		proto_tree_add_text(tree, tvb, offset, 0,
		    "ERROR: Couldn't parse %s: %s", field_name, errstr);
		call_dissector(data_handle,
		    tvb_new_subset(tvb, offset, -1, -1), pinfo, tree);
	}
}

static int read_string_value(ASN1_SCK *a, proto_tree *tree, int hf_id,
	proto_item **new_item, char **s, int start, guint length)
{
  guchar *string;
  proto_item *temp_item = NULL;
  int ret;

  if (length)
  {
    ret = asn1_string_value_decode(a, length, &string);
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
    string = g_realloc(string, length + 1);
    string[length] = '\0';
  }
  else
    string = "(null)";

  if (hf_id)
    temp_item = proto_tree_add_string(tree, hf_id, a->tvb, start, a->offset 
- start, string);
  if (new_item)
    *new_item = temp_item;

  if (s && length)
    *s = string;
  else
	  if (length)
			g_free(string);
  return ASN1_ERR_NOERROR;
}
static void
show_provider_reason(ASN1_SCK *asn,proto_tree *pres_tree,tvbuff_t *tvb,int 
*offset,int item_len,int type)
{
	  proto_item *ms;
	  proto_item *pr;
	  proto_tree *pres_tree_ms = NULL;
	  proto_tree *pres_tree_pr = NULL;
	  int		off      = *offset;
	  int		value=0;
	  int		new_item_len = item_len+(asn->offset-*offset);

				ms = proto_tree_add_text(pres_tree, tvb, *offset, new_item_len,
										val_to_str(type, sequence_top_vals,
										"Unknown item (0x%02x)"));
				pres_tree_ms = proto_item_add_subtree(ms, ett_pres_ms);
				value	=	get_integer_value(asn,item_len,offset);
				pr = proto_tree_add_text(pres_tree_ms, tvb, *offset, new_item_len,
										val_to_str(value, provider_reason_values_vals,
										"Unknown item (0x%02x)"));
				pres_tree_pr = proto_item_add_subtree(pr, ett_pres_ms);
				print_value(asn,pres_tree_pr,tvb,offset,item_len);
				asn->offset = *offset = off+new_item_len;
}
static void
show_presentation_selector (ASN1_SCK *asn,proto_tree *pres_tree,tvbuff_t 
*tvb,int *offset,int item_len,int type)
{
	  proto_item *ms;
	  proto_tree *pres_tree_ms = NULL;
	  int ret;
	  char *s;

				ms = proto_tree_add_text(pres_tree, tvb, *offset, 
item_len+(asn->offset-*offset),
										val_to_str(type, sequence_top_vals,
										"Unknown item (0x%02x)"));


				pres_tree_ms = proto_item_add_subtree(ms, ett_pres_ms);

				ret = read_string_value(asn, pres_tree,0,NULL, &s, 
*offset+(asn->offset-*offset), item_len);
				if(ret == ASN1_ERR_NOERROR)
				{
					if( item_len)
					{
							proto_tree_add_text(pres_tree_ms, tvb, *offset+2, item_len,
											"String:%s",s);
							g_free(s);
					}
					else
					{
							proto_tree_add_text(pres_tree_ms, tvb, *offset+2, item_len,
											"Zero selector length");

					}
				}



}
/* display top sequence  */
static void
show_sequence_top(ASN1_SCK *asn,proto_tree *pres_tree,tvbuff_t 
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
/* do we have enough bytes to dissect this item ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < item_len )
			{
					proto_tree_add_text(pres_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					break;
			}
		/*   get  tag     */
			type = tvb_get_guint8(tvb, *offset);
		/* decode header  */
			ret = asn1_header_decode(asn, &cls, &con, &tag, &def, &len1);

			if (ret != ASN1_ERR_NOERROR)
			{
							dissect_parse_error(tvb, *offset, pinfo, pres_tree,
									"sequence error", ret);
				break;
			}
			item_len = item_len - (asn->offset - *offset);
						/*
						* [APPLICATION <tag>]
						*/
						switch (tag)
							{
								case TAG_01:
									/* Calling-presentation-selector and
									   User data have the same tag number
									   Try to recognize which one do we really have */
									if( con == ASN1_CON)
									{
										/* it is User data */
										/* print it                 */
										show_user_data(asn,pres_tree,tvb,offset,len1,type);
										break;
									}
									/*  it is Calling-presentation-selector  */
									/*  simply go below, we don't need to break here */

								case CALLED_PRESENTATION_SELECTOR:
								case RESPONDING_PRESENTATION_SELECTOR:
								/*case CALLING_PRESENTATION_SELECTOR:*/
								/*
								* [Called-presentation-selector]
								* [Calling-presentation-selector]
								* [Responding-presentation-selector]
								*/
									show_presentation_selector(asn,pres_tree,tvb,offset,len1,tag);
									break;
								case DEFAULT_CONTEXT_NAME:
								case PRESENTATION_CONTEXT_DEFINITION_LIST:
									show_presentation_context_definition(asn,pres_tree,tvb,offset,len1,tag);
									break;
								case PROTOCOL_VERSION:
								/*case TAG_00:  */
									if(cls == ASN1_APL)
									{
										/* yes, it is application */
											 *offset = asn->offset;
											item_len = len1;
											continue;
									}
									show_protocol_version(asn,pres_tree,tvb,offset,len1,tag);
									break;
								case PRESENTATION_CONTEXT_DEFINITION_RESULT_LIST:
								case DEFAULT_CONTEXT_RESULT:
									show_presentation_context_definition(asn,pres_tree,tvb,offset,len1,tag);
									break;
								case PRESENTATION_REQUIREMENTS:
									show_presentation_requirements(asn,pres_tree,tvb,offset,len1,tag);
									break;
								case PROVIDER_REASON:
									show_provider_reason(asn,pres_tree,tvb,offset,len1,tag);
									break;
								/* to do */

								case USER_SESSION_REQUIREMENTS:

									itm = proto_tree_add_text(pres_tree, tvb, *offset,(asn->offset 
-*offset)+ len1,
											val_to_str(tag, sequence_top_vals,"Unknown item (0x%02x)"));
								(asn->offset)+=len1;
									break;

								default:
									itm = proto_tree_add_text(pres_tree, tvb, *offset,(asn->offset 
-*offset)+ len1,
											"Unknown tag: %x",tag);
									(asn->offset)+=len1;
							}

		item_len-=len1;
		*offset = asn->offset;
	}

}
static void
show_connection_request_confirm(ASN1_SCK *asn,proto_tree *pres_tree,tvbuff_t 
*tvb,packet_info *pinfo,int *offset,int* item_len)
{
  guint8 type;
  guint length;
  proto_tree *pres_tree_ms = NULL;
  proto_item *ms;
			/*  get type of set  */
			while ( tvb_reported_length_remaining(tvb, *offset) > 0 )
			{
				int asn1_tag;
			/*  get item type  */
			type = tvb_get_guint8(tvb, *offset);
			asn1_tag = type & 0x1f;
			/* skip type */
			(*offset)++;
			asn->offset = *offset;
			/* get length  */
				if (read_length(asn, pres_tree, 0, item_len) != ASN1_ERR_NOERROR)
				{
					return;
				}
			/* do we have enough bytes to dissect ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < 
(guint)*item_len )
			{
					proto_tree_add_text(pres_tree, tvb, *offset, -1,
							"Wrong item.Need %u bytes but have %u", *item_len,length);
				return;
			}
				ms = proto_tree_add_text(pres_tree, tvb, *offset-1, 
*item_len+(asn->offset-*offset)+1,
										val_to_str(asn1_tag, cr_vals,
										"Unknown item (0x%02x)"));
				pres_tree_ms = proto_item_add_subtree(ms, ett_pres_ms);

			switch(asn1_tag)
				{
			case MODE_SELECTOR:
				proto_tree_add_uint(pres_tree_ms, hf_pres_ms_type, tvb, (*offset)-1, 1, 
type);
				proto_tree_add_text(pres_tree_ms, tvb, *offset, (asn->offset-*offset),
										"Length:%u",*item_len);
				*offset=asn->offset;
				show_integer(asn,pres_tree_ms,tvb,offset,*item_len);
					break;
			case SET_TOP:
			case SEQUENCE_TOP:
				proto_tree_add_uint(pres_tree_ms, hf_pres_seq_type, tvb, (*offset)-1, 1, 
type);
				proto_tree_add_text(pres_tree_ms, tvb, *offset, (asn->offset-*offset),
										"Length:%u",*item_len);
				*offset=asn->offset;
				show_sequence_top(asn,pres_tree_ms,tvb,pinfo,offset,*item_len);
					break;
			default:
					proto_tree_add_text(pres_tree, tvb, (*offset)-1, 
*item_len+(asn->offset-*offset)+1,
					"Unknown asn.1 parameter: (0x%02x).Tag :(0x%02x)", type,asn1_tag);
					(*offset)+=*item_len+(asn->offset-*offset);
					asn->offset = *offset;
				}

			}
}


/*
* Dissect an Ppdu.
*/
static int
dissect_ppdu(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree 
*tree)
{
  proto_item *ti;
  proto_tree *pres_tree = NULL;
  guint length;
  guint       rest_len;
  guint  s_type;
  ASN1_SCK asn;
  guint cp_type_len;
/* do we have spdu type from the session dissector?  */
	if( !pinfo->private_data )
				{
				if(tree)
						{
					proto_tree_add_text(tree, tvb, offset, -1,
							"Internal error:can't get spdu type from session dissector.");
					return  FALSE;
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
							"Internal error:wrong spdu type %x from session dissector.",session->spdu_type);
					return  FALSE;
						}
					}
				}
/* get type of tag      */
	s_type = tvb_get_guint8(tvb, offset);
		/*  set up type of Ppdu */
  	if (check_col(pinfo->cinfo, COL_INFO))
					col_add_str(pinfo->cinfo, COL_INFO,
						val_to_str(session->spdu_type, ses_vals, "Unknown Ppdu type (0x%02x)"));
  if (tree)
	{
		ti = proto_tree_add_item(tree, proto_pres, tvb, offset, -1,
		    FALSE);
		pres_tree = proto_item_add_subtree(ti, ett_pres);
	}
	offset++;
/*    open asn.1 stream    */
	asn1_open(&asn, tvb, offset);

	switch(session->spdu_type)
	{
		case SES_REFUSE:
			proto_tree_add_uint(pres_tree, hf_pres_type, tvb, offset-1, 1, s_type);
		if (read_length(&asn, pres_tree, hf_cp_type_message_length, &cp_type_len) 
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
					proto_tree_add_text(pres_tree, tvb, offset, -1,
							"Wrong Ppdu.Need %u bytes but have %u", cp_type_len,length);
				}
			return FALSE;
			}
				{
				asn.offset = offset;
				show_sequence_top(&asn,pres_tree,tvb,pinfo,&offset,cp_type_len);
				offset=asn.offset;
				}
			break;
		case SES_CONNECTION_REQUEST:
		case SES_CONNECTION_ACCEPT:
			proto_tree_add_uint(pres_tree, hf_pres_type, tvb, offset-1, 1, s_type);

			if (read_length(&asn, pres_tree, hf_cp_type_message_length, &cp_type_len) 
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
					proto_tree_add_text(pres_tree, tvb, offset, -1,
							"Wrong Ppdu.Need %u bytes but have %u", cp_type_len,length);
				}
			return FALSE;
			}
			{
			show_connection_request_confirm(&asn,pres_tree,tvb,pinfo,&offset,&cp_type_len);
			}
				break;
		case SES_ABORT:
	  			/* get length  */
				if (read_length(&asn, pres_tree, 0, &rest_len) != ASN1_ERR_NOERROR)
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
					proto_tree_add_text(pres_tree, tvb, offset, -1,
							"Wrong Ppdu.Need %u bytes but have %u", rest_len,length);
					}
				return FALSE;
				}
				if(session->abort_type == SESSION_USER_ABORT )
				{
					/* is it PC */
					if(s_type == ASN1_CLASS_PC+ASN1_CLASS_CONTEXT_SPECIFIC)
					{
							{
							offset=asn.offset;
							show_sequence_top(&asn,pres_tree,tvb,pinfo,&offset,rest_len);
							offset=asn.offset;
							}
					}
					else
					{
							{
							offset=asn.offset;
							show_session_provider_abort(&asn,pres_tree,tvb,&offset,rest_len);
							offset=asn.offset;
							}
					}
				}
				else
				{
							{
							offset=asn.offset;
							show_sequence_top(&asn,pres_tree,tvb,pinfo,&offset,rest_len);
							offset=asn.offset;
							}
				}
			break;
		default:
			{
				proto_item *ms;
				proto_tree *pres_tree_ms = NULL;
				/* back to length  */
				  offset--;
	  			/* get length  */
				if (read_length(&asn, pres_tree, 0, &rest_len) != ASN1_ERR_NOERROR)
						{
					return  FALSE;
						}
				if(!rest_len)
				{
					guint       rest_pdu_len = 0;
					/* do we really haven't any more bytes ? */
					if(	(rest_pdu_len = tvb_reported_length_remaining(tvb, offset)) )
					{
						/*
						 * we have but can't say how many from asn1 information.
						 * use pdu len instead
						 */
						if(rest_pdu_len > 2)
						{
						rest_len = rest_pdu_len;
						}
					}
				}
                if( ((gint)rest_len) > 0) {
				ms = proto_tree_add_text(pres_tree, tvb, offset, rest_len,
										val_to_str(session->spdu_type, ses_vals, "Unknown Ppdu type (0x%02x)"));
				pres_tree_ms = proto_item_add_subtree(ms, ett_pres_ms);
				show_user_data(&asn,pres_tree_ms,tvb,&offset,rest_len,s_type);
                }
			}
	}
/*    close asn.1 stream    */
	  asn1_close(&asn, &offset);

	return offset;
}

/*
* Dissect PPDUs inside a SPDU.
*/
static void
dissect_pres(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
/* first, try to check length   */
/* do we have at least 4 bytes  */
	if (!tvb_bytes_exist(tvb, 0, 4))
	{
			proto_tree_add_text(tree, tvb, offset, tvb_reported_length_remaining(tvb, 
offset),
								"User data");
			return;  /* no, it isn't a presentation PDU */
	}

	/*  we can't make any additional checking here   */
	/*  postpone it before dissector will have more information */

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "PRES");
  	if (check_col(pinfo->cinfo, COL_INFO))
  		col_clear(pinfo->cinfo, COL_INFO);
	/* save pointers for calling the acse dissector  */
	global_tree = tree;
	global_pinfo = pinfo;

	while (tvb_reported_length_remaining(tvb, offset) > 0)
			{
		offset = dissect_ppdu(tvb, offset, pinfo, tree);
		if(offset == FALSE )
							{
									proto_tree_add_text(tree, tvb, offset, -1,"Internal error");
									offset = tvb_length(tvb);
									break;
							}
			}
}

void
proto_register_pres(void)
{
	static hf_register_info hf[] =
	{
		{
			&hf_pres_type,
			{
				"PPDU Type",
				"pres.type",
				FT_UINT8,
				BASE_DEC,
				VALS(pres_vals),
				0x0,
				"", HFILL
			}
		},
		{
			&hf_pres_length,
			{
				"Length",
				"pres.length",
				FT_UINT16,
				BASE_DEC,
				NULL,
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
			&hf_pres_rc_type,
			{
				"Connection reqiest/confirm",
				"pres.type",
				FT_UINT8,
				BASE_DEC,
				VALS(pres_vals),
				0x0,
				"Connection reqiest/confirm",
				HFILL
			}
		},

		{
			&hf_pres_ms_type,
			{
				"Mode selector",
				"pres.mode.selector",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Mode select",
				HFILL
			}
		},
		{
			&hf_pres_protocol_version,
			{
				"Protocol version",
				"pres.protocol.version",
				FT_UINT16,
				BASE_HEX,
				NULL,
				0x0,
				"Protocol version",
				HFILL
			}
		},
		{
			&hf_value,
			{
				"Value",
				"pres.value",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Value",
				HFILL
			}
		},

		{
			&hf_pres_seq_type,
			{
				"Sequence",
				"pres.sequence",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Mode select",
				HFILL
			}
		},

		{
			&hf_protocol_version,
			{
				"Protocol version 1",
				"pres.protocol.version",
				FT_BOOLEAN, 16,
				NULL,
				PRES_PROTOCOL_VERGION,
				"Protocol version 1",
				HFILL
			}
		},
		{
			&hf_context_management,
			{
				"Context management",
				"pres.context.management",
				FT_BOOLEAN, 16,
				NULL,
				PRES_CONTEXT_MANAGEMENT,
				"Context management",
				HFILL
			}
		},
		{
			&hf_restoration,
			{
				"Restoration",
				"pres.restoration",
				FT_BOOLEAN, 16,
				NULL,
				PRES_RESTORATION,
				"Restoration",
				HFILL
			}
		},


	};

	static gint *ett[] =
	{
		&ett_pres,
		&ett_pres_param,
		&ett_pres_rc,
		&ett_pres_ms,
		&ett_pres_itm,
	};
	module_t *pres_module;


	proto_pres = proto_register_protocol(PROTO_STRING_PRES, "PRES", "pres");
	proto_register_field_array(proto_pres, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	pres_module = prefs_register_protocol(proto_pres, NULL);

	/*
	 * Register the dissector by name, so other dissectors can
	 * grab it by name rather than just referring to it directly
	 * (you can't refer to it directly from a plugin dissector
	 * on Windows without stuffing it into the Big Transfer Vector).
	 */
	register_dissector("pres", dissect_pres, proto_pres);
}

void
proto_reg_handoff_pres(void)
{
	/*   find data dissector  */
	data_handle = find_dissector("data");
	/* define acse sub dissector */
	acse_handle = find_dissector("acse");
}
