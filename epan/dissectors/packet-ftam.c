/* packet-ftam.c
*
* Routine to dissect OSI ISO 8571 FTAM Protocol packets
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


#include "packet-frame.h"
#include "packet-ftam.h"
#include <epan/prefs.h>

#include <epan/strutil.h>

#include "asn1.h"
#include "format-oid.h"

#include "packet-ses.h"
#include "packet-pres.h"
extern const value_string ses_vals[];
static struct SESSION_DATA_STRUCTURE* session = NULL;



/* ftam header fields             */
static int proto_ftam          = -1;
/* ftam fields defining a sub tree */
static gint ett_ftam           = -1;
static gint ett_ftam_param     = -1;
static gint ett_ftam_rc           = -1;
static gint ett_ftam_ms           = -1;
static gint ett_ftam_itm           = -1;
/* dissector for data */
static dissector_handle_t data_handle;
/*
----------------------------------------------------------------------------------------------------------*/
static int hf_ftam_type        = -1;
static int hf_cp_type_message_length = -1;
static int hf_protocol_version       = -1;

/*   functional units flags */
static int hf_functional_unit_restart_data_transfer	= -1;
static int hf_functional_unit_recovery	= -1;
static int hf_functional_unit_fadu_locking	= -1;
static int hf_functional_unit_grouping	= -1;
static int hf_functional_unit_limited_file_management	= -1;
static int hf_functional_unit_enhanced_file_management	= -1;
static int hf_functional_unit_file_access	= -1;
static int hf_functional_unit_read	= -1;
static int hf_functional_unit_write	= -1;
/*    service classes   */
static int hf_service_class_access_class	= -1;
static int hf_service_class_transfer_and_management_class	= -1;
static int hf_service_class_transfer_class	= -1;
static int hf_service_class_management_class	= -1;
static int hf_service_class_unconstrained_class	= -1;

/*  attribute groups  */
static int hf_attribute_groups_storage		= -1;
static int hf_attribute_groups_security		= -1;
static int hf_attribute_groups_private		= -1;
/*   access    */
static int hf_filename_attribute_read				= -1;
static int hf_filename_attribute_insert				= -1;
static int hf_filename_attribute_replace			= -1;
static int hf_filename_attribute_extend				= -1;
static int hf_filename_attribute_erase				= -1;
static int hf_filename_attribute_read_attribute		= -1;
static int hf_filename_attribute_change_attribute	= -1;
static int hf_filename_attribute_delete_file		= -1;
/* mode  */
static int hf_processing_mode_read					= -1;
static int hf_processing_mode_replace				= -1;
static int hf_processing_mode_insert				= -1;
static int hf_processing_mode_extend				= -1;
static int hf_processing_mode_erase					= -1;

static int hf_permitted_action_attribute_read				= -1;
static int hf_permitted_action_attribute_insert				= -1;
static int hf_permitted_action_attribute_replace			= -1;
static int hf_permitted_action_attribute_extend				= -1;
static int hf_permitted_action_attribute_erase				= -1;
static int hf_permitted_action_attribute_read_attribute		= -1;
static int hf_permitted_action_attribute_change_attribute	= -1;
static int hf_permitted_action_attribute_delete_file		= -1;
static int hf_permitted_action_traversal					= -1;
static int hf_permitted_action_reverse_traversal			= -1;
static int hf_permitted_action_random_order					= -1;

static int hf_nbs9_read_filename							= -1;
static int hf_nbs9_read_permitted_actions					= -1;
static int hf_nbs9_read_contents_type						= -1;
static int hf_nbs9_read_storage_account						= -1;
static int hf_nbs9_read_date_and_time_of_creation			= -1;
static int hf_nbs9_read_date_and_time_of_last_modification	= -1;
static int hf_nbs9_read_date_and_time_of_read_access		= -1;
static int hf_nbs9_read_date_and_time_of_attribute_modification	= -1;
static int hf_nbs9_read_identity_of_creator					= -1;
static int hf_nbs9_read_identity_of_last_reader				= -1;
static int hf_nbs9_read_identity_of_last_modifier			= -1;	
static int hf_nbs9_read_identity_of_last_attribute_modifier	= -1;
static int hf_nbs9_read_file_availability					= -1;
static int hf_nbs9_read_filesize							= -1;
static int hf_nbs9_read_future_filesize						= -1;
static int hf_nbs9_read_access_control						= -1;
static int hf_nbs9_read_legal_qualifications				= -1;
static int hf_nbs9_read_private_use							= -1;

static const value_string ftam_data_vals[] =
{
  {FTAM_GRAPHIC_STRING,  "Graphic String" },
  {FTAM_TELEX_STRING,  "Teletex String" },
  {FTAM_VIDEO_STRING,  "Videotex String" },
  {FTAM_IA5_STRING,  "IA5String" },
  {FTAM_VISIBLE_STRING,  "Visible String" },
  {FTAM_GENERAL_STRING,  "General String" },
  {FTAM_PRINTABLE_STRING,  "Printable String" },
  {FTAM_OCTET_STRING,  "OCTET String" },
  {FTAM_NODE_DESCRIPTOR_DATA_ELEMENT,  "Node Descriptor Data Element" },
  {FTAM_ENTER_SUBTREE_DATA_ELEMENT,  "Enter subtree Data Element" },
  {FTAM_EXIT_SUBTREE_DATA_ELEMENT,  "Exit subtree Data Element" },
  {FTAM_DATATYPE_NBS9,  "Datatype NBS9" },
};
static const value_string ftam_pdu_vals[] =
{
  {FTAM_F_INITIALIZE_REQUEST,  "f-initialize request" },
  {FTAM_F_INITIALIZE_RESPONSE,  "f-initialize response" },
  {FTAM_F_TERMINATE_REQUEST,  "f-terminate request" },
  {FTAM_F_TERMINATE_RESPONSE,  "f-terminate response" },
  {FTAM_F_U_ABORT_REQUEST,  "f-u-abort request" },
  {FTAM_F_SELECT_REQUEST,  "f-select request" },
  {FTAM_F_SELECT_RESPONSE,  "f-select response" },
  {FTAM_F_DESELECT_REQUEST,  "f-deselect request" },
  {FTAM_F_DESELECT_RESPONSE,  "f-deselect response" },
  {FTAM_F_CREATE_REQUEST,  "f-create request" },
  {FTAM_F_CREATE_RESPONSE,  "f-create response" },
  {FTAM_F_DELETE_REQUEST,  "f-delete request" },
  {FTAM_F_DELETE_RESPONSE,  "f-delete response" },
  {FTAM_F_READ_ATTRIB_REQUEST,  "f-read-attrib request" },
  {FTAM_F_READ_ATTRIB_RESPONSE,  "f-read-attrib response" },
  {FTAM_F_CHANGE_ATTRIB_REQUEST,  "f-change-attrib request" },
  {FTAM_F_CHANGE_ATTRIB_RESPONSE,  "f-change-attrib response" },
  {FTAM_F_OPEN_REQUEST,  "f-open request" },
  {FTAM_F_OPEN_RESPONSE,  "f-open response" },
  {FTAM_F_CLOSE_REQUEST,  "f-close request" },
  {FTAM_F_CLOSE_RESPONSE,  "f-close response" },
  {FTAM_F_BEGIN_GROUP_REQUEST,  "f-begin-group request" },
  {FTAM_F_BEGIN_GROUP_RESPONSE,  "f-begin-group response" },
  {FTAM_F_END_GROUP_REQUEST,  "f-end-group request" },
  {FTAM_F_END_GROUP_RESPONSE,  "f-end-group response" },
  {FTAM_F_RECOVER_REQUEST,  "f-recover request" },
  {FTAM_F_RECOVER_RESPONSE,  "f-recover response" },
  {FTAM_F_LOCATE_REQUEST,  "f-locate request" },
  {FTAM_F_LOCATE_RESPONSE,  "f-locate response" },
  {FTAM_F_ERASE_REQUEST,  "f-erase request" },
  {FTAM_F_ERASE_RESPONSE,  "f-erase response" },
  {FTAM_F_READ_REQUEST,  "f-read request" },
  {FTAM_F_WRITE_REQUEST,  "f-write request" },
  {FTAM_F_DATA_END_REQUEST,  "f-data end request" },
  {FTAM_F_TRANSFER_END_REQUEST,  "f-transfer end request" },
  {FTAM_F_TRANSFER_END_RESPONSE,  "f-transfer end response" },
  {FTAM_F_CANCEL_REQUEST,  "f-cancel request" },
  {FTAM_F_CANCEL_RESPONSE,  "f-cancel response" },
  {FTAM_F_REASTART_REQUEST,  "f-restart request" },
  {FTAM_F_REASTART_RESPONSE,  "f-restart response" },
  {0,             NULL           }
};
static const value_string contents_type_list_vals[] =
{
  {FTAM_DOCUMENT_TYPE, "Document type"},
  {FTAM_ABSTRACT_SYNTAX_NAME, "Abstract syntax name"},
  {0, NULL}
};

static const value_string request_sequence_top_vals[] =
{
  {FTAM_RESPONSE_STATE_RESULT, "State result"},
  {FTAM_PROTOCOL_VERSION, "Protocol version"},
  {FTAM_IMPLEMENTATION_INFORMATION, "Implementation information"},
  {FTAM_PRESENTATION_CONTEXT_MANAGEMENT, "Presentation context management"},
  {FTAM_SERVICE_CLASS, "Service class"},
  {FTAM_FUNCTIONAL_UNITS, "Functional units"},
  {FTAM_ATTRIBUTE_GROUPS, "Attribute groups"},
  {FTAM_SHARED_ASE_INFORMATION, "Shared ASE information"},
  {FTAM_QUALITY_OF_SERVICE, "Ftam quality of service"},
  {FTAM_CONTENTS_TYPE_LIST, "Contents type list"},
  {FTAM_INITIATOR_IDENTIFY, "Initiator identity"},
  {FTAM_ACCOUNT,"Account"},
  {FTAM_FILESTORE_PASSWORD,"Filestore password"},
  {FTAM_CHECKPOINT_WINDOW,"Checkpoint window"},
  {FTAM_RESPONSE_ACTION_RESULT, "Action result"},
  {FTAM_RESPONSE_DIAGNOSTIC, "Diagnostic"},
  {FTAM_CHARGING,"Charging"},
  {0, NULL}
};

static const value_string diagnostic_sequence_list_vals[] =
{
  {FTAM_DIAGNOSTIC_TYPE, "Diagnostic type"},
  {FTAM_ERROR_IDENTIFIER, "Error identifier"},
  {FTAM_ERROR_OBSERVER, "Error observer"},
  {FTAM_ERROR_SOURCE, "Error source"},
  {FTAM_SUGGESTED_DELAY, "Suggested delay"},
  {FTAM_FURTHER_DETAILS, "Further details"},
  {0, NULL}
};
static const value_string diag_definition_vals[] =
{
  {SEQUENCE, "Sequence"},
  {0, NULL}
};
static const value_string entity_reference_vals[] =
{
  {FTAM_NO_CATEGORIZATION_POSSIBLE, "No categorization possible"},
  {FTAM_INITIATING_FILE_SERVICE_USER, "Initiating file service user"},
  {FTAM_INITIATING_FILE_PROTOCOL_MASHINE, "Initiating file protocol machine"},
  {FTAM_SERVICE_SUPPORTING_THE_FILE_PROTOCOL_MACHINE, "Service supporting the file protocol machine"},
  {FTAM_RESPONDING_FILE_PROTOCOL_MASHINE, "Responding file protocol machine"},
  {FTAM_RESPONDING_FILE_SERVICE_USER, "Responding file service user"},
  {0, NULL}
};
static const value_string diagnostic_type_vals[] =
{
  {FTAM_DIAGNOSTIC_INFORMATIVE, "Informative"},
  {FTAM_DIAGNOSTIC_TRANSIENT, "Transient"},
  {FTAM_DIAGNOSTIC_PERMANENT, "Permanent"},
  {0, NULL}
};
static const value_string response_state_vals[] =
{
  {FTAM_RESPONSE_STATE_SUCCESS, "Success"},
  {FTAM_RESPONSE_STATE_FAILURE, "failure"},
  {0, NULL}
};
static const value_string response_action_result_vals[] =
{
  {FTAM_RESPONSE_ACTION_RESULT_SUCCESS, "Success"},
  {FTAM_RESPONSE_ACTION_RESULT_TRANSIENT_ERROR, "Transient error"},
  {FTAM_RESPONSE_ACTION_RESULT_PERMANENT_ERROR, "Permanent error"},
  {0, NULL}
};
static const value_string select_request_vals[] =
{
  {FTAM_SELECT_ATTRIBUTES, "Select attributes"},
  {FTAM_CREATE_ATTRIBUTES, "Create attributes"},
  {FTAM_ACCESS_REQUEST, "Access request"},
  {FTAM_ACCSESS_PASSWORDS, "Access passwords"},
  {FTAM_SHARED_ASE_INFORMATION, "Shared ASE information"},
  {FTAM_ACCOUNT,"Account"},  
  {FTAM_OVERRIDE,"Override"},  
          /*no concurrency-control   yet */
  {0, NULL}
};
static const value_string select_attribute_vals[] =
{
  {FTAM_CREATE_FILENAME_ATTRIBUTES, "File name attributes"},
  {FTAM_CREATE_PERMITTED_ACTIONS_ATTRIBUTE, "Permitted actions attribute"},
  {FTAM_CREATE_CONTENTS_TYPE,"Contents type"},
  {FTAM_CREATE_ACCOUNT_ATTRIBUTE,"Account attribute"},
  {FTAM_CREATE_FILE_AVAILABILITY_ATTRIBUTE,"File availability attribute"},
  {FTAM_CREATE_FILESIZE_ATTRIBUTE,"Filesize attribute"},
  {FTAM_CREATE_ACCESS_CONTROL_ATTRIBUTE,"Access control attribute"},
  {FTAM_CREATE_ACCESS_LEGAL_AUALIFICATION_ATTRIBUTE,"Legal aualification attribute"},
  {FTAM_CREATE_ACCESS_PRIVATE_USE_ATTRIBUTE,"Private use attribute"},
  {0, NULL}
};
static const value_string open_request_vals[] =
{
  {FTAM_PROCESSING_MODE, "Processing mode"},
  {FTAM_CONTENTS_TYPE, "Contents type"},
  {FTAM_CONCURENCY_CONTROL, "Concurrency control"},
  {FTAM_SHARED_ASE_INFORMATION, "Shared ASE information"},
  {FTAM_ENABLE_FADU_LOCKING,"Enable fadu locking"},  
  {FTAM_ACTIVITY_IDENTIFIER,"Activity identifier"},  
  {FTAM_RECOVERY_MODE,"Recovery mode"},  
  {FTAM_REMOTE_CONTEXTS,"Remove contexts"},  
  {FTAM_DEFINE_CONTEXTS,"Define contexts"},  
  {0, NULL}
};
static const value_string contents_type_vals[] =
{
  {FTAM_CONTENTS_TYPE_UNKNOWN, "Unknown"},
  {FTAM_CONTENTS_TYPE_PROPOSED, "Proposed"},
  {0, NULL}
};
static const value_string contents_type_proposed_vals[] =
{
  {FTAM_CONTENTS_TYPE_PROPOSED_DOCUMENT_TYPE, "Document type"},
  {FTAM_CONTENTS_TYPE_PROPOSED_CONSTRAINT_SET, "Constraint set and abstract syntax"},
  {0, NULL}
};
static const value_string contents_type_proposed_document_type_vals[] =
{
  {FTAM_CONTENTS_TYPE_PROPOSED_DOCUMENT_TYPE_NAME, "Document type name"},
  {FTAM_CONTENTS_TYPE_PROPOSED_DOCUMENT_TYPE_PARAMETER, "Parameter"},
  {0, NULL}
};
static const value_string override_vals[] =
{
  {FTAM_CREATE_FAILURE, "Create failure"},
  {FTAM_SELECT_OLD_FILE, "Select old file"},
  {FTAM_DELETE_AND_CREATE_WITH_OLD_ATTRIBUTES, "Delete and create with old attributes"},
  {FTAM_DELETE_AND_CREATE_WITH_NEW_ATTRIBUTES, "Delete and create with new attributes"},
  {0, NULL}
};
static const value_string read_write_vals[] =
{
  {FTAM_FILE_ACCESS_DATA_UNIT_IDENTITY, "File access data unit identity"},
  {FTAM_FILE_ACCESS_CONTEXT, "Access context"},
  {FTAM_FILE_FADU_LOCK, "Fadu lock"},
  {FTAM_FILE_ACCESS_DATA_UNIT_OPERATION, "File access data unit operation"},
  {0, NULL}
};
static const value_string fadu_vals[] =
{
  {FTAM_FADU_FIRST_LAST, "First/Last"},
  {FTAM_FADU_RELATIVE, "Relative"},
  {FTAM_FADU_BEGIN_END, "Begin/End"},
  {FTAM_FADU_SINGLE_NAME, "Single name"},
  {FTAM_FADU_NAME_LIST, "Name list"},
  {FTAM_FADU_FADU_NUMBER, "FADU number"},
  {0, NULL}
};
static const value_string first_last_vals[] =
{
  {FTAM_FADU_FIRST, "First"},
  {FTAM_FADU_LAST, "LAST"},
  {0, NULL}
};
static const value_string relative_vals[] =
{
  {FTAM_FADU_PREVIOUS, "Previous"},
  {FTAM_FADU_CURRENT, "Current"},
  {FTAM_FADU_NEXT, "Next"},
  {0, NULL}
};
static const value_string begin_end_vals[] =
{
  {FTAM_FADU_BEGIN, "Begin"},
  {FTAM_FADU_END, "End"},
  {0, NULL}
};
static const value_string access_context_vals[] =
{
  {FTAM_HIERARCHICAL_ALL_DATA_UNITS, "Hierarchical all data units"},
  {FTAM_HIERARCHICAL_NO_DATA_UNITS, "Hierarchical no data units"},
  {FTAM_ALL_DATA_UNITS, "Flat all data units"},
  {FTAM_ONE_LEVEL_DATA_UNITS, "Flat one level data units"},
  {FTAM_SINGLE_DATA_UNITS, "Flat single data units"},
  {FTAM_UNSTRUCTURED_ALL_DATA_UNITS, "Unstructured all data units"},
  {FTAM_UNSTRUCTURED_SINGLE_DATA_UNITS, "Unstructured single data units"},
  {0, NULL}
};
static const value_string access_data_unit_operation_vals[] =
{
  {FTAM_ACCESS_INSERT, "Insert"},
  {FTAM_ACCESS_REPLACE, "Replace"},
  {FTAM_ACCESS_EXTEND, "Extend"},
  {0, NULL}
};



static const value_string ftam_parameters_vals[] =
{
  {FTAM_UNIVERSAL_CLASS_NUMBER, "Universal class number"},
  {FTAM_MAXIMUM_STRING_LENGTH, "Maximum string length"},
  {FTAM_STRING_SIGNIFICANCE, "String significance"},
  {0, NULL}
};

static const value_string universal_class_number_vals[] =
{
  {FTAM_PRINTABLE_LENGTH, "Printable string"},
  {FTAM_GRAPHIC_STRING, "Graphic string"},
  {FTAM_TELEX_STRING, "Teletex string"},
  {FTAM_VIDEO_STRING, "Video texstring"},
  {FTAM_IA5_STRING, "ia5string"},
  {FTAM_VISIBLE_STRING, "Visible string"},
  {FTAM_GENERAL_STRING, "General string"},
  {0, NULL}
};


static const value_string string_significance_vals[] =
{
  {FTAM_VARIABLE, "Variable"},
  {FTAM_FIXED, "Fixed"},
  {FTAM_NOT_SIGNIFICANT, "Not significant"},
  {0, NULL}
};
static const value_string read_attributes_vals[] =
{
  {FTAM_READ_ATTRIBUTE_FILENAME, "Filename"},
  {FTAM_READ_ATTRIBUTE_PERMITTED_ACTIONS, "Permitted actions"},
  {FTAM_READ_ATTRIBUTE_CONTENTS_TYPE, "Contents type"},
  {FTAM_READ_ATTRIBUTE_STORAGE_ACCOUNT, "Storage account"},
  {FTAM_READ_ATTRIBUTE_DATA_AND_TIME_OF_CREATION, "Date and time of creation"},
  {FTAM_READ_ATTRIBUTE_DATA_AND_TIME_OF_LAST_MODIFICATION, "Date and time of last modification"},
  {FTAM_READ_ATTRIBUTE_DATA_AND_TIME_OF_LAST_READ_ACCESS, "Date and time of last read access"},
  {FTAM_READ_ATTRIBUTE_DATA_AND_TIME_OF_LAST_ATTRIBUTE_MODIFICATION, "Date and time of last attribute modification"},
  {FTAM_READ_ATTRIBUTE_IDENTITY_OF_CREATOR, "Identity of creator"},
  {FTAM_READ_ATTRIBUTE_IDENTITY_OF_LAST_MODIFIER, "Identity of last modifier"},
  {FTAM_READ_ATTRIBUTE_IDENTITY_OF_LAST_READER, "Identity of last reader"},
  {FTAM_READ_ATTRIBUTE_IDENTITY_OF_LAST_ATTRIBUTE_MODIFIER, "Identity of last attribute modifier"},
  {FTAM_READ_ATTRIBUTE_FILE_AVAILABILITY, "File availability"},
  {FTAM_READ_ATTRIBUTE_FILESIZE, "Filesize"},
  {FTAM_READ_ATTRIBUTE_FUTURE_FILESIZE, "Future filesize"},
  {FTAM_READ_ATTRIBUTE_ACCESS_CONTROL, "Access control"},
  {FTAM_READ_ATTRIBUTE_LEGAL_QUALIFICATION, "legal qualification"},
  {FTAM_READ_ATTRIBUTE_PRIVATE_USE, "Private use"},
  {0, NULL}
};
static const value_string date_and_time_vals[] =
{
  {FTAM_DATE_AND_TIME_NO_VALUE_AVAILABLE, "No value available"},
  {FTAM_DATE_AND_TIME_ACTUAL_VALUE, "actual values"},
  {0, NULL}
};
static const value_string identity_vals[] =
{
  {FTAM_DATE_IDENTITY_NO_VALUE_AVAILABLE, "No value available"},
  {FTAM_USER_IDENTITY, "actual values"},
  {0, NULL}
};
static const value_string read_attribute_vals[] =
{
  {FTAM_READ_ATTRIBUTES, "Read attributes"},
  {0, NULL}
};

/*   function definitions */
static void
show_contents_type(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t
*tvb,int *offset,int item_len);
static void
show_contents_type_proposed(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t
*tvb,int *offset,int item_len);
static void
show_select_create_attributes(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t *tvb,int
*offset,int item_len);
static void
show_nbs9_parameters(ASN1_SCK *asn,proto_tree *ftam_tree_itm,tvbuff_t *tvb,int
*offset,int item_len);


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
    proto_tree_add_uint(tree, hf_id, a->tvb, start, a->offset-start,length);

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
    temp_item = proto_tree_add_uint(tree, hf_id, a->tvb, start,a->offset-start, integer);

  if (new_item)
    *new_item = temp_item;

  return ASN1_ERR_NOERROR;
}

static void
show_graphic_string(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t *tvb,int
*offset,int item_len,int tag)
{
	  proto_tree *ftam_tree_itm = NULL;
	  proto_item *itm;
	  gint length;
	  gint header_len = (asn->offset -*offset);
/* do we have enough bytes to dissect this item ? */
			if( ( length = tvb_reported_length_remaining(tvb, *offset))  <
										header_len+ item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					return;
			}

	  itm = proto_tree_add_text(ftam_tree, tvb, *offset,(asn->offset -*offset)+
								item_len,
								val_to_str(tag, request_sequence_top_vals,"Unknown item (0x%02x)"));
	  ftam_tree_itm = proto_item_add_subtree(itm, ett_ftam_itm);
	  *offset = asn->offset;
	  proto_tree_add_text(ftam_tree_itm, tvb, *offset, item_len,GRAPHIC_STRING);
	  *offset = *offset + item_len;
	  asn->offset = *offset;
}
static void
show_graphic_string_nameless(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t *tvb,int
*offset,int item_len)
{
	  gint length;
	  gint header_len = (asn->offset -*offset);
	  gint	new_item_len;
/* do we have enough bytes to dissect this item ? */
			if( ( length = tvb_reported_length_remaining(tvb, *offset))  <
										header_len+ item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					return;
			}

			/* skip type */
			(*offset)++;
			asn->offset = *offset;
			/* get length  */
				if (read_length(asn, ftam_tree, 0, &new_item_len) != ASN1_ERR_NOERROR)
				{
					return  ;
				}
			/* do we have enough bytes to dissect ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  <
														new_item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, new_item_len,
							"Wrong item.Need %u bytes but have %u", new_item_len,length);
				    return ;
			}

			*offset = asn->offset;
			proto_tree_add_text(ftam_tree, tvb, *offset, new_item_len,GRAPHIC_STRING);
}
static void
show_file_store_password(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t *tvb,int
*offset,int item_len,int tag)
{
	  proto_tree *ftam_tree_itm = NULL;
	  proto_item *itm;
	  gint length;
	  gint header_len = (asn->offset -*offset);
/* do we have enough bytes to dissect this item ? */
			if( ( length = tvb_reported_length_remaining(tvb, *offset))  <
										header_len+ item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					return;
			}

	  itm = proto_tree_add_text(ftam_tree, tvb, *offset,(asn->offset -*offset)+
								item_len,
								val_to_str(tag, request_sequence_top_vals,"Unknown item (0x%02x)"));
	  ftam_tree_itm = proto_item_add_subtree(itm, ett_ftam_itm);
	  *offset = asn->offset;
	  show_graphic_string_nameless(asn,ftam_tree_itm,tvb,offset,item_len-header_len );
	  *offset = *offset + item_len;
	  asn->offset = *offset;
}

static void
show_attribute_groups(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t *tvb,int
*offset,int item_len,int tag)
{
	  proto_tree *ftam_tree_itm = NULL;
	  proto_item *itm;
	  guint8      flags;
	  gint length;
/* do we have enough bytes to dissect this item ? */
			if( ( length = tvb_reported_length_remaining(tvb, *offset))  <
										(asn->offset -*offset)+ item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					return;
			}
	  itm = proto_tree_add_text(ftam_tree, tvb, *offset,(asn->offset -*offset)+
								item_len,
								val_to_str(tag, request_sequence_top_vals,"Unknown item (0x%02x)"));
	  ftam_tree_itm = proto_item_add_subtree(itm, ett_ftam_itm);
	  *offset = asn->offset;
	  flags = tvb_get_guint8(tvb, (*offset)+1);
	  proto_tree_add_boolean(ftam_tree_itm,hf_attribute_groups_storage, tvb, (*offset)+1,1,flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_attribute_groups_security, tvb, (*offset)+1,1,flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_attribute_groups_private, tvb, (*offset)+1,1,flags);
	  *offset = *offset + item_len;
	  asn->offset = *offset;
}

static void
show_create_permitted_actions_attribute(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t *tvb,int
*offset,int item_len)
{
	  guint16      flags;
	  gint length;
/* do we have enough bytes to dissect this item ? */
			if( ( length = tvb_reported_length_remaining(tvb, *offset))  <
										(asn->offset -*offset)+ item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					return;
			}
	  *offset = asn->offset+1;
	  flags = tvb_get_ntohs(tvb,*offset);
	  proto_tree_add_boolean(ftam_tree,hf_permitted_action_attribute_read, tvb, (*offset),2,flags);
	  proto_tree_add_boolean(ftam_tree,hf_permitted_action_attribute_insert, tvb, (*offset),2,flags);
	  proto_tree_add_boolean(ftam_tree,hf_permitted_action_attribute_replace, tvb, (*offset),2,flags);
	  proto_tree_add_boolean(ftam_tree,hf_permitted_action_attribute_extend, tvb, (*offset),2,flags);
	  proto_tree_add_boolean(ftam_tree,hf_permitted_action_attribute_erase, tvb, (*offset),2,flags);
	  proto_tree_add_boolean(ftam_tree,hf_permitted_action_attribute_read_attribute, tvb, (*offset),2,flags);
	  proto_tree_add_boolean(ftam_tree,hf_permitted_action_attribute_change_attribute, tvb, (*offset),2,flags);
	  proto_tree_add_boolean(ftam_tree,hf_permitted_action_attribute_delete_file, tvb, (*offset),2,flags);
	  proto_tree_add_boolean(ftam_tree,hf_permitted_action_traversal, tvb, (*offset),2,flags);
	  proto_tree_add_boolean(ftam_tree,hf_permitted_action_random_order, tvb, (*offset),2,flags);

	  *offset = *offset + item_len;
	  asn->offset = *offset;
}
static void
show_processing_mode(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t *tvb,int
*offset,int item_len)
{
	  guint16      flags;
	  gint length;
/* do we have enough bytes to dissect this item ? */
			if( ( length = tvb_reported_length_remaining(tvb, *offset))  <
										(asn->offset -*offset)+ item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					return;
			}
	  *offset = asn->offset;
	  flags = tvb_get_ntohs(tvb,*offset);
	  proto_tree_add_boolean(ftam_tree,hf_processing_mode_read, tvb, (*offset),2,flags);
	  proto_tree_add_boolean(ftam_tree,hf_processing_mode_replace, tvb, (*offset),2,flags);
	  proto_tree_add_boolean(ftam_tree,hf_processing_mode_insert, tvb, (*offset),2,flags);
	  proto_tree_add_boolean(ftam_tree,hf_processing_mode_extend, tvb, (*offset),2,flags);
	  proto_tree_add_boolean(ftam_tree,hf_processing_mode_erase, tvb, (*offset),2,flags);
	  *offset = *offset + item_len;
	  asn->offset = *offset;
}
static void
show_access_attributes(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t *tvb,int
*offset,int item_len)
{
	  guint16      flags;
	  gint length;
/* do we have enough bytes to dissect this item ? */
			if( ( length = tvb_reported_length_remaining(tvb, *offset))  <
										(asn->offset -*offset)+ item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					return;
			}
	  *offset = asn->offset;
	  flags = tvb_get_ntohs(tvb,*offset);
	  proto_tree_add_boolean(ftam_tree,hf_filename_attribute_read, tvb, (*offset),2,flags);
	  proto_tree_add_boolean(ftam_tree,hf_filename_attribute_insert, tvb, (*offset),2,flags);
	  proto_tree_add_boolean(ftam_tree,hf_filename_attribute_replace, tvb, (*offset),2,flags);
	  proto_tree_add_boolean(ftam_tree,hf_filename_attribute_extend, tvb, (*offset),2,flags);
	  proto_tree_add_boolean(ftam_tree,hf_filename_attribute_erase, tvb, (*offset),2,flags);
	  proto_tree_add_boolean(ftam_tree,hf_filename_attribute_read_attribute, tvb, (*offset),2,flags);
	  proto_tree_add_boolean(ftam_tree,hf_filename_attribute_change_attribute, tvb, (*offset),2,flags);
	  proto_tree_add_boolean(ftam_tree,hf_filename_attribute_delete_file, tvb, (*offset),2,flags);
	  *offset = *offset + item_len;
	  asn->offset = *offset;
}
static void
show_service_classes(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t *tvb,int
*offset,int item_len,int tag)
{
	  proto_tree *ftam_tree_itm = NULL;
	  proto_item *itm;
	  guint8      flags;
	  gint length;
/* do we have enough bytes to dissect this item ? */
			if( ( length = tvb_reported_length_remaining(tvb, *offset))  <
										(asn->offset -*offset)+ item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					return;
			}
	  itm = proto_tree_add_text(ftam_tree, tvb, *offset,(asn->offset -*offset)+
								item_len,
								val_to_str(tag, request_sequence_top_vals,"Unknown item (0x%02x)"));
	  ftam_tree_itm = proto_item_add_subtree(itm, ett_ftam_itm);
	  *offset = asn->offset;
	  flags = tvb_get_guint8(tvb, (*offset)+1);
	  proto_tree_add_boolean(ftam_tree_itm,hf_service_class_unconstrained_class, tvb, (*offset)+1,1,flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_service_class_management_class, tvb, (*offset)+1,1,flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_service_class_transfer_class, tvb, (*offset)+1,1,flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_service_class_transfer_and_management_class, tvb, (*offset)+1,1,flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_service_class_transfer_and_management_class, tvb, (*offset)+1,1,flags);
	  *offset = *offset + item_len;
	  asn->offset = *offset;
}

static void
show_functional_units(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t *tvb,int
*offset,int item_len,int tag)
{
	  proto_tree *ftam_tree_itm = NULL;
	  proto_item *itm;
	  guint16       flags;
	  gint length;
/* do we have enough bytes to dissect this item ? */
			if( ( length = tvb_reported_length_remaining(tvb, *offset))  <
										(asn->offset -*offset)+ item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					return;
			}
	  itm = proto_tree_add_text(ftam_tree, tvb, *offset,(asn->offset -*offset)+
								item_len,
								val_to_str(tag, request_sequence_top_vals,"Unknown item (0x%02x)"));
	  ftam_tree_itm = proto_item_add_subtree(itm, ett_ftam_itm);
	  *offset = asn->offset;
	  flags = tvb_get_ntohs(tvb, (*offset)+1);
	  proto_tree_add_boolean(ftam_tree_itm,hf_functional_unit_read, tvb, (*offset)+1,2, flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_functional_unit_write, tvb, (*offset)+1,2, flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_functional_unit_file_access, tvb, (*offset)+1,2, flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_functional_unit_limited_file_management, tvb, (*offset)+1,2, flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_functional_unit_enhanced_file_management, tvb, (*offset)+1,2, flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_functional_unit_grouping, tvb, (*offset)+1,2, flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_functional_unit_fadu_locking, tvb, (*offset)+1,2, flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_functional_unit_recovery, tvb, (*offset)+1,2, flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_functional_unit_restart_data_transfer, tvb, (*offset)+1,2, flags);
	  *offset = *offset + item_len;
	  asn->offset = *offset;
}
static void
show_nbs9_parameters(ASN1_SCK *asn,proto_tree *ftam_tree_itm,tvbuff_t *tvb,int
*offset,int item_len)
{
	  guint16       flags;
	  gint length;
	  guint8  flag;
/* do we have enough bytes to dissect this item ? */
			if( ( length = tvb_reported_length_remaining(tvb, *offset))  <
										(asn->offset -*offset)+ item_len )
			{
					proto_tree_add_text(ftam_tree_itm, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					return;
			}
	  *offset = asn->offset;
	  flags = tvb_get_ntohs(tvb, (*offset)+3);
	  proto_tree_add_boolean(ftam_tree_itm,hf_nbs9_read_filename, tvb, (*offset)+3,2, flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_nbs9_read_permitted_actions, tvb, (*offset)+3,2, flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_nbs9_read_contents_type, tvb, (*offset)+3,2, flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_nbs9_read_storage_account, tvb, (*offset)+3,2, flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_nbs9_read_date_and_time_of_creation, tvb, (*offset)+3,2, flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_nbs9_read_date_and_time_of_last_modification, tvb, (*offset)+3,2, flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_nbs9_read_date_and_time_of_read_access, tvb, (*offset)+3,2, flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_nbs9_read_date_and_time_of_attribute_modification, tvb, (*offset)+3,2, flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_nbs9_read_identity_of_creator, tvb, (*offset)+3,2, flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_nbs9_read_identity_of_last_reader, tvb, (*offset)+3,2, flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_nbs9_read_identity_of_last_attribute_modifier, tvb, (*offset)+3,2, flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_nbs9_read_file_availability, tvb, (*offset)+1,3, flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_nbs9_read_filesize, tvb, (*offset)+1,3, flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_nbs9_read_future_filesize, tvb, (*offset)+3,2, flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_nbs9_read_access_control, tvb, (*offset)+3,2, flags);
	  flag = tvb_get_guint8(tvb, (*offset)+5 );
	  proto_tree_add_boolean(ftam_tree_itm,hf_nbs9_read_legal_qualifications, tvb, (*offset)+5,1, flags);
	  proto_tree_add_boolean(ftam_tree_itm,hf_nbs9_read_private_use, tvb, (*offset)+5,1, flag);
	  *offset = *offset + item_len;
	  asn->offset = *offset;
}
static void
show_protocol_version(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t *tvb,int
*offset,int item_len,int tag)
{
	  proto_tree *ftam_tree_itm = NULL;
	  proto_item *itm;
	  guint16       flags;
	  gint length;
/* do we have enough bytes to dissect this item ? */
			if( ( length = tvb_reported_length_remaining(tvb, *offset))  <
										(asn->offset -*offset)+ item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					return;
			}

	  itm = proto_tree_add_text(ftam_tree, tvb, *offset,(asn->offset -*offset)+
								item_len,
								val_to_str(tag, request_sequence_top_vals,"Unknown item (0x%02x)"));
	  ftam_tree_itm = proto_item_add_subtree(itm, ett_ftam_itm);
	  *offset = asn->offset;
	  flags = tvb_get_ntohs(tvb, *offset);
	  proto_tree_add_boolean(ftam_tree_itm,hf_protocol_version, tvb, *offset,
							2, flags);
	  *offset = *offset + item_len;
	  asn->offset = *offset;
}
static void
print_oid_value(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t *tvb,int
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
		proto_tree_add_text(ftam_tree, tvb, *offset,length,"Value:%s",
							display_string);
		g_free(display_string);
		(*offset)=start+item_len;
		asn->offset = (*offset);
}

static void
contents_type_list_data(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t *tvb,int
*offset,int item_len)
{
	  proto_tree *ftam_tree_ms = NULL;
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
				if (read_length(asn, ftam_tree, 0, &new_item_len) != ASN1_ERR_NOERROR)
				{
					(*offset)=start+item_len;
					asn->offset = (*offset);
					return  ;
				}
			/* do we have enough bytes to dissect ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  <
														new_item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, new_item_len,
							"Wrong item.Need %u bytes but have %u", new_item_len,length);
					(*offset)=start+item_len;
					asn->offset = (*offset);
				    return ;
			}
				header_len = asn->offset - (*offset) +1;
					ms = proto_tree_add_text(ftam_tree, tvb, *offset-1,
										new_item_len+(asn->offset-*offset)+1,
										val_to_str(type, contents_type_list_vals,
										"Unknown item (0x%02x)"));
				ftam_tree_ms = proto_item_add_subtree(ms, ett_ftam_ms);
				*offset = asn->offset;
			switch(type)
				{
			case FTAM_ABSTRACT_SYNTAX_NAME:
			case FTAM_DOCUMENT_TYPE:
				print_oid_value(asn,ftam_tree_ms,tvb,offset,new_item_len);
					break;
			default:
					proto_tree_add_text(ftam_tree, tvb, *offset,
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
contents_type_list(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t *tvb,int
*offset,int item_len,int tag)
{
	  proto_tree *ftam_tree_pc = NULL;
	  proto_item *itu;
	  guint		start = asn->offset;
	  guint		item_length = item_len;
	  guint		new_item_len;
	  guint		length;
			itu = proto_tree_add_text(ftam_tree, tvb,
										*offset,item_len+(asn->offset-*offset),
					val_to_str(tag, request_sequence_top_vals,"Unknown item (0x%02x)"));
			ftam_tree_pc = proto_item_add_subtree(itu, ett_ftam_ms);
			switch(tag)
			{
			case FTAM_CONTENTS_TYPE_LIST:
				/* get length  */
				(*offset)++;
				asn->offset = *offset;
				if (read_length(asn, ftam_tree, 0, &new_item_len) != ASN1_ERR_NOERROR)
					{
					(*offset)=start+item_len;
					asn->offset = (*offset);
					return  ;
					}
				/* do we have enough bytes to dissect ? */
				if( ( length =tvb_reported_length_remaining(tvb, *offset)) < new_item_len )
					{
					proto_tree_add_text(ftam_tree_pc, tvb, *offset, new_item_len,
							"Wrong item.Need %u bytes but have %u", new_item_len,length);
					(*offset)=start+item_len;
					asn->offset = (*offset);
				    return ;
					}
				*offset = asn->offset;
				contents_type_list_data(asn,ftam_tree_pc,tvb,offset,new_item_len);
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
show_access_context(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t
*tvb,int *offset,int item_len)
{
	int ret;
	guint cls, con, tag,len1;
	gint  type;
	gboolean def;
	gint length;
	int offset_save = *offset;
/* do we have enough bytes to dissect this item ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					return;
			}
		/*   get  tag     */
			type = tvb_get_guint8(tvb, *offset);
		/* decode header  */
			ret = asn1_header_decode(asn, &cls, &con, &tag, &def, &len1);

			if (ret != ASN1_ERR_NOERROR)
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Sequence error %u", ret);

				return;
			}
			/* add header  */
			item_len = item_len - (asn->offset - *offset);
			offset_save += (asn->offset - *offset);
			/* align to value */
			*offset = asn->offset;
			 
			proto_tree_add_text(ftam_tree, tvb,*offset,len1,
								val_to_str(tvb_get_guint8(tvb,*offset), access_context_vals,"Unknown item (0x%02x)"));


			item_len-=len1;
			*offset = asn->offset = offset_save+len1;

}

/* display attribute identity  */
static void
show_attribute_identity(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t
*tvb,int *offset,int item_len)
{
	int ret;
	guint cls, con, tag,len1;
	gint  type;
	gboolean def;
	gint length;
	int offset_save = *offset;
	proto_item *itm;
    proto_tree *ftam_tree_ms = NULL;

/* do we have enough bytes to dissect this item ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					return;
			}
		/*   get  tag     */
			type = tvb_get_guint8(tvb, *offset);
		/* decode header  */
			ret = asn1_header_decode(asn, &cls, &con, &tag, &def, &len1);

			if (ret != ASN1_ERR_NOERROR)
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Sequence error %u", ret);
				return;
			}
			itm = proto_tree_add_text(ftam_tree, tvb,*offset,len1,
								val_to_str(tag, identity_vals,"Unknown item (0x%02x)"));
			ftam_tree_ms = proto_item_add_subtree(itm, ett_ftam_ms);

			switch(tag)
			{
				case FTAM_USER_IDENTITY:
					/* add header  */
					item_len = item_len - (asn->offset - *offset);
					offset_save += (asn->offset - *offset);
					/* align to value */
					*offset = asn->offset;
					proto_tree_add_text(ftam_tree_ms, tvb,*offset,len1,
								"String");
					break;
				default:;
			}


			item_len-=len1;
			*offset = asn->offset = offset_save+len1;

}

/* display attribute date  */
static void
show_attribute_data_and_time(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t
*tvb,int *offset,int item_len)
{
	int ret;
	guint cls, con, tag,len1;
	gint  type;
	gboolean def;
	gint length;
	int offset_save = *offset;
	proto_item *itm;
    proto_tree *ftam_tree_ms = NULL;

/* do we have enough bytes to dissect this item ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					return;
			}
		/*   get  tag     */
			type = tvb_get_guint8(tvb, *offset);
		/* decode header  */
			ret = asn1_header_decode(asn, &cls, &con, &tag, &def, &len1);

			if (ret != ASN1_ERR_NOERROR)
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Sequence error %u", ret);
				return;
			}
			itm = proto_tree_add_text(ftam_tree, tvb,*offset,len1,
								val_to_str(tag, date_and_time_vals,"Unknown item (0x%02x)"));
			ftam_tree_ms = proto_item_add_subtree(itm, ett_ftam_ms);

			switch(tag)
			{
				case FTAM_DATE_AND_TIME_ACTUAL_VALUE:
					/* add header  */
					item_len = item_len - (asn->offset - *offset);
					offset_save += (asn->offset - *offset);
					/* align to value */
					*offset = asn->offset;
					proto_tree_add_text(ftam_tree_ms, tvb,*offset,len1,
								"Generalized Time");
					break;
				default:;
			}


			item_len-=len1;
			*offset = asn->offset = offset_save+len1;

}



/* display read attribute structure  */
static void
show_read_attributes(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t
*tvb,packet_info *pinfo,int *offset,int item_len)
{
	int ret;
	guint cls, con, tag,len1;
	gboolean def;
	proto_item *itm;
	gint length;
	gint new_item_len;
    proto_tree *ftam_tree_ms = NULL;


	while(item_len > 0 )
	{
			int offset_save = *offset;
/* do we have enough bytes to dissect this item ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					break;
			}
		/* decode header  */
			ret = asn1_header_decode(asn, &cls, &con, &tag, &def, &len1);

			if (ret != ASN1_ERR_NOERROR)
			{
							dissect_parse_error(tvb, *offset, pinfo, ftam_tree,
									"sequence error", ret);
				break;
			}
			/* add header  */
			item_len = item_len - (asn->offset - *offset);
			offset_save += (asn->offset - *offset);
			itm = proto_tree_add_text(ftam_tree, tvb, (*offset),(asn->offset-*offset)+ len1,
										val_to_str(tag, read_attributes_vals,
										"Unknown item (0x%02x)"));
	        ftam_tree_ms = proto_item_add_subtree(itm, ett_ftam_ms);

						/*
						* [APPLICATION <tag>]
						*/
			switch (tag)
				{
			case FTAM_CREATE_FILENAME_ATTRIBUTES:
				/* get length  */
				(*offset)++;
				asn->offset = *offset;
				if (read_length(asn, ftam_tree, 0, &new_item_len) != ASN1_ERR_NOERROR)
					{
							item_len-=len1;
							*offset = asn->offset = offset_save+len1;
							return  ;
					}
				/* do we have enough bytes to dissect ? */
				if( ( length =tvb_reported_length_remaining(tvb, *offset)) < new_item_len )
					{
					proto_tree_add_text(ftam_tree_ms, tvb, *offset, new_item_len,
							"Wrong item.Need %u bytes but have %u", new_item_len,length);
							item_len-=len1;
							*offset = asn->offset = offset_save+len1;

				    return ;
					}
				*offset = asn->offset;
				show_graphic_string_nameless(asn,ftam_tree_ms,tvb,offset,new_item_len);
				break;
			case FTAM_CREATE_PERMITTED_ACTIONS_ATTRIBUTE:
				*offset = asn->offset;
				show_create_permitted_actions_attribute(asn,ftam_tree_ms,tvb,offset,len1);
				break;
			case FTAM_READ_ATTRIBUTE_IDENTITY_OF_CREATOR:
			case FTAM_READ_ATTRIBUTE_IDENTITY_OF_LAST_MODIFIER:
			case FTAM_READ_ATTRIBUTE_IDENTITY_OF_LAST_READER:
			case FTAM_READ_ATTRIBUTE_IDENTITY_OF_LAST_ATTRIBUTE_MODIFIER:
				*offset = asn->offset;
				show_attribute_identity(asn,ftam_tree_ms,tvb,offset,len1);
				break;

			case FTAM_CREATE_CONTENTS_TYPE:
				*offset = asn->offset;
				show_contents_type_proposed(asn,ftam_tree_ms,tvb,offset,len1);
				break;
			case FTAM_READ_ATTRIBUTE_DATA_AND_TIME_OF_CREATION:
			case FTAM_READ_ATTRIBUTE_DATA_AND_TIME_OF_LAST_MODIFICATION:
			case FTAM_READ_ATTRIBUTE_DATA_AND_TIME_OF_LAST_READ_ACCESS:
			case FTAM_READ_ATTRIBUTE_DATA_AND_TIME_OF_LAST_ATTRIBUTE_MODIFICATION:
				*offset = asn->offset;
				show_attribute_data_and_time(asn,ftam_tree_ms,tvb,offset,len1);
				break;


			default:
				if (match_strval(tag, read_attributes_vals) == NULL)
												{
				proto_tree_add_text(ftam_tree_ms, tvb, *offset,(asn->offset-*offset)+ len1,
									"Unknown tag: %x",tag);
												}
				}
		item_len-=len1;
		*offset = asn->offset = offset_save+len1;
	}
}

/* display nbs9 structure  */
static void
show_nbs9(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t
*tvb,packet_info *pinfo,int *offset,int item_len)
{
	int ret;
	guint cls, con, tag,len1;
	gboolean def;
	gint length;
	proto_item *itm;
    proto_tree *ftam_tree_ms = NULL;
	while(item_len > 0 )
	{
			int offset_save = *offset;
/* do we have enough bytes to dissect this item ? */

			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					break;
			}
		/* decode header  */
			ret = asn1_header_decode(asn, &cls, &con, &tag, &def, &len1);

			if (ret != ASN1_ERR_NOERROR)
			{
							dissect_parse_error(tvb, *offset, pinfo, ftam_tree,
									"sequence error", ret);
				break;
			}
			/* add header  */
			item_len = item_len - (asn->offset - *offset);
			offset_save += (asn->offset - *offset);

			itm = proto_tree_add_text(ftam_tree, tvb, (*offset),(asn->offset-*offset)+ len1,
										val_to_str(tag, read_attribute_vals,
										"Unknown item (0x%02x)"));
	        ftam_tree_ms = proto_item_add_subtree(itm, ett_ftam_ms);
						/*
						* [APPLICATION <tag>]
						*/
						switch (tag)
							{
								case FTAM_READ_ATTRIBUTES:
										*offset = asn->offset;
										show_read_attributes(asn,ftam_tree_ms,tvb,pinfo,offset,len1);
										break;
								default:
									proto_tree_add_text(ftam_tree_ms, tvb, *offset,(asn->offset-*offset)+ len1,
											"Unknown tag: %x",tag);
							}
		item_len-=len1;
		*offset = asn->offset = offset_save+len1;
	}
}

/* display request top sequence  */
static void
show_request_sequence_top(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t
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
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					break;
			}
		/*   get  tag     */
			type = tvb_get_guint8(tvb, *offset);
		/* decode header  */
			ret = asn1_header_decode(asn, &cls, &con, &tag, &def, &len1);

			if (ret != ASN1_ERR_NOERROR)
			{
							dissect_parse_error(tvb, *offset, pinfo, ftam_tree,
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
								case FTAM_IMPLEMENTATION_INFORMATION:
								case FTAM_INITIATOR_IDENTIFY:
									show_graphic_string(asn,ftam_tree,tvb,offset,len1,tag);
									break;
								case FTAM_FILESTORE_PASSWORD:
									show_file_store_password(asn,ftam_tree,tvb,offset,len1,tag);
									break;
								case FTAM_FUNCTIONAL_UNITS:
									show_functional_units(asn,ftam_tree,tvb,offset,len1,tag);									
									break;
								case FTAM_ATTRIBUTE_GROUPS:
									show_attribute_groups(asn,ftam_tree,tvb,offset,len1,tag);									
									break;
								case FTAM_SERVICE_CLASS:
									show_service_classes(asn,ftam_tree,tvb,offset,len1,tag);									
									break;
								case FTAM_ACCOUNT:
									if( con == ASN1_CON)
									{
										/* it is FTAM_ACCOUNT   */
									show_graphic_string(asn,ftam_tree,tvb,offset,len1,tag);
									break;
									}
									/* no,it is FTAM_CHECKPOINT_WINDOW, go below */
									tag = FTAM_CHECKPOINT_WINDOW;


								case FTAM_PRESENTATION_CONTEXT_MANAGEMENT:
								case FTAM_QUALITY_OF_SERVICE:
									{
									proto_tree *ftam_tree_pr = NULL;
									proto_item *pr;
									guint	ret;
									guint	value;
									pr = proto_tree_add_text(ftam_tree,tvb,*offset,
									len1+(asn->offset-*offset),
									val_to_str(tag ,request_sequence_top_vals,
									"Unknown item (0x%02x)"));
									ftam_tree_pr = proto_item_add_subtree(pr, ett_ftam_ms);
									ret = read_integer_value(asn,ftam_tree_pr, 0, NULL, &value, asn->offset, len1);
									if (ret == ASN1_ERR_NOERROR )
										{
												*offset = asn->offset;
												itm = proto_tree_add_text(ftam_tree_pr, tvb, (*offset)-len1,
												len1,
												"Integer value: %u",value);
										}
									}
									break;
								case FTAM_CONTENTS_TYPE_LIST:
									contents_type_list(asn,ftam_tree,tvb,offset,len1,tag);
									break;
								case FTAM_PROTOCOL_VERSION:
									show_protocol_version(asn,ftam_tree,tvb,offset,len1,tag);
									break;
								case FTAM_SHARED_ASE_INFORMATION:
									proto_tree_add_text(ftam_tree, tvb, *offset,(asn->offset -*offset)+len1,
														val_to_str(tag, request_sequence_top_vals,"Unknown item (0x%02x)"));
									break;
								default:
									proto_tree_add_text(ftam_tree, tvb, *offset,(asn->offset-*offset)+ len1,
											"Unknown tag: %x",tag);
							}
		item_len-=len1;
		*offset = asn->offset = offset_save+len1;
	}
}
static void
show_error_identifier(ASN1_SCK *asn,proto_tree 
*ftam_tree,tvbuff_t *tvb,int *offset,int item_len)
{
	guint	ret;
	guint	value;
	ret = read_integer_value(asn,ftam_tree, 0, NULL, &value, asn->offset, item_len);
	if (ret == ASN1_ERR_NOERROR )
		{
				*offset = asn->offset;
				proto_tree_add_text(ftam_tree, tvb, (*offset)-item_len,
										item_len,
										"Integer value: %u",value);
		}
}
static void
show_diagnostic_type(ASN1_SCK *asn,proto_tree 
*ftam_tree,tvbuff_t *tvb,int *offset,int item_len)
{
	guint	ret;
	guint	value;
	ret = read_integer_value(asn,ftam_tree, 0, NULL, &value, asn->offset, item_len);
	if (ret == ASN1_ERR_NOERROR )
		{
				*offset = asn->offset;
				proto_tree_add_text(ftam_tree, tvb, (*offset)-item_len, item_len,
										val_to_str(value, diagnostic_type_vals,
										"Unknown item (0x%02x)"));

		}
}
static void
show_entity_reference(ASN1_SCK *asn,proto_tree 
*ftam_tree,tvbuff_t *tvb,int *offset,int item_len)
{
	guint	ret;
	guint	value;
	ret = read_integer_value(asn,ftam_tree, 0, NULL, &value, asn->offset, item_len);
	if (ret == ASN1_ERR_NOERROR )
		{
				*offset = asn->offset;
				proto_tree_add_text(ftam_tree, tvb, (*offset)-item_len, item_len,
										val_to_str(value, entity_reference_vals,
										"Unknown item (0x%02x)"));

		}
}
static void
show_response_state(ASN1_SCK *asn,proto_tree 
*ftam_tree,tvbuff_t *tvb,int *offset,int item_len)
{
	guint	ret;
	guint	value;
	ret = read_integer_value(asn,ftam_tree, 0, NULL, &value, asn->offset, item_len);
	if (ret == ASN1_ERR_NOERROR )
		{
				*offset = asn->offset;
				proto_tree_add_text(ftam_tree, tvb, (*offset)-item_len, item_len,
										val_to_str(value, response_state_vals,
										"Unknown item (0x%02x)"));

		}
}
static void
show_response_action_result(ASN1_SCK *asn,proto_tree 
*ftam_tree,tvbuff_t *tvb,int *offset,int item_len)
{
	guint	ret;
	guint	value;
	ret = read_integer_value(asn,ftam_tree, 0, NULL, &value, asn->offset, item_len);
	if (ret == ASN1_ERR_NOERROR )
		{
				*offset = asn->offset;
				proto_tree_add_text(ftam_tree, tvb, (*offset)-item_len, item_len,
										val_to_str(value, response_action_result_vals,
										"Unknown item (0x%02x)"));

		}
}

static void
show_diagnostic_seq(ASN1_SCK *asn,proto_tree 
*ftam_tree,tvbuff_t *tvb,int *offset,int item_len)
{
	  proto_tree *ftam_tree_ms = NULL;
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
				if (read_length(asn, ftam_tree, 0, &new_item_len) != ASN1_ERR_NOERROR)
				{
					(*offset)=start+item_len;
					asn->offset = (*offset);
					return  ;
				}

			/* do we have enough bytes to dissect ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < new_item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, new_item_len,
							"Wrong item.Need %u bytes but have %u", new_item_len,length);
					(*offset)=start+item_len;
					asn->offset = (*offset);
				    return ;
			}
				header_len = asn->offset - (*offset) +1;
				ms = proto_tree_add_text(ftam_tree, tvb, *offset-1, new_item_len+(asn->offset-*offset)+1,
										val_to_str(type, diagnostic_sequence_list_vals,
										"Unknown item (0x%02x)"));
				ftam_tree_ms = proto_item_add_subtree(ms, ett_ftam_ms);
				*offset = asn->offset = (*offset)+1;


			switch(type)
				{
			case FTAM_FURTHER_DETAILS:
				(*offset)-=2;
				show_graphic_string_nameless(asn,ftam_tree_ms,tvb,offset,new_item_len);
					break;
			case FTAM_ERROR_IDENTIFIER:
				show_error_identifier(asn,ftam_tree_ms,tvb,offset,new_item_len);
				break;
			case FTAM_DIAGNOSTIC_TYPE:
				show_diagnostic_type(asn,ftam_tree_ms,tvb,offset,new_item_len);
				break;
			case FTAM_ERROR_OBSERVER:
			case FTAM_ERROR_SOURCE:
				show_entity_reference(asn,ftam_tree_ms,tvb,offset,new_item_len);
				break;
			default:
					proto_tree_add_text(ftam_tree_ms, tvb, *offset, new_item_len+(asn->offset-*offset),
					"Unknown asn.1 parameter: (0x%02x)", type);
				}
				*offset = old_offset+new_item_len+header_len;
				item_len-=new_item_len+header_len;
			}
			/*   align the pointer */
			(*offset)=start+item_len;
			asn->offset = (*offset);
}


/* display diagnostic in the f-initiate response */
static void
show_diagnostic(ASN1_SCK *asn,proto_tree 
*ftam_tree,tvbuff_t *tvb,int *offset,int item_len,int tag)
{
	  proto_tree *ftam_tree_ms = NULL;
	  proto_tree *ftam_tree_pc = NULL;
	  proto_item *itm;
	  gint    length;
	  guint   type;
	  guint   header_len;
	  proto_item *ms;
	  gint   new_item_len;
	  guint   start = asn->offset;
	  guint	  item_length = item_len;

			itm = proto_tree_add_text(ftam_tree, tvb, *offset,item_len+(asn->offset-*offset),
					val_to_str(tag, request_sequence_top_vals,"Unknown item (0x%02x)"));
			ftam_tree_pc = proto_item_add_subtree(itm, ett_ftam_ms);

/* do we have enough bytes to dissect ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < item_len )
			{
					proto_tree_add_text(ftam_tree_pc, tvb, *offset, item_len,
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
				if (read_length(asn, ftam_tree_pc, 0, &new_item_len) != ASN1_ERR_NOERROR)
				{
					/*   align the pointer */
					(*offset)=start+item_length;
					asn->offset = (*offset);
					return  ;
				}
				header_len = asn->offset - (*offset) +1;
			/* do we have enough bytes to dissect ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < new_item_len )
			{
					proto_tree_add_text(ftam_tree_pc, tvb, *offset, new_item_len,
							"Wrong item.Need %u bytes but have %u", new_item_len,length);
					/*   align the pointer */
					(*offset)=start+item_length;
					asn->offset = (*offset);
					return ;
			}
				ms = proto_tree_add_text(ftam_tree_pc, tvb, *offset-1, new_item_len+(asn->offset-*offset)+1,
										val_to_str(type, diag_definition_vals,
										"Unknown item (0x%02x)"));
				ftam_tree_ms = proto_item_add_subtree(ms, ett_ftam_ms);
				*offset = asn->offset;


			switch(type)
				{

			case SEQUENCE:
			show_diagnostic_seq(asn,ftam_tree_ms,tvb,offset,new_item_len);

			*offset = old_offset+(new_item_len+header_len);
					break;

			default:
					proto_tree_add_text(ftam_tree_ms, tvb, *offset, new_item_len+(asn->offset-*offset),
					"Unknown asn.1 parameter: (0x%02x)", type);
					*offset = old_offset+(new_item_len+header_len);
				}
				item_len = item_len -  (new_item_len+header_len);

			}


					/*   align the pointer */
					(*offset)=start+item_length;
					asn->offset = (*offset);
}

/* display response top sequence  */
static void
show_response_sequence_top(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t
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
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					break;
			}
		/*   get  tag     */
			type = tvb_get_guint8(tvb, *offset);
		/* decode header  */
			ret = asn1_header_decode(asn, &cls, &con, &tag, &def, &len1);

			if (ret != ASN1_ERR_NOERROR)
			{
							dissect_parse_error(tvb, *offset, pinfo, ftam_tree,
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
								case FTAM_IMPLEMENTATION_INFORMATION:
									if( con == ASN1_CON)
									{
										/* it is FTAM_CONTETS_TYPE   */
										*offset = asn->offset;
										show_contents_type_proposed(asn,ftam_tree,tvb,offset,len1);
										break;
									}
									/* no, it is implementation information.Just go below */

								case FTAM_INITIATOR_IDENTIFY:
									show_graphic_string(asn,ftam_tree,tvb,offset,len1,tag);
									break;
								case FTAM_FILESTORE_PASSWORD:
									show_file_store_password(asn,ftam_tree,tvb,offset,len1,tag);
									break;
								case FTAM_FUNCTIONAL_UNITS:
									show_functional_units(asn,ftam_tree,tvb,offset,len1,tag);									
									break;
								case FTAM_CHARGING:
									proto_tree_add_text(ftam_tree,tvb,*offset,
									len1+(asn->offset-*offset),
									val_to_str(tag ,request_sequence_top_vals,
									"Unknown item (0x%02x)"));
									break;

								case FTAM_ATTRIBUTE_GROUPS:
									if( cls == ASN1_APL)
									{
										/* it is FTAM_RESPONSE_ACTION_RESULT   */
									proto_tree *ftam_tree_pr = NULL;
									proto_item *pr;
									pr = proto_tree_add_text(ftam_tree,tvb,*offset,
									len1+(asn->offset-*offset),
									val_to_str(FTAM_RESPONSE_ACTION_RESULT ,request_sequence_top_vals,
									"Unknown item (0x%02x)"));
									ftam_tree_pr = proto_item_add_subtree(pr, ett_ftam_ms);
									show_response_action_result(asn,ftam_tree_pr,tvb,offset,len1);
									}
									else
									{
									show_attribute_groups(asn,ftam_tree,tvb,offset,len1,tag);									
									}
									break;
								case FTAM_SERVICE_CLASS:
									show_service_classes(asn,ftam_tree,tvb,offset,len1,tag);									
									break;
								case FTAM_CREATE_ATTRIBUTES:
									*offset = asn->offset;
									show_select_create_attributes(asn,ftam_tree,tvb,offset,len1);
									break;

								case FTAM_RESPONSE_STATE_RESULT:
									{
									proto_tree *ftam_tree_pr = NULL;
									proto_item *pr;
									pr = proto_tree_add_text(ftam_tree,tvb,*offset,
									len1+(asn->offset-*offset),
									val_to_str(tag ,request_sequence_top_vals,
									"Unknown item (0x%02x)"));
									ftam_tree_pr = proto_item_add_subtree(pr, ett_ftam_ms);
									show_response_state(asn,ftam_tree_pr,tvb,offset,len1);
									}
									break;
								case FTAM_ACCOUNT:
									if( con == ASN1_CON)
									{
										/* it is FTAM_ACCOUNT   */
									show_graphic_string(asn,ftam_tree,tvb,offset,len1,tag);
									break;
									}
									/* no,it is FTAM_CHECKPOINT_WINDOW, go below */
									tag = FTAM_CHECKPOINT_WINDOW;
								case FTAM_PRESENTATION_CONTEXT_MANAGEMENT:
								case FTAM_QUALITY_OF_SERVICE:
									{
									proto_tree *ftam_tree_pr = NULL;
									proto_item *pr;
									guint	ret;
									guint	value;
									pr = proto_tree_add_text(ftam_tree,tvb,*offset,
									len1+(asn->offset-*offset),
									val_to_str(tag ,request_sequence_top_vals,
									"Unknown item (0x%02x)"));
									ftam_tree_pr = proto_item_add_subtree(pr, ett_ftam_ms);
									ret = read_integer_value(asn,ftam_tree_pr, 0, NULL, &value, asn->offset, len1);
									if (ret == ASN1_ERR_NOERROR )
										{
												*offset = asn->offset;
												itm = proto_tree_add_text(ftam_tree_pr, tvb, (*offset)-len1,
												len1,
												"Integer value: %u",value);
										}
									}
									break;
								case FTAM_CONTENTS_TYPE_LIST:
									contents_type_list(asn,ftam_tree,tvb,offset,len1,tag);
									break;
								case FTAM_PROTOCOL_VERSION:
									show_protocol_version(asn,ftam_tree,tvb,offset,len1,tag);
									break;
								case FTAM_SHARED_ASE_INFORMATION:
									proto_tree_add_text(ftam_tree, tvb, *offset,(asn->offset -*offset)+len1,
														val_to_str(tag, request_sequence_top_vals,"Unknown item (0x%02x)"));
									break;
								case FTAM_RESPONSE_DIAGNOSTIC:
									show_diagnostic(asn,ftam_tree,tvb,offset,len1,tag);
									break;
								case FTAM_SELECT_ATTRIBUTES:
									*offset = asn->offset;
									show_select_create_attributes(asn,ftam_tree,tvb,offset,len1);
									break;

								default:
									itm = proto_tree_add_text(ftam_tree, tvb, *offset,(asn->offset-*offset)+ len1,
											"Unknown tag: %x",tag);
							}
		item_len-=len1;
		*offset = asn->offset = offset_save+len1;
	}
}

static void
show_select_create_attributes(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t *tvb,int
*offset,int item_len)
{
	  proto_tree *ftam_tree_pc = NULL;
	  proto_item *itu;
	  guint		start = asn->offset;
	  int		new_item_len;
	  int		length;
	  int ret;
	  guint cls, con, tag,len1;
	  gint		type;
	  gboolean def;

	while(item_len > 0 )
	{
			int offset_save = *offset;
/* do we have enough bytes to dissect this item ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					break;
			}
		/*   get  tag     */
			type = tvb_get_guint8(tvb, *offset);
		/* decode header  */
			ret = asn1_header_decode(asn, &cls, &con, &tag, &def, &len1);

			if (ret != ASN1_ERR_NOERROR)
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"sequence error %u", ret);
				break;
			}
			type = type & 0x1f;

			itu = proto_tree_add_text(ftam_tree, tvb,*offset,len1+(asn->offset-*offset),
					val_to_str(type, select_attribute_vals,"Unknown item (0x%02x)"));
			ftam_tree_pc = proto_item_add_subtree(itu, ett_ftam_ms);

			/* add header  */
			item_len = item_len - (asn->offset - *offset);
			offset_save += (asn->offset - *offset);
			switch(type)
			{
			case FTAM_CREATE_FILENAME_ATTRIBUTES:
				/* get length  */
				(*offset)++;
				asn->offset = *offset;
				if (read_length(asn, ftam_tree, 0, &new_item_len) != ASN1_ERR_NOERROR)
					{
					(*offset)=start+item_len;
					asn->offset = (*offset);
					return  ;
					}
				/* do we have enough bytes to dissect ? */
				if( ( length =tvb_reported_length_remaining(tvb, *offset)) < new_item_len )
					{
					proto_tree_add_text(ftam_tree_pc, tvb, *offset, new_item_len,
							"Wrong item.Need %u bytes but have %u", new_item_len,length);
					(*offset)=start+item_len;
					asn->offset = (*offset);
				    return ;
					}
				*offset = asn->offset;
				show_graphic_string_nameless(asn,ftam_tree_pc,tvb,offset,new_item_len);
				break;
			case FTAM_CREATE_PERMITTED_ACTIONS_ATTRIBUTE:
				*offset = asn->offset;
				show_create_permitted_actions_attribute(asn,ftam_tree_pc,tvb,offset,len1);
				break;

			case FTAM_CREATE_CONTENTS_TYPE:
				*offset = asn->offset;
				show_contents_type_proposed(asn,ftam_tree_pc,tvb,offset,len1);
				break;

			default:
				break;
			}

		item_len-=len1;
		*offset = asn->offset = offset_save+len1;
	}
}

/* display select_request  */
static void
show_select_request(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t
*tvb,packet_info *pinfo,int *offset,int item_len)
{
	int ret;
	guint cls, con, tag,len1;
	gint  type;
	gboolean def;
	proto_item *itm;
	gint length;
    proto_tree *ftam_tree_ms = NULL;
	proto_item *ms;

	while(item_len > 0 )
	{
			int offset_save = *offset;
/* do we have enough bytes to dissect this item ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					break;
			}
		/*   get  tag     */
			type = tvb_get_guint8(tvb, *offset);
		/* decode header  */
			ret = asn1_header_decode(asn, &cls, &con, &tag, &def, &len1);

			if (ret != ASN1_ERR_NOERROR)
			{
							dissect_parse_error(tvb, *offset, pinfo, ftam_tree,
									"sequence error", ret);
				break;
			}
			ms = proto_tree_add_text(ftam_tree, tvb, *offset, len1+(asn->offset-*offset),
										val_to_str(tag, select_request_vals,
										"Unknown item (0x%02x)"));
			ftam_tree_ms = proto_item_add_subtree(ms, ett_ftam_ms);

			/* add header  */
			item_len = item_len - (asn->offset - *offset);
			offset_save += (asn->offset - *offset);
						/*
						* [APPLICATION <tag>]
						*/
						switch (tag)
							{
								case FTAM_OVERRIDE:

									proto_tree_add_text(ftam_tree_ms, tvb, asn->offset,len1,
														val_to_str(tvb_get_guint8(tvb, asn->offset), override_vals,"Unknown item (0x%02x)"));
									break;
								case FTAM_ACCOUNT:
									show_graphic_string(asn,ftam_tree_ms,tvb,offset,len1,tag);
									break;
								case FTAM_SELECT_ATTRIBUTES:
								case FTAM_CREATE_ATTRIBUTES:
									*offset = asn->offset;
									show_select_create_attributes(asn,ftam_tree_ms,tvb,offset,len1);
									break;

								case FTAM_SHARED_ASE_INFORMATION:
									proto_tree_add_text(ftam_tree_ms, tvb, *offset,(asn->offset -*offset)+len1,
														val_to_str(tag, request_sequence_top_vals,"Unknown item (0x%02x)"));
									break;
								case FTAM_ACCESS_REQUEST:
									show_access_attributes(asn,ftam_tree_ms,tvb,offset,len1);
									break;
								default:
									itm = proto_tree_add_text(ftam_tree_ms, tvb, *offset,(asn->offset-*offset)+ len1,
											"Unknown tag: %x",tag);
							}
		item_len-=len1;
		*offset = asn->offset = offset_save+len1;
	}
}


/* display select_request  */
static void
show_ftam_parameters(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t
*tvb,int *offset,int item_len)
{
	int ret;
	guint cls, con, tag,len1;
	gint  type;
	gboolean def;
	proto_item *itm;
	gint length;
    proto_tree *ftam_tree_ms = NULL;
	proto_item *ms;
		/* decode header  */
			ret = asn1_header_decode(asn, &cls, &con, &tag, &def, &item_len);

			if (ret != ASN1_ERR_NOERROR)
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"sequence error %u", ret);
				return;
			}
			*offset = asn->offset;

	while(item_len > 0 )
	{
			int offset_save = *offset;
/* do we have enough bytes to dissect this item ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					break;
			}
		/*   get  tag     */
			type = tvb_get_guint8(tvb, *offset);
		/* decode header  */
			ret = asn1_header_decode(asn, &cls, &con, &tag, &def, &len1);

			if (ret != ASN1_ERR_NOERROR)
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"sequence error %u", ret);
				break;
			}
			ms = proto_tree_add_text(ftam_tree, tvb, *offset, len1+(asn->offset-*offset),
										val_to_str(tag, ftam_parameters_vals,
										"Unknown item (0x%02x)"));
			ftam_tree_ms = proto_item_add_subtree(ms, ett_ftam_ms);

			/* add header  */
			item_len = item_len - (asn->offset - *offset);
			offset_save += (asn->offset - *offset);
						/*
						* [APPLICATION <tag>]
						*/
						switch (tag)
							{
								case FTAM_UNIVERSAL_CLASS_NUMBER:
									*offset =asn->offset;
									proto_tree_add_text(ftam_tree_ms, tvb, *offset, len1,
														val_to_str(tvb_get_guint8(tvb, *offset),
														universal_class_number_vals,"Unknown item (0x%02x)"));
									break;
								case FTAM_STRING_SIGNIFICANCE:
									*offset =asn->offset;
									proto_tree_add_text(ftam_tree_ms, tvb, *offset, len1,
														val_to_str(tvb_get_guint8(tvb, *offset),
														string_significance_vals,"Unknown item (0x%02x)"));
									break;

								default:
									itm = proto_tree_add_text(ftam_tree_ms, tvb, *offset,(asn->offset-*offset)+ len1,
											"Unknown tag: %x",tag);
							}
		item_len-=len1;
		*offset = asn->offset = offset_save+len1;
	}
}



/* display contents type  proposed document type*/
static void
show_contents_type_proposed_document_type(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t
*tvb,int *offset,int item_len)
{
	int ret;
	guint cls, con, tag,len1;
	gint  type;
	gboolean def;
	proto_item *itm;
	gint length;
    proto_tree *ftam_tree_ms = NULL;
	proto_item *ms;
	gboolean   nbs9 = FALSE;
	gint		tp;  

	while(item_len > 0 )
	{
			int offset_save = *offset;
/* do we have enough bytes to dissect this item ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					break;
			}
		/*   get  tag     */
			type = tvb_get_guint8(tvb, *offset);
		/* decode header  */
			ret = asn1_header_decode(asn, &cls, &con, &tag, &def, &len1);

			if (ret != ASN1_ERR_NOERROR)
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"sequence error %u", ret);

				break;
			}
			ms = proto_tree_add_text(ftam_tree, tvb, *offset, len1+(asn->offset-*offset),
										val_to_str(tag, contents_type_proposed_document_type_vals,
										"Unknown item (0x%02x)"));
			ftam_tree_ms = proto_item_add_subtree(ms, ett_ftam_ms);

			/* add header  */
			item_len = item_len - (asn->offset - *offset);
			offset_save += (asn->offset - *offset);
						/*
						* [APPLICATION <tag>]
						*/
						switch (tag)
							{
								case FTAM_CONTENTS_TYPE_PROPOSED_DOCUMENT_TYPE_NAME:
									if( (tp=tvb_get_guint8(tvb, (*offset)+2))  == NBS9_OID )
									{
										nbs9 = TRUE;
									}
									print_oid_value(asn,ftam_tree_ms,tvb,offset,len1);
									*offset = asn->offset;
									break;
								case FTAM_CONTENTS_TYPE_PROPOSED_DOCUMENT_TYPE_PARAMETER:
									if(nbs9)
									{
										/* it is NBS9 directory */ 
										*offset = asn->offset;
										show_nbs9_parameters(asn,ftam_tree_ms,tvb,offset,len1);
										break;
									}
									else
									{
										show_ftam_parameters(asn,ftam_tree_ms,tvb,offset,len1);
									}
								default:
										if (match_strval(tag, contents_type_proposed_document_type_vals) == NULL)
												{
									itm = proto_tree_add_text(ftam_tree_ms, tvb, *offset,(asn->offset-*offset)+ len1,
											"Unknown tag: %x",tag);
												}
							}
		item_len-=len1;
		*offset = asn->offset = offset_save+len1;
	}
}

/* display contents type  proposed */
static void
show_contents_type_proposed(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t
*tvb,int *offset,int item_len)
{
	int ret;
	guint cls, con, tag,len1;
	gint  type;
	gboolean def;
	proto_item *itm;
	gint length;
    proto_tree *ftam_tree_ms = NULL;
	proto_item *ms;

	while(item_len > 0 )
	{
			int offset_save = *offset;
/* do we have enough bytes to dissect this item ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					break;
			}
		/*   get  tag     */
			type = tvb_get_guint8(tvb, *offset);
		/* decode header  */
			ret = asn1_header_decode(asn, &cls, &con, &tag, &def, &len1);

			if (ret != ASN1_ERR_NOERROR)
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"sequence error %u", ret);

				break;
			}
			ms = proto_tree_add_text(ftam_tree, tvb, *offset, len1+(asn->offset-*offset),
										val_to_str(tag, contents_type_proposed_vals,
										"Unknown item (0x%02x)"));
			ftam_tree_ms = proto_item_add_subtree(ms, ett_ftam_ms);

			/* add header  */
			item_len = item_len - (asn->offset - *offset);
			offset_save += (asn->offset - *offset);
						/*
						* [APPLICATION <tag>]
						*/
						switch (tag)
							{
								case FTAM_CONTENTS_TYPE_PROPOSED_DOCUMENT_TYPE:
									*offset = asn->offset;
									show_contents_type_proposed_document_type(asn,ftam_tree_ms,tvb,offset,len1);
									break;
								default:
										if (match_strval(tag, contents_type_proposed_vals) == NULL)
												{
									itm = proto_tree_add_text(ftam_tree_ms, tvb, *offset,(asn->offset-*offset)+ len1,
											"Unknown tag: %x",tag);
												}
							}
		item_len-=len1;
		*offset = asn->offset = offset_save+len1;
	}
}

/* display FADU indetity type  */
static void
show_fadu_identity_type(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t
*tvb,int *offset,int item_len)
{
	int ret;
	guint cls, con, tag,len1;
	gint  type;
	gboolean def;
	proto_item *itm;
	gint length;
    proto_tree *ftam_tree_ms = NULL;
	proto_item *ms;

	while(item_len > 0 )
	{
			int offset_save = *offset;
/* do we have enough bytes to dissect this item ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					break;
			}
		/*   get  tag     */
			type = tvb_get_guint8(tvb, *offset);
		/* decode header  */
			ret = asn1_header_decode(asn, &cls, &con, &tag, &def, &len1);

			if (ret != ASN1_ERR_NOERROR)
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, len1,
							"sequence error %u", ret);

				break;
			}
			ms = proto_tree_add_text(ftam_tree, tvb, *offset, len1+(asn->offset-*offset),
										val_to_str(tag, fadu_vals,
										"Unknown item (0x%02x)"));
			ftam_tree_ms = proto_item_add_subtree(ms, ett_ftam_ms);

			/* add header  */
			item_len = item_len - (asn->offset - *offset);
			offset_save += (asn->offset - *offset);
						/*
						* [APPLICATION <tag>]
						*/
						switch (tag)
							{
								case FTAM_FADU_FIRST_LAST:
									*offset = asn->offset;
									proto_tree_add_text(ftam_tree_ms, tvb, *offset, len1,
										val_to_str(tvb_get_guint8(tvb, *offset), first_last_vals,"Unknown item (0x%02x)"));
									break;
								case FTAM_FADU_RELATIVE:
									*offset = asn->offset;
									proto_tree_add_text(ftam_tree_ms, tvb, *offset, len1,
										val_to_str(tvb_get_guint8(tvb, *offset), relative_vals,"Unknown item (0x%02x)"));
									break;
								case FTAM_FADU_BEGIN_END:
									*offset = asn->offset;
									proto_tree_add_text(ftam_tree_ms, tvb, *offset, len1,
										val_to_str(tvb_get_guint8(tvb, *offset), begin_end_vals,"Unknown item (0x%02x)"));
									break;

								default:
										if (match_strval(tag, contents_type_vals) == NULL)
												{
									itm = proto_tree_add_text(ftam_tree_ms, tvb, *offset,(asn->offset-*offset)+ len1,
											"Unknown tag: %x",tag);
												}
							}
		item_len-=len1;
		*offset = asn->offset = offset_save+len1;
	}
}




/* display contents type  */
static void
show_contents_type(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t
*tvb,int *offset,int item_len)
{
	int ret;
	guint cls, con, tag,len1;
	gint  type;
	gboolean def;
	proto_item *itm;
	gint length;
    proto_tree *ftam_tree_ms = NULL;
	proto_item *ms;

	while(item_len > 0 )
	{
			int offset_save = *offset;
/* do we have enough bytes to dissect this item ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					break;
			}
		/*   get  tag     */
			type = tvb_get_guint8(tvb, *offset);
		/* decode header  */
			ret = asn1_header_decode(asn, &cls, &con, &tag, &def, &len1);

			if (ret != ASN1_ERR_NOERROR)
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, len1,
							"sequence error %u", ret);

				break;
			}
			ms = proto_tree_add_text(ftam_tree, tvb, *offset, len1+(asn->offset-*offset),
										val_to_str(tag, contents_type_vals,
										"Unknown item (0x%02x)"));
			ftam_tree_ms = proto_item_add_subtree(ms, ett_ftam_ms);

			/* add header  */
			item_len = item_len - (asn->offset - *offset);
			offset_save += (asn->offset - *offset);
						/*
						* [APPLICATION <tag>]
						*/
						switch (tag)
							{
								case FTAM_CONTENTS_TYPE_PROPOSED:
									*offset = asn->offset;
									show_contents_type_proposed(asn,ftam_tree_ms,tvb,offset,len1);
									break;
								default:
										if (match_strval(tag, contents_type_vals) == NULL)
												{
									itm = proto_tree_add_text(ftam_tree_ms, tvb, *offset,(asn->offset-*offset)+ len1,
											"Unknown tag: %x",tag);
												}
							}
		item_len-=len1;
		*offset = asn->offset = offset_save+len1;
	}
}
/* display read and write request  */
static void
show_read_write_request(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t
*tvb,packet_info *pinfo,int *offset,int item_len)
{
	int ret;
	guint cls, con, tag,len1;
	gint  type;
	gboolean def;
	proto_item *itm;
	gint length;
    proto_tree *ftam_tree_ms = NULL;
	proto_item *ms;

	while(item_len > 0 )
	{
			int offset_save = *offset;
/* do we have enough bytes to dissect this item ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					break;
			}
		/*   get  tag     */
			type = tvb_get_guint8(tvb, *offset);
		/* decode header  */
			ret = asn1_header_decode(asn, &cls, &con, &tag, &def, &len1);

			if (ret != ASN1_ERR_NOERROR)
			{
							dissect_parse_error(tvb, *offset, pinfo, ftam_tree,
									"sequence error", ret);
				break;
			}
			ms = proto_tree_add_text(ftam_tree, tvb, *offset, len1+(asn->offset-*offset),
										val_to_str(tag, read_write_vals,
										"Unknown item (0x%02x)"));
			ftam_tree_ms = proto_item_add_subtree(ms, ett_ftam_ms);

			/* add header  */
			item_len = item_len - (asn->offset - *offset);
			offset_save += (asn->offset - *offset);
						/*
						* [APPLICATION <tag>]
						*/
						switch (tag)
							{
								case FTAM_FILE_ACCESS_DATA_UNIT_OPERATION:
									*offset = asn->offset;
									proto_tree_add_text(ftam_tree_ms, tvb, *offset, len1,
										val_to_str(tvb_get_guint8(tvb, *offset), access_data_unit_operation_vals,
										"Unknown item (0x%02x)"));

									break;
								case FTAM_FILE_ACCESS_DATA_UNIT_IDENTITY:
									*offset = asn->offset;
									show_fadu_identity_type(asn,ftam_tree_ms,tvb,offset,len1);
									break;
								case FTAM_FILE_ACCESS_CONTEXT:
									*offset = asn->offset;
									show_access_context(asn,ftam_tree_ms,tvb,offset,len1);
									break;

								default:
										if (match_strval(tag, ftam_pdu_vals) == NULL)
												{
									itm = proto_tree_add_text(ftam_tree_ms, tvb, *offset,(asn->offset-*offset)+ len1,
											"Unknown tag: %x",tag);
												}
							}
		item_len-=len1;
		*offset = asn->offset = offset_save+len1;
	}
}

/* display open_request  */
static void
show_open_request(ASN1_SCK *asn,proto_tree *ftam_tree,tvbuff_t
*tvb,packet_info *pinfo,int *offset,int item_len)
{
	int ret;
	guint cls, con, tag,len1;
	gint  type;
	gboolean def;
	proto_item *itm;
	gint length;
    proto_tree *ftam_tree_ms = NULL;
	proto_item *ms;

	while(item_len > 0 )
	{
			int offset_save = *offset;
/* do we have enough bytes to dissect this item ? */
			if( ( length =tvb_reported_length_remaining(tvb, *offset))  < item_len )
			{
					proto_tree_add_text(ftam_tree, tvb, *offset, item_len,
							"Wrong Item.Need %u bytes but have %u", item_len,length);
					break;
			}
		/*   get  tag     */
			type = tvb_get_guint8(tvb, *offset);
		/* decode header  */
			ret = asn1_header_decode(asn, &cls, &con, &tag, &def, &len1);

			if (ret != ASN1_ERR_NOERROR)
			{
							dissect_parse_error(tvb, *offset, pinfo, ftam_tree,
									"sequence error", ret);
				break;
			}
			ms = proto_tree_add_text(ftam_tree, tvb, *offset, len1+(asn->offset-*offset),
										val_to_str(tag, open_request_vals,
										"Unknown item (0x%02x)"));
			ftam_tree_ms = proto_item_add_subtree(ms, ett_ftam_ms);

			/* add header  */
			item_len = item_len - (asn->offset - *offset);
			offset_save += (asn->offset - *offset);
						/*
						* [APPLICATION <tag>]
						*/
						switch (tag)
							{
								case FTAM_PROCESSING_MODE:
									show_processing_mode(asn,ftam_tree_ms,tvb,offset,len1);
									break;
								case FTAM_CONTENTS_TYPE:
									*offset = asn->offset;
									show_contents_type(asn,ftam_tree_ms,tvb,offset,len1);
									break;
								case FTAM_SHARED_ASE_INFORMATION:

									break;
								default:
										if (match_strval(tag, ftam_pdu_vals) == NULL)
												{
									itm = proto_tree_add_text(ftam_tree_ms, tvb, *offset,(asn->offset-*offset)+ len1,
											"Unknown tag: %x",tag);
												}
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
  proto_tree *ftam_tree = NULL;
  guint length;
  guint       rest_len;
  guint  s_type;
  ASN1_SCK asn;
  guint cp_type_len;
/* get type of tag      */
	s_type = tvb_get_guint8(tvb, offset);
	/*  is it data bulk pdu  ? */
  if (tree)
	{
		ti = proto_tree_add_item(tree, proto_ftam, tvb, offset, -1,
								FALSE);
		ftam_tree = proto_item_add_subtree(ti, ett_ftam);
	}

	if(s_type == DATA_BULK_PDU )
	{
		if(tree)
		{
				proto_tree_add_text(ftam_tree, tvb, offset, 1,
							"Bulk data Pdu");
		}
		/* skip additional data type byte   */
				offset++;
		/* get type of tag      */
		s_type = tvb_get_guint8(tvb, offset);  /*set application bite  */

	}
	offset++;
/*    open asn.1 stream    */
	asn1_open(&asn, tvb, offset);

	/* is it data PDU  ? */
	if( session->abort_type == DATA_BLOCK )
	{
			proto_item *ms;
			proto_tree *ftam_tree_ms = NULL;
			int save_offset;
		/*  set up type of pdu */
  	if (check_col(pinfo->cinfo, COL_INFO))
					col_add_str(pinfo->cinfo, COL_INFO,"FTAM data PDU");

	  	/* get length  */
		if (read_length(&asn, ftam_tree_ms, 0, &rest_len) != ASN1_ERR_NOERROR)
				{
					return  FALSE;
				}
		ms = proto_tree_add_text(ftam_tree, tvb, offset-1, rest_len+(asn.offset-offset)+1,
										val_to_str(s_type, ftam_data_vals, "Unknown pdu type (0x%02x)"));
		ftam_tree_ms = proto_item_add_subtree(ms, ett_ftam_ms);

			/* skip length   */
			offset = asn.offset;
			/* do we have enough bytes to dissect ? */
			if( ( length =tvb_reported_length_remaining(tvb, offset))  < rest_len
					)
			{
				if(tree)
				{
					proto_tree_add_text(ftam_tree, tvb, offset, -1,
							"Wrong pdu.Need %u bytes but have %u", rest_len,length);
				}
			return FALSE;
			}
			save_offset = asn.offset;

		switch(s_type)
		{
		case FTAM_DATATYPE_NBS9:
			show_nbs9(&asn,ftam_tree_ms,tvb,pinfo,&offset,rest_len);
			break;
		case FTAM_PRINTABLE_LENGTH:
		case FTAM_GRAPHIC_STRING:
		case FTAM_TELEX_STRING:
		case FTAM_IA5_STRING:
		case FTAM_VISIBLE_STRING:
		case FTAM_GENERAL_STRING:
		case FTAM_OCTET_STRING:
		case FTAM_PRINTABLE_STRING:
			break;
		default:
			{
			if(tree)
				{
				ms = proto_tree_add_text(ftam_tree, tvb, offset, rest_len+(asn.offset-offset),
										"Unknown pdu type (0x%02x)",s_type);
				}
			}

		}
		offset =rest_len+save_offset;
		asn.offset=offset;
		/*    close asn.1 stream    */
		asn1_close(&asn, &offset);
		return offset ; 
	}
	/* no, it is not data PDU */
	/*  set up type of pdu */
  	if (check_col(pinfo->cinfo, COL_INFO))
					col_add_str(pinfo->cinfo, COL_INFO,
						val_to_str(s_type, ftam_pdu_vals, "Unknown pdu type (0x%02x)"));

	switch(s_type)
	{
		case FTAM_F_INITIALIZE_REQUEST:
		case FTAM_F_INITIALIZE_RESPONSE:
		case FTAM_F_TERMINATE_REQUEST:
		case FTAM_F_TERMINATE_RESPONSE:
		case FTAM_F_U_ABORT_REQUEST:
		case FTAM_F_P_ABORT_REQUEST:
		case FTAM_F_DESELECT_RESPONSE:
		case FTAM_F_DELETE_RESPONSE:
		case FTAM_F_CLOSE_RESPONSE:
		case FTAM_F_ERASE_RESPONSE:
		case FTAM_F_TRANSFER_END_REQUEST:
		case FTAM_F_CANCEL_REQUEST:
		case FTAM_F_CANCEL_RESPONSE:
		case FTAM_F_CREATE_RESPONSE:
		case FTAM_F_OPEN_RESPONSE:
		case FTAM_F_SELECT_RESPONSE:

			proto_tree_add_uint(ftam_tree, hf_ftam_type, tvb, offset-1, 1, s_type);
			if (read_length(&asn, ftam_tree, hf_cp_type_message_length, &cp_type_len)
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
					proto_tree_add_text(ftam_tree, tvb, offset, -1,
							"Wrong pdu.Need %u bytes but have %u", cp_type_len,length);
				}
			return FALSE;
			}
			if(tree)
			{
				if(s_type == FTAM_F_INITIALIZE_REQUEST)
				{
				show_request_sequence_top(&asn,ftam_tree,tvb,pinfo,&offset,cp_type_len);
				}
				else
				{
				show_response_sequence_top(&asn,ftam_tree,tvb,pinfo,&offset,cp_type_len);
				}

			}
				break;
		case FTAM_F_SELECT_REQUEST:
		case FTAM_F_CREATE_REQUEST:
			proto_tree_add_uint(ftam_tree, hf_ftam_type, tvb, offset-1, 1, s_type);
			if (read_length(&asn, ftam_tree, hf_cp_type_message_length, &cp_type_len)
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
					proto_tree_add_text(ftam_tree, tvb, offset, -1,
							"Wrong pdu.Need %u bytes but have %u", cp_type_len,length);
				}
			return FALSE;
			}
			if(tree)
			{
				show_select_request(&asn,ftam_tree,tvb,pinfo,&offset,cp_type_len);
			}
				break;
		case FTAM_F_OPEN_REQUEST:
			proto_tree_add_uint(ftam_tree, hf_ftam_type, tvb, offset-1, 1, s_type);
			if (read_length(&asn, ftam_tree, hf_cp_type_message_length, &cp_type_len)
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
					proto_tree_add_text(ftam_tree, tvb, offset, -1,
							"Wrong pdu.Need %u bytes but have %u", cp_type_len,length);
				}
			return FALSE;
			}
			if(tree)
			{
				show_open_request(&asn,ftam_tree,tvb,pinfo,&offset,cp_type_len);
			}
				break;
		case FTAM_F_READ_REQUEST:
		case FTAM_F_WRITE_REQUEST:
			proto_tree_add_uint(ftam_tree, hf_ftam_type, tvb, offset-1, 1, s_type);
			if (read_length(&asn, ftam_tree, hf_cp_type_message_length, &cp_type_len)
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
					proto_tree_add_text(ftam_tree, tvb, offset, -1,
							"Wrong pdu.Need %u bytes but have %u", cp_type_len,length);
				}
			return FALSE;
			}
			if(tree)
			{
				show_read_write_request(&asn,ftam_tree,tvb,pinfo,&offset,cp_type_len);
			}
				break;

		default:
			{
				proto_item *ms;
				proto_tree *ftam_tree_ms = NULL;
				/* back to type  */
				  offset--;
	  			/* get length  */
				if (read_length(&asn, ftam_tree, 0, &rest_len) != ASN1_ERR_NOERROR)
						{
					return  FALSE;
						}
				ms = proto_tree_add_text(ftam_tree, tvb, offset, rest_len+(asn.offset-offset),
										val_to_str(s_type, ftam_pdu_vals, "Unknown pdu type (0x%02x)"));
				ftam_tree_ms = proto_item_add_subtree(ms, ett_ftam_ms);
				offset+=rest_len+(asn.offset-offset)+1;
				asn.offset=offset;
			}
	}
/*    close asn.1 stream    */
	  asn1_close(&asn, &offset);

	return offset;
}

/*
* Dissect FTAM PDUs inside a PPDU.
*/
static void
dissect_ftam(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
  guint  s_type;

/* first, try to check length   */
/* do we have at least 2 bytes  */
	if (!tvb_bytes_exist(tvb, 0, 2))
	{
	proto_tree_add_text(tree, tvb, offset,tvb_reported_length_remaining(tvb,offset),
								"User data");
			return;  /* no, it isn't a FTAM PDU */
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
							"Internal error:wrong spdu type %x from session dissector.",session->spdu_type);
					return  ;
						}
					}
				}

/* get type of tag      */
	s_type = tvb_get_guint8(tvb, offset);

	/* check PDU type */
	if(session->abort_type != DATA_BLOCK )
	{
			if (match_strval(s_type, ftam_pdu_vals) == NULL)
				{
					return ;  /* no, it isn't a FTAM PDU */
				}
	}
	else
	{
			if (match_strval(s_type, ftam_data_vals) == NULL)
				{
					return ;  /* no, it isn't a FTAM PDU */
				}
	}

	/*  we can't make any additional checking here   */
	/*  postpone it before dissector will have more information */

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "FTAM");
  	if (check_col(pinfo->cinfo, COL_INFO))
  		col_clear(pinfo->cinfo, COL_INFO);

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
proto_register_ftam(void)
{
	static hf_register_info hf[] =
	{
		{
			&hf_ftam_type,
			{
				"PDU Type",
				"ftam.type",
				FT_UINT8,
				BASE_DEC,
				VALS(ftam_pdu_vals),
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
				"ftam.protocol.version",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_PROTOCOL_VERGION,
				"Protocol version 1",
				HFILL
			}
		},
		{
			&hf_functional_unit_read,
			{
				"Read",
				"ftam.functional.units.read",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_FUNCTIONAL_UNIT_READ,
				"Read",
				HFILL
			}
		},
		{
			&hf_functional_unit_write,
			{
				"Write",
				"ftam.functional.units.write",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_FUNCTIONAL_UNIT_WRITE,
				"Write",
				HFILL
			}
		},
		{
			&hf_functional_unit_file_access,
			{
				"File access",
				"ftam.functional.units.file_access",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_FUNCTIONAL_UNIT_FILE_ACCESS,
				"File access",
				HFILL
			}
		},
		{
			&hf_functional_unit_limited_file_management,
			{
				"Limited file management",
				"ftam.functional.units.limited_file_management",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_FUNCTIONAL_UNIT_LIMITED_FILE_MANAGEMENT,
				"Limited file management",
				HFILL
			}
		},
		{
			&hf_functional_unit_enhanced_file_management,
			{
				"Enhanced file management",
				"ftam.functional.units.enhanced_file_management",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_FUNCTIONAL_UNIT_ENHANCED_FILE_MANAGEMENT,
				"Enhanced file management",
				HFILL
			}
		},
		{
			&hf_functional_unit_grouping,
			{
				"Grouping",
				"ftam.functional.units.grouping",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_FUNCTIONAL_UNIT_GROUPING,
				"Grouping",
				HFILL
			}
		},
		{
			&hf_functional_unit_fadu_locking,
			{
				"Fadu locking",
				"ftam.functional.units.fadu_locking",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_FUNCTIONAL_FADU_LOCKING,
				"Fadu locking",
				HFILL
			}
		},
		{
			&hf_functional_unit_recovery,
			{
				"Recovery",
				"ftam.functional.units.recovery",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_FUNCTIONAL_UNIT_RECOVERY,
				"Recovery",
				HFILL
			}
		},
		{
			&hf_functional_unit_restart_data_transfer,
			{
				"Restart data transfer",
				"ftam.functional.units.restart_data_transfer",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_FUNCTIONAL_UNIT_RESTART_DATA_TRANSFER,
				"Restart data transfer",
				HFILL
			}
		},
		{
			&hf_service_class_unconstrained_class,
			{
				"Unconstrained class",
				"ftam.functional.units.unconstrained_class",
				FT_BOOLEAN, 8,
				NULL,
				FTAM_FUNCTIONAL_UNIT_UNCONSTRAINED_CLASS,
				"Unconstrained class",
				HFILL
			}
		},
		{
			&hf_service_class_management_class,
			{
				"Management class",
				"ftam.functional.units.management_class",
				FT_BOOLEAN, 8,
				NULL,
				FTAM_FUNCTIONAL_UNIT_MANAGEMENT_CLASS,
				"Management class",
				HFILL
			}
		},
		{
			&hf_service_class_transfer_class,
			{
				"Transfer class",
				"ftam.functional.units.transfer_class",
				FT_BOOLEAN, 8,
				NULL,
				FTAM_FUNCTIONAL_UNIT_TRANSFER_CLASS,
				"Transfer class",
				HFILL
			}
		},
		{
			&hf_service_class_transfer_and_management_class,
			{
				"Transfer and management class",
				"ftam.functional.units.transfer_and_management_class",
				FT_BOOLEAN, 8,
				NULL,
				FTAM_FUNCTIONAL_UNIT_TRANSFER_AND_MANAGEMENT_CLASS,
				"Transfer and management class",
				HFILL
			}
		},
		{
			&hf_service_class_access_class,
			{
				"Access class",
				"ftam.functional.units.access_class",
				FT_BOOLEAN, 8,
				NULL,
				FTAM_FUNCTIONAL_UNIT_ACESS_CLASS,
				"access class",
				HFILL
			}
		},
		{
			&hf_attribute_groups_storage,
			{
				"Storage",
				"ftam.attribute.group.storage",
				FT_BOOLEAN, 8,
				NULL,
				FTAM_ATTRIBUTE_GROUPS_STORAGE,
				"Storage",
				HFILL
			}
		},
		{
			&hf_attribute_groups_security,
			{
				"Security",
				"ftam.attribute.group.security",
				FT_BOOLEAN, 8,
				NULL,
				FTAM_ATTRIBUTE_GROUPS_SECURITY,
				"Security",
				HFILL
			}
		},
		{
			&hf_attribute_groups_private,
			{
				"Private",
				"ftam.attribute.group.private",
				FT_BOOLEAN, 8,
				NULL,
				FTAM_ATTRIBUTE_GROUPS_PRIVATE,
				"Private",
				HFILL
			}
		},
		{
			&hf_filename_attribute_read,
			{
				"Read",
				"ftam.filename.attribute.read",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_FILENAME_ATTRIBUTE_READ,
				"Read",
				HFILL
			}
		},
		{
			&hf_filename_attribute_insert,
			{
				"Insert",
				"ftam.filename.attribute.insert",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_FILENAME_ATTRIBUTE_INSERT,
				"Insert",
				HFILL
			}
		},
		{
			&hf_filename_attribute_replace,
			{
				"Replace",
				"ftam.filename.attribute.replace",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_FILENAME_ATTRIBUTE_REPLACE,
				"Replace",
				HFILL
			}
		},
		{
			&hf_filename_attribute_extend,
			{
				"Extend",
				"ftam.filename.attribute.extend",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_FILENAME_ATTRIBUTE_EXTEND,
				"Extend",
				HFILL
			}
		},
		{
			&hf_filename_attribute_erase,
			{
				"Erase",
				"ftam.filename.attribute.erase",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_FILENAME_ATTRIBUTE_ERASE,
				"Erase",
				HFILL
			}
		},
		{
			&hf_filename_attribute_read_attribute,
			{
				"Read attribute",
				"ftam.filename.attribute.read_attribute",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_FILENAME_ATTRIBUTE_READ_ATTRIBUTE,
				"Read attribute",
				HFILL
			}
		},
		{
			&hf_filename_attribute_change_attribute,
			{
				"Change attribute",
				"ftam.filename.attribute.change_attribute",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_FILENAME_ATTRIBUTE_CHANGE_ATTRIBUTE,
				"Change attribute",
				HFILL
			}
		},
		{
			&hf_filename_attribute_delete_file,
			{
				"Delete file",
				"ftam.filename.attribute.delete_file",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_FILENAME_ATTRIBUTE_DELETE_FILE,
				"Delete file",
				HFILL
			}
		},
		{
			&hf_processing_mode_read,
			{
				"f-read",
				"ftam.processing.mode.read",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_PROCESSING_MODE_READ,
				"f-read",
				HFILL
			}
		},
		{
			&hf_processing_mode_replace,
			{
				"f-replace",
				"ftam.processing.mode.replace",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_PROCESSING_MODE_REPLACE,
				"f-replace",
				HFILL
			}
		},
		{
			&hf_processing_mode_insert,
			{
				"f-insert",
				"ftam.processing.mode.insert",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_PROCESSING_MODE_INSERT,
				"f-insert",
				HFILL
			}
		},
		{
			&hf_processing_mode_extend,
			{
				"f-extend",
				"ftam.processing.mode.extend",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_PROCESSING_MODE_EXTEND,
				"f-extend",
				HFILL
			}
		},
		{
			&hf_processing_mode_erase,
			{
				"f-erase",
				"ftam.processing.mode.erase",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_PROCESSING_MODE_ERASE,
				"f-erase",
				HFILL
			}
		},
		{
			&hf_permitted_action_attribute_read,
			{
				"Read",
				"ftam.permitted.action.attribute.read",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_PERMITTED_ACTION_ATTRIBUTE_READ,
				"Read",
				HFILL
			}
		},
		{
			&hf_permitted_action_attribute_insert,
			{
				"Insert",
				"ftam.permitted.action.attribute.insert",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_PERMITTED_ACTION_ATTRIBUTE_INSERT,
				"Insert",
				HFILL
			}
		},

		{
			&hf_permitted_action_attribute_replace,
			{
				"Replace",
				"ftam.permitted.action.attribute.replace",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_PERMITTED_ACTION_ATTRIBUTE_REPLACE,
				"Replace",
				HFILL
			}
		},
		{
			&hf_permitted_action_attribute_extend,
			{
				"Extend",
				"ftam.permitted.action.attribute.extend",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_PERMITTED_ACTION_ATTRIBUTE_EXTEND,
				"Extend",
				HFILL
			}
		},
		{
			&hf_permitted_action_attribute_erase,
			{
				"Erase",
				"ftam.permitted.action.attribute.erase",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_PERMITTED_ACTION_ATTRIBUTE_ERASE,
				"Erase",
				HFILL
			}
		},
		{
			&hf_permitted_action_attribute_read_attribute,
			{
				"Read attribute",
				"ftam.permitted.action.attribute.read.attribute",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_PERMITTED_ACTION_ATTRIBUTE_READ_ATTRIBUTE,
				"Read attribute",
				HFILL
			}
		},
		{
			&hf_permitted_action_attribute_change_attribute,
			{
				"Change attribute",
				"ftam.permitted.action.attribute.read.attribute",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_PERMITTED_ACTION_ATTRIBUTE_CHANGE_ATTRIBUTE,
				"Change attribute",
				HFILL
			}
		},
		{
			&hf_permitted_action_attribute_delete_file,
			{
				"Delete file",
				"ftam.permitted.action.attribute.delete.file",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_PERMITTED_ACTION_ATTRIBUTE_DELETE_FILE,
				"Delete file",
				HFILL
			}
		},
		{
			&hf_permitted_action_traversal,
			{
				"Traversal",
				"ftam.permitted.action.attribute.traversal",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_PERMITTED_ACTION_ATTRIBUTE_TRAVERSAL,
				"Traversal",
				HFILL
			}
		},
		{
			&hf_permitted_action_reverse_traversal,
			{
				"Reverse traversal",
				"ftam.permitted.action.attribute.reverse.traversal",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_PERMITTED_ACTION_ATTRIBUTE_REVERSE_TRAVERSAL,
				"Reverse raversal",
				HFILL
			}
		},
		{
			&hf_permitted_action_random_order,
			{
				"Random order",
				"ftam.permitted.action.attribute.random.order",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_PERMITTED_ACTION_ATTRIBUTE_RANDOM_ORDER,
				"Random order",
				HFILL
			}
		},
		{
			&hf_nbs9_read_filename,
			{
				"Read filename",
				"ftam.nbs9.read.filename",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_NBS9_READ_FILENAME,
				"Read filename",
				HFILL
			}
		},
		{
			&hf_nbs9_read_permitted_actions,
			{
				"Read permitted actions",
				"ftam.nbs9.read.permitted.actions",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_NBS9_READ_PERMITTED_ACTIONS,
				"Read permitted actions",
				HFILL
			}
		},
		{
			&hf_nbs9_read_contents_type,
			{
				"Read contents type",
				"ftam.nbs9.read.contents.type",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_NBS9_READ_CONTENTS_TYPE,
				"Read contents type",
				HFILL
			}
		},
		{
			&hf_nbs9_read_storage_account,
			{
				"Read storage account",
				"ftam.nbs9.read.storage.account",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_NBS9_READ_STORAGE_ACCOUNT,
				"Read storage account",
				HFILL
			}
		},
		{
			&hf_nbs9_read_date_and_time_of_creation,
			{
				"Read  date and time of creation",
				"ftam.nbs9.read.date.and.time.of.creation",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_NBS9_READ_DATE_AND_TIME_OF_CREATION,
				"Read date and time of creation",
				HFILL
			}
		},
		{
			&hf_nbs9_read_date_and_time_of_last_modification,
			{
				"Read  date and time of last modification",
				"ftam.nbs9.read.date.and.time.of.last.modification",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_NBS9_READ_DATE_AND_TIME_OF_LAST_MODIFICATION,
				"Read date and time of last modification",
				HFILL
			}
		},
		{
			&hf_nbs9_read_date_and_time_of_read_access,
			{
				"Read  date and time of last read access",
				"ftam.nbs9.read.date.and.time.of.last.read.access",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_NBS9_READ_DATE_AND_TIME_OF_LAST_READ_ACCESS,
				"Read date and time of last read access",
				HFILL
			}
		},
		{
			&hf_nbs9_read_date_and_time_of_attribute_modification,
			{
				"Read  date and time of last attribute modification",
				"ftam.nbs9.read.date.and.time.of.last.attribute.modification",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_NBS9_READ_DATE_AND_TIME_OF_LAST_ATTRIBUTE_MODIFICATION,
				"Read date and time of last attribute modification",
				HFILL
			}
		},
		{
			&hf_nbs9_read_identity_of_creator,
			{
				"Read identity of creator",
				"ftam.nbs9.read.identity.of.creator",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_NBS9_READ_IDENTITY_OF_CREATOR,
				"Read identity of creator",
				HFILL
			}
		},
		{
			&hf_nbs9_read_identity_of_last_modifier,
			{
				"Read identity of last modifier",
				"ftam.nbs9.read.identity.of.last.modifier",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_NBS9_READ_IDENTITY_OF_LAST_MODIFIER,
				"Read identity of last modifier",
				HFILL
			}
		},
		{
			&hf_nbs9_read_identity_of_last_reader,
			{
				"Read identity of last reader",
				"ftam.nbs9.read.identity.of.last.reader",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_NBS9_READ_IDENTITY_OF_LAST_READER,
				"Read identity of last reader",
				HFILL
			}
		},
		{
			&hf_nbs9_read_identity_of_last_attribute_modifier,
			{
				"Read identity of last attribute modifier",
				"ftam.nbs9.read.identity.of.last.attribute.modifier",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_NBS9_READ_IDENTITY_OF_LAST_ATTRIBUTE_MODIFIER,
				"Read identity of last attribute modifier",
				HFILL
			}
		},
		{
			&hf_nbs9_read_file_availability,
			{
				"Read file availability",
				"ftam.nbs9.read.file.availability",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_NBS9_READ_FILE_AVAILABILITY,
				"Read file availability",
				HFILL
			}
		},
		{
			&hf_nbs9_read_filesize,
			{
				"Read filesize",
				"ftam.nbs9.read.file.filesize",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_NBS9_READ_FILESIZE,
				"Read filesize",
				HFILL
			}
		},
		{
			&hf_nbs9_read_future_filesize,
			{
				"Read future filesize",
				"ftam.nbs9.read.future.filesize",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_NBS9_READ_FUTURE_FILESIZE,
				"Read future filesize",
				HFILL
			}
		},
		{
			&hf_nbs9_read_access_control,
			{
				"Read access control",
				"ftam.nbs9.read.access_control",
				FT_BOOLEAN, 16,
				NULL,
				FTAM_NBS9_READ_ACCESS_CONTROL,
				"Read access control",
				HFILL
			}
		},
		{
			&hf_nbs9_read_legal_qualifications,
			{
				"Read legal qualifications",
				"ftam.nbs9.read.legal.qualifications",
				FT_BOOLEAN, 8,
				NULL,
				FTAM_NBS9_READ_LEGAL_QUALIFICATIONS,
				"Read legal qualifications",
				HFILL
			}
		},

		{
			&hf_nbs9_read_private_use,
			{
				"Read private use",
				"ftam.nbs9.read.private.use",
				FT_BOOLEAN, 8,
				NULL,
				FTAM_NBS9_READ_PRIVATE_USE,
				"Read private use",
				HFILL
			}
		},
	};
	static gint *ett[] =
	{
		&ett_ftam,
		&ett_ftam_param,
		&ett_ftam_rc,
		&ett_ftam_ms,
		&ett_ftam_itm,
	};
	module_t *ftam_module;
	proto_ftam = proto_register_protocol(PROTO_STRING_FTAM, "FTAM", "ftam");
	proto_register_field_array(proto_ftam, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	ftam_module = prefs_register_protocol(proto_ftam, NULL);
}

void
proto_reg_handoff_ftam(void)
{
	dissector_handle_t ftam_handle;

	/*   find data dissector  */
	data_handle = find_dissector("data");
	ftam_handle = create_dissector_handle(dissect_ftam,proto_ftam);
	/* Register in acse oid table  */
	dissector_add_string("acse.application_context", "1.0.8571.1.1", ftam_handle); 
}



