/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* ./packet-ftbp.c                                                            */
/* ../../tools/asn2eth.py -X -b -e -p ftbp -c ftbp.cnf -s packet-ftbp-template ftbp.asn */

/* Input file: packet-ftbp-template.c */

#line 1 "packet-ftbp-template.c"
/* packet-ftbp.c
 * Routines for File Transfer Body Part (FTBP) dissection (used in X.420 content)
 * Graeme Lunt 2005
 *
 * $Id$
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
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"

#include "packet-acse.h"
#include "packet-ftam.h"
#include "packet-x411.h" 
#include "packet-x420.h" 

#include "packet-ftbp.h"

#define PNAME  "X.420 File Transfer Body Part"
#define PSNAME "FTBP"
#define PFNAME "ftbp"

/* Initialize the protocol and registered fields */
int proto_ftbp = -1;


/*--- Included file: packet-ftbp-hf.c ---*/
#line 1 "packet-ftbp-hf.c"
static int hf_ftbp_FileTransferParameters_PDU = -1;  /* FileTransferParameters */
static int hf_ftbp_FileTransferData_PDU = -1;     /* FileTransferData */
static int hf_ftbp_related_stored_file = -1;      /* RelatedStoredFile */
static int hf_ftbp_contents_type = -1;            /* ContentsTypeParameter */
static int hf_ftbp_environment = -1;              /* EnvironmentParameter */
static int hf_ftbp_compression = -1;              /* CompressionParameter */
static int hf_ftbp_file_attributes = -1;          /* FileAttributes */
static int hf_ftbp_extensions = -1;               /* ExtensionsField */
static int hf_ftbp_FileTransferData_item = -1;    /* EXTERNAL */
static int hf_ftbp_RelatedStoredFile_item = -1;   /* RelatedStoredFile_item */
static int hf_ftbp_file_identifier = -1;          /* FileIdentifier */
static int hf_ftbp_relationship = -1;             /* Relationship */
static int hf_ftbp_pathname_and_version = -1;     /* PathnameandVersion */
static int hf_ftbp_cross_reference = -1;          /* CrossReference */
static int hf_ftbp_pathname = -1;                 /* Pathname_Attribute */
static int hf_ftbp_file_version = -1;             /* GraphicString */
static int hf_ftbp_application_cross_reference = -1;  /* OCTET_STRING */
static int hf_ftbp_message_reference = -1;        /* MessageReference */
static int hf_ftbp_body_part_reference = -1;      /* INTEGER */
static int hf_ftbp_user = -1;                     /* ORName */
static int hf_ftbp_user_relative_identifier = -1;  /* PrintableString */
static int hf_ftbp_explicit_relationship = -1;    /* ExplicitRelationship */
static int hf_ftbp_descriptive_relationship = -1;  /* GraphicString */
static int hf_ftbp_document_type = -1;            /* T_document_type */
static int hf_ftbp_document_type_name = -1;       /* Document_Type_Name */
static int hf_ftbp_parameter = -1;                /* T_parameter */
static int hf_ftbp_constraint_set_and_abstract_syntax = -1;  /* T_constraint_set_and_abstract_syntax */
static int hf_ftbp_constraint_set_name = -1;      /* Constraint_Set_Name */
static int hf_ftbp_abstract_syntax_name = -1;     /* Abstract_Syntax_Name */
static int hf_ftbp_application_reference = -1;    /* GeneralIdentifier */
static int hf_ftbp_machine = -1;                  /* GeneralIdentifier */
static int hf_ftbp_operating_system = -1;         /* OBJECT_IDENTIFIER */
static int hf_ftbp_user_visible_string = -1;      /* T_user_visible_string */
static int hf_ftbp_user_visible_string_item = -1;  /* GraphicString */
static int hf_ftbp_registered_identifier = -1;    /* OBJECT_IDENTIFIER */
static int hf_ftbp_descriptive_identifier = -1;   /* T_descriptive_identifier */
static int hf_ftbp_descriptive_identifier_item = -1;  /* GraphicString */
static int hf_ftbp_compression_algorithm_id = -1;  /* OBJECT_IDENTIFIER */
static int hf_ftbp_compression_algorithm_param = -1;  /* T_compression_algorithm_param */
static int hf_ftbp_permitted_actions = -1;        /* Permitted_Actions_Attribute */
static int hf_ftbp_storage_account = -1;          /* Account_Attribute */
static int hf_ftbp_date_and_time_of_creation = -1;  /* Date_and_Time_Attribute */
static int hf_ftbp_date_and_time_of_last_modification = -1;  /* Date_and_Time_Attribute */
static int hf_ftbp_date_and_time_of_last_read_access = -1;  /* Date_and_Time_Attribute */
static int hf_ftbp_date_and_time_of_last_attribute_modification = -1;  /* Date_and_Time_Attribute */
static int hf_ftbp_identity_of_creator = -1;      /* User_Identity_Attribute */
static int hf_ftbp_identity_of_last_modifier = -1;  /* User_Identity_Attribute */
static int hf_ftbp_identity_of_last_reader = -1;  /* User_Identity_Attribute */
static int hf_ftbp_identity_of_last_attribute_modifier = -1;  /* User_Identity_Attribute */
static int hf_ftbp_object_availability = -1;      /* Object_Availability_Attribute */
static int hf_ftbp_object_size = -1;              /* Object_Size_Attribute */
static int hf_ftbp_future_object_size = -1;       /* Object_Size_Attribute */
static int hf_ftbp_access_control = -1;           /* Access_Control_Attribute */
static int hf_ftbp_legal_qualifications = -1;     /* Legal_Qualification_Attribute */
static int hf_ftbp_private_use = -1;              /* Private_Use_Attribute */
static int hf_ftbp_attribute_extensions = -1;     /* Attribute_Extensions */
static int hf_ftbp_incomplete_pathname = -1;      /* Pathname */
static int hf_ftbp_complete_pathname = -1;        /* Pathname */
static int hf_ftbp_no_value_available = -1;       /* NULL */
static int hf_ftbp_account_actual_values = -1;    /* Account */
static int hf_ftbp_identity_actual_values = -1;   /* User_Identity */
static int hf_ftbp_actual_values = -1;            /* SET_OF_Access_Control_Element */
static int hf_ftbp_actual_values_item = -1;       /* Access_Control_Element */
static int hf_ftbp_action_list = -1;              /* Access_Request */
static int hf_ftbp_concurrency_access = -1;       /* Concurrency_Access */
static int hf_ftbp_identity = -1;                 /* User_Identity */
static int hf_ftbp_passwords = -1;                /* Access_Passwords */
static int hf_ftbp_location = -1;                 /* Application_Entity_Title */
static int hf_ftbp_read_password = -1;            /* Password */
static int hf_ftbp_insert_password = -1;          /* Password */
static int hf_ftbp_replace_password = -1;         /* Password */
static int hf_ftbp_extend_password = -1;          /* Password */
static int hf_ftbp_erase_password = -1;           /* Password */
static int hf_ftbp_read_attribute_password = -1;  /* Password */
static int hf_ftbp_change_attribute_password = -1;  /* Password */
static int hf_ftbp_delete_password = -1;          /* Password */
static int hf_ftbp_pass_passwords = -1;           /* Pass_Passwords */
static int hf_ftbp_link_password = -1;            /* Password */
static int hf_ftbp_graphic_string = -1;           /* GraphicString */
static int hf_ftbp_octet_string = -1;             /* OCTET_STRING */
static int hf_ftbp_Pass_Passwords_item = -1;      /* Password */
static int hf_ftbp_ap_title = -1;                 /* AP_title */
static int hf_ftbp_ae_qualifier = -1;             /* AE_qualifier */
/* named bits */
static int hf_ftbp_Access_Request_read = -1;
static int hf_ftbp_Access_Request_insert = -1;
static int hf_ftbp_Access_Request_replace = -1;
static int hf_ftbp_Access_Request_extend = -1;
static int hf_ftbp_Access_Request_erase = -1;
static int hf_ftbp_Access_Request_read_attribute = -1;
static int hf_ftbp_Access_Request_change_attribute = -1;
static int hf_ftbp_Access_Request_delete_object = -1;

/*--- End of included file: packet-ftbp-hf.c ---*/
#line 54 "packet-ftbp-template.c"

/* Initialize the subtree pointers */
static gint ett_ftbp = -1;

/*--- Included file: packet-ftbp-ett.c ---*/
#line 1 "packet-ftbp-ett.c"
static gint ett_ftbp_FileTransferParameters = -1;
static gint ett_ftbp_FileTransferData = -1;
static gint ett_ftbp_RelatedStoredFile = -1;
static gint ett_ftbp_RelatedStoredFile_item = -1;
static gint ett_ftbp_FileIdentifier = -1;
static gint ett_ftbp_PathnameandVersion = -1;
static gint ett_ftbp_CrossReference = -1;
static gint ett_ftbp_MessageReference = -1;
static gint ett_ftbp_Relationship = -1;
static gint ett_ftbp_Contents_Type_Attribute = -1;
static gint ett_ftbp_T_document_type = -1;
static gint ett_ftbp_T_constraint_set_and_abstract_syntax = -1;
static gint ett_ftbp_EnvironmentParameter = -1;
static gint ett_ftbp_T_user_visible_string = -1;
static gint ett_ftbp_GeneralIdentifier = -1;
static gint ett_ftbp_T_descriptive_identifier = -1;
static gint ett_ftbp_CompressionParameter = -1;
static gint ett_ftbp_FileAttributes = -1;
static gint ett_ftbp_Pathname_Attribute = -1;
static gint ett_ftbp_Account_Attribute = -1;
static gint ett_ftbp_User_Identity_Attribute = -1;
static gint ett_ftbp_Access_Control_Attribute = -1;
static gint ett_ftbp_SET_OF_Access_Control_Element = -1;
static gint ett_ftbp_Access_Control_Element = -1;
static gint ett_ftbp_Access_Request = -1;
static gint ett_ftbp_Access_Passwords = -1;
static gint ett_ftbp_Password = -1;
static gint ett_ftbp_Pass_Passwords = -1;
static gint ett_ftbp_Application_Entity_Title = -1;

/*--- End of included file: packet-ftbp-ett.c ---*/
#line 58 "packet-ftbp-template.c"


/*--- Included file: packet-ftbp-fn.c ---*/
#line 1 "packet-ftbp-fn.c"
/*--- Fields for imported types ---*/

static int dissect_extensions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x420_ExtensionsField(TRUE, tvb, offset, pinfo, tree, hf_ftbp_extensions);
}
static int dissect_FileTransferData_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acse_EXTERNAL(FALSE, tvb, offset, pinfo, tree, hf_ftbp_FileTransferData_item);
}
static int dissect_user_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ORName(TRUE, tvb, offset, pinfo, tree, hf_ftbp_user);
}
static int dissect_permitted_actions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftam_Permitted_Actions_Attribute(TRUE, tvb, offset, pinfo, tree, hf_ftbp_permitted_actions);
}
static int dissect_date_and_time_of_creation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftam_Date_and_Time_Attribute(TRUE, tvb, offset, pinfo, tree, hf_ftbp_date_and_time_of_creation);
}
static int dissect_date_and_time_of_last_modification_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftam_Date_and_Time_Attribute(TRUE, tvb, offset, pinfo, tree, hf_ftbp_date_and_time_of_last_modification);
}
static int dissect_date_and_time_of_last_read_access_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftam_Date_and_Time_Attribute(TRUE, tvb, offset, pinfo, tree, hf_ftbp_date_and_time_of_last_read_access);
}
static int dissect_date_and_time_of_last_attribute_modification_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftam_Date_and_Time_Attribute(TRUE, tvb, offset, pinfo, tree, hf_ftbp_date_and_time_of_last_attribute_modification);
}
static int dissect_object_availability_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftam_Object_Availability_Attribute(TRUE, tvb, offset, pinfo, tree, hf_ftbp_object_availability);
}
static int dissect_object_size_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftam_Object_Size_Attribute(TRUE, tvb, offset, pinfo, tree, hf_ftbp_object_size);
}
static int dissect_future_object_size_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftam_Object_Size_Attribute(TRUE, tvb, offset, pinfo, tree, hf_ftbp_future_object_size);
}
static int dissect_legal_qualifications_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftam_Legal_Qualification_Attribute(TRUE, tvb, offset, pinfo, tree, hf_ftbp_legal_qualifications);
}
static int dissect_private_use_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftam_Private_Use_Attribute(TRUE, tvb, offset, pinfo, tree, hf_ftbp_private_use);
}
static int dissect_attribute_extensions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftam_Attribute_Extensions(TRUE, tvb, offset, pinfo, tree, hf_ftbp_attribute_extensions);
}
static int dissect_incomplete_pathname_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftam_Pathname(TRUE, tvb, offset, pinfo, tree, hf_ftbp_incomplete_pathname);
}
static int dissect_complete_pathname_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftam_Pathname(TRUE, tvb, offset, pinfo, tree, hf_ftbp_complete_pathname);
}
static int dissect_concurrency_access_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftam_Concurrency_Access(TRUE, tvb, offset, pinfo, tree, hf_ftbp_concurrency_access);
}
static int dissect_ap_title(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acse_AP_title(FALSE, tvb, offset, pinfo, tree, hf_ftbp_ap_title);
}
static int dissect_ae_qualifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acse_AE_qualifier(FALSE, tvb, offset, pinfo, tree, hf_ftbp_ae_qualifier);
}


static const value_string ftbp_Pathname_Attribute_vals[] = {
  {   0, "incomplete-pathname" },
  {  23, "complete-pathname" },
  { 0, NULL }
};

static const ber_choice_t Pathname_Attribute_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_incomplete_pathname_impl },
  {  23, BER_CLASS_CON, 23, 0, dissect_complete_pathname_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ftbp_Pathname_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Pathname_Attribute_choice, hf_index, ett_ftbp_Pathname_Attribute,
                                 NULL);

  return offset;
}
static int dissect_pathname(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_Pathname_Attribute(FALSE, tvb, offset, pinfo, tree, hf_ftbp_pathname);
}
static int dissect_pathname_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_Pathname_Attribute(TRUE, tvb, offset, pinfo, tree, hf_ftbp_pathname);
}



static int
dissect_ftbp_GraphicString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_file_version_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_GraphicString(TRUE, tvb, offset, pinfo, tree, hf_ftbp_file_version);
}
static int dissect_descriptive_relationship_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_GraphicString(TRUE, tvb, offset, pinfo, tree, hf_ftbp_descriptive_relationship);
}
static int dissect_user_visible_string_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_GraphicString(FALSE, tvb, offset, pinfo, tree, hf_ftbp_user_visible_string_item);
}
static int dissect_descriptive_identifier_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_GraphicString(FALSE, tvb, offset, pinfo, tree, hf_ftbp_descriptive_identifier_item);
}
static int dissect_graphic_string(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_GraphicString(FALSE, tvb, offset, pinfo, tree, hf_ftbp_graphic_string);
}


static const ber_sequence_t PathnameandVersion_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_pathname_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_file_version_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ftbp_PathnameandVersion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PathnameandVersion_sequence, hf_index, ett_ftbp_PathnameandVersion);

  return offset;
}
static int dissect_pathname_and_version_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_PathnameandVersion(TRUE, tvb, offset, pinfo, tree, hf_ftbp_pathname_and_version);
}



static int
dissect_ftbp_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_application_cross_reference_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_ftbp_application_cross_reference);
}
static int dissect_octet_string(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_ftbp_octet_string);
}



static int
dissect_ftbp_PrintableString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_user_relative_identifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_PrintableString(TRUE, tvb, offset, pinfo, tree, hf_ftbp_user_relative_identifier);
}


static const ber_sequence_t MessageReference_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_user_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_user_relative_identifier_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ftbp_MessageReference(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              MessageReference_set, hf_index, ett_ftbp_MessageReference);

  return offset;
}
static int dissect_message_reference_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_MessageReference(TRUE, tvb, offset, pinfo, tree, hf_ftbp_message_reference);
}



static int
dissect_ftbp_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_body_part_reference_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_ftbp_body_part_reference);
}


static const ber_sequence_t CrossReference_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_application_cross_reference_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_message_reference_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_body_part_reference_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ftbp_CrossReference(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CrossReference_sequence, hf_index, ett_ftbp_CrossReference);

  return offset;
}
static int dissect_cross_reference_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_CrossReference(TRUE, tvb, offset, pinfo, tree, hf_ftbp_cross_reference);
}


static const value_string ftbp_FileIdentifier_vals[] = {
  {   0, "pathname-and-version" },
  {   1, "cross-reference" },
  { 0, NULL }
};

static const ber_choice_t FileIdentifier_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_pathname_and_version_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_cross_reference_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ftbp_FileIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 FileIdentifier_choice, hf_index, ett_ftbp_FileIdentifier,
                                 NULL);

  return offset;
}
static int dissect_file_identifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_FileIdentifier(FALSE, tvb, offset, pinfo, tree, hf_ftbp_file_identifier);
}


static const value_string ftbp_ExplicitRelationship_vals[] = {
  {   0, "unspecified" },
  {   1, "new-file" },
  {   2, "replacement" },
  {   3, "extension" },
  { 0, NULL }
};


static int
dissect_ftbp_ExplicitRelationship(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_explicit_relationship_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_ExplicitRelationship(TRUE, tvb, offset, pinfo, tree, hf_ftbp_explicit_relationship);
}


static const value_string ftbp_Relationship_vals[] = {
  {   0, "explicit-relationship" },
  {   1, "descriptive-relationship" },
  { 0, NULL }
};

static const ber_choice_t Relationship_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_explicit_relationship_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_descriptive_relationship_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ftbp_Relationship(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Relationship_choice, hf_index, ett_ftbp_Relationship,
                                 NULL);

  return offset;
}
static int dissect_relationship(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_Relationship(FALSE, tvb, offset, pinfo, tree, hf_ftbp_relationship);
}


static const ber_sequence_t RelatedStoredFile_item_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_file_identifier },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_relationship },
  { 0, 0, 0, NULL }
};

static int
dissect_ftbp_RelatedStoredFile_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RelatedStoredFile_item_sequence, hf_index, ett_ftbp_RelatedStoredFile_item);

  return offset;
}
static int dissect_RelatedStoredFile_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_RelatedStoredFile_item(FALSE, tvb, offset, pinfo, tree, hf_ftbp_RelatedStoredFile_item);
}


static const ber_sequence_t RelatedStoredFile_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_RelatedStoredFile_item },
};

static int
dissect_ftbp_RelatedStoredFile(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 RelatedStoredFile_set_of, hf_index, ett_ftbp_RelatedStoredFile);

  return offset;
}
static int dissect_related_stored_file_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_RelatedStoredFile(TRUE, tvb, offset, pinfo, tree, hf_ftbp_related_stored_file);
}



static int
dissect_ftbp_Document_Type_Name(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_document_type_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_Document_Type_Name(FALSE, tvb, offset, pinfo, tree, hf_ftbp_document_type_name);
}



static int
dissect_ftbp_T_parameter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 26 "ftbp.cnf"
/* XXX: Not implemented yet */



  return offset;
}
static int dissect_parameter_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_T_parameter(TRUE, tvb, offset, pinfo, tree, hf_ftbp_parameter);
}


static const ber_sequence_t T_document_type_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_document_type_name },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_parameter_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ftbp_T_document_type(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_document_type_sequence, hf_index, ett_ftbp_T_document_type);

  return offset;
}
static int dissect_document_type_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_T_document_type(TRUE, tvb, offset, pinfo, tree, hf_ftbp_document_type);
}



static int
dissect_ftbp_Constraint_Set_Name(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_constraint_set_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_Constraint_Set_Name(FALSE, tvb, offset, pinfo, tree, hf_ftbp_constraint_set_name);
}



static int
dissect_ftbp_Abstract_Syntax_Name(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_abstract_syntax_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_Abstract_Syntax_Name(FALSE, tvb, offset, pinfo, tree, hf_ftbp_abstract_syntax_name);
}


static const ber_sequence_t T_constraint_set_and_abstract_syntax_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_constraint_set_name },
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_abstract_syntax_name },
  { 0, 0, 0, NULL }
};

static int
dissect_ftbp_T_constraint_set_and_abstract_syntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_constraint_set_and_abstract_syntax_sequence, hf_index, ett_ftbp_T_constraint_set_and_abstract_syntax);

  return offset;
}
static int dissect_constraint_set_and_abstract_syntax_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_T_constraint_set_and_abstract_syntax(TRUE, tvb, offset, pinfo, tree, hf_ftbp_constraint_set_and_abstract_syntax);
}


static const value_string ftbp_Contents_Type_Attribute_vals[] = {
  {   0, "document-type" },
  {   1, "constraint-set-and-abstract-syntax" },
  { 0, NULL }
};

static const ber_choice_t Contents_Type_Attribute_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_document_type_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_constraint_set_and_abstract_syntax_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ftbp_Contents_Type_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Contents_Type_Attribute_choice, hf_index, ett_ftbp_Contents_Type_Attribute,
                                 NULL);

  return offset;
}



static int
dissect_ftbp_ContentsTypeParameter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ftbp_Contents_Type_Attribute(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_contents_type_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_ContentsTypeParameter(TRUE, tvb, offset, pinfo, tree, hf_ftbp_contents_type);
}



static int
dissect_ftbp_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_operating_system_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_OBJECT_IDENTIFIER(TRUE, tvb, offset, pinfo, tree, hf_ftbp_operating_system);
}
static int dissect_registered_identifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_OBJECT_IDENTIFIER(TRUE, tvb, offset, pinfo, tree, hf_ftbp_registered_identifier);
}
static int dissect_compression_algorithm_id_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_OBJECT_IDENTIFIER(TRUE, tvb, offset, pinfo, tree, hf_ftbp_compression_algorithm_id);
}


static const ber_sequence_t T_descriptive_identifier_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_GraphicString, BER_FLAGS_NOOWNTAG, dissect_descriptive_identifier_item },
};

static int
dissect_ftbp_T_descriptive_identifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_descriptive_identifier_sequence_of, hf_index, ett_ftbp_T_descriptive_identifier);

  return offset;
}
static int dissect_descriptive_identifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_T_descriptive_identifier(TRUE, tvb, offset, pinfo, tree, hf_ftbp_descriptive_identifier);
}


static const value_string ftbp_GeneralIdentifier_vals[] = {
  {   0, "registered-identifier" },
  {   1, "descriptive-identifier" },
  { 0, NULL }
};

static const ber_choice_t GeneralIdentifier_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_registered_identifier_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_descriptive_identifier_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ftbp_GeneralIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 GeneralIdentifier_choice, hf_index, ett_ftbp_GeneralIdentifier,
                                 NULL);

  return offset;
}
static int dissect_application_reference_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_GeneralIdentifier(TRUE, tvb, offset, pinfo, tree, hf_ftbp_application_reference);
}
static int dissect_machine_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_GeneralIdentifier(TRUE, tvb, offset, pinfo, tree, hf_ftbp_machine);
}


static const ber_sequence_t T_user_visible_string_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_GraphicString, BER_FLAGS_NOOWNTAG, dissect_user_visible_string_item },
};

static int
dissect_ftbp_T_user_visible_string(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_user_visible_string_sequence_of, hf_index, ett_ftbp_T_user_visible_string);

  return offset;
}
static int dissect_user_visible_string_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_T_user_visible_string(TRUE, tvb, offset, pinfo, tree, hf_ftbp_user_visible_string);
}


static const ber_sequence_t EnvironmentParameter_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_application_reference_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_machine_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_operating_system_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_user_visible_string_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ftbp_EnvironmentParameter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EnvironmentParameter_sequence, hf_index, ett_ftbp_EnvironmentParameter);

  return offset;
}
static int dissect_environment_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_EnvironmentParameter(TRUE, tvb, offset, pinfo, tree, hf_ftbp_environment);
}



static int
dissect_ftbp_T_compression_algorithm_param(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 29 "ftbp.cnf"
/* XXX: Not implemented yet */

  return offset;
}
static int dissect_compression_algorithm_param_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_T_compression_algorithm_param(TRUE, tvb, offset, pinfo, tree, hf_ftbp_compression_algorithm_param);
}


static const ber_sequence_t CompressionParameter_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_compression_algorithm_id_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_compression_algorithm_param_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ftbp_CompressionParameter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CompressionParameter_sequence, hf_index, ett_ftbp_CompressionParameter);

  return offset;
}
static int dissect_compression_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_CompressionParameter(TRUE, tvb, offset, pinfo, tree, hf_ftbp_compression);
}



static int
dissect_ftbp_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_no_value_available_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_NULL(TRUE, tvb, offset, pinfo, tree, hf_ftbp_no_value_available);
}



static int
dissect_ftbp_Account(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_account_actual_values(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_Account(FALSE, tvb, offset, pinfo, tree, hf_ftbp_account_actual_values);
}


static const value_string ftbp_Account_Attribute_vals[] = {
  {   0, "no-value-available" },
  {   1, "actual-values" },
  { 0, NULL }
};

static const ber_choice_t Account_Attribute_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_no_value_available_impl },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_GraphicString, BER_FLAGS_NOOWNTAG, dissect_account_actual_values },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ftbp_Account_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Account_Attribute_choice, hf_index, ett_ftbp_Account_Attribute,
                                 NULL);

  return offset;
}
static int dissect_storage_account_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_Account_Attribute(TRUE, tvb, offset, pinfo, tree, hf_ftbp_storage_account);
}



static int
dissect_ftbp_User_Identity(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_identity_actual_values(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_User_Identity(FALSE, tvb, offset, pinfo, tree, hf_ftbp_identity_actual_values);
}
static int dissect_identity_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_User_Identity(TRUE, tvb, offset, pinfo, tree, hf_ftbp_identity);
}


static const value_string ftbp_User_Identity_Attribute_vals[] = {
  {   0, "no-value-available" },
  {   1, "actual-values" },
  { 0, NULL }
};

static const ber_choice_t User_Identity_Attribute_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_no_value_available_impl },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_GraphicString, BER_FLAGS_NOOWNTAG, dissect_identity_actual_values },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ftbp_User_Identity_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 User_Identity_Attribute_choice, hf_index, ett_ftbp_User_Identity_Attribute,
                                 NULL);

  return offset;
}
static int dissect_identity_of_creator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_User_Identity_Attribute(TRUE, tvb, offset, pinfo, tree, hf_ftbp_identity_of_creator);
}
static int dissect_identity_of_last_modifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_User_Identity_Attribute(TRUE, tvb, offset, pinfo, tree, hf_ftbp_identity_of_last_modifier);
}
static int dissect_identity_of_last_reader_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_User_Identity_Attribute(TRUE, tvb, offset, pinfo, tree, hf_ftbp_identity_of_last_reader);
}
static int dissect_identity_of_last_attribute_modifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_User_Identity_Attribute(TRUE, tvb, offset, pinfo, tree, hf_ftbp_identity_of_last_attribute_modifier);
}


static const asn_namedbit Access_Request_bits[] = {
  {  0, &hf_ftbp_Access_Request_read, -1, -1, "read", NULL },
  {  1, &hf_ftbp_Access_Request_insert, -1, -1, "insert", NULL },
  {  2, &hf_ftbp_Access_Request_replace, -1, -1, "replace", NULL },
  {  3, &hf_ftbp_Access_Request_extend, -1, -1, "extend", NULL },
  {  4, &hf_ftbp_Access_Request_erase, -1, -1, "erase", NULL },
  {  5, &hf_ftbp_Access_Request_read_attribute, -1, -1, "read-attribute", NULL },
  {  6, &hf_ftbp_Access_Request_change_attribute, -1, -1, "change-attribute", NULL },
  {  7, &hf_ftbp_Access_Request_delete_object, -1, -1, "delete-object", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_ftbp_Access_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    Access_Request_bits, hf_index, ett_ftbp_Access_Request,
                                    NULL);

  return offset;
}
static int dissect_action_list_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_Access_Request(TRUE, tvb, offset, pinfo, tree, hf_ftbp_action_list);
}


static const value_string ftbp_Password_vals[] = {
  {   0, "graphic-string" },
  {   1, "octet-string" },
  { 0, NULL }
};

static const ber_choice_t Password_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_GraphicString, BER_FLAGS_NOOWNTAG, dissect_graphic_string },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_octet_string },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ftbp_Password(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Password_choice, hf_index, ett_ftbp_Password,
                                 NULL);

  return offset;
}
static int dissect_read_password_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_Password(TRUE, tvb, offset, pinfo, tree, hf_ftbp_read_password);
}
static int dissect_insert_password_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_Password(TRUE, tvb, offset, pinfo, tree, hf_ftbp_insert_password);
}
static int dissect_replace_password_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_Password(TRUE, tvb, offset, pinfo, tree, hf_ftbp_replace_password);
}
static int dissect_extend_password_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_Password(TRUE, tvb, offset, pinfo, tree, hf_ftbp_extend_password);
}
static int dissect_erase_password_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_Password(TRUE, tvb, offset, pinfo, tree, hf_ftbp_erase_password);
}
static int dissect_read_attribute_password_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_Password(TRUE, tvb, offset, pinfo, tree, hf_ftbp_read_attribute_password);
}
static int dissect_change_attribute_password_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_Password(TRUE, tvb, offset, pinfo, tree, hf_ftbp_change_attribute_password);
}
static int dissect_delete_password_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_Password(TRUE, tvb, offset, pinfo, tree, hf_ftbp_delete_password);
}
static int dissect_link_password_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_Password(TRUE, tvb, offset, pinfo, tree, hf_ftbp_link_password);
}
static int dissect_Pass_Passwords_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_Password(FALSE, tvb, offset, pinfo, tree, hf_ftbp_Pass_Passwords_item);
}


static const ber_sequence_t Pass_Passwords_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_Pass_Passwords_item },
};

static int
dissect_ftbp_Pass_Passwords(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      Pass_Passwords_sequence_of, hf_index, ett_ftbp_Pass_Passwords);

  return offset;
}
static int dissect_pass_passwords_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_Pass_Passwords(TRUE, tvb, offset, pinfo, tree, hf_ftbp_pass_passwords);
}


static const ber_sequence_t Access_Passwords_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_read_password_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_insert_password_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_replace_password_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_extend_password_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_erase_password_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_read_attribute_password_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_change_attribute_password_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_delete_password_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_pass_passwords_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_link_password_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ftbp_Access_Passwords(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Access_Passwords_sequence, hf_index, ett_ftbp_Access_Passwords);

  return offset;
}
static int dissect_passwords_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_Access_Passwords(TRUE, tvb, offset, pinfo, tree, hf_ftbp_passwords);
}


static const ber_sequence_t Application_Entity_Title_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_ap_title },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_ae_qualifier },
  { 0, 0, 0, NULL }
};

static int
dissect_ftbp_Application_Entity_Title(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Application_Entity_Title_sequence, hf_index, ett_ftbp_Application_Entity_Title);

  return offset;
}
static int dissect_location_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_Application_Entity_Title(TRUE, tvb, offset, pinfo, tree, hf_ftbp_location);
}


static const ber_sequence_t Access_Control_Element_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_action_list_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_concurrency_access_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_identity_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_passwords_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_location_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ftbp_Access_Control_Element(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Access_Control_Element_sequence, hf_index, ett_ftbp_Access_Control_Element);

  return offset;
}
static int dissect_actual_values_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_Access_Control_Element(FALSE, tvb, offset, pinfo, tree, hf_ftbp_actual_values_item);
}


static const ber_sequence_t SET_OF_Access_Control_Element_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_actual_values_item },
};

static int
dissect_ftbp_SET_OF_Access_Control_Element(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_Access_Control_Element_set_of, hf_index, ett_ftbp_SET_OF_Access_Control_Element);

  return offset;
}
static int dissect_actual_values_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_SET_OF_Access_Control_Element(TRUE, tvb, offset, pinfo, tree, hf_ftbp_actual_values);
}


static const value_string ftbp_Access_Control_Attribute_vals[] = {
  {   0, "no-value-available" },
  {   1, "actual-values" },
  { 0, NULL }
};

static const ber_choice_t Access_Control_Attribute_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_no_value_available_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_actual_values_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ftbp_Access_Control_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Access_Control_Attribute_choice, hf_index, ett_ftbp_Access_Control_Attribute,
                                 NULL);

  return offset;
}
static int dissect_access_control_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_Access_Control_Attribute(TRUE, tvb, offset, pinfo, tree, hf_ftbp_access_control);
}


static const ber_sequence_t FileAttributes_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_pathname },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_permitted_actions_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_storage_account_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_date_and_time_of_creation_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_date_and_time_of_last_modification_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_date_and_time_of_last_read_access_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_date_and_time_of_last_attribute_modification_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_identity_of_creator_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_identity_of_last_modifier_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_identity_of_last_reader_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_identity_of_last_attribute_modifier_impl },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_object_availability_impl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_object_size_impl },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_future_object_size_impl },
  { BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_access_control_impl },
  { BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_legal_qualifications_impl },
  { BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_private_use_impl },
  { BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_attribute_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ftbp_FileAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   FileAttributes_sequence, hf_index, ett_ftbp_FileAttributes);

  return offset;
}
static int dissect_file_attributes_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ftbp_FileAttributes(TRUE, tvb, offset, pinfo, tree, hf_ftbp_file_attributes);
}


static const ber_sequence_t FileTransferParameters_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_related_stored_file_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_contents_type_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_environment_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_compression_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_file_attributes_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ftbp_FileTransferParameters(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   FileTransferParameters_sequence, hf_index, ett_ftbp_FileTransferParameters);

  return offset;
}


static const ber_sequence_t FileTransferData_sequence_of[1] = {
  { BER_CLASS_UNI, 8, BER_FLAGS_NOOWNTAG, dissect_FileTransferData_item },
};

static int
dissect_ftbp_FileTransferData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      FileTransferData_sequence_of, hf_index, ett_ftbp_FileTransferData);

  return offset;
}

/*--- PDUs ---*/

static void dissect_FileTransferParameters_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ftbp_FileTransferParameters(FALSE, tvb, 0, pinfo, tree, hf_ftbp_FileTransferParameters_PDU);
}
static void dissect_FileTransferData_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ftbp_FileTransferData(FALSE, tvb, 0, pinfo, tree, hf_ftbp_FileTransferData_PDU);
}


/*--- End of included file: packet-ftbp-fn.c ---*/
#line 60 "packet-ftbp-template.c"


/*--- proto_register_ftbp -------------------------------------------*/
void proto_register_ftbp(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {

/*--- Included file: packet-ftbp-hfarr.c ---*/
#line 1 "packet-ftbp-hfarr.c"
    { &hf_ftbp_FileTransferParameters_PDU,
      { "FileTransferParameters", "ftbp.FileTransferParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "FileTransferParameters", HFILL }},
    { &hf_ftbp_FileTransferData_PDU,
      { "FileTransferData", "ftbp.FileTransferData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FileTransferData", HFILL }},
    { &hf_ftbp_related_stored_file,
      { "related-stored-file", "ftbp.related_stored_file",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FileTransferParameters/related-stored-file", HFILL }},
    { &hf_ftbp_contents_type,
      { "contents-type", "ftbp.contents_type",
        FT_UINT32, BASE_DEC, VALS(ftbp_Contents_Type_Attribute_vals), 0,
        "FileTransferParameters/contents-type", HFILL }},
    { &hf_ftbp_environment,
      { "environment", "ftbp.environment",
        FT_NONE, BASE_NONE, NULL, 0,
        "FileTransferParameters/environment", HFILL }},
    { &hf_ftbp_compression,
      { "compression", "ftbp.compression",
        FT_NONE, BASE_NONE, NULL, 0,
        "FileTransferParameters/compression", HFILL }},
    { &hf_ftbp_file_attributes,
      { "file-attributes", "ftbp.file_attributes",
        FT_NONE, BASE_NONE, NULL, 0,
        "FileTransferParameters/file-attributes", HFILL }},
    { &hf_ftbp_extensions,
      { "extensions", "ftbp.extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FileTransferParameters/extensions", HFILL }},
    { &hf_ftbp_FileTransferData_item,
      { "Item", "ftbp.FileTransferData_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "FileTransferData/_item", HFILL }},
    { &hf_ftbp_RelatedStoredFile_item,
      { "Item", "ftbp.RelatedStoredFile_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RelatedStoredFile/_item", HFILL }},
    { &hf_ftbp_file_identifier,
      { "file-identifier", "ftbp.file_identifier",
        FT_UINT32, BASE_DEC, VALS(ftbp_FileIdentifier_vals), 0,
        "RelatedStoredFile/_item/file-identifier", HFILL }},
    { &hf_ftbp_relationship,
      { "relationship", "ftbp.relationship",
        FT_UINT32, BASE_DEC, VALS(ftbp_Relationship_vals), 0,
        "RelatedStoredFile/_item/relationship", HFILL }},
    { &hf_ftbp_pathname_and_version,
      { "pathname-and-version", "ftbp.pathname_and_version",
        FT_NONE, BASE_NONE, NULL, 0,
        "FileIdentifier/pathname-and-version", HFILL }},
    { &hf_ftbp_cross_reference,
      { "cross-reference", "ftbp.cross_reference",
        FT_NONE, BASE_NONE, NULL, 0,
        "FileIdentifier/cross-reference", HFILL }},
    { &hf_ftbp_pathname,
      { "pathname", "ftbp.pathname",
        FT_UINT32, BASE_DEC, VALS(ftbp_Pathname_Attribute_vals), 0,
        "", HFILL }},
    { &hf_ftbp_file_version,
      { "file-version", "ftbp.file_version",
        FT_STRING, BASE_NONE, NULL, 0,
        "PathnameandVersion/file-version", HFILL }},
    { &hf_ftbp_application_cross_reference,
      { "application-cross-reference", "ftbp.application_cross_reference",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CrossReference/application-cross-reference", HFILL }},
    { &hf_ftbp_message_reference,
      { "message-reference", "ftbp.message_reference",
        FT_NONE, BASE_NONE, NULL, 0,
        "CrossReference/message-reference", HFILL }},
    { &hf_ftbp_body_part_reference,
      { "body-part-reference", "ftbp.body_part_reference",
        FT_INT32, BASE_DEC, NULL, 0,
        "CrossReference/body-part-reference", HFILL }},
    { &hf_ftbp_user,
      { "user", "ftbp.user",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageReference/user", HFILL }},
    { &hf_ftbp_user_relative_identifier,
      { "user-relative-identifier", "ftbp.user_relative_identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "MessageReference/user-relative-identifier", HFILL }},
    { &hf_ftbp_explicit_relationship,
      { "explicit-relationship", "ftbp.explicit_relationship",
        FT_INT32, BASE_DEC, VALS(ftbp_ExplicitRelationship_vals), 0,
        "Relationship/explicit-relationship", HFILL }},
    { &hf_ftbp_descriptive_relationship,
      { "descriptive-relationship", "ftbp.descriptive_relationship",
        FT_STRING, BASE_NONE, NULL, 0,
        "Relationship/descriptive-relationship", HFILL }},
    { &hf_ftbp_document_type,
      { "document-type", "ftbp.document_type",
        FT_NONE, BASE_NONE, NULL, 0,
        "Contents-Type-Attribute/document-type", HFILL }},
    { &hf_ftbp_document_type_name,
      { "document-type-name", "ftbp.document_type_name",
        FT_OID, BASE_NONE, NULL, 0,
        "Contents-Type-Attribute/document-type/document-type-name", HFILL }},
    { &hf_ftbp_parameter,
      { "parameter", "ftbp.parameter",
        FT_NONE, BASE_NONE, NULL, 0,
        "Contents-Type-Attribute/document-type/parameter", HFILL }},
    { &hf_ftbp_constraint_set_and_abstract_syntax,
      { "constraint-set-and-abstract-syntax", "ftbp.constraint_set_and_abstract_syntax",
        FT_NONE, BASE_NONE, NULL, 0,
        "Contents-Type-Attribute/constraint-set-and-abstract-syntax", HFILL }},
    { &hf_ftbp_constraint_set_name,
      { "constraint-set-name", "ftbp.constraint_set_name",
        FT_OID, BASE_NONE, NULL, 0,
        "Contents-Type-Attribute/constraint-set-and-abstract-syntax/constraint-set-name", HFILL }},
    { &hf_ftbp_abstract_syntax_name,
      { "abstract-syntax-name", "ftbp.abstract_syntax_name",
        FT_OID, BASE_NONE, NULL, 0,
        "Contents-Type-Attribute/constraint-set-and-abstract-syntax/abstract-syntax-name", HFILL }},
    { &hf_ftbp_application_reference,
      { "application-reference", "ftbp.application_reference",
        FT_UINT32, BASE_DEC, VALS(ftbp_GeneralIdentifier_vals), 0,
        "EnvironmentParameter/application-reference", HFILL }},
    { &hf_ftbp_machine,
      { "machine", "ftbp.machine",
        FT_UINT32, BASE_DEC, VALS(ftbp_GeneralIdentifier_vals), 0,
        "EnvironmentParameter/machine", HFILL }},
    { &hf_ftbp_operating_system,
      { "operating-system", "ftbp.operating_system",
        FT_OID, BASE_NONE, NULL, 0,
        "EnvironmentParameter/operating-system", HFILL }},
    { &hf_ftbp_user_visible_string,
      { "user-visible-string", "ftbp.user_visible_string",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EnvironmentParameter/user-visible-string", HFILL }},
    { &hf_ftbp_user_visible_string_item,
      { "Item", "ftbp.user_visible_string_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "EnvironmentParameter/user-visible-string/_item", HFILL }},
    { &hf_ftbp_registered_identifier,
      { "registered-identifier", "ftbp.registered_identifier",
        FT_OID, BASE_NONE, NULL, 0,
        "GeneralIdentifier/registered-identifier", HFILL }},
    { &hf_ftbp_descriptive_identifier,
      { "descriptive-identifier", "ftbp.descriptive_identifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralIdentifier/descriptive-identifier", HFILL }},
    { &hf_ftbp_descriptive_identifier_item,
      { "Item", "ftbp.descriptive_identifier_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralIdentifier/descriptive-identifier/_item", HFILL }},
    { &hf_ftbp_compression_algorithm_id,
      { "compression-algorithm-id", "ftbp.compression_algorithm_id",
        FT_OID, BASE_NONE, NULL, 0,
        "CompressionParameter/compression-algorithm-id", HFILL }},
    { &hf_ftbp_compression_algorithm_param,
      { "compression-algorithm-param", "ftbp.compression_algorithm_param",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompressionParameter/compression-algorithm-param", HFILL }},
    { &hf_ftbp_permitted_actions,
      { "permitted-actions", "ftbp.permitted_actions",
        FT_BYTES, BASE_HEX, NULL, 0,
        "FileAttributes/permitted-actions", HFILL }},
    { &hf_ftbp_storage_account,
      { "storage-account", "ftbp.storage_account",
        FT_UINT32, BASE_DEC, VALS(ftbp_Account_Attribute_vals), 0,
        "FileAttributes/storage-account", HFILL }},
    { &hf_ftbp_date_and_time_of_creation,
      { "date-and-time-of-creation", "ftbp.date_and_time_of_creation",
        FT_UINT32, BASE_DEC, VALS(ftam_Date_and_Time_Attribute_vals), 0,
        "FileAttributes/date-and-time-of-creation", HFILL }},
    { &hf_ftbp_date_and_time_of_last_modification,
      { "date-and-time-of-last-modification", "ftbp.date_and_time_of_last_modification",
        FT_UINT32, BASE_DEC, VALS(ftam_Date_and_Time_Attribute_vals), 0,
        "FileAttributes/date-and-time-of-last-modification", HFILL }},
    { &hf_ftbp_date_and_time_of_last_read_access,
      { "date-and-time-of-last-read-access", "ftbp.date_and_time_of_last_read_access",
        FT_UINT32, BASE_DEC, VALS(ftam_Date_and_Time_Attribute_vals), 0,
        "FileAttributes/date-and-time-of-last-read-access", HFILL }},
    { &hf_ftbp_date_and_time_of_last_attribute_modification,
      { "date-and-time-of-last-attribute-modification", "ftbp.date_and_time_of_last_attribute_modification",
        FT_UINT32, BASE_DEC, VALS(ftam_Date_and_Time_Attribute_vals), 0,
        "FileAttributes/date-and-time-of-last-attribute-modification", HFILL }},
    { &hf_ftbp_identity_of_creator,
      { "identity-of-creator", "ftbp.identity_of_creator",
        FT_UINT32, BASE_DEC, VALS(ftbp_User_Identity_Attribute_vals), 0,
        "FileAttributes/identity-of-creator", HFILL }},
    { &hf_ftbp_identity_of_last_modifier,
      { "identity-of-last-modifier", "ftbp.identity_of_last_modifier",
        FT_UINT32, BASE_DEC, VALS(ftbp_User_Identity_Attribute_vals), 0,
        "FileAttributes/identity-of-last-modifier", HFILL }},
    { &hf_ftbp_identity_of_last_reader,
      { "identity-of-last-reader", "ftbp.identity_of_last_reader",
        FT_UINT32, BASE_DEC, VALS(ftbp_User_Identity_Attribute_vals), 0,
        "FileAttributes/identity-of-last-reader", HFILL }},
    { &hf_ftbp_identity_of_last_attribute_modifier,
      { "identity-of-last-attribute-modifier", "ftbp.identity_of_last_attribute_modifier",
        FT_UINT32, BASE_DEC, VALS(ftbp_User_Identity_Attribute_vals), 0,
        "FileAttributes/identity-of-last-attribute-modifier", HFILL }},
    { &hf_ftbp_object_availability,
      { "object-availability", "ftbp.object_availability",
        FT_UINT32, BASE_DEC, VALS(ftam_Object_Availability_Attribute_vals), 0,
        "FileAttributes/object-availability", HFILL }},
    { &hf_ftbp_object_size,
      { "object-size", "ftbp.object_size",
        FT_UINT32, BASE_DEC, VALS(ftam_Object_Size_Attribute_vals), 0,
        "FileAttributes/object-size", HFILL }},
    { &hf_ftbp_future_object_size,
      { "future-object-size", "ftbp.future_object_size",
        FT_UINT32, BASE_DEC, VALS(ftam_Object_Size_Attribute_vals), 0,
        "FileAttributes/future-object-size", HFILL }},
    { &hf_ftbp_access_control,
      { "access-control", "ftbp.access_control",
        FT_UINT32, BASE_DEC, VALS(ftbp_Access_Control_Attribute_vals), 0,
        "FileAttributes/access-control", HFILL }},
    { &hf_ftbp_legal_qualifications,
      { "legal-qualifications", "ftbp.legal_qualifications",
        FT_UINT32, BASE_DEC, VALS(ftam_Legal_Qualification_Attribute_vals), 0,
        "FileAttributes/legal-qualifications", HFILL }},
    { &hf_ftbp_private_use,
      { "private-use", "ftbp.private_use",
        FT_UINT32, BASE_DEC, VALS(ftam_Private_Use_Attribute_vals), 0,
        "FileAttributes/private-use", HFILL }},
    { &hf_ftbp_attribute_extensions,
      { "attribute-extensions", "ftbp.attribute_extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FileAttributes/attribute-extensions", HFILL }},
    { &hf_ftbp_incomplete_pathname,
      { "incomplete-pathname", "ftbp.incomplete_pathname",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Pathname-Attribute/incomplete-pathname", HFILL }},
    { &hf_ftbp_complete_pathname,
      { "complete-pathname", "ftbp.complete_pathname",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Pathname-Attribute/complete-pathname", HFILL }},
    { &hf_ftbp_no_value_available,
      { "no-value-available", "ftbp.no_value_available",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ftbp_account_actual_values,
      { "actual-values", "ftbp.actual_values",
        FT_STRING, BASE_NONE, NULL, 0,
        "Account-Attribute/actual-values", HFILL }},
    { &hf_ftbp_identity_actual_values,
      { "actual-values", "ftbp.actual_values",
        FT_STRING, BASE_NONE, NULL, 0,
        "User-Identity-Attribute/actual-values", HFILL }},
    { &hf_ftbp_actual_values,
      { "actual-values", "ftbp.actual_values",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Access-Control-Attribute/actual-values", HFILL }},
    { &hf_ftbp_actual_values_item,
      { "Item", "ftbp.actual_values_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "Access-Control-Attribute/actual-values/_item", HFILL }},
    { &hf_ftbp_action_list,
      { "action-list", "ftbp.action_list",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Access-Control-Element/action-list", HFILL }},
    { &hf_ftbp_concurrency_access,
      { "concurrency-access", "ftbp.concurrency_access",
        FT_NONE, BASE_NONE, NULL, 0,
        "Access-Control-Element/concurrency-access", HFILL }},
    { &hf_ftbp_identity,
      { "identity", "ftbp.identity",
        FT_STRING, BASE_NONE, NULL, 0,
        "Access-Control-Element/identity", HFILL }},
    { &hf_ftbp_passwords,
      { "passwords", "ftbp.passwords",
        FT_NONE, BASE_NONE, NULL, 0,
        "Access-Control-Element/passwords", HFILL }},
    { &hf_ftbp_location,
      { "location", "ftbp.location",
        FT_NONE, BASE_NONE, NULL, 0,
        "Access-Control-Element/location", HFILL }},
    { &hf_ftbp_read_password,
      { "read-password", "ftbp.read_password",
        FT_UINT32, BASE_DEC, VALS(ftbp_Password_vals), 0,
        "Access-Passwords/read-password", HFILL }},
    { &hf_ftbp_insert_password,
      { "insert-password", "ftbp.insert_password",
        FT_UINT32, BASE_DEC, VALS(ftbp_Password_vals), 0,
        "Access-Passwords/insert-password", HFILL }},
    { &hf_ftbp_replace_password,
      { "replace-password", "ftbp.replace_password",
        FT_UINT32, BASE_DEC, VALS(ftbp_Password_vals), 0,
        "Access-Passwords/replace-password", HFILL }},
    { &hf_ftbp_extend_password,
      { "extend-password", "ftbp.extend_password",
        FT_UINT32, BASE_DEC, VALS(ftbp_Password_vals), 0,
        "Access-Passwords/extend-password", HFILL }},
    { &hf_ftbp_erase_password,
      { "erase-password", "ftbp.erase_password",
        FT_UINT32, BASE_DEC, VALS(ftbp_Password_vals), 0,
        "Access-Passwords/erase-password", HFILL }},
    { &hf_ftbp_read_attribute_password,
      { "read-attribute-password", "ftbp.read_attribute_password",
        FT_UINT32, BASE_DEC, VALS(ftbp_Password_vals), 0,
        "Access-Passwords/read-attribute-password", HFILL }},
    { &hf_ftbp_change_attribute_password,
      { "change-attribute-password", "ftbp.change_attribute_password",
        FT_UINT32, BASE_DEC, VALS(ftbp_Password_vals), 0,
        "Access-Passwords/change-attribute-password", HFILL }},
    { &hf_ftbp_delete_password,
      { "delete-password", "ftbp.delete_password",
        FT_UINT32, BASE_DEC, VALS(ftbp_Password_vals), 0,
        "Access-Passwords/delete-password", HFILL }},
    { &hf_ftbp_pass_passwords,
      { "pass-passwords", "ftbp.pass_passwords",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Access-Passwords/pass-passwords", HFILL }},
    { &hf_ftbp_link_password,
      { "link-password", "ftbp.link_password",
        FT_UINT32, BASE_DEC, VALS(ftbp_Password_vals), 0,
        "Access-Passwords/link-password", HFILL }},
    { &hf_ftbp_graphic_string,
      { "graphic-string", "ftbp.graphic_string",
        FT_STRING, BASE_NONE, NULL, 0,
        "Password/graphic-string", HFILL }},
    { &hf_ftbp_octet_string,
      { "octet-string", "ftbp.octet_string",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Password/octet-string", HFILL }},
    { &hf_ftbp_Pass_Passwords_item,
      { "Item", "ftbp.Pass_Passwords_item",
        FT_UINT32, BASE_DEC, VALS(ftbp_Password_vals), 0,
        "Pass-Passwords/_item", HFILL }},
    { &hf_ftbp_ap_title,
      { "ap-title", "ftbp.ap_title",
        FT_UINT32, BASE_DEC, VALS(acse_AP_title_vals), 0,
        "Application-Entity-Title/ap-title", HFILL }},
    { &hf_ftbp_ae_qualifier,
      { "ae-qualifier", "ftbp.ae_qualifier",
        FT_UINT32, BASE_DEC, VALS(acse_ASO_qualifier_vals), 0,
        "Application-Entity-Title/ae-qualifier", HFILL }},
    { &hf_ftbp_Access_Request_read,
      { "read", "ftbp.read",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_ftbp_Access_Request_insert,
      { "insert", "ftbp.insert",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_ftbp_Access_Request_replace,
      { "replace", "ftbp.replace",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_ftbp_Access_Request_extend,
      { "extend", "ftbp.extend",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_ftbp_Access_Request_erase,
      { "erase", "ftbp.erase",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_ftbp_Access_Request_read_attribute,
      { "read-attribute", "ftbp.read-attribute",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_ftbp_Access_Request_change_attribute,
      { "change-attribute", "ftbp.change-attribute",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_ftbp_Access_Request_delete_object,
      { "delete-object", "ftbp.delete-object",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},

/*--- End of included file: packet-ftbp-hfarr.c ---*/
#line 69 "packet-ftbp-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_ftbp,

/*--- Included file: packet-ftbp-ettarr.c ---*/
#line 1 "packet-ftbp-ettarr.c"
    &ett_ftbp_FileTransferParameters,
    &ett_ftbp_FileTransferData,
    &ett_ftbp_RelatedStoredFile,
    &ett_ftbp_RelatedStoredFile_item,
    &ett_ftbp_FileIdentifier,
    &ett_ftbp_PathnameandVersion,
    &ett_ftbp_CrossReference,
    &ett_ftbp_MessageReference,
    &ett_ftbp_Relationship,
    &ett_ftbp_Contents_Type_Attribute,
    &ett_ftbp_T_document_type,
    &ett_ftbp_T_constraint_set_and_abstract_syntax,
    &ett_ftbp_EnvironmentParameter,
    &ett_ftbp_T_user_visible_string,
    &ett_ftbp_GeneralIdentifier,
    &ett_ftbp_T_descriptive_identifier,
    &ett_ftbp_CompressionParameter,
    &ett_ftbp_FileAttributes,
    &ett_ftbp_Pathname_Attribute,
    &ett_ftbp_Account_Attribute,
    &ett_ftbp_User_Identity_Attribute,
    &ett_ftbp_Access_Control_Attribute,
    &ett_ftbp_SET_OF_Access_Control_Element,
    &ett_ftbp_Access_Control_Element,
    &ett_ftbp_Access_Request,
    &ett_ftbp_Access_Passwords,
    &ett_ftbp_Password,
    &ett_ftbp_Pass_Passwords,
    &ett_ftbp_Application_Entity_Title,

/*--- End of included file: packet-ftbp-ettarr.c ---*/
#line 75 "packet-ftbp-template.c"
  };

  /* Register protocol */
  proto_ftbp = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_ftbp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_ftbp --- */
void proto_reg_handoff_ftbp(void) {

/*--- Included file: packet-ftbp-dis-tab.c ---*/
#line 1 "packet-ftbp-dis-tab.c"
  register_ber_oid_dissector("2.6.1.11.12", dissect_FileTransferParameters_PDU, proto_ftbp, "id-ep-file-transfer");
  register_ber_oid_dissector("2.6.1.4.12", dissect_FileTransferData_PDU, proto_ftbp, "id-et-file-transfer");


/*--- End of included file: packet-ftbp-dis-tab.c ---*/
#line 90 "packet-ftbp-template.c"

}
