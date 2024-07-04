/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-ftam.c                                                              */
/* asn2wrs.py -b -q -L -p ftam -c ./ftam.cnf -s ./packet-ftam-template -D . -O ../.. ISO8571-FTAM.asn */

/* packet-ftam_asn1.c
 * Routine to dissect OSI ISO 8571 FTAM Protocol packets
 * based on the ASN.1 specification from http://www.itu.int/ITU-T/asn1/database/iso/8571-4/1988/
 *
 * also based on original handwritten dissector by
 * Yuriy Sidelnikov <YSidelnikov@hotmail.com>
 *
 * Anders Broman and Ronnie Sahlberg 2005 - 2006
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-ftam.h"

#define PNAME  "ISO 8571 FTAM"
#define PSNAME "FTAM"
#define PFNAME "ftam"

void proto_register_ftam(void);
void proto_reg_handoff_ftam(void);

/* Initialize the protocol and registered fields */
static int proto_ftam;

/* Declare the function to avoid a compiler warning */
static int dissect_ftam_OR_Set(bool implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_);

static int hf_ftam_unstructured_text;              /* ISO FTAM unstructured text */
static int hf_ftam_unstructured_binary;            /* ISO FTAM unstructured binary */
static int hf_ftam_fTAM_Regime_PDU;               /* FTAM_Regime_PDU */
static int hf_ftam_file_PDU;                      /* File_PDU */
static int hf_ftam_bulk_Data_PDU;                 /* Bulk_Data_PDU */
static int hf_ftam_fSM_PDU;                       /* FSM_PDU */
static int hf_ftam_f_initialize_request;          /* F_INITIALIZE_request */
static int hf_ftam_f_initialize_response;         /* F_INITIALIZE_response */
static int hf_ftam_f_terminate_request;           /* F_TERMINATE_request */
static int hf_ftam_f_terminate_response;          /* F_TERMINATE_response */
static int hf_ftam_f_u_abort_request;             /* F_U_ABORT_request */
static int hf_ftam_f_p_abort_request;             /* F_P_ABORT_request */
static int hf_ftam_protocol_Version;              /* Protocol_Version */
static int hf_ftam_implementation_information;    /* Implementation_Information */
static int hf_ftam_presentation_tontext_management;  /* BOOLEAN */
static int hf_ftam_service_class;                 /* Service_Class */
static int hf_ftam_functional_units;              /* Functional_Units */
static int hf_ftam_attribute_groups;              /* Attribute_Groups */
static int hf_ftam_shared_ASE_information;        /* Shared_ASE_Information */
static int hf_ftam_ftam_quality_of_Service;       /* FTAM_Quality_of_Service */
static int hf_ftam_contents_type_list;            /* Contents_Type_List */
static int hf_ftam_initiator_identity;            /* User_Identity */
static int hf_ftam_account;                       /* Account */
static int hf_ftam_filestore_password;            /* Password */
static int hf_ftam_checkpoint_window;             /* INTEGER */
static int hf_ftam_state_result;                  /* State_Result */
static int hf_ftam_action_result;                 /* Action_Result */
static int hf_ftam_diagnostic;                    /* Diagnostic */
static int hf_ftam__untag_item;                   /* Contents_Type_List_item */
static int hf_ftam_document_type_name;            /* Document_Type_Name */
static int hf_ftam_abstract_Syntax_name;          /* Abstract_Syntax_Name */
static int hf_ftam_charging;                      /* Charging */
static int hf_ftam_f_select_request;              /* F_SELECT_request */
static int hf_ftam_f_select_response;             /* F_SELECT_response */
static int hf_ftam_f_deselect_request;            /* F_DESELECT_request */
static int hf_ftam_f_deselect_response;           /* F_DESELECT_response */
static int hf_ftam_f_create_request;              /* F_CREATE_request */
static int hf_ftam_f_create_response;             /* F_CREATE_response */
static int hf_ftam_f_delete_request;              /* F_DELETE_request */
static int hf_ftam_f_delete_response;             /* F_DELETE_response */
static int hf_ftam_f_read_attrib_request;         /* F_READ_ATTRIB_request */
static int hf_ftam_f_read_attrib_response;        /* F_READ_ATTRIB_response */
static int hf_ftam_f_Change_attrib_reques;        /* F_CHANGE_ATTRIB_request */
static int hf_ftam_f_Change_attrib_respon;        /* F_CHANGE_ATTRIB_response */
static int hf_ftam_f_open_request;                /* F_OPEN_request */
static int hf_ftam_f_open_response;               /* F_OPEN_response */
static int hf_ftam_f_close_request;               /* F_CLOSE_request */
static int hf_ftam_f_close_response;              /* F_CLOSE_response */
static int hf_ftam_f_begin_group_request;         /* F_BEGIN_GROUP_request */
static int hf_ftam_f_begin_group_response;        /* F_BEGIN_GROUP_response */
static int hf_ftam_f_end_group_request;           /* F_END_GROUP_request */
static int hf_ftam_f_end_group_response;          /* F_END_GROUP_response */
static int hf_ftam_f_recover_request;             /* F_RECOVER_request */
static int hf_ftam_f_recover_response;            /* F_RECOVER_response */
static int hf_ftam_f_locate_request;              /* F_LOCATE_request */
static int hf_ftam_f_locate_response;             /* F_LOCATE_response */
static int hf_ftam_f_erase_request;               /* F_ERASE_request */
static int hf_ftam_f_erase_response;              /* F_ERASE_response */
static int hf_ftam_select_attributes;             /* Select_Attributes */
static int hf_ftam_requested_access;              /* Access_Request */
static int hf_ftam_access_passwords;              /* Access_Passwords */
static int hf_ftam_path_access_passwords;         /* Path_Access_Passwords */
static int hf_ftam_concurrency_control;           /* Concurrency_Control */
static int hf_ftam_referent_indicator;            /* Referent_Indicator */
static int hf_ftam_override;                      /* Override */
static int hf_ftam_initial_attributes;            /* Create_Attributes */
static int hf_ftam_create_password;               /* Password */
static int hf_ftam_attribute_names;               /* Attribute_Names */
static int hf_ftam_attribute_extension_names;     /* Attribute_Extension_Names */
static int hf_ftam_read_attributes;               /* Read_Attributes */
static int hf_ftam_attributes;                    /* Change_Attributes */
static int hf_ftam_processing_mode;               /* T_processing_mode */
static int hf_ftam_open_contents_type;            /* T_open_contents_type */
static int hf_ftam_unknown;                       /* NULL */
static int hf_ftam_proposed;                      /* Contents_Type_Attribute */
static int hf_ftam_enable_fadu_locking;           /* BOOLEAN */
static int hf_ftam_activity_identifier;           /* Activity_Identifier */
static int hf_ftam_request_recovery_mode;         /* T_request_recovery_mode */
static int hf_ftam_remove_contexts;               /* SET_OF_Abstract_Syntax_Name */
static int hf_ftam_remove_contexts_item;          /* Abstract_Syntax_Name */
static int hf_ftam_define_contexts;               /* SET_OF_Abstract_Syntax_Name */
static int hf_ftam_define_contexts_item;          /* Abstract_Syntax_Name */
static int hf_ftam_degree_of_overlap;             /* Degree_Of_Overlap */
static int hf_ftam_transfer_window;               /* INTEGER */
static int hf_ftam_contents_type;                 /* Contents_Type_Attribute */
static int hf_ftam_response_recovery_mode;        /* T_response_recovery_mode */
static int hf_ftam_presentation_action;           /* BOOLEAN */
static int hf_ftam_threshold;                     /* INTEGER */
static int hf_ftam_bulk_transfer_number;          /* INTEGER */
static int hf_ftam_recovefy_Point;                /* INTEGER */
static int hf_ftam_concurrent_bulk_transfer_number;  /* INTEGER */
static int hf_ftam_concurrent_recovery_point;     /* INTEGER */
static int hf_ftam_last_transfer_end_read_response;  /* INTEGER */
static int hf_ftam_last_transfer_end_write_response;  /* INTEGER */
static int hf_ftam_recovety_Point;                /* INTEGER */
static int hf_ftam_last_transfer_end_read_request;  /* INTEGER */
static int hf_ftam_last_transfer_end_write_request;  /* INTEGER */
static int hf_ftam_file_access_data_unit_identity;  /* FADU_Identity */
static int hf_ftam_fadu_lock;                     /* FADU_Lock */
static int hf_ftam_f_read_request;                /* F_READ_request */
static int hf_ftam_f_write_request;               /* F_WRITE_request */
static int hf_ftam_f_data_end_request;            /* F_DATA_END_request */
static int hf_ftam_f_transfer_end_request;        /* F_TRANSFER_END_request */
static int hf_ftam_f_transfer_end_response;       /* F_TRANSFER_END_response */
static int hf_ftam_f_cancel_request;              /* F_CANCEL_request */
static int hf_ftam_f_cancel_response;             /* F_CANCEL_response */
static int hf_ftam_f_restart_request;             /* F_RESTART_request */
static int hf_ftam_f_restart_response;            /* F_RESTART_response */
static int hf_ftam_read_access_context;           /* Access_Context */
static int hf_ftam_transfer_number;               /* INTEGER */
static int hf_ftam_file_access_data_unit_Operation;  /* T_file_access_data_unit_Operation */
static int hf_ftam_request_type;                  /* Request_Type */
static int hf_ftam_checkpoint_identifier;         /* INTEGER */
static int hf_ftam_access_context;                /* T_access_context */
static int hf_ftam_level_number;                  /* INTEGER */
static int hf_ftam_read_password;                 /* Password */
static int hf_ftam_insert_password;               /* Password */
static int hf_ftam_replace_password;              /* Password */
static int hf_ftam_extend_password;               /* Password */
static int hf_ftam_erase_password;                /* Password */
static int hf_ftam_read_attribute_password;       /* Password */
static int hf_ftam_change_attribute_password;     /* Password */
static int hf_ftam_delete_password;               /* Password */
static int hf_ftam_pass_passwords;                /* Pass_Passwords */
static int hf_ftam_link_password;                 /* Password */
static int hf_ftam_pathname;                      /* Pathname_Attribute */
static int hf_ftam_storage_account;               /* Account_Attribute */
static int hf_ftam_object_availability;           /* Object_Availability_Attribute */
static int hf_ftam_future_Object_size;            /* Object_Size_Attribute */
static int hf_ftam_change_attributes_access_control;  /* Access_Control_Change_Attribute */
static int hf_ftam_change_path_access_control;    /* Access_Control_Change_Attribute */
static int hf_ftam_legal_qualification;           /* Legal_Qualification_Attribute */
static int hf_ftam_private_use;                   /* Private_Use_Attribute */
static int hf_ftam_attribute_extensions;          /* Attribute_Extensions */
static int hf_ftam__untag_item_01;                /* Charging_item */
static int hf_ftam_resource_identifier;           /* GraphicString */
static int hf_ftam_charging_unit;                 /* GraphicString */
static int hf_ftam_charging_value;                /* INTEGER */
static int hf_ftam_read;                          /* Lock */
static int hf_ftam_insert;                        /* Lock */
static int hf_ftam_replace;                       /* Lock */
static int hf_ftam_extend;                        /* Lock */
static int hf_ftam_erase;                         /* Lock */
static int hf_ftam_read_attribute;                /* Lock */
static int hf_ftam_change_attribute;              /* Lock */
static int hf_ftam_delete_Object;                 /* Lock */
static int hf_ftam_object_type;                   /* Object_Type_Attribute */
static int hf_ftam_permitted_actions;             /* Permitted_Actions_Attribute */
static int hf_ftam_access_control;                /* Access_Control_Attribute */
static int hf_ftam_path_access_control;           /* Access_Control_Attribute */
static int hf_ftam__untag_item_02;                /* Diagnostic_item */
static int hf_ftam_diagnostic_type;               /* T_diagnostic_type */
static int hf_ftam_error_identifier;              /* INTEGER */
static int hf_ftam_error_observer;                /* Entity_Reference */
static int hf_ftam_error_Source;                  /* Entity_Reference */
static int hf_ftam_suggested_delay;               /* INTEGER */
static int hf_ftam_further_details;               /* GraphicString */
static int hf_ftam_first_last;                    /* T_first_last */
static int hf_ftam_relative;                      /* T_relative */
static int hf_ftam_begin_end;                     /* T_begin_end */
static int hf_ftam_single_name;                   /* Node_Name */
static int hf_ftam_name_list;                     /* SEQUENCE_OF_Node_Name */
static int hf_ftam_name_list_item;                /* Node_Name */
static int hf_ftam_fadu_number;                   /* INTEGER */
static int hf_ftam_graphicString;                 /* GraphicString */
static int hf_ftam_octetString;                   /* OCTET_STRING */
static int hf_ftam_linked_Object;                 /* Pathname_Attribute */
static int hf_ftam_child_objects;                 /* Child_Objects_Attribute */
static int hf_ftam_primaty_pathname;              /* Pathname_Attribute */
static int hf_ftam_date_and_time_of_creation;     /* Date_and_Time_Attribute */
static int hf_ftam_date_and_time_of_last_modification;  /* Date_and_Time_Attribute */
static int hf_ftam_date_and_time_of_last_read_access;  /* Date_and_Time_Attribute */
static int hf_ftam_date_and_time_of_last_attribute_modification;  /* Date_and_Time_Attribute */
static int hf_ftam_identity_of_creator;           /* User_Identity_Attribute */
static int hf_ftam_identity_of_last_modifier;     /* User_Identity_Attribute */
static int hf_ftam_identity_of_last_reader;       /* User_Identity_Attribute */
static int hf_ftam_identity_last_attribute_modifier;  /* User_Identity_Attribute */
static int hf_ftam_object_size;                   /* Object_Size_Attribute */
static int hf_ftam_no_value_available;            /* NULL */
static int hf_ftam_actual_values3;                /* SET_OF_Access_Control_Element */
static int hf_ftam_actual_values3_item;           /* Access_Control_Element */
static int hf_ftam_actual_values1;                /* T_actual_values1 */
static int hf_ftam_insert_values;                 /* SET_OF_Access_Control_Element */
static int hf_ftam_insert_values_item;            /* Access_Control_Element */
static int hf_ftam_delete_values;                 /* SET_OF_Access_Control_Element */
static int hf_ftam_delete_values_item;            /* Access_Control_Element */
static int hf_ftam_action_list;                   /* Access_Request */
static int hf_ftam_concurrency_access;            /* Concurrency_Access */
static int hf_ftam_identity;                      /* User_Identity */
static int hf_ftam_passwords;                     /* Access_Passwords */
static int hf_ftam_location;                      /* Application_Entity_Title */
static int hf_ftam_read_key;                      /* Concurrency_Key */
static int hf_ftam_insert_key;                    /* Concurrency_Key */
static int hf_ftam_replace_key;                   /* Concurrency_Key */
static int hf_ftam_extend_key;                    /* Concurrency_Key */
static int hf_ftam_erase_key;                     /* Concurrency_Key */
static int hf_ftam_read_attribute_key;            /* Concurrency_Key */
static int hf_ftam_change_attribute_key;          /* Concurrency_Key */
static int hf_ftam_delete_Object_key;             /* Concurrency_Key */
static int hf_ftam_actual_values2;                /* Account */
static int hf_ftam_document_type;                 /* T_document_type */
static int hf_ftam_parameter;                     /* T_parameter */
static int hf_ftam_constraint_set_and_abstract_Syntax;  /* T_constraint_set_and_abstract_Syntax */
static int hf_ftam_constraint_set_name;           /* Constraint_Set_Name */
static int hf_ftam_actual_values5;                /* GeneralizedTime */
static int hf_ftam_actual_values8;                /* T_actual_values8 */
static int hf_ftam_incomplete_pathname;           /* Pathname */
static int hf_ftam_complete_pathname;             /* Pathname */
static int hf_ftam_actual_values7;                /* INTEGER */
static int hf_ftam_actual_values9;                /* GraphicString */
static int hf_ftam_abstract_Syntax_not_supported;  /* NULL */
static int hf_ftam_actual_values4;                /* EXTERNAL */
static int hf_ftam_actual_values6;                /* User_Identity */
static int hf_ftam_Child_Objects_Attribute_item;  /* GraphicString */
static int hf_ftam_f_Change_prefix_request;       /* F_CHANGE_PREFIX_request */
static int hf_ftam_f_Change_prefix_response;      /* F_CHANGE_PREFIX_response */
static int hf_ftam_f_list_request;                /* F_LIST_request */
static int hf_ftam_f_list_response;               /* F_LIST_response */
static int hf_ftam_f_group_select_request;        /* F_GROUP_SELECT_request */
static int hf_ftam_f_group_select_response;       /* F_GROUP_SELECT_response */
static int hf_ftam_f_group_delete_request;        /* F_GROUP_DELETE_request */
static int hf_ftam_f_group_delete_response;       /* F_GROUP_DELETE_response */
static int hf_ftam_f_group_move_request;          /* F_GROUP_MOVE_request */
static int hf_ftam_f_group_move_response;         /* F_GROUP_MOVE_response */
static int hf_ftam_f_group_copy_request;          /* F_GROUP_COPY_request */
static int hf_ftam_f_group_copy_response;         /* F_GROUP_COPY_response */
static int hf_ftam_f_group_list_request;          /* F_GROUP_LIST_request */
static int hf_ftam_f_group_list_response;         /* F_GROUP_LIST_response */
static int hf_ftam_f_group_Change_attrib_request;  /* F_GROUP_CHANGE_ATTRIB_request */
static int hf_ftam_f_group_Change_attrib_response;  /* F_GROUP_CHANGE_ATTRIB_response */
static int hf_ftam_f_select_another_request;      /* F_SELECT_ANOTHER_request */
static int hf_ftam_f_select_another_response;     /* F_SELECT_ANOTHER_response */
static int hf_ftam_f_create_directory_request;    /* F_CREATE_DIRECTORY_request */
static int hf_ftam_f_create_directory_response;   /* F_CREATE_DIRECTORY_response */
static int hf_ftam_f_link_request;                /* F_LINK_request */
static int hf_ftam_f_link_response;               /* F_LINK_response */
static int hf_ftam_f_unlink_request;              /* F_UNLINK_request */
static int hf_ftam_f_unlink_response;             /* F_UNLINK_response */
static int hf_ftam_f_read_link_attrib_request;    /* F_READ_LINK_ATTRIB_request */
static int hf_ftam_f_read_link_attrib_response;   /* F_READ_LINK_ATTRIB_response */
static int hf_ftam_f_Change_link_attrib_request;  /* F_CHANGE_LINK_ATTRIB_request */
static int hf_ftam_f_Change_Iink_attrib_response;  /* F_CHANGE_LINK_ATTRIB_response */
static int hf_ftam_f_move_request;                /* F_MOVE_request */
static int hf_ftam_f_move_response;               /* F_MOVE_response */
static int hf_ftam_f_copy_request;                /* F_COPY_request */
static int hf_ftam_f_copy_response;               /* F_COPY_response */
static int hf_ftam_reset;                         /* BOOLEAN */
static int hf_ftam_destination_file_directory;    /* Destination_File_Directory */
static int hf_ftam_attribute_value_asset_tions;   /* Attribute_Value_Assertions */
static int hf_ftam_scope;                         /* Scope */
static int hf_ftam_objects_attributes_list;       /* Objects_Attributes_List */
static int hf_ftam_attribute_value_assertions;    /* Attribute_Value_Assertions */
static int hf_ftam_maximum_set_size;              /* INTEGER */
static int hf_ftam_request_Operation_result;      /* Request_Operation_Result */
static int hf_ftam_operation_result;              /* Operation_Result */
static int hf_ftam_error_action;                  /* Error_Action */
static int hf_ftam_last_member_indicator;         /* BOOLEAN */
static int hf_ftam_shared_ASE_infonnation;        /* Shared_ASE_Information */
static int hf_ftam_target_object;                 /* Pathname_Attribute */
static int hf_ftam_target_Object;                 /* Pathname_Attribute */
static int hf_ftam_read_link_attributes;          /* Read_Attributes */
static int hf_ftam_Attribute_Extension_Names_item;  /* Attribute_Extension_Set_Name */
static int hf_ftam_extension_set_identifier;      /* Extension_Set_Identifier */
static int hf_ftam_extension_attribute_names;     /* SEQUENCE_OF_Extension_Attribute_identifier */
static int hf_ftam_extension_attribute_names_item;  /* Extension_Attribute_identifier */
static int hf_ftam_Attribute_Extensions_item;     /* Attribute_Extension_Set */
static int hf_ftam_extension_set_attributes;      /* SEQUENCE_OF_Extension_Attribute */
static int hf_ftam_extension_set_attributes_item;  /* Extension_Attribute */
static int hf_ftam_extension_attribute_identifier;  /* T_extension_attribute_identifier */
static int hf_ftam_extension_attribute;           /* T_extension_attribute */
static int hf_ftam__untag_item_03;                /* T__untag_item */
static int hf_ftam_root_directory;                /* Pathname_Attribute */
static int hf_ftam_retrieval_scope;               /* T_retrieval_scope */
static int hf_ftam_OR_Set_item;                   /* AND_Set */
static int hf_ftam_AND_Set_item;                  /* AND_Set_item */
static int hf_ftam_pathname_Pattern;              /* Pathname_Pattern */
static int hf_ftam_object_type_Pattern;           /* Integer_Pattern */
static int hf_ftam_permitted_actions_Pattern;     /* Bitstring_Pattern */
static int hf_ftam_contents_type_Pattern;         /* Contents_Type_Pattern */
static int hf_ftam_linked_Object_Pattern;         /* Pathname_Pattern */
static int hf_ftam_child_objects_Pattern;         /* Pathname_Pattern */
static int hf_ftam_primaty_pathname_Pattern;      /* Pathname_Pattern */
static int hf_ftam_storage_account_Pattern;       /* String_Pattern */
static int hf_ftam_date_and_time_of_creation_Pattern;  /* Date_and_Time_Pattern */
static int hf_ftam_date_and_time_of_last_modification_Pattern;  /* Date_and_Time_Pattern */
static int hf_ftam_date_and_time_of_last_read_access_Pattern;  /* Date_and_Time_Pattern */
static int hf_ftam_date_and_time_of_last_attribute_modification_Pattern;  /* Date_and_Time_Pattern */
static int hf_ftam_identity_of_creator_Pattern;   /* User_Identity_Pattern */
static int hf_ftam_identity_of_last_modifier_Pattern;  /* User_Identity_Pattern */
static int hf_ftam_identity_of_last_reader_Pattern;  /* User_Identity_Pattern */
static int hf_ftam_identity_of_last_attribute_modifier_Pattern;  /* User_Identity_Pattern */
static int hf_ftam_object_availabiiity_Pattern;   /* Boolean_Pattern */
static int hf_ftam_object_size_Pattern;           /* Integer_Pattern */
static int hf_ftam_future_object_size_Pattern;    /* Integer_Pattern */
static int hf_ftam_legal_quailfication_Pattern;   /* String_Pattern */
static int hf_ftam_attribute_extensions_pattern;  /* Attribute_Extensions_Pattern */
static int hf_ftam_equality_comparision;          /* Equality_Comparision */
static int hf_ftam_pathname_value;                /* T_pathname_value */
static int hf_ftam_pathname_value_item;           /* T_pathname_value_item */
static int hf_ftam_string_match;                  /* String_Pattern */
static int hf_ftam_any_match;                     /* NULL */
static int hf_ftam_string_value;                  /* T_string_value */
static int hf_ftam_string_value_item;             /* T_string_value_item */
static int hf_ftam_substring_match;               /* GraphicString */
static int hf_ftam_number_of_characters_match;    /* INTEGER */
static int hf_ftam_match_bitstring;               /* BIT_STRING */
static int hf_ftam_significance_bitstring;        /* BIT_STRING */
static int hf_ftam_relational_camparision;        /* Equality_Comparision */
static int hf_ftam_time_and_date_value;           /* GeneralizedTime */
static int hf_ftam_relational_comparision;        /* Relational_Comparision */
static int hf_ftam_integer_value;                 /* INTEGER */
static int hf_ftam_object_identifier_value;       /* OBJECT_IDENTIFIER */
static int hf_ftam_boolean_value;                 /* BOOLEAN */
static int hf_ftam_document_type_Pattern;         /* Object_Identifier_Pattern */
static int hf_ftam_constraint_set_abstract_Syntax_Pattern;  /* T_constraint_set_abstract_Syntax_Pattern */
static int hf_ftam_constraint_Set_Pattern;        /* Object_Identifier_Pattern */
static int hf_ftam_abstract_Syntax_Pattern;       /* Object_Identifier_Pattern */
static int hf_ftam_Attribute_Extensions_Pattern_item;  /* Attribute_Extensions_Pattern_item */
static int hf_ftam_extension_set_attribute_Patterns;  /* T_extension_set_attribute_Patterns */
static int hf_ftam_extension_set_attribute_Patterns_item;  /* T_extension_set_attribute_Patterns_item */
static int hf_ftam_attribute_extension_attribute_identifier;  /* T_attribute_extension_attribute_identifier */
static int hf_ftam_extension_attribute_Pattern;   /* T_extension_attribute_Pattern */
static int hf_ftam__untag_item_04;                /* Read_Attributes */
static int hf_ftam_success_Object_count;          /* INTEGER */
static int hf_ftam_success_Object_names;          /* SEQUENCE_OF_Pathname */
static int hf_ftam_success_Object_names_item;     /* Pathname */
static int hf_ftam_Pathname_item;                 /* GraphicString */
static int hf_ftam_Pass_Passwords_item;           /* Password */
static int hf_ftam__untag_item_05;                /* Path_Access_Passwords_item */
static int hf_ftam_ap;                            /* AP_title */
static int hf_ftam_ae;                            /* AE_qualifier */
/* named bits */
static int hf_ftam_Protocol_Version_U_version_1;
static int hf_ftam_Protocol_Version_U_version_2;
static int hf_ftam_Service_Class_U_unconstrained_class;
static int hf_ftam_Service_Class_U_management_class;
static int hf_ftam_Service_Class_U_transfer_class;
static int hf_ftam_Service_Class_U_transfer_and_management_class;
static int hf_ftam_Service_Class_U_access_class;
static int hf_ftam_Functional_Units_U_spare_bit0;
static int hf_ftam_Functional_Units_U_spare_bit1;
static int hf_ftam_Functional_Units_U_read;
static int hf_ftam_Functional_Units_U_write;
static int hf_ftam_Functional_Units_U_file_access;
static int hf_ftam_Functional_Units_U_limited_file_management;
static int hf_ftam_Functional_Units_U_enhanced_file_management;
static int hf_ftam_Functional_Units_U_grouping;
static int hf_ftam_Functional_Units_U_fadu_locking;
static int hf_ftam_Functional_Units_U_recovery;
static int hf_ftam_Functional_Units_U_restart_data_transfer;
static int hf_ftam_Functional_Units_U_limited_filestore_management;
static int hf_ftam_Functional_Units_U_enhanced_filestore_management;
static int hf_ftam_Functional_Units_U_object_manipulation;
static int hf_ftam_Functional_Units_U_group_manipulation;
static int hf_ftam_Functional_Units_U_consecutive_access;
static int hf_ftam_Functional_Units_U_concurrent_access;
static int hf_ftam_Attribute_Groups_U_storage;
static int hf_ftam_Attribute_Groups_U_security;
static int hf_ftam_Attribute_Groups_U_private;
static int hf_ftam_Attribute_Groups_U_extension;
static int hf_ftam_T_processing_mode_f_read;
static int hf_ftam_T_processing_mode_f_insert;
static int hf_ftam_T_processing_mode_f_replace;
static int hf_ftam_T_processing_mode_f_extend;
static int hf_ftam_T_processing_mode_f_erase;
static int hf_ftam_Access_Request_U_read;
static int hf_ftam_Access_Request_U_insert;
static int hf_ftam_Access_Request_U_replace;
static int hf_ftam_Access_Request_U_extend;
static int hf_ftam_Access_Request_U_erase;
static int hf_ftam_Access_Request_U_read_attribute;
static int hf_ftam_Access_Request_U_change_attribute;
static int hf_ftam_Access_Request_U_delete_Object;
static int hf_ftam_Concurrency_Key_not_required;
static int hf_ftam_Concurrency_Key_shared;
static int hf_ftam_Concurrency_Key_exclusive;
static int hf_ftam_Concurrency_Key_no_access;
static int hf_ftam_Permitted_Actions_Attribute_read;
static int hf_ftam_Permitted_Actions_Attribute_insert;
static int hf_ftam_Permitted_Actions_Attribute_replace;
static int hf_ftam_Permitted_Actions_Attribute_extend;
static int hf_ftam_Permitted_Actions_Attribute_erase;
static int hf_ftam_Permitted_Actions_Attribute_read_attribute;
static int hf_ftam_Permitted_Actions_Attribute_change_attribute;
static int hf_ftam_Permitted_Actions_Attribute_delete_Object;
static int hf_ftam_Permitted_Actions_Attribute_traversal;
static int hf_ftam_Permitted_Actions_Attribute_reverse_traversal;
static int hf_ftam_Permitted_Actions_Attribute_random_Order;
static int hf_ftam_Permitted_Actions_Attribute_pass;
static int hf_ftam_Permitted_Actions_Attribute_link;
static int hf_ftam_Equality_Comparision_no_value_available_matches;
static int hf_ftam_Equality_Comparision_equals_matches;
static int hf_ftam_Relational_Comparision_no_value_available_matches;
static int hf_ftam_Relational_Comparision_equals_matches;
static int hf_ftam_Relational_Comparision_less_than_matches;
static int hf_ftam_Relational_Comparision_greater_than_matches;
static int hf_ftam_Attribute_Names_read_pathname;
static int hf_ftam_Attribute_Names_read_permitted_actions;
static int hf_ftam_Attribute_Names_read_contents_type;
static int hf_ftam_Attribute_Names_read_storage_account;
static int hf_ftam_Attribute_Names_read_date_and_time_of_creation;
static int hf_ftam_Attribute_Names_read_date_and_time_of_last_modification;
static int hf_ftam_Attribute_Names_read_date_and_time_of_last_read_access;
static int hf_ftam_Attribute_Names_read_date_and_time_of_last_attribute_modification;
static int hf_ftam_Attribute_Names_read_identity_of_creator;
static int hf_ftam_Attribute_Names_read_identity_of_last_modifier;
static int hf_ftam_Attribute_Names_read_identity_of_last_reader;
static int hf_ftam_Attribute_Names_read_identity_of_last_attribute_modifier;
static int hf_ftam_Attribute_Names_read_Object_availability;
static int hf_ftam_Attribute_Names_read_Object_size;
static int hf_ftam_Attribute_Names_read_future_Object_size;
static int hf_ftam_Attribute_Names_read_access_control;
static int hf_ftam_Attribute_Names_read_l8gal_qualifiCatiOnS;
static int hf_ftam_Attribute_Names_read_private_use;
static int hf_ftam_Attribute_Names_read_Object_type;
static int hf_ftam_Attribute_Names_read_linked_Object;
static int hf_ftam_Attribute_Names_read_primary_pathname;
static int hf_ftam_Attribute_Names_read_path_access_control;
static int hf_ftam_Attribute_Names_spare_bit22;
static int hf_ftam_Attribute_Names_read_Child_objects;

/* Initialize the subtree pointers */
static int ett_ftam;
static int ett_ftam_PDU;
static int ett_ftam_FTAM_Regime_PDU;
static int ett_ftam_F_INITIALIZE_request;
static int ett_ftam_F_INITIALIZE_response;
static int ett_ftam_Protocol_Version_U;
static int ett_ftam_Service_Class_U;
static int ett_ftam_Functional_Units_U;
static int ett_ftam_Attribute_Groups_U;
static int ett_ftam_Contents_Type_List_U;
static int ett_ftam_Contents_Type_List_item;
static int ett_ftam_F_TERMINATE_request;
static int ett_ftam_F_TERMINATE_response;
static int ett_ftam_F_U_ABORT_request;
static int ett_ftam_F_P_ABORT_request;
static int ett_ftam_File_PDU;
static int ett_ftam_F_SELECT_request;
static int ett_ftam_F_SELECT_response;
static int ett_ftam_F_DESELECT_request;
static int ett_ftam_F_DESELECT_response;
static int ett_ftam_F_CREATE_request;
static int ett_ftam_F_CREATE_response;
static int ett_ftam_F_DELETE_request;
static int ett_ftam_F_DELETE_response;
static int ett_ftam_F_READ_ATTRIB_request;
static int ett_ftam_F_READ_ATTRIB_response;
static int ett_ftam_F_CHANGE_ATTRIB_request;
static int ett_ftam_F_CHANGE_ATTRIB_response;
static int ett_ftam_F_OPEN_request;
static int ett_ftam_T_processing_mode;
static int ett_ftam_T_open_contents_type;
static int ett_ftam_SET_OF_Abstract_Syntax_Name;
static int ett_ftam_F_OPEN_response;
static int ett_ftam_F_CLOSE_request;
static int ett_ftam_F_CLOSE_response;
static int ett_ftam_F_BEGIN_GROUP_request;
static int ett_ftam_F_BEGIN_GROUP_response;
static int ett_ftam_F_END_GROUP_request;
static int ett_ftam_F_END_GROUP_response;
static int ett_ftam_F_RECOVER_request;
static int ett_ftam_F_RECOVER_response;
static int ett_ftam_F_LOCATE_request;
static int ett_ftam_F_LOCATE_response;
static int ett_ftam_F_ERASE_request;
static int ett_ftam_F_ERASE_response;
static int ett_ftam_Bulk_Data_PDU;
static int ett_ftam_F_READ_request;
static int ett_ftam_F_WRITE_request;
static int ett_ftam_F_DATA_END_request;
static int ett_ftam_F_TRANSFER_END_request;
static int ett_ftam_F_TRANSFER_END_response;
static int ett_ftam_F_CANCEL_request;
static int ett_ftam_F_CANCEL_response;
static int ett_ftam_F_RESTART_request;
static int ett_ftam_F_RESTART_response;
static int ett_ftam_Access_Context_U;
static int ett_ftam_Access_Passwords_U;
static int ett_ftam_Access_Request_U;
static int ett_ftam_Change_Attributes_U;
static int ett_ftam_Charging_U;
static int ett_ftam_Charging_item;
static int ett_ftam_Concurrency_Control_U;
static int ett_ftam_Create_Attributes_U;
static int ett_ftam_Diagnostic_U;
static int ett_ftam_Diagnostic_item;
static int ett_ftam_FADU_Identity_U;
static int ett_ftam_SEQUENCE_OF_Node_Name;
static int ett_ftam_Password_U;
static int ett_ftam_Read_Attributes_U;
static int ett_ftam_Select_Attributes_U;
static int ett_ftam_Access_Control_Attribute;
static int ett_ftam_SET_OF_Access_Control_Element;
static int ett_ftam_Access_Control_Change_Attribute;
static int ett_ftam_T_actual_values1;
static int ett_ftam_Access_Control_Element;
static int ett_ftam_Concurrency_Access;
static int ett_ftam_Concurrency_Key;
static int ett_ftam_Account_Attribute;
static int ett_ftam_Contents_Type_Attribute;
static int ett_ftam_T_document_type;
static int ett_ftam_T_constraint_set_and_abstract_Syntax;
static int ett_ftam_Date_and_Time_Attribute;
static int ett_ftam_Object_Availability_Attribute;
static int ett_ftam_Pathname_Attribute;
static int ett_ftam_Object_Size_Attribute;
static int ett_ftam_Legal_Qualification_Attribute;
static int ett_ftam_Permitted_Actions_Attribute;
static int ett_ftam_Private_Use_Attribute;
static int ett_ftam_User_Identity_Attribute;
static int ett_ftam_Child_Objects_Attribute;
static int ett_ftam_FSM_PDU;
static int ett_ftam_F_CHANGE_PREFIX_request;
static int ett_ftam_F_CHANGE_PREFIX_response;
static int ett_ftam_F_LIST_request;
static int ett_ftam_F_LIST_response;
static int ett_ftam_F_GROUP_SELECT_request;
static int ett_ftam_F_GROUP_SELECT_response;
static int ett_ftam_F_GROUP_DELETE_request;
static int ett_ftam_F_GROUP_DELETE_response;
static int ett_ftam_F_GROUP_MOVE_request;
static int ett_ftam_F_GROUP_MOVE_response;
static int ett_ftam_F_GROUP_COPY_request;
static int ett_ftam_F_GROUP_COPY_response;
static int ett_ftam_F_GROUP_LIST_request;
static int ett_ftam_F_GROUP_LIST_response;
static int ett_ftam_F_GROUP_CHANGE_ATTRIB_request;
static int ett_ftam_F_GROUP_CHANGE_ATTRIB_response;
static int ett_ftam_F_SELECT_ANOTHER_request;
static int ett_ftam_F_SELECT_ANOTHER_response;
static int ett_ftam_F_CREATE_DIRECTORY_request;
static int ett_ftam_F_CREATE_DIRECTORY_response;
static int ett_ftam_F_LINK_request;
static int ett_ftam_F_LINK_response;
static int ett_ftam_F_UNLINK_request;
static int ett_ftam_F_UNLINK_response;
static int ett_ftam_F_READ_LINK_ATTRIB_request;
static int ett_ftam_F_READ_LINK_ATTRIB_response;
static int ett_ftam_F_CHANGE_LINK_ATTRIB_request;
static int ett_ftam_F_CHANGE_LINK_ATTRIB_response;
static int ett_ftam_F_MOVE_request;
static int ett_ftam_F_MOVE_response;
static int ett_ftam_F_COPY_request;
static int ett_ftam_F_COPY_response;
static int ett_ftam_Attribute_Extension_Names;
static int ett_ftam_Attribute_Extension_Set_Name;
static int ett_ftam_SEQUENCE_OF_Extension_Attribute_identifier;
static int ett_ftam_Attribute_Extensions;
static int ett_ftam_Attribute_Extension_Set;
static int ett_ftam_SEQUENCE_OF_Extension_Attribute;
static int ett_ftam_Extension_Attribute;
static int ett_ftam_Scope_U;
static int ett_ftam_T__untag_item;
static int ett_ftam_OR_Set;
static int ett_ftam_AND_Set;
static int ett_ftam_AND_Set_item;
static int ett_ftam_Equality_Comparision;
static int ett_ftam_Relational_Comparision;
static int ett_ftam_Pathname_Pattern;
static int ett_ftam_T_pathname_value;
static int ett_ftam_T_pathname_value_item;
static int ett_ftam_String_Pattern;
static int ett_ftam_T_string_value;
static int ett_ftam_T_string_value_item;
static int ett_ftam_Bitstring_Pattern;
static int ett_ftam_Date_and_Time_Pattern;
static int ett_ftam_Integer_Pattern;
static int ett_ftam_Object_Identifier_Pattern;
static int ett_ftam_Boolean_Pattern;
static int ett_ftam_Contents_Type_Pattern;
static int ett_ftam_T_constraint_set_abstract_Syntax_Pattern;
static int ett_ftam_Attribute_Extensions_Pattern;
static int ett_ftam_Attribute_Extensions_Pattern_item;
static int ett_ftam_T_extension_set_attribute_Patterns;
static int ett_ftam_T_extension_set_attribute_Patterns_item;
static int ett_ftam_SEQUENCE_OF_Read_Attributes;
static int ett_ftam_Operation_Result_U;
static int ett_ftam_SEQUENCE_OF_Pathname;
static int ett_ftam_Pathname;
static int ett_ftam_Pass_Passwords;
static int ett_ftam_Path_Access_Passwords_U;
static int ett_ftam_Path_Access_Passwords_item;
static int ett_ftam_Attribute_Names;
static int ett_ftam_AE_title;

static expert_field ei_ftam_zero_pdu;


static int * const Protocol_Version_U_bits[] = {
  &hf_ftam_Protocol_Version_U_version_1,
  &hf_ftam_Protocol_Version_U_version_2,
  NULL
};

static int
dissect_ftam_Protocol_Version_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Protocol_Version_U_bits, 2, hf_index, ett_ftam_Protocol_Version_U,
                                    NULL);

  return offset;
}



static int
dissect_ftam_Protocol_Version(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 0, true, dissect_ftam_Protocol_Version_U);

  return offset;
}



static int
dissect_ftam_GraphicString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_ftam_Implementation_Information(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 1, true, dissect_ftam_GraphicString);

  return offset;
}



static int
dissect_ftam_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static int * const Service_Class_U_bits[] = {
  &hf_ftam_Service_Class_U_unconstrained_class,
  &hf_ftam_Service_Class_U_management_class,
  &hf_ftam_Service_Class_U_transfer_class,
  &hf_ftam_Service_Class_U_transfer_and_management_class,
  &hf_ftam_Service_Class_U_access_class,
  NULL
};

static int
dissect_ftam_Service_Class_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Service_Class_U_bits, 5, hf_index, ett_ftam_Service_Class_U,
                                    NULL);

  return offset;
}



static int
dissect_ftam_Service_Class(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 3, true, dissect_ftam_Service_Class_U);

  return offset;
}


static int * const Functional_Units_U_bits[] = {
  &hf_ftam_Functional_Units_U_spare_bit0,
  &hf_ftam_Functional_Units_U_spare_bit1,
  &hf_ftam_Functional_Units_U_read,
  &hf_ftam_Functional_Units_U_write,
  &hf_ftam_Functional_Units_U_file_access,
  &hf_ftam_Functional_Units_U_limited_file_management,
  &hf_ftam_Functional_Units_U_enhanced_file_management,
  &hf_ftam_Functional_Units_U_grouping,
  &hf_ftam_Functional_Units_U_fadu_locking,
  &hf_ftam_Functional_Units_U_recovery,
  &hf_ftam_Functional_Units_U_restart_data_transfer,
  &hf_ftam_Functional_Units_U_limited_filestore_management,
  &hf_ftam_Functional_Units_U_enhanced_filestore_management,
  &hf_ftam_Functional_Units_U_object_manipulation,
  &hf_ftam_Functional_Units_U_group_manipulation,
  &hf_ftam_Functional_Units_U_consecutive_access,
  &hf_ftam_Functional_Units_U_concurrent_access,
  NULL
};

static int
dissect_ftam_Functional_Units_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Functional_Units_U_bits, 17, hf_index, ett_ftam_Functional_Units_U,
                                    NULL);

  return offset;
}



static int
dissect_ftam_Functional_Units(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 4, true, dissect_ftam_Functional_Units_U);

  return offset;
}


static int * const Attribute_Groups_U_bits[] = {
  &hf_ftam_Attribute_Groups_U_storage,
  &hf_ftam_Attribute_Groups_U_security,
  &hf_ftam_Attribute_Groups_U_private,
  &hf_ftam_Attribute_Groups_U_extension,
  NULL
};

static int
dissect_ftam_Attribute_Groups_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Attribute_Groups_U_bits, 4, hf_index, ett_ftam_Attribute_Groups_U,
                                    NULL);

  return offset;
}



static int
dissect_ftam_Attribute_Groups(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 5, true, dissect_ftam_Attribute_Groups_U);

  return offset;
}



static int
dissect_ftam_EXTERNAL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_external_type(implicit_tag, tree, tvb, offset, actx, hf_index, NULL);

  return offset;
}



static int
dissect_ftam_Shared_ASE_Information(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 20, true, dissect_ftam_EXTERNAL);

  return offset;
}


static const value_string ftam_FTAM_Quality_of_Service_U_vals[] = {
  {   0, "no-recovery" },
  {   1, "class-1-recovery" },
  {   2, "class-2-recovery" },
  {   3, "class-3-recovery" },
  { 0, NULL }
};


static int
dissect_ftam_FTAM_Quality_of_Service_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ftam_FTAM_Quality_of_Service(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 6, true, dissect_ftam_FTAM_Quality_of_Service_U);

  return offset;
}



static int
dissect_ftam_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &actx->external.direct_reference);

  return offset;
}



static int
dissect_ftam_Document_Type_Name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 14, true, dissect_ftam_OBJECT_IDENTIFIER);

  return offset;
}



static int
dissect_ftam_Abstract_Syntax_Name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 0, true, dissect_ftam_OBJECT_IDENTIFIER);

  return offset;
}


static const value_string ftam_Contents_Type_List_item_vals[] = {
  {  14, "document-type-name" },
  {   0, "abstract-Syntax-name" },
  { 0, NULL }
};

static const ber_choice_t Contents_Type_List_item_choice[] = {
  {  14, &hf_ftam_document_type_name, BER_CLASS_APP, 14, BER_FLAGS_NOOWNTAG, dissect_ftam_Document_Type_Name },
  {   0, &hf_ftam_abstract_Syntax_name, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_ftam_Abstract_Syntax_Name },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Contents_Type_List_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Contents_Type_List_item_choice, hf_index, ett_ftam_Contents_Type_List_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t Contents_Type_List_U_sequence_of[1] = {
  { &hf_ftam__untag_item    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ftam_Contents_Type_List_item },
};

static int
dissect_ftam_Contents_Type_List_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Contents_Type_List_U_sequence_of, hf_index, ett_ftam_Contents_Type_List_U);

  return offset;
}



static int
dissect_ftam_Contents_Type_List(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 7, true, dissect_ftam_Contents_Type_List_U);

  return offset;
}



static int
dissect_ftam_User_Identity(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 22, true, dissect_ftam_GraphicString);

  return offset;
}



static int
dissect_ftam_Account(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 4, true, dissect_ftam_GraphicString);

  return offset;
}



static int
dissect_ftam_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string ftam_Password_U_vals[] = {
  {   0, "graphicString" },
  {   1, "octetString" },
  { 0, NULL }
};

static const ber_choice_t Password_U_choice[] = {
  {   0, &hf_ftam_graphicString  , BER_CLASS_UNI, BER_UNI_TAG_GraphicString, BER_FLAGS_NOOWNTAG, dissect_ftam_GraphicString },
  {   1, &hf_ftam_octetString    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ftam_OCTET_STRING },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Password_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Password_U_choice, hf_index, ett_ftam_Password_U,
                                 NULL);

  return offset;
}



static int
dissect_ftam_Password(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 17, false, dissect_ftam_Password_U);

  return offset;
}



static int
dissect_ftam_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t F_INITIALIZE_request_sequence[] = {
  { &hf_ftam_protocol_Version, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Protocol_Version },
  { &hf_ftam_implementation_information, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Implementation_Information },
  { &hf_ftam_presentation_tontext_management, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_BOOLEAN },
  { &hf_ftam_service_class  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Service_Class },
  { &hf_ftam_functional_units, BER_CLASS_CON, 4, BER_FLAGS_NOOWNTAG, dissect_ftam_Functional_Units },
  { &hf_ftam_attribute_groups, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Attribute_Groups },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_ftam_quality_of_Service, BER_CLASS_CON, 6, BER_FLAGS_NOOWNTAG, dissect_ftam_FTAM_Quality_of_Service },
  { &hf_ftam_contents_type_list, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Contents_Type_List },
  { &hf_ftam_initiator_identity, BER_CLASS_APP, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_User_Identity },
  { &hf_ftam_account        , BER_CLASS_APP, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Account },
  { &hf_ftam_filestore_password, BER_CLASS_APP, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Password },
  { &hf_ftam_checkpoint_window, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_INITIALIZE_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_INITIALIZE_request_sequence, hf_index, ett_ftam_F_INITIALIZE_request);

  return offset;
}


static const value_string ftam_State_Result_U_vals[] = {
  {   0, "success" },
  {   1, "failure" },
  { 0, NULL }
};


static int
dissect_ftam_State_Result_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ftam_State_Result(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 21, true, dissect_ftam_State_Result_U);

  return offset;
}


static const value_string ftam_Action_Result_U_vals[] = {
  {   0, "success" },
  {   1, "transient-error" },
  {   2, "permanent-error" },
  { 0, NULL }
};


static int
dissect_ftam_Action_Result_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ftam_Action_Result(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 5, true, dissect_ftam_Action_Result_U);

  return offset;
}


static const value_string ftam_T_diagnostic_type_vals[] = {
  {   0, "informative" },
  {   1, "transient" },
  {   2, "permanent" },
  { 0, NULL }
};


static int
dissect_ftam_T_diagnostic_type(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string ftam_Entity_Reference_vals[] = {
  {   0, "no-categorization-possible" },
  {   1, "initiating-file-service-user" },
  {   2, "initiating-file-protocol-machine" },
  {   3, "service-supporting-the-file-protocol-machine" },
  {   4, "responding-file-protocol-machine" },
  {   5, "responding-file-service-user" },
  { 0, NULL }
};


static int
dissect_ftam_Entity_Reference(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t Diagnostic_item_sequence[] = {
  { &hf_ftam_diagnostic_type, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_T_diagnostic_type },
  { &hf_ftam_error_identifier, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_error_observer , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ftam_Entity_Reference },
  { &hf_ftam_error_Source   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ftam_Entity_Reference },
  { &hf_ftam_suggested_delay, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_further_details, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_GraphicString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Diagnostic_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Diagnostic_item_sequence, hf_index, ett_ftam_Diagnostic_item);

  return offset;
}


static const ber_sequence_t Diagnostic_U_sequence_of[1] = {
  { &hf_ftam__untag_item_02 , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic_item },
};

static int
dissect_ftam_Diagnostic_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Diagnostic_U_sequence_of, hf_index, ett_ftam_Diagnostic_U);

  return offset;
}



static int
dissect_ftam_Diagnostic(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 13, true, dissect_ftam_Diagnostic_U);

  return offset;
}


static const ber_sequence_t F_INITIALIZE_response_sequence[] = {
  { &hf_ftam_state_result   , BER_CLASS_APP, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_State_Result },
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_protocol_Version, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Protocol_Version },
  { &hf_ftam_implementation_information, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Implementation_Information },
  { &hf_ftam_presentation_tontext_management, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_BOOLEAN },
  { &hf_ftam_service_class  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Service_Class },
  { &hf_ftam_functional_units, BER_CLASS_CON, 4, BER_FLAGS_NOOWNTAG, dissect_ftam_Functional_Units },
  { &hf_ftam_attribute_groups, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Attribute_Groups },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_ftam_quality_of_Service, BER_CLASS_CON, 6, BER_FLAGS_NOOWNTAG, dissect_ftam_FTAM_Quality_of_Service },
  { &hf_ftam_contents_type_list, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Contents_Type_List },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { &hf_ftam_checkpoint_window, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_INITIALIZE_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_INITIALIZE_response_sequence, hf_index, ett_ftam_F_INITIALIZE_response);

  return offset;
}


static const ber_sequence_t F_TERMINATE_request_sequence[] = {
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_TERMINATE_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_TERMINATE_request_sequence, hf_index, ett_ftam_F_TERMINATE_request);

  return offset;
}


static const ber_sequence_t Charging_item_sequence[] = {
  { &hf_ftam_resource_identifier, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_GraphicString },
  { &hf_ftam_charging_unit  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_GraphicString },
  { &hf_ftam_charging_value , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Charging_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Charging_item_sequence, hf_index, ett_ftam_Charging_item);

  return offset;
}


static const ber_sequence_t Charging_U_sequence_of[1] = {
  { &hf_ftam__untag_item_01 , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ftam_Charging_item },
};

static int
dissect_ftam_Charging_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Charging_U_sequence_of, hf_index, ett_ftam_Charging_U);

  return offset;
}



static int
dissect_ftam_Charging(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 9, true, dissect_ftam_Charging_U);

  return offset;
}


static const ber_sequence_t F_TERMINATE_response_sequence[] = {
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_charging       , BER_CLASS_APP, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Charging },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_TERMINATE_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_TERMINATE_response_sequence, hf_index, ett_ftam_F_TERMINATE_response);

  return offset;
}


static const ber_sequence_t F_U_ABORT_request_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_U_ABORT_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_U_ABORT_request_sequence, hf_index, ett_ftam_F_U_ABORT_request);

  return offset;
}


static const ber_sequence_t F_P_ABORT_request_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_P_ABORT_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_P_ABORT_request_sequence, hf_index, ett_ftam_F_P_ABORT_request);

  return offset;
}


static const value_string ftam_FTAM_Regime_PDU_vals[] = {
  {   0, "f-initialize-request" },
  {   1, "f-initialize-response" },
  {   2, "f-terminate-request" },
  {   3, "f-terminate-response" },
  {   4, "f-u-abort-request" },
  {   5, "f-p-abort-request" },
  { 0, NULL }
};

static const ber_choice_t FTAM_Regime_PDU_choice[] = {
  {   0, &hf_ftam_f_initialize_request, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_F_INITIALIZE_request },
  {   1, &hf_ftam_f_initialize_response, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_F_INITIALIZE_response },
  {   2, &hf_ftam_f_terminate_request, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ftam_F_TERMINATE_request },
  {   3, &hf_ftam_f_terminate_response, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ftam_F_TERMINATE_response },
  {   4, &hf_ftam_f_u_abort_request, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_ftam_F_U_ABORT_request },
  {   5, &hf_ftam_f_p_abort_request, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_ftam_F_P_ABORT_request },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_FTAM_Regime_PDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int branch_taken;

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 FTAM_Regime_PDU_choice, hf_index, ett_ftam_FTAM_Regime_PDU,
                                 &branch_taken);


  if( (branch_taken!=-1) && ftam_FTAM_Regime_PDU_vals[branch_taken].strptr ){
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s:", ftam_FTAM_Regime_PDU_vals[branch_taken].strptr);
  }


  return offset;
}


static const ber_sequence_t Pathname_sequence_of[1] = {
  { &hf_ftam_Pathname_item  , BER_CLASS_UNI, BER_UNI_TAG_GraphicString, BER_FLAGS_NOOWNTAG, dissect_ftam_GraphicString },
};

int
dissect_ftam_Pathname(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Pathname_sequence_of, hf_index, ett_ftam_Pathname);

  return offset;
}


static const value_string ftam_Pathname_Attribute_vals[] = {
  {   0, "incomplete-pathname" },
  {   1, "complete-pathname" },
  { 0, NULL }
};

static const ber_choice_t Pathname_Attribute_choice[] = {
  {   0, &hf_ftam_incomplete_pathname, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_Pathname },
  {   1, &hf_ftam_complete_pathname, BER_CLASS_APP, 23, BER_FLAGS_IMPLTAG, dissect_ftam_Pathname },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Pathname_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Pathname_Attribute_choice, hf_index, ett_ftam_Pathname_Attribute,
                                 NULL);

  return offset;
}


static const ber_sequence_t Select_Attributes_U_sequence[] = {
  { &hf_ftam_pathname       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ftam_Pathname_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Select_Attributes_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Select_Attributes_U_sequence, hf_index, ett_ftam_Select_Attributes_U);

  return offset;
}



static int
dissect_ftam_Select_Attributes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 19, true, dissect_ftam_Select_Attributes_U);

  return offset;
}


static int * const Access_Request_U_bits[] = {
  &hf_ftam_Access_Request_U_read,
  &hf_ftam_Access_Request_U_insert,
  &hf_ftam_Access_Request_U_replace,
  &hf_ftam_Access_Request_U_extend,
  &hf_ftam_Access_Request_U_erase,
  &hf_ftam_Access_Request_U_read_attribute,
  &hf_ftam_Access_Request_U_change_attribute,
  &hf_ftam_Access_Request_U_delete_Object,
  NULL
};

static int
dissect_ftam_Access_Request_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Access_Request_U_bits, 8, hf_index, ett_ftam_Access_Request_U,
                                    NULL);

  return offset;
}



static int
dissect_ftam_Access_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 3, true, dissect_ftam_Access_Request_U);

  return offset;
}


static const ber_sequence_t Pass_Passwords_sequence_of[1] = {
  { &hf_ftam_Pass_Passwords_item, BER_CLASS_APP, 17, BER_FLAGS_NOOWNTAG, dissect_ftam_Password },
};

static int
dissect_ftam_Pass_Passwords(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Pass_Passwords_sequence_of, hf_index, ett_ftam_Pass_Passwords);

  return offset;
}


static const ber_sequence_t Access_Passwords_U_sequence[] = {
  { &hf_ftam_read_password  , BER_CLASS_CON, 0, 0, dissect_ftam_Password },
  { &hf_ftam_insert_password, BER_CLASS_CON, 1, 0, dissect_ftam_Password },
  { &hf_ftam_replace_password, BER_CLASS_CON, 2, 0, dissect_ftam_Password },
  { &hf_ftam_extend_password, BER_CLASS_CON, 3, 0, dissect_ftam_Password },
  { &hf_ftam_erase_password , BER_CLASS_CON, 4, 0, dissect_ftam_Password },
  { &hf_ftam_read_attribute_password, BER_CLASS_CON, 5, 0, dissect_ftam_Password },
  { &hf_ftam_change_attribute_password, BER_CLASS_CON, 6, 0, dissect_ftam_Password },
  { &hf_ftam_delete_password, BER_CLASS_CON, 7, 0, dissect_ftam_Password },
  { &hf_ftam_pass_passwords , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_Pass_Passwords },
  { &hf_ftam_link_password  , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL, dissect_ftam_Password },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Access_Passwords_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Access_Passwords_U_sequence, hf_index, ett_ftam_Access_Passwords_U);

  return offset;
}



static int
dissect_ftam_Access_Passwords(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 2, true, dissect_ftam_Access_Passwords_U);

  return offset;
}


static const ber_sequence_t Path_Access_Passwords_item_sequence[] = {
  { &hf_ftam_read_password  , BER_CLASS_CON, 0, 0, dissect_ftam_Password },
  { &hf_ftam_insert_password, BER_CLASS_CON, 1, 0, dissect_ftam_Password },
  { &hf_ftam_replace_password, BER_CLASS_CON, 2, 0, dissect_ftam_Password },
  { &hf_ftam_extend_password, BER_CLASS_CON, 3, 0, dissect_ftam_Password },
  { &hf_ftam_erase_password , BER_CLASS_CON, 4, 0, dissect_ftam_Password },
  { &hf_ftam_read_attribute_password, BER_CLASS_CON, 5, 0, dissect_ftam_Password },
  { &hf_ftam_change_attribute_password, BER_CLASS_CON, 6, 0, dissect_ftam_Password },
  { &hf_ftam_delete_password, BER_CLASS_CON, 7, 0, dissect_ftam_Password },
  { &hf_ftam_pass_passwords , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_ftam_Pass_Passwords },
  { &hf_ftam_link_password  , BER_CLASS_CON, 9, 0, dissect_ftam_Password },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Path_Access_Passwords_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Path_Access_Passwords_item_sequence, hf_index, ett_ftam_Path_Access_Passwords_item);

  return offset;
}


static const ber_sequence_t Path_Access_Passwords_U_sequence_of[1] = {
  { &hf_ftam__untag_item_05 , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ftam_Path_Access_Passwords_item },
};

static int
dissect_ftam_Path_Access_Passwords_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Path_Access_Passwords_U_sequence_of, hf_index, ett_ftam_Path_Access_Passwords_U);

  return offset;
}



static int
dissect_ftam_Path_Access_Passwords(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 27, true, dissect_ftam_Path_Access_Passwords_U);

  return offset;
}


static const value_string ftam_Lock_vals[] = {
  {   0, "not-required" },
  {   1, "shared" },
  {   2, "exclusive" },
  {   3, "no-access" },
  { 0, NULL }
};


static int
dissect_ftam_Lock(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t Concurrency_Control_U_sequence[] = {
  { &hf_ftam_read           , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_Lock },
  { &hf_ftam_insert         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_Lock },
  { &hf_ftam_replace        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ftam_Lock },
  { &hf_ftam_extend         , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ftam_Lock },
  { &hf_ftam_erase          , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_ftam_Lock },
  { &hf_ftam_read_attribute , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_ftam_Lock },
  { &hf_ftam_change_attribute, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_ftam_Lock },
  { &hf_ftam_delete_Object  , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_ftam_Lock },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Concurrency_Control_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Concurrency_Control_U_sequence, hf_index, ett_ftam_Concurrency_Control_U);

  return offset;
}



static int
dissect_ftam_Concurrency_Control(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 10, true, dissect_ftam_Concurrency_Control_U);

  return offset;
}


static const ber_sequence_t F_SELECT_request_sequence[] = {
  { &hf_ftam_select_attributes, BER_CLASS_APP, 19, BER_FLAGS_NOOWNTAG, dissect_ftam_Select_Attributes },
  { &hf_ftam_requested_access, BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_ftam_Access_Request },
  { &hf_ftam_access_passwords, BER_CLASS_APP, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Access_Passwords },
  { &hf_ftam_path_access_passwords, BER_CLASS_APP, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Path_Access_Passwords },
  { &hf_ftam_concurrency_control, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Concurrency_Control },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_account        , BER_CLASS_APP, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Account },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_SELECT_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_SELECT_request_sequence, hf_index, ett_ftam_F_SELECT_request);

  return offset;
}



static int
dissect_ftam_Referent_Indicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 29, true, dissect_ftam_BOOLEAN);

  return offset;
}


static const ber_sequence_t F_SELECT_response_sequence[] = {
  { &hf_ftam_state_result   , BER_CLASS_APP, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_State_Result },
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_select_attributes, BER_CLASS_APP, 19, BER_FLAGS_NOOWNTAG, dissect_ftam_Select_Attributes },
  { &hf_ftam_referent_indicator, BER_CLASS_APP, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Referent_Indicator },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_SELECT_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_SELECT_response_sequence, hf_index, ett_ftam_F_SELECT_response);

  return offset;
}


static const ber_sequence_t F_DESELECT_request_sequence[] = {
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_DESELECT_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_DESELECT_request_sequence, hf_index, ett_ftam_F_DESELECT_request);

  return offset;
}


static const ber_sequence_t F_DESELECT_response_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_charging       , BER_CLASS_APP, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Charging },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_DESELECT_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_DESELECT_response_sequence, hf_index, ett_ftam_F_DESELECT_response);

  return offset;
}


static const value_string ftam_Override_vals[] = {
  {   0, "create-failure" },
  {   1, "select-old-Object" },
  {   2, "delete-and-create-with-old-attributes" },
  {   3, "delete-and-create-with-new-attributes" },
  { 0, NULL }
};


static int
dissect_ftam_Override(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string ftam_Object_Type_Attribute_vals[] = {
  {   0, "file" },
  {   1, "file-directory" },
  {   2, "reference" },
  { 0, NULL }
};


static int
dissect_ftam_Object_Type_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static int * const Permitted_Actions_Attribute_bits[] = {
  &hf_ftam_Permitted_Actions_Attribute_read,
  &hf_ftam_Permitted_Actions_Attribute_insert,
  &hf_ftam_Permitted_Actions_Attribute_replace,
  &hf_ftam_Permitted_Actions_Attribute_extend,
  &hf_ftam_Permitted_Actions_Attribute_erase,
  &hf_ftam_Permitted_Actions_Attribute_read_attribute,
  &hf_ftam_Permitted_Actions_Attribute_change_attribute,
  &hf_ftam_Permitted_Actions_Attribute_delete_Object,
  &hf_ftam_Permitted_Actions_Attribute_traversal,
  &hf_ftam_Permitted_Actions_Attribute_reverse_traversal,
  &hf_ftam_Permitted_Actions_Attribute_random_Order,
  &hf_ftam_Permitted_Actions_Attribute_pass,
  &hf_ftam_Permitted_Actions_Attribute_link,
  NULL
};

int
dissect_ftam_Permitted_Actions_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Permitted_Actions_Attribute_bits, 13, hf_index, ett_ftam_Permitted_Actions_Attribute,
                                    NULL);

  return offset;
}



static int
dissect_ftam_T_parameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  if (actx->external.direct_reference) {
    offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);
  }


  return offset;
}


static const ber_sequence_t T_document_type_sequence[] = {
  { &hf_ftam_document_type_name, BER_CLASS_APP, 14, BER_FLAGS_NOOWNTAG, dissect_ftam_Document_Type_Name },
  { &hf_ftam_parameter      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_ftam_T_parameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_T_document_type(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_document_type_sequence, hf_index, ett_ftam_T_document_type);

  return offset;
}



static int
dissect_ftam_Constraint_Set_Name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 11, true, dissect_ftam_OBJECT_IDENTIFIER);

  return offset;
}


static const ber_sequence_t T_constraint_set_and_abstract_Syntax_sequence[] = {
  { &hf_ftam_constraint_set_name, BER_CLASS_APP, 11, BER_FLAGS_NOOWNTAG, dissect_ftam_Constraint_Set_Name },
  { &hf_ftam_abstract_Syntax_name, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_ftam_Abstract_Syntax_Name },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_T_constraint_set_and_abstract_Syntax(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_constraint_set_and_abstract_Syntax_sequence, hf_index, ett_ftam_T_constraint_set_and_abstract_Syntax);

  return offset;
}


static const value_string ftam_Contents_Type_Attribute_vals[] = {
  {   0, "document-type" },
  {   1, "constraint-set-and-abstract-Syntax" },
  { 0, NULL }
};

static const ber_choice_t Contents_Type_Attribute_choice[] = {
  {   0, &hf_ftam_document_type  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_T_document_type },
  {   1, &hf_ftam_constraint_set_and_abstract_Syntax, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_T_constraint_set_and_abstract_Syntax },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Contents_Type_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Contents_Type_Attribute_choice, hf_index, ett_ftam_Contents_Type_Attribute,
                                 NULL);

  return offset;
}



static int
dissect_ftam_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string ftam_Account_Attribute_vals[] = {
  {   0, "no-value-available" },
  {   1, "actual-values" },
  { 0, NULL }
};

static const ber_choice_t Account_Attribute_choice[] = {
  {   0, &hf_ftam_no_value_available, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_NULL },
  {   1, &hf_ftam_actual_values2 , BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_ftam_Account },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Account_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Account_Attribute_choice, hf_index, ett_ftam_Account_Attribute,
                                 NULL);

  return offset;
}


static const value_string ftam_T_actual_values8_vals[] = {
  {   0, "immediate-availability" },
  {   1, "deferred-availability" },
  { 0, NULL }
};


static int
dissect_ftam_T_actual_values8(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


const value_string ftam_Object_Availability_Attribute_vals[] = {
  {   0, "no-value-available" },
  {   1, "actual-values" },
  { 0, NULL }
};

static const ber_choice_t Object_Availability_Attribute_choice[] = {
  {   0, &hf_ftam_no_value_available, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_NULL },
  {   1, &hf_ftam_actual_values8 , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_T_actual_values8 },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_ftam_Object_Availability_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Object_Availability_Attribute_choice, hf_index, ett_ftam_Object_Availability_Attribute,
                                 NULL);

  return offset;
}


const value_string ftam_Object_Size_Attribute_vals[] = {
  {   0, "no-value-available" },
  {   1, "actual-values" },
  { 0, NULL }
};

static const ber_choice_t Object_Size_Attribute_choice[] = {
  {   0, &hf_ftam_no_value_available, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_NULL },
  {   1, &hf_ftam_actual_values7 , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_ftam_Object_Size_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Object_Size_Attribute_choice, hf_index, ett_ftam_Object_Size_Attribute,
                                 NULL);

  return offset;
}


static int * const Concurrency_Key_bits[] = {
  &hf_ftam_Concurrency_Key_not_required,
  &hf_ftam_Concurrency_Key_shared,
  &hf_ftam_Concurrency_Key_exclusive,
  &hf_ftam_Concurrency_Key_no_access,
  NULL
};

static int
dissect_ftam_Concurrency_Key(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Concurrency_Key_bits, 4, hf_index, ett_ftam_Concurrency_Key,
                                    NULL);

  return offset;
}


static const ber_sequence_t Concurrency_Access_sequence[] = {
  { &hf_ftam_read_key       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_Concurrency_Key },
  { &hf_ftam_insert_key     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_Concurrency_Key },
  { &hf_ftam_replace_key    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ftam_Concurrency_Key },
  { &hf_ftam_extend_key     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ftam_Concurrency_Key },
  { &hf_ftam_erase_key      , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_ftam_Concurrency_Key },
  { &hf_ftam_read_attribute_key, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_ftam_Concurrency_Key },
  { &hf_ftam_change_attribute_key, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_ftam_Concurrency_Key },
  { &hf_ftam_delete_Object_key, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_ftam_Concurrency_Key },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_ftam_Concurrency_Access(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Concurrency_Access_sequence, hf_index, ett_ftam_Concurrency_Access);

  return offset;
}



static int
dissect_ftam_AP_title(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  /* XXX have no idea about this one */

  return offset;
}



static int
dissect_ftam_AE_qualifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  /* XXX have no idea about this one */


  return offset;
}


static const ber_sequence_t AE_title_sequence[] = {
  { &hf_ftam_ap             , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_ftam_AP_title },
  { &hf_ftam_ae             , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_ftam_AE_qualifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_AE_title(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AE_title_sequence, hf_index, ett_ftam_AE_title);

  return offset;
}



static int
dissect_ftam_Application_Entity_Title(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 7, false, dissect_ftam_AE_title);

  return offset;
}


static const ber_sequence_t Access_Control_Element_sequence[] = {
  { &hf_ftam_action_list    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_Access_Request },
  { &hf_ftam_concurrency_access, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_Concurrency_Access },
  { &hf_ftam_identity       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_User_Identity },
  { &hf_ftam_passwords      , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_Access_Passwords },
  { &hf_ftam_location       , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_Application_Entity_Title },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Access_Control_Element(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Access_Control_Element_sequence, hf_index, ett_ftam_Access_Control_Element);

  return offset;
}


static const ber_sequence_t SET_OF_Access_Control_Element_set_of[1] = {
  { &hf_ftam_actual_values3_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ftam_Access_Control_Element },
};

static int
dissect_ftam_SET_OF_Access_Control_Element(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_Access_Control_Element_set_of, hf_index, ett_ftam_SET_OF_Access_Control_Element);

  return offset;
}


static const value_string ftam_Access_Control_Attribute_vals[] = {
  {   0, "no-value-available" },
  {   1, "actual-values" },
  { 0, NULL }
};

static const ber_choice_t Access_Control_Attribute_choice[] = {
  {   0, &hf_ftam_no_value_available, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_NULL },
  {   1, &hf_ftam_actual_values3 , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_SET_OF_Access_Control_Element },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Access_Control_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Access_Control_Attribute_choice, hf_index, ett_ftam_Access_Control_Attribute,
                                 NULL);

  return offset;
}


const value_string ftam_Legal_Qualification_Attribute_vals[] = {
  {   0, "no-value-available" },
  {   1, "actual-values" },
  { 0, NULL }
};

static const ber_choice_t Legal_Qualification_Attribute_choice[] = {
  {   0, &hf_ftam_no_value_available, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_NULL },
  {   1, &hf_ftam_actual_values9 , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_GraphicString },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_ftam_Legal_Qualification_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Legal_Qualification_Attribute_choice, hf_index, ett_ftam_Legal_Qualification_Attribute,
                                 NULL);

  return offset;
}


const value_string ftam_Private_Use_Attribute_vals[] = {
  {   0, "no-value-available" },
  {   1, "abstract-Syntax-not-supported" },
  {   2, "actual-values" },
  { 0, NULL }
};

static const ber_choice_t Private_Use_Attribute_choice[] = {
  {   0, &hf_ftam_no_value_available, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_NULL },
  {   1, &hf_ftam_abstract_Syntax_not_supported, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_NULL },
  {   2, &hf_ftam_actual_values4 , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ftam_EXTERNAL },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_ftam_Private_Use_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Private_Use_Attribute_choice, hf_index, ett_ftam_Private_Use_Attribute,
                                 NULL);

  return offset;
}



static int
dissect_ftam_Extension_Set_Identifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_ftam_T_extension_attribute_identifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &actx->external.direct_reference);

  return offset;
}



static int
dissect_ftam_T_extension_attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  if (actx->external.direct_reference) {
    offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);
  }


  return offset;
}


static const ber_sequence_t Extension_Attribute_sequence[] = {
  { &hf_ftam_extension_attribute_identifier, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_ftam_T_extension_attribute_identifier },
  { &hf_ftam_extension_attribute, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_ftam_T_extension_attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Extension_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Extension_Attribute_sequence, hf_index, ett_ftam_Extension_Attribute);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Extension_Attribute_sequence_of[1] = {
  { &hf_ftam_extension_set_attributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ftam_Extension_Attribute },
};

static int
dissect_ftam_SEQUENCE_OF_Extension_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Extension_Attribute_sequence_of, hf_index, ett_ftam_SEQUENCE_OF_Extension_Attribute);

  return offset;
}


static const ber_sequence_t Attribute_Extension_Set_sequence[] = {
  { &hf_ftam_extension_set_identifier, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_Extension_Set_Identifier },
  { &hf_ftam_extension_set_attributes, BER_CLASS_CON, 1, 0, dissect_ftam_SEQUENCE_OF_Extension_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Attribute_Extension_Set(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Attribute_Extension_Set_sequence, hf_index, ett_ftam_Attribute_Extension_Set);

  return offset;
}


static const ber_sequence_t Attribute_Extensions_sequence_of[1] = {
  { &hf_ftam_Attribute_Extensions_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ftam_Attribute_Extension_Set },
};

int
dissect_ftam_Attribute_Extensions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Attribute_Extensions_sequence_of, hf_index, ett_ftam_Attribute_Extensions);

  return offset;
}


static const ber_sequence_t Create_Attributes_U_sequence[] = {
  { &hf_ftam_pathname       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ftam_Pathname_Attribute },
  { &hf_ftam_object_type    , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_Object_Type_Attribute },
  { &hf_ftam_permitted_actions, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_Permitted_Actions_Attribute },
  { &hf_ftam_contents_type  , BER_CLASS_CON, 2, BER_FLAGS_NOTCHKTAG, dissect_ftam_Contents_Type_Attribute },
  { &hf_ftam_storage_account, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Account_Attribute },
  { &hf_ftam_object_availability, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Object_Availability_Attribute },
  { &hf_ftam_future_Object_size, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Object_Size_Attribute },
  { &hf_ftam_access_control , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Access_Control_Attribute },
  { &hf_ftam_path_access_control, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Access_Control_Attribute },
  { &hf_ftam_legal_qualification, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Legal_Qualification_Attribute },
  { &hf_ftam_private_use    , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Private_Use_Attribute },
  { &hf_ftam_attribute_extensions, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_Attribute_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Create_Attributes_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Create_Attributes_U_sequence, hf_index, ett_ftam_Create_Attributes_U);

  return offset;
}



static int
dissect_ftam_Create_Attributes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 12, true, dissect_ftam_Create_Attributes_U);

  return offset;
}


static const ber_sequence_t F_CREATE_request_sequence[] = {
  { &hf_ftam_override       , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_Override },
  { &hf_ftam_initial_attributes, BER_CLASS_APP, 12, BER_FLAGS_NOOWNTAG, dissect_ftam_Create_Attributes },
  { &hf_ftam_create_password, BER_CLASS_APP, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Password },
  { &hf_ftam_requested_access, BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_ftam_Access_Request },
  { &hf_ftam_access_passwords, BER_CLASS_APP, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Access_Passwords },
  { &hf_ftam_path_access_passwords, BER_CLASS_APP, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Path_Access_Passwords },
  { &hf_ftam_concurrency_control, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Concurrency_Control },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_account        , BER_CLASS_APP, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Account },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_CREATE_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_CREATE_request_sequence, hf_index, ett_ftam_F_CREATE_request);

  return offset;
}


static const ber_sequence_t F_CREATE_response_sequence[] = {
  { &hf_ftam_state_result   , BER_CLASS_APP, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_State_Result },
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_initial_attributes, BER_CLASS_APP, 12, BER_FLAGS_NOOWNTAG, dissect_ftam_Create_Attributes },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_CREATE_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_CREATE_response_sequence, hf_index, ett_ftam_F_CREATE_response);

  return offset;
}


static const ber_sequence_t F_DELETE_request_sequence[] = {
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_DELETE_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_DELETE_request_sequence, hf_index, ett_ftam_F_DELETE_request);

  return offset;
}


static const ber_sequence_t F_DELETE_response_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_charging       , BER_CLASS_APP, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Charging },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_DELETE_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_DELETE_response_sequence, hf_index, ett_ftam_F_DELETE_response);

  return offset;
}


static int * const Attribute_Names_bits[] = {
  &hf_ftam_Attribute_Names_read_pathname,
  &hf_ftam_Attribute_Names_read_permitted_actions,
  &hf_ftam_Attribute_Names_read_contents_type,
  &hf_ftam_Attribute_Names_read_storage_account,
  &hf_ftam_Attribute_Names_read_date_and_time_of_creation,
  &hf_ftam_Attribute_Names_read_date_and_time_of_last_modification,
  &hf_ftam_Attribute_Names_read_date_and_time_of_last_read_access,
  &hf_ftam_Attribute_Names_read_date_and_time_of_last_attribute_modification,
  &hf_ftam_Attribute_Names_read_identity_of_creator,
  &hf_ftam_Attribute_Names_read_identity_of_last_modifier,
  &hf_ftam_Attribute_Names_read_identity_of_last_reader,
  &hf_ftam_Attribute_Names_read_identity_of_last_attribute_modifier,
  &hf_ftam_Attribute_Names_read_Object_availability,
  &hf_ftam_Attribute_Names_read_Object_size,
  &hf_ftam_Attribute_Names_read_future_Object_size,
  &hf_ftam_Attribute_Names_read_access_control,
  &hf_ftam_Attribute_Names_read_l8gal_qualifiCatiOnS,
  &hf_ftam_Attribute_Names_read_private_use,
  &hf_ftam_Attribute_Names_read_Object_type,
  &hf_ftam_Attribute_Names_read_linked_Object,
  &hf_ftam_Attribute_Names_read_primary_pathname,
  &hf_ftam_Attribute_Names_read_path_access_control,
  &hf_ftam_Attribute_Names_spare_bit22,
  &hf_ftam_Attribute_Names_read_Child_objects,
  NULL
};

static int
dissect_ftam_Attribute_Names(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Attribute_Names_bits, 24, hf_index, ett_ftam_Attribute_Names,
                                    NULL);

  return offset;
}



static int
dissect_ftam_Extension_Attribute_identifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Extension_Attribute_identifier_sequence_of[1] = {
  { &hf_ftam_extension_attribute_names_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_ftam_Extension_Attribute_identifier },
};

static int
dissect_ftam_SEQUENCE_OF_Extension_Attribute_identifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Extension_Attribute_identifier_sequence_of, hf_index, ett_ftam_SEQUENCE_OF_Extension_Attribute_identifier);

  return offset;
}


static const ber_sequence_t Attribute_Extension_Set_Name_sequence[] = {
  { &hf_ftam_extension_set_identifier, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_Extension_Set_Identifier },
  { &hf_ftam_extension_attribute_names, BER_CLASS_CON, 1, 0, dissect_ftam_SEQUENCE_OF_Extension_Attribute_identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Attribute_Extension_Set_Name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Attribute_Extension_Set_Name_sequence, hf_index, ett_ftam_Attribute_Extension_Set_Name);

  return offset;
}


static const ber_sequence_t Attribute_Extension_Names_sequence_of[1] = {
  { &hf_ftam_Attribute_Extension_Names_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ftam_Attribute_Extension_Set_Name },
};

static int
dissect_ftam_Attribute_Extension_Names(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Attribute_Extension_Names_sequence_of, hf_index, ett_ftam_Attribute_Extension_Names);

  return offset;
}


static const ber_sequence_t F_READ_ATTRIB_request_sequence[] = {
  { &hf_ftam_attribute_names, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_Attribute_Names },
  { &hf_ftam_attribute_extension_names, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_Attribute_Extension_Names },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_READ_ATTRIB_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_READ_ATTRIB_request_sequence, hf_index, ett_ftam_F_READ_ATTRIB_request);

  return offset;
}


static const ber_sequence_t Child_Objects_Attribute_set_of[1] = {
  { &hf_ftam_Child_Objects_Attribute_item, BER_CLASS_UNI, BER_UNI_TAG_GraphicString, BER_FLAGS_NOOWNTAG, dissect_ftam_GraphicString },
};

static int
dissect_ftam_Child_Objects_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 Child_Objects_Attribute_set_of, hf_index, ett_ftam_Child_Objects_Attribute);

  return offset;
}



static int
dissect_ftam_GeneralizedTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


const value_string ftam_Date_and_Time_Attribute_vals[] = {
  {   0, "no-value-available" },
  {   1, "actual-values" },
  { 0, NULL }
};

static const ber_choice_t Date_and_Time_Attribute_choice[] = {
  {   0, &hf_ftam_no_value_available, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_NULL },
  {   1, &hf_ftam_actual_values5 , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_GeneralizedTime },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_ftam_Date_and_Time_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Date_and_Time_Attribute_choice, hf_index, ett_ftam_Date_and_Time_Attribute,
                                 NULL);

  return offset;
}


static const value_string ftam_User_Identity_Attribute_vals[] = {
  {   0, "no-value-available" },
  {   1, "actual-values" },
  { 0, NULL }
};

static const ber_choice_t User_Identity_Attribute_choice[] = {
  {   0, &hf_ftam_no_value_available, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_NULL },
  {   1, &hf_ftam_actual_values6 , BER_CLASS_APP, 22, BER_FLAGS_NOOWNTAG, dissect_ftam_User_Identity },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_User_Identity_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 User_Identity_Attribute_choice, hf_index, ett_ftam_User_Identity_Attribute,
                                 NULL);

  return offset;
}


static const ber_sequence_t Read_Attributes_U_sequence[] = {
  { &hf_ftam_pathname       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ftam_Pathname_Attribute },
  { &hf_ftam_object_type    , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_Object_Type_Attribute },
  { &hf_ftam_permitted_actions, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_Permitted_Actions_Attribute },
  { &hf_ftam_contents_type  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Contents_Type_Attribute },
  { &hf_ftam_linked_Object  , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Pathname_Attribute },
  { &hf_ftam_child_objects  , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL, dissect_ftam_Child_Objects_Attribute },
  { &hf_ftam_primaty_pathname, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Pathname_Attribute },
  { &hf_ftam_storage_account, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Account_Attribute },
  { &hf_ftam_date_and_time_of_creation, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Date_and_Time_Attribute },
  { &hf_ftam_date_and_time_of_last_modification, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Date_and_Time_Attribute },
  { &hf_ftam_date_and_time_of_last_read_access, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Date_and_Time_Attribute },
  { &hf_ftam_date_and_time_of_last_attribute_modification, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Date_and_Time_Attribute },
  { &hf_ftam_identity_of_creator, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_User_Identity_Attribute },
  { &hf_ftam_identity_of_last_modifier, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_User_Identity_Attribute },
  { &hf_ftam_identity_of_last_reader, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_User_Identity_Attribute },
  { &hf_ftam_identity_last_attribute_modifier, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_User_Identity_Attribute },
  { &hf_ftam_object_availability, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Object_Availability_Attribute },
  { &hf_ftam_object_size    , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Object_Size_Attribute },
  { &hf_ftam_future_Object_size, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Object_Size_Attribute },
  { &hf_ftam_access_control , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Access_Control_Attribute },
  { &hf_ftam_path_access_control, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Access_Control_Attribute },
  { &hf_ftam_legal_qualification, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Legal_Qualification_Attribute },
  { &hf_ftam_private_use    , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Private_Use_Attribute },
  { &hf_ftam_attribute_extensions, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_Attribute_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Read_Attributes_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Read_Attributes_U_sequence, hf_index, ett_ftam_Read_Attributes_U);

  return offset;
}



static int
dissect_ftam_Read_Attributes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 18, true, dissect_ftam_Read_Attributes_U);

  return offset;
}


static const ber_sequence_t F_READ_ATTRIB_response_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_read_attributes, BER_CLASS_APP, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Read_Attributes },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_READ_ATTRIB_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_READ_ATTRIB_response_sequence, hf_index, ett_ftam_F_READ_ATTRIB_response);

  return offset;
}


static const ber_sequence_t T_actual_values1_sequence[] = {
  { &hf_ftam_insert_values  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_SET_OF_Access_Control_Element },
  { &hf_ftam_delete_values  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_SET_OF_Access_Control_Element },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_T_actual_values1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_actual_values1_sequence, hf_index, ett_ftam_T_actual_values1);

  return offset;
}


static const value_string ftam_Access_Control_Change_Attribute_vals[] = {
  {   0, "no-value-available" },
  {   1, "actual-values" },
  { 0, NULL }
};

static const ber_choice_t Access_Control_Change_Attribute_choice[] = {
  {   0, &hf_ftam_no_value_available, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_NULL },
  {   1, &hf_ftam_actual_values1 , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_T_actual_values1 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Access_Control_Change_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Access_Control_Change_Attribute_choice, hf_index, ett_ftam_Access_Control_Change_Attribute,
                                 NULL);

  return offset;
}


static const ber_sequence_t Change_Attributes_U_sequence[] = {
  { &hf_ftam_pathname       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ftam_Pathname_Attribute },
  { &hf_ftam_storage_account, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Account_Attribute },
  { &hf_ftam_object_availability, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Object_Availability_Attribute },
  { &hf_ftam_future_Object_size, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Object_Size_Attribute },
  { &hf_ftam_change_attributes_access_control, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Access_Control_Change_Attribute },
  { &hf_ftam_change_path_access_control, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Access_Control_Change_Attribute },
  { &hf_ftam_legal_qualification, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Legal_Qualification_Attribute },
  { &hf_ftam_private_use    , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Private_Use_Attribute },
  { &hf_ftam_attribute_extensions, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_Attribute_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Change_Attributes_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Change_Attributes_U_sequence, hf_index, ett_ftam_Change_Attributes_U);

  return offset;
}



static int
dissect_ftam_Change_Attributes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 8, true, dissect_ftam_Change_Attributes_U);

  return offset;
}


static const ber_sequence_t F_CHANGE_ATTRIB_request_sequence[] = {
  { &hf_ftam_attributes     , BER_CLASS_APP, 8, BER_FLAGS_NOOWNTAG, dissect_ftam_Change_Attributes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_CHANGE_ATTRIB_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_CHANGE_ATTRIB_request_sequence, hf_index, ett_ftam_F_CHANGE_ATTRIB_request);

  return offset;
}


static const ber_sequence_t F_CHANGE_ATTRIB_response_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_attributes     , BER_CLASS_APP, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Change_Attributes },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_CHANGE_ATTRIB_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_CHANGE_ATTRIB_response_sequence, hf_index, ett_ftam_F_CHANGE_ATTRIB_response);

  return offset;
}


static int * const T_processing_mode_bits[] = {
  &hf_ftam_T_processing_mode_f_read,
  &hf_ftam_T_processing_mode_f_insert,
  &hf_ftam_T_processing_mode_f_replace,
  &hf_ftam_T_processing_mode_f_extend,
  &hf_ftam_T_processing_mode_f_erase,
  NULL
};

static int
dissect_ftam_T_processing_mode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_processing_mode_bits, 5, hf_index, ett_ftam_T_processing_mode,
                                    NULL);

  return offset;
}


static const value_string ftam_T_open_contents_type_vals[] = {
  {   0, "unknown" },
  {   1, "proposed" },
  { 0, NULL }
};

static const ber_choice_t T_open_contents_type_choice[] = {
  {   0, &hf_ftam_unknown        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_NULL },
  {   1, &hf_ftam_proposed       , BER_CLASS_CON, 1, 0, dissect_ftam_Contents_Type_Attribute },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_T_open_contents_type(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_open_contents_type_choice, hf_index, ett_ftam_T_open_contents_type,
                                 NULL);

  return offset;
}



static int
dissect_ftam_Activity_Identifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 6, true, dissect_ftam_INTEGER);

  return offset;
}


static const value_string ftam_T_request_recovery_mode_vals[] = {
  {   0, "none" },
  {   1, "at-start-of-file" },
  {   2, "at-any-active-Checkpoint" },
  { 0, NULL }
};


static int
dissect_ftam_T_request_recovery_mode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SET_OF_Abstract_Syntax_Name_set_of[1] = {
  { &hf_ftam_remove_contexts_item, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_ftam_Abstract_Syntax_Name },
};

static int
dissect_ftam_SET_OF_Abstract_Syntax_Name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_Abstract_Syntax_Name_set_of, hf_index, ett_ftam_SET_OF_Abstract_Syntax_Name);

  return offset;
}


static const value_string ftam_Degree_Of_Overlap_U_vals[] = {
  {   0, "normal" },
  {   1, "consecutive" },
  {   2, "concurrent" },
  { 0, NULL }
};


static int
dissect_ftam_Degree_Of_Overlap_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ftam_Degree_Of_Overlap(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 30, true, dissect_ftam_Degree_Of_Overlap_U);

  return offset;
}


static const ber_sequence_t F_OPEN_request_sequence[] = {
  { &hf_ftam_processing_mode, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_T_processing_mode },
  { &hf_ftam_open_contents_type, BER_CLASS_CON, 1, 0, dissect_ftam_T_open_contents_type },
  { &hf_ftam_concurrency_control, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Concurrency_Control },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_enable_fadu_locking, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_BOOLEAN },
  { &hf_ftam_activity_identifier, BER_CLASS_APP, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Activity_Identifier },
  { &hf_ftam_request_recovery_mode, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_T_request_recovery_mode },
  { &hf_ftam_remove_contexts, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_SET_OF_Abstract_Syntax_Name },
  { &hf_ftam_define_contexts, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_SET_OF_Abstract_Syntax_Name },
  { &hf_ftam_degree_of_overlap, BER_CLASS_APP, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Degree_Of_Overlap },
  { &hf_ftam_transfer_window, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_OPEN_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_OPEN_request_sequence, hf_index, ett_ftam_F_OPEN_request);

  return offset;
}


static const value_string ftam_T_response_recovery_mode_vals[] = {
  {   0, "none" },
  {   1, "at-start-of-file" },
  {   2, "at-any-active-Checkpoint" },
  { 0, NULL }
};


static int
dissect_ftam_T_response_recovery_mode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t F_OPEN_response_sequence[] = {
  { &hf_ftam_state_result   , BER_CLASS_APP, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_State_Result },
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_contents_type  , BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_ftam_Contents_Type_Attribute },
  { &hf_ftam_concurrency_control, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Concurrency_Control },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { &hf_ftam_response_recovery_mode, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_T_response_recovery_mode },
  { &hf_ftam_presentation_action, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_BOOLEAN },
  { &hf_ftam_degree_of_overlap, BER_CLASS_APP, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Degree_Of_Overlap },
  { &hf_ftam_transfer_window, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_OPEN_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_OPEN_response_sequence, hf_index, ett_ftam_F_OPEN_response);

  return offset;
}


static const ber_sequence_t F_CLOSE_request_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_CLOSE_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_CLOSE_request_sequence, hf_index, ett_ftam_F_CLOSE_request);

  return offset;
}


static const ber_sequence_t F_CLOSE_response_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_CLOSE_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_CLOSE_response_sequence, hf_index, ett_ftam_F_CLOSE_response);

  return offset;
}


static const ber_sequence_t F_BEGIN_GROUP_request_sequence[] = {
  { &hf_ftam_threshold      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_BEGIN_GROUP_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_BEGIN_GROUP_request_sequence, hf_index, ett_ftam_F_BEGIN_GROUP_request);

  return offset;
}


static const ber_sequence_t F_BEGIN_GROUP_response_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_BEGIN_GROUP_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_BEGIN_GROUP_response_sequence, hf_index, ett_ftam_F_BEGIN_GROUP_response);

  return offset;
}


static const ber_sequence_t F_END_GROUP_request_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_END_GROUP_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_END_GROUP_request_sequence, hf_index, ett_ftam_F_END_GROUP_request);

  return offset;
}


static const ber_sequence_t F_END_GROUP_response_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_END_GROUP_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_END_GROUP_response_sequence, hf_index, ett_ftam_F_END_GROUP_response);

  return offset;
}


static const ber_sequence_t F_RECOVER_request_sequence[] = {
  { &hf_ftam_activity_identifier, BER_CLASS_APP, 6, BER_FLAGS_NOOWNTAG, dissect_ftam_Activity_Identifier },
  { &hf_ftam_bulk_transfer_number, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_requested_access, BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_ftam_Access_Request },
  { &hf_ftam_access_passwords, BER_CLASS_APP, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Access_Passwords },
  { &hf_ftam_recovefy_Point , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_remove_contexts, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_SET_OF_Abstract_Syntax_Name },
  { &hf_ftam_define_contexts, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_SET_OF_Abstract_Syntax_Name },
  { &hf_ftam_concurrent_bulk_transfer_number, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_concurrent_recovery_point, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_last_transfer_end_read_response, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_last_transfer_end_write_response, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_RECOVER_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_RECOVER_request_sequence, hf_index, ett_ftam_F_RECOVER_request);

  return offset;
}


static const ber_sequence_t F_RECOVER_response_sequence[] = {
  { &hf_ftam_state_result   , BER_CLASS_APP, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_State_Result },
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_contents_type  , BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_ftam_Contents_Type_Attribute },
  { &hf_ftam_recovety_Point , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { &hf_ftam_presentation_action, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_BOOLEAN },
  { &hf_ftam_concurrent_recovery_point, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_last_transfer_end_read_request, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_last_transfer_end_write_request, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_RECOVER_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_RECOVER_response_sequence, hf_index, ett_ftam_F_RECOVER_response);

  return offset;
}


static const value_string ftam_T_first_last_vals[] = {
  {   0, "first" },
  {   1, "last" },
  { 0, NULL }
};


static int
dissect_ftam_T_first_last(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string ftam_T_relative_vals[] = {
  {   0, "previous" },
  {   1, "current" },
  {   2, "next" },
  { 0, NULL }
};


static int
dissect_ftam_T_relative(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string ftam_T_begin_end_vals[] = {
  {   0, "begin" },
  {   1, "end" },
  { 0, NULL }
};


static int
dissect_ftam_T_begin_end(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ftam_Node_Name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_external_type(implicit_tag, tree, tvb, offset, actx, hf_index, NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Node_Name_sequence_of[1] = {
  { &hf_ftam_name_list_item , BER_CLASS_UNI, BER_UNI_TAG_EXTERNAL, BER_FLAGS_NOOWNTAG, dissect_ftam_Node_Name },
};

static int
dissect_ftam_SEQUENCE_OF_Node_Name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Node_Name_sequence_of, hf_index, ett_ftam_SEQUENCE_OF_Node_Name);

  return offset;
}


static const value_string ftam_FADU_Identity_U_vals[] = {
  {   0, "first-last" },
  {   1, "relative" },
  {   2, "begin-end" },
  {   3, "single-name" },
  {   4, "name-list" },
  {   5, "fadu-number" },
  { 0, NULL }
};

static const ber_choice_t FADU_Identity_U_choice[] = {
  {   0, &hf_ftam_first_last     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_T_first_last },
  {   1, &hf_ftam_relative       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_T_relative },
  {   2, &hf_ftam_begin_end      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ftam_T_begin_end },
  {   3, &hf_ftam_single_name    , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ftam_Node_Name },
  {   4, &hf_ftam_name_list      , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_ftam_SEQUENCE_OF_Node_Name },
  {   5, &hf_ftam_fadu_number    , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_FADU_Identity_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 FADU_Identity_U_choice, hf_index, ett_ftam_FADU_Identity_U,
                                 NULL);

  return offset;
}



static int
dissect_ftam_FADU_Identity(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 15, false, dissect_ftam_FADU_Identity_U);

  return offset;
}


static const value_string ftam_FADU_Lock_U_vals[] = {
  {   0, "off" },
  {   1, "on" },
  { 0, NULL }
};


static int
dissect_ftam_FADU_Lock_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ftam_FADU_Lock(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 16, true, dissect_ftam_FADU_Lock_U);

  return offset;
}


static const ber_sequence_t F_LOCATE_request_sequence[] = {
  { &hf_ftam_file_access_data_unit_identity, BER_CLASS_APP, 15, BER_FLAGS_NOOWNTAG, dissect_ftam_FADU_Identity },
  { &hf_ftam_fadu_lock      , BER_CLASS_APP, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_FADU_Lock },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_LOCATE_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_LOCATE_request_sequence, hf_index, ett_ftam_F_LOCATE_request);

  return offset;
}


static const ber_sequence_t F_LOCATE_response_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_file_access_data_unit_identity, BER_CLASS_APP, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_FADU_Identity },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_LOCATE_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_LOCATE_response_sequence, hf_index, ett_ftam_F_LOCATE_response);

  return offset;
}


static const ber_sequence_t F_ERASE_request_sequence[] = {
  { &hf_ftam_file_access_data_unit_identity, BER_CLASS_APP, 15, BER_FLAGS_NOOWNTAG, dissect_ftam_FADU_Identity },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_ERASE_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_ERASE_request_sequence, hf_index, ett_ftam_F_ERASE_request);

  return offset;
}


static const ber_sequence_t F_ERASE_response_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_ERASE_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_ERASE_response_sequence, hf_index, ett_ftam_F_ERASE_response);

  return offset;
}


static const value_string ftam_File_PDU_vals[] = {
  {   6, "f-select-request" },
  {   7, "f-select-response" },
  {   8, "f-deselect-request" },
  {   9, "f-deselect-response" },
  {  10, "f-create-request" },
  {  11, "f-create-response" },
  {  12, "f-delete-request" },
  {  13, "f-delete-response" },
  {  14, "f-read-attrib-request" },
  {  15, "f-read-attrib-response" },
  {  16, "f-Change-attrib-reques" },
  {  17, "f-Change-attrib-respon" },
  {  18, "f-open-request" },
  {  19, "f-open-response" },
  {  20, "f-close-request" },
  {  21, "f-close-response" },
  {  22, "f-begin-group-request" },
  {  23, "f-begin-group-response" },
  {  24, "f-end-group-request" },
  {  25, "f-end-group-response" },
  {  26, "f-recover-request" },
  {  27, "f-recover-response" },
  {  28, "f-locate-request" },
  {  29, "f-locate-response" },
  {  30, "f-erase-request" },
  {  31, "f-erase-response" },
  { 0, NULL }
};

static const ber_choice_t File_PDU_choice[] = {
  {   6, &hf_ftam_f_select_request, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_ftam_F_SELECT_request },
  {   7, &hf_ftam_f_select_response, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_ftam_F_SELECT_response },
  {   8, &hf_ftam_f_deselect_request, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_ftam_F_DESELECT_request },
  {   9, &hf_ftam_f_deselect_response, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_ftam_F_DESELECT_response },
  {  10, &hf_ftam_f_create_request, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_ftam_F_CREATE_request },
  {  11, &hf_ftam_f_create_response, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_ftam_F_CREATE_response },
  {  12, &hf_ftam_f_delete_request, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_ftam_F_DELETE_request },
  {  13, &hf_ftam_f_delete_response, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_ftam_F_DELETE_response },
  {  14, &hf_ftam_f_read_attrib_request, BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_ftam_F_READ_ATTRIB_request },
  {  15, &hf_ftam_f_read_attrib_response, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_ftam_F_READ_ATTRIB_response },
  {  16, &hf_ftam_f_Change_attrib_reques, BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_ftam_F_CHANGE_ATTRIB_request },
  {  17, &hf_ftam_f_Change_attrib_respon, BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_ftam_F_CHANGE_ATTRIB_response },
  {  18, &hf_ftam_f_open_request , BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_ftam_F_OPEN_request },
  {  19, &hf_ftam_f_open_response, BER_CLASS_CON, 19, BER_FLAGS_IMPLTAG, dissect_ftam_F_OPEN_response },
  {  20, &hf_ftam_f_close_request, BER_CLASS_CON, 20, BER_FLAGS_IMPLTAG, dissect_ftam_F_CLOSE_request },
  {  21, &hf_ftam_f_close_response, BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_ftam_F_CLOSE_response },
  {  22, &hf_ftam_f_begin_group_request, BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_ftam_F_BEGIN_GROUP_request },
  {  23, &hf_ftam_f_begin_group_response, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_ftam_F_BEGIN_GROUP_response },
  {  24, &hf_ftam_f_end_group_request, BER_CLASS_CON, 24, BER_FLAGS_IMPLTAG, dissect_ftam_F_END_GROUP_request },
  {  25, &hf_ftam_f_end_group_response, BER_CLASS_CON, 25, BER_FLAGS_IMPLTAG, dissect_ftam_F_END_GROUP_response },
  {  26, &hf_ftam_f_recover_request, BER_CLASS_CON, 26, BER_FLAGS_IMPLTAG, dissect_ftam_F_RECOVER_request },
  {  27, &hf_ftam_f_recover_response, BER_CLASS_CON, 27, BER_FLAGS_IMPLTAG, dissect_ftam_F_RECOVER_response },
  {  28, &hf_ftam_f_locate_request, BER_CLASS_CON, 28, BER_FLAGS_IMPLTAG, dissect_ftam_F_LOCATE_request },
  {  29, &hf_ftam_f_locate_response, BER_CLASS_CON, 29, BER_FLAGS_IMPLTAG, dissect_ftam_F_LOCATE_response },
  {  30, &hf_ftam_f_erase_request, BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_ftam_F_ERASE_request },
  {  31, &hf_ftam_f_erase_response, BER_CLASS_CON, 31, BER_FLAGS_IMPLTAG, dissect_ftam_F_ERASE_response },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_File_PDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int branch_taken;

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 File_PDU_choice, hf_index, ett_ftam_File_PDU,
                                 &branch_taken);


  if( (branch_taken!=-1) && ftam_File_PDU_vals[branch_taken].strptr ){
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s:", ftam_File_PDU_vals[branch_taken].strptr);
  }


  return offset;
}


static const value_string ftam_T_access_context_vals[] = {
  {   0, "hierarchical-all-data-units" },
  {   1, "hierarchical-no-data-units" },
  {   2, "flat-all-data-units" },
  {   3, "flat-one-level-data-unit" },
  {   4, "flat-Single-data-unit" },
  {   5, "unstructured-all-data-units" },
  {   6, "unstructured-Single-data-unit" },
  { 0, NULL }
};


static int
dissect_ftam_T_access_context(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t Access_Context_U_sequence[] = {
  { &hf_ftam_access_context , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_T_access_context },
  { &hf_ftam_level_number   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Access_Context_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Access_Context_U_sequence, hf_index, ett_ftam_Access_Context_U);

  return offset;
}



static int
dissect_ftam_Access_Context(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 1, true, dissect_ftam_Access_Context_U);

  return offset;
}


static const ber_sequence_t F_READ_request_sequence[] = {
  { &hf_ftam_file_access_data_unit_identity, BER_CLASS_APP, 15, BER_FLAGS_NOOWNTAG, dissect_ftam_FADU_Identity },
  { &hf_ftam_read_access_context, BER_CLASS_APP, 1, BER_FLAGS_NOOWNTAG, dissect_ftam_Access_Context },
  { &hf_ftam_fadu_lock      , BER_CLASS_APP, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_FADU_Lock },
  { &hf_ftam_transfer_number, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_READ_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_READ_request_sequence, hf_index, ett_ftam_F_READ_request);

  return offset;
}


static const value_string ftam_T_file_access_data_unit_Operation_vals[] = {
  {   0, "insert" },
  {   1, "replace" },
  {   2, "extend" },
  { 0, NULL }
};


static int
dissect_ftam_T_file_access_data_unit_Operation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t F_WRITE_request_sequence[] = {
  { &hf_ftam_file_access_data_unit_Operation, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_T_file_access_data_unit_Operation },
  { &hf_ftam_file_access_data_unit_identity, BER_CLASS_APP, 15, BER_FLAGS_NOOWNTAG, dissect_ftam_FADU_Identity },
  { &hf_ftam_fadu_lock      , BER_CLASS_APP, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_FADU_Lock },
  { &hf_ftam_transfer_number, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_WRITE_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_WRITE_request_sequence, hf_index, ett_ftam_F_WRITE_request);

  return offset;
}


static const ber_sequence_t F_DATA_END_request_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_DATA_END_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_DATA_END_request_sequence, hf_index, ett_ftam_F_DATA_END_request);

  return offset;
}


static const value_string ftam_Request_Type_U_vals[] = {
  {   0, "read" },
  {   1, "write" },
  { 0, NULL }
};


static int
dissect_ftam_Request_Type_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ftam_Request_Type(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 31, true, dissect_ftam_Request_Type_U);

  return offset;
}


static const ber_sequence_t F_TRANSFER_END_request_sequence[] = {
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_request_type   , BER_CLASS_APP, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Request_Type },
  { &hf_ftam_transfer_number, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_last_transfer_end_read_response, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_last_transfer_end_write_response, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_TRANSFER_END_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_TRANSFER_END_request_sequence, hf_index, ett_ftam_F_TRANSFER_END_request);

  return offset;
}


static const ber_sequence_t F_TRANSFER_END_response_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { &hf_ftam_request_type   , BER_CLASS_APP, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Request_Type },
  { &hf_ftam_transfer_number, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_TRANSFER_END_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_TRANSFER_END_response_sequence, hf_index, ett_ftam_F_TRANSFER_END_response);

  return offset;
}


static const ber_sequence_t F_CANCEL_request_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { &hf_ftam_request_type   , BER_CLASS_APP, 31, BER_FLAGS_NOOWNTAG, dissect_ftam_Request_Type },
  { &hf_ftam_transfer_number, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_last_transfer_end_read_request, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_last_transfer_end_read_response, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_last_transfer_end_write_request, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_last_transfer_end_write_response, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_CANCEL_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_CANCEL_request_sequence, hf_index, ett_ftam_F_CANCEL_request);

  return offset;
}


static const ber_sequence_t F_CANCEL_response_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { &hf_ftam_request_type   , BER_CLASS_APP, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Request_Type },
  { &hf_ftam_transfer_number, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_last_transfer_end_read_request, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_last_transfer_end_read_response, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_last_transfer_end_write_request, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_last_transfer_end_write_response, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_CANCEL_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_CANCEL_response_sequence, hf_index, ett_ftam_F_CANCEL_response);

  return offset;
}


static const ber_sequence_t F_RESTART_request_sequence[] = {
  { &hf_ftam_checkpoint_identifier, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_request_type   , BER_CLASS_APP, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Request_Type },
  { &hf_ftam_transfer_number, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_last_transfer_end_read_request, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_last_transfer_end_read_response, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_last_transfer_end_write_request, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_last_transfer_end_write_response, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_RESTART_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_RESTART_request_sequence, hf_index, ett_ftam_F_RESTART_request);

  return offset;
}


static const ber_sequence_t F_RESTART_response_sequence[] = {
  { &hf_ftam_checkpoint_identifier, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_request_type   , BER_CLASS_APP, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Request_Type },
  { &hf_ftam_transfer_number, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_last_transfer_end_read_request, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_last_transfer_end_read_response, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_last_transfer_end_write_request, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_last_transfer_end_write_response, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_RESTART_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_RESTART_response_sequence, hf_index, ett_ftam_F_RESTART_response);

  return offset;
}


static const value_string ftam_Bulk_Data_PDU_vals[] = {
  {  32, "f-read-request" },
  {  33, "f-write-request" },
  {  34, "f-data-end-request" },
  {  35, "f-transfer-end-request" },
  {  36, "f-transfer-end-response" },
  {  37, "f-cancel-request" },
  {  38, "f-cancel-response" },
  {  39, "f-restart-request" },
  {  40, "f-restart-response" },
  { 0, NULL }
};

static const ber_choice_t Bulk_Data_PDU_choice[] = {
  {  32, &hf_ftam_f_read_request , BER_CLASS_CON, 32, BER_FLAGS_IMPLTAG, dissect_ftam_F_READ_request },
  {  33, &hf_ftam_f_write_request, BER_CLASS_CON, 33, BER_FLAGS_IMPLTAG, dissect_ftam_F_WRITE_request },
  {  34, &hf_ftam_f_data_end_request, BER_CLASS_CON, 34, BER_FLAGS_IMPLTAG, dissect_ftam_F_DATA_END_request },
  {  35, &hf_ftam_f_transfer_end_request, BER_CLASS_CON, 35, BER_FLAGS_IMPLTAG, dissect_ftam_F_TRANSFER_END_request },
  {  36, &hf_ftam_f_transfer_end_response, BER_CLASS_CON, 36, BER_FLAGS_IMPLTAG, dissect_ftam_F_TRANSFER_END_response },
  {  37, &hf_ftam_f_cancel_request, BER_CLASS_CON, 37, BER_FLAGS_IMPLTAG, dissect_ftam_F_CANCEL_request },
  {  38, &hf_ftam_f_cancel_response, BER_CLASS_CON, 38, BER_FLAGS_IMPLTAG, dissect_ftam_F_CANCEL_response },
  {  39, &hf_ftam_f_restart_request, BER_CLASS_CON, 39, BER_FLAGS_IMPLTAG, dissect_ftam_F_RESTART_request },
  {  40, &hf_ftam_f_restart_response, BER_CLASS_CON, 40, BER_FLAGS_IMPLTAG, dissect_ftam_F_RESTART_response },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Bulk_Data_PDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int branch_taken;

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Bulk_Data_PDU_choice, hf_index, ett_ftam_Bulk_Data_PDU,
                                 &branch_taken);


  if( (branch_taken!=-1) && ftam_Bulk_Data_PDU_vals[branch_taken].strptr ){
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s:", ftam_Bulk_Data_PDU_vals[branch_taken].strptr);
  }


  return offset;
}



static int
dissect_ftam_Destination_File_Directory(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 24, false, dissect_ftam_Pathname_Attribute);

  return offset;
}


static const ber_sequence_t F_CHANGE_PREFIX_request_sequence[] = {
  { &hf_ftam_reset          , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_BOOLEAN },
  { &hf_ftam_destination_file_directory, BER_CLASS_APP, 24, BER_FLAGS_NOOWNTAG, dissect_ftam_Destination_File_Directory },
  { &hf_ftam_access_passwords, BER_CLASS_APP, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Access_Passwords },
  { &hf_ftam_path_access_passwords, BER_CLASS_APP, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Path_Access_Passwords },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_CHANGE_PREFIX_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_CHANGE_PREFIX_request_sequence, hf_index, ett_ftam_F_CHANGE_PREFIX_request);

  return offset;
}


static const ber_sequence_t F_CHANGE_PREFIX_response_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_destination_file_directory, BER_CLASS_APP, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Destination_File_Directory },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_CHANGE_PREFIX_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_CHANGE_PREFIX_response_sequence, hf_index, ett_ftam_F_CHANGE_PREFIX_response);

  return offset;
}


static int * const Equality_Comparision_bits[] = {
  &hf_ftam_Equality_Comparision_no_value_available_matches,
  &hf_ftam_Equality_Comparision_equals_matches,
  NULL
};

static int
dissect_ftam_Equality_Comparision(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Equality_Comparision_bits, 2, hf_index, ett_ftam_Equality_Comparision,
                                    NULL);

  return offset;
}


static const value_string ftam_T_string_value_item_vals[] = {
  {   2, "substring-match" },
  {   3, "any-match" },
  {   4, "number-of-characters-match" },
  { 0, NULL }
};

static const ber_choice_t T_string_value_item_choice[] = {
  {   2, &hf_ftam_substring_match, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ftam_GraphicString },
  {   3, &hf_ftam_any_match      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ftam_NULL },
  {   4, &hf_ftam_number_of_characters_match, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_T_string_value_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_string_value_item_choice, hf_index, ett_ftam_T_string_value_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_string_value_sequence_of[1] = {
  { &hf_ftam_string_value_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ftam_T_string_value_item },
};

static int
dissect_ftam_T_string_value(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_string_value_sequence_of, hf_index, ett_ftam_T_string_value);

  return offset;
}


static const ber_sequence_t String_Pattern_sequence[] = {
  { &hf_ftam_equality_comparision, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_Equality_Comparision },
  { &hf_ftam_string_value   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_T_string_value },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_String_Pattern(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   String_Pattern_sequence, hf_index, ett_ftam_String_Pattern);

  return offset;
}


static const value_string ftam_T_pathname_value_item_vals[] = {
  {   2, "string-match" },
  {   3, "any-match" },
  { 0, NULL }
};

static const ber_choice_t T_pathname_value_item_choice[] = {
  {   2, &hf_ftam_string_match   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ftam_String_Pattern },
  {   3, &hf_ftam_any_match      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ftam_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_T_pathname_value_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_pathname_value_item_choice, hf_index, ett_ftam_T_pathname_value_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_pathname_value_sequence_of[1] = {
  { &hf_ftam_pathname_value_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ftam_T_pathname_value_item },
};

static int
dissect_ftam_T_pathname_value(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_pathname_value_sequence_of, hf_index, ett_ftam_T_pathname_value);

  return offset;
}


static const ber_sequence_t Pathname_Pattern_sequence[] = {
  { &hf_ftam_equality_comparision, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_Equality_Comparision },
  { &hf_ftam_pathname_value , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_T_pathname_value },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Pathname_Pattern(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Pathname_Pattern_sequence, hf_index, ett_ftam_Pathname_Pattern);

  return offset;
}


static int * const Relational_Comparision_bits[] = {
  &hf_ftam_Relational_Comparision_no_value_available_matches,
  &hf_ftam_Relational_Comparision_equals_matches,
  &hf_ftam_Relational_Comparision_less_than_matches,
  &hf_ftam_Relational_Comparision_greater_than_matches,
  NULL
};

static int
dissect_ftam_Relational_Comparision(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Relational_Comparision_bits, 4, hf_index, ett_ftam_Relational_Comparision,
                                    NULL);

  return offset;
}


static const ber_sequence_t Integer_Pattern_sequence[] = {
  { &hf_ftam_relational_comparision, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_Relational_Comparision },
  { &hf_ftam_integer_value  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Integer_Pattern(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Integer_Pattern_sequence, hf_index, ett_ftam_Integer_Pattern);

  return offset;
}



static int
dissect_ftam_BIT_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t Bitstring_Pattern_sequence[] = {
  { &hf_ftam_equality_comparision, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_Equality_Comparision },
  { &hf_ftam_match_bitstring, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_BIT_STRING },
  { &hf_ftam_significance_bitstring, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ftam_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Bitstring_Pattern(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Bitstring_Pattern_sequence, hf_index, ett_ftam_Bitstring_Pattern);

  return offset;
}


static const ber_sequence_t Object_Identifier_Pattern_sequence[] = {
  { &hf_ftam_equality_comparision, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_Equality_Comparision },
  { &hf_ftam_object_identifier_value, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_OBJECT_IDENTIFIER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Object_Identifier_Pattern(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Object_Identifier_Pattern_sequence, hf_index, ett_ftam_Object_Identifier_Pattern);

  return offset;
}


static const ber_sequence_t T_constraint_set_abstract_Syntax_Pattern_sequence[] = {
  { &hf_ftam_constraint_Set_Pattern, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_Object_Identifier_Pattern },
  { &hf_ftam_abstract_Syntax_Pattern, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_Object_Identifier_Pattern },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_T_constraint_set_abstract_Syntax_Pattern(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_constraint_set_abstract_Syntax_Pattern_sequence, hf_index, ett_ftam_T_constraint_set_abstract_Syntax_Pattern);

  return offset;
}


static const value_string ftam_Contents_Type_Pattern_vals[] = {
  {   0, "document-type-Pattern" },
  {   1, "constraint-set-abstract-Syntax-Pattern" },
  { 0, NULL }
};

static const ber_choice_t Contents_Type_Pattern_choice[] = {
  {   0, &hf_ftam_document_type_Pattern, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_Object_Identifier_Pattern },
  {   1, &hf_ftam_constraint_set_abstract_Syntax_Pattern, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_T_constraint_set_abstract_Syntax_Pattern },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Contents_Type_Pattern(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Contents_Type_Pattern_choice, hf_index, ett_ftam_Contents_Type_Pattern,
                                 NULL);

  return offset;
}


static const ber_sequence_t Date_and_Time_Pattern_sequence[] = {
  { &hf_ftam_relational_camparision, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_Equality_Comparision },
  { &hf_ftam_time_and_date_value, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_GeneralizedTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Date_and_Time_Pattern(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Date_and_Time_Pattern_sequence, hf_index, ett_ftam_Date_and_Time_Pattern);

  return offset;
}



static int
dissect_ftam_User_Identity_Pattern(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ftam_String_Pattern(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t Boolean_Pattern_sequence[] = {
  { &hf_ftam_equality_comparision, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_Equality_Comparision },
  { &hf_ftam_boolean_value  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Boolean_Pattern(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Boolean_Pattern_sequence, hf_index, ett_ftam_Boolean_Pattern);

  return offset;
}



static int
dissect_ftam_T_attribute_extension_attribute_identifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &actx->external.direct_reference);

  return offset;
}



static int
dissect_ftam_T_extension_attribute_Pattern(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  if (actx->external.direct_reference) {
    offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);
  }


  return offset;
}


static const ber_sequence_t T_extension_set_attribute_Patterns_item_sequence[] = {
  { &hf_ftam_attribute_extension_attribute_identifier, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_ftam_T_attribute_extension_attribute_identifier },
  { &hf_ftam_extension_attribute_Pattern, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_ftam_T_extension_attribute_Pattern },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_T_extension_set_attribute_Patterns_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_extension_set_attribute_Patterns_item_sequence, hf_index, ett_ftam_T_extension_set_attribute_Patterns_item);

  return offset;
}


static const ber_sequence_t T_extension_set_attribute_Patterns_sequence_of[1] = {
  { &hf_ftam_extension_set_attribute_Patterns_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ftam_T_extension_set_attribute_Patterns_item },
};

static int
dissect_ftam_T_extension_set_attribute_Patterns(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_extension_set_attribute_Patterns_sequence_of, hf_index, ett_ftam_T_extension_set_attribute_Patterns);

  return offset;
}


static const ber_sequence_t Attribute_Extensions_Pattern_item_sequence[] = {
  { &hf_ftam_extension_set_identifier, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_Extension_Set_Identifier },
  { &hf_ftam_extension_set_attribute_Patterns, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_T_extension_set_attribute_Patterns },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Attribute_Extensions_Pattern_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Attribute_Extensions_Pattern_item_sequence, hf_index, ett_ftam_Attribute_Extensions_Pattern_item);

  return offset;
}


static const ber_sequence_t Attribute_Extensions_Pattern_sequence_of[1] = {
  { &hf_ftam_Attribute_Extensions_Pattern_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ftam_Attribute_Extensions_Pattern_item },
};

static int
dissect_ftam_Attribute_Extensions_Pattern(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Attribute_Extensions_Pattern_sequence_of, hf_index, ett_ftam_Attribute_Extensions_Pattern);

  return offset;
}


static const value_string ftam_AND_Set_item_vals[] = {
  {   0, "pathname-Pattern" },
  {  18, "object-type-Pattern" },
  {   1, "permitted-actions-Pattern" },
  {   2, "contents-type-Pattern" },
  {  19, "linked-Object-Pattern" },
  {  23, "child-objects-Pattern" },
  {  20, "primaty-pathname-Pattern" },
  {   3, "storage-account-Pattern" },
  {   4, "date-and-time-of-creation-Pattern" },
  {   5, "date-and-time-of-last-modification-Pattern" },
  {   6, "date-and-time-of-last-read-access-Pattern" },
  {   7, "date-and-time-of-last-attribute-modification-Pattern" },
  {   8, "identity-of-creator-Pattern" },
  {   9, "identity-of-last-modifier-Pattern" },
  {  10, "identity-of-last-reader-Pattern" },
  {  11, "identity-of-last-attribute-modifier-Pattern" },
  {  12, "object-availabiiity-Pattern" },
  {  13, "object-size-Pattern" },
  {  14, "future-object-size-Pattern" },
  {  16, "legal-quailfication-Pattern" },
  {  22, "attribute-extensions-pattern" },
  { 0, NULL }
};

static const ber_choice_t AND_Set_item_choice[] = {
  {   0, &hf_ftam_pathname_Pattern, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_Pathname_Pattern },
  {  18, &hf_ftam_object_type_Pattern, BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_ftam_Integer_Pattern },
  {   1, &hf_ftam_permitted_actions_Pattern, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_Bitstring_Pattern },
  {   2, &hf_ftam_contents_type_Pattern, BER_CLASS_CON, 2, 0, dissect_ftam_Contents_Type_Pattern },
  {  19, &hf_ftam_linked_Object_Pattern, BER_CLASS_CON, 19, BER_FLAGS_IMPLTAG, dissect_ftam_Pathname_Pattern },
  {  23, &hf_ftam_child_objects_Pattern, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_ftam_Pathname_Pattern },
  {  20, &hf_ftam_primaty_pathname_Pattern, BER_CLASS_CON, 20, BER_FLAGS_IMPLTAG, dissect_ftam_Pathname_Pattern },
  {   3, &hf_ftam_storage_account_Pattern, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ftam_String_Pattern },
  {   4, &hf_ftam_date_and_time_of_creation_Pattern, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_ftam_Date_and_Time_Pattern },
  {   5, &hf_ftam_date_and_time_of_last_modification_Pattern, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_ftam_Date_and_Time_Pattern },
  {   6, &hf_ftam_date_and_time_of_last_read_access_Pattern, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_ftam_Date_and_Time_Pattern },
  {   7, &hf_ftam_date_and_time_of_last_attribute_modification_Pattern, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_ftam_Date_and_Time_Pattern },
  {   8, &hf_ftam_identity_of_creator_Pattern, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_ftam_User_Identity_Pattern },
  {   9, &hf_ftam_identity_of_last_modifier_Pattern, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_ftam_User_Identity_Pattern },
  {  10, &hf_ftam_identity_of_last_reader_Pattern, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_ftam_User_Identity_Pattern },
  {  11, &hf_ftam_identity_of_last_attribute_modifier_Pattern, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_ftam_User_Identity_Pattern },
  {  12, &hf_ftam_object_availabiiity_Pattern, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_ftam_Boolean_Pattern },
  {  13, &hf_ftam_object_size_Pattern, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_ftam_Integer_Pattern },
  {  14, &hf_ftam_future_object_size_Pattern, BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_ftam_Integer_Pattern },
  {  16, &hf_ftam_legal_quailfication_Pattern, BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_ftam_String_Pattern },
  {  22, &hf_ftam_attribute_extensions_pattern, BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_ftam_Attribute_Extensions_Pattern },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_AND_Set_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AND_Set_item_choice, hf_index, ett_ftam_AND_Set_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t AND_Set_sequence_of[1] = {
  { &hf_ftam_AND_Set_item   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ftam_AND_Set_item },
};

static int
dissect_ftam_AND_Set(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      AND_Set_sequence_of, hf_index, ett_ftam_AND_Set);

  return offset;
}


static const ber_sequence_t OR_Set_sequence_of[1] = {
  { &hf_ftam_OR_Set_item    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ftam_AND_Set },
};

static int
dissect_ftam_OR_Set(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      OR_Set_sequence_of, hf_index, ett_ftam_OR_Set);

  return offset;
}



static int
dissect_ftam_Attribute_Value_Assertions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 26, true, dissect_ftam_OR_Set);

  return offset;
}


static const value_string ftam_T_retrieval_scope_vals[] = {
  {   0, "child" },
  {   1, "all" },
  { 0, NULL }
};


static int
dissect_ftam_T_retrieval_scope(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T__untag_item_sequence[] = {
  { &hf_ftam_root_directory , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ftam_Pathname_Attribute },
  { &hf_ftam_retrieval_scope, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_T_retrieval_scope },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_T__untag_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T__untag_item_sequence, hf_index, ett_ftam_T__untag_item);

  return offset;
}


static const ber_sequence_t Scope_U_sequence_of[1] = {
  { &hf_ftam__untag_item_03 , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ftam_T__untag_item },
};

static int
dissect_ftam_Scope_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Scope_U_sequence_of, hf_index, ett_ftam_Scope_U);

  return offset;
}



static int
dissect_ftam_Scope(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 28, true, dissect_ftam_Scope_U);

  return offset;
}


static const ber_sequence_t F_LIST_request_sequence[] = {
  { &hf_ftam_attribute_value_asset_tions, BER_CLASS_APP, 26, BER_FLAGS_NOOWNTAG, dissect_ftam_Attribute_Value_Assertions },
  { &hf_ftam_scope          , BER_CLASS_APP, 28, BER_FLAGS_NOOWNTAG, dissect_ftam_Scope },
  { &hf_ftam_access_passwords, BER_CLASS_APP, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Access_Passwords },
  { &hf_ftam_path_access_passwords, BER_CLASS_APP, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Path_Access_Passwords },
  { &hf_ftam_attribute_names, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_Attribute_Names },
  { &hf_ftam_attribute_extension_names, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_Attribute_Extension_Names },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_LIST_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_LIST_request_sequence, hf_index, ett_ftam_F_LIST_request);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Read_Attributes_sequence_of[1] = {
  { &hf_ftam__untag_item_04 , BER_CLASS_APP, 18, BER_FLAGS_NOOWNTAG, dissect_ftam_Read_Attributes },
};

static int
dissect_ftam_SEQUENCE_OF_Read_Attributes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Read_Attributes_sequence_of, hf_index, ett_ftam_SEQUENCE_OF_Read_Attributes);

  return offset;
}



static int
dissect_ftam_Objects_Attributes_List(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 25, true, dissect_ftam_SEQUENCE_OF_Read_Attributes);

  return offset;
}


static const ber_sequence_t F_LIST_response_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_objects_attributes_list, BER_CLASS_APP, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Objects_Attributes_List },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_LIST_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_LIST_response_sequence, hf_index, ett_ftam_F_LIST_response);

  return offset;
}


static const ber_sequence_t F_GROUP_SELECT_request_sequence[] = {
  { &hf_ftam_attribute_value_assertions, BER_CLASS_APP, 26, BER_FLAGS_NOOWNTAG, dissect_ftam_Attribute_Value_Assertions },
  { &hf_ftam_requested_access, BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_ftam_Access_Request },
  { &hf_ftam_access_passwords, BER_CLASS_APP, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Access_Passwords },
  { &hf_ftam_path_access_passwords, BER_CLASS_APP, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Path_Access_Passwords },
  { &hf_ftam_concurrency_control, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Concurrency_Control },
  { &hf_ftam_maximum_set_size, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  { &hf_ftam_scope          , BER_CLASS_APP, 28, BER_FLAGS_NOOWNTAG, dissect_ftam_Scope },
  { &hf_ftam_account        , BER_CLASS_APP, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Account },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_GROUP_SELECT_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_GROUP_SELECT_request_sequence, hf_index, ett_ftam_F_GROUP_SELECT_request);

  return offset;
}


static const ber_sequence_t F_GROUP_SELECT_response_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_GROUP_SELECT_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_GROUP_SELECT_response_sequence, hf_index, ett_ftam_F_GROUP_SELECT_response);

  return offset;
}


static const value_string ftam_Request_Operation_Result_U_vals[] = {
  {   0, "summary" },
  {   1, "fiii-list" },
  { 0, NULL }
};


static int
dissect_ftam_Request_Operation_Result_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ftam_Request_Operation_Result(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 31, true, dissect_ftam_Request_Operation_Result_U);

  return offset;
}


static const ber_sequence_t F_GROUP_DELETE_request_sequence[] = {
  { &hf_ftam_request_Operation_result, BER_CLASS_APP, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Request_Operation_Result },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_GROUP_DELETE_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_GROUP_DELETE_request_sequence, hf_index, ett_ftam_F_GROUP_DELETE_request);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Pathname_sequence_of[1] = {
  { &hf_ftam_success_Object_names_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ftam_Pathname },
};

static int
dissect_ftam_SEQUENCE_OF_Pathname(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Pathname_sequence_of, hf_index, ett_ftam_SEQUENCE_OF_Pathname);

  return offset;
}


static const value_string ftam_Operation_Result_U_vals[] = {
  {   0, "success-Object-count" },
  {   1, "success-Object-names" },
  { 0, NULL }
};

static const ber_choice_t Operation_Result_U_choice[] = {
  {   0, &hf_ftam_success_Object_count, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_INTEGER },
  {   1, &hf_ftam_success_Object_names, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_SEQUENCE_OF_Pathname },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_Operation_Result_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Operation_Result_U_choice, hf_index, ett_ftam_Operation_Result_U,
                                 NULL);

  return offset;
}



static int
dissect_ftam_Operation_Result(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 30, false, dissect_ftam_Operation_Result_U);

  return offset;
}


static const ber_sequence_t F_GROUP_DELETE_response_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_charging       , BER_CLASS_APP, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Charging },
  { &hf_ftam_operation_result, BER_CLASS_APP, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Operation_Result },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_GROUP_DELETE_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_GROUP_DELETE_response_sequence, hf_index, ett_ftam_F_GROUP_DELETE_response);

  return offset;
}


static const value_string ftam_Error_Action_vals[] = {
  {   0, "terminate" },
  {   1, "continue" },
  { 0, NULL }
};


static int
dissect_ftam_Error_Action(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t F_GROUP_MOVE_request_sequence[] = {
  { &hf_ftam_destination_file_directory, BER_CLASS_APP, 24, BER_FLAGS_NOOWNTAG, dissect_ftam_Destination_File_Directory },
  { &hf_ftam_override       , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_Override },
  { &hf_ftam_error_action   , BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_ftam_Error_Action },
  { &hf_ftam_create_password, BER_CLASS_APP, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Password },
  { &hf_ftam_access_passwords, BER_CLASS_APP, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Access_Passwords },
  { &hf_ftam_path_access_passwords, BER_CLASS_APP, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Path_Access_Passwords },
  { &hf_ftam_request_Operation_result, BER_CLASS_APP, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Request_Operation_Result },
  { &hf_ftam_attributes     , BER_CLASS_APP, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Change_Attributes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_GROUP_MOVE_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_GROUP_MOVE_request_sequence, hf_index, ett_ftam_F_GROUP_MOVE_request);

  return offset;
}


static const ber_sequence_t F_GROUP_MOVE_response_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_destination_file_directory, BER_CLASS_APP, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Destination_File_Directory },
  { &hf_ftam_operation_result, BER_CLASS_APP, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Operation_Result },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_GROUP_MOVE_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_GROUP_MOVE_response_sequence, hf_index, ett_ftam_F_GROUP_MOVE_response);

  return offset;
}


static const ber_sequence_t F_GROUP_COPY_request_sequence[] = {
  { &hf_ftam_destination_file_directory, BER_CLASS_APP, 24, BER_FLAGS_NOOWNTAG, dissect_ftam_Destination_File_Directory },
  { &hf_ftam_override       , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_Override },
  { &hf_ftam_error_action   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_Error_Action },
  { &hf_ftam_create_password, BER_CLASS_APP, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Password },
  { &hf_ftam_access_passwords, BER_CLASS_APP, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Access_Passwords },
  { &hf_ftam_path_access_passwords, BER_CLASS_APP, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Path_Access_Passwords },
  { &hf_ftam_request_Operation_result, BER_CLASS_APP, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Request_Operation_Result },
  { &hf_ftam_attributes     , BER_CLASS_APP, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Change_Attributes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_GROUP_COPY_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_GROUP_COPY_request_sequence, hf_index, ett_ftam_F_GROUP_COPY_request);

  return offset;
}


static const ber_sequence_t F_GROUP_COPY_response_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_destination_file_directory, BER_CLASS_APP, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Destination_File_Directory },
  { &hf_ftam_operation_result, BER_CLASS_APP, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Operation_Result },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_GROUP_COPY_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_GROUP_COPY_response_sequence, hf_index, ett_ftam_F_GROUP_COPY_response);

  return offset;
}


static const ber_sequence_t F_GROUP_LIST_request_sequence[] = {
  { &hf_ftam_attribute_names, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_Attribute_Names },
  { &hf_ftam_attribute_extension_names, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_Attribute_Extension_Names },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_GROUP_LIST_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_GROUP_LIST_request_sequence, hf_index, ett_ftam_F_GROUP_LIST_request);

  return offset;
}


static const ber_sequence_t F_GROUP_LIST_response_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_objects_attributes_list, BER_CLASS_APP, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Objects_Attributes_List },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_GROUP_LIST_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_GROUP_LIST_response_sequence, hf_index, ett_ftam_F_GROUP_LIST_response);

  return offset;
}


static const ber_sequence_t F_GROUP_CHANGE_ATTRIB_request_sequence[] = {
  { &hf_ftam_attributes     , BER_CLASS_APP, 8, BER_FLAGS_NOOWNTAG, dissect_ftam_Change_Attributes },
  { &hf_ftam_error_action   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ftam_Error_Action },
  { &hf_ftam_request_Operation_result, BER_CLASS_APP, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Request_Operation_Result },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_GROUP_CHANGE_ATTRIB_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_GROUP_CHANGE_ATTRIB_request_sequence, hf_index, ett_ftam_F_GROUP_CHANGE_ATTRIB_request);

  return offset;
}


static const ber_sequence_t F_GROUP_CHANGE_ATTRIB_response_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_operation_result, BER_CLASS_APP, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Operation_Result },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_GROUP_CHANGE_ATTRIB_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_GROUP_CHANGE_ATTRIB_response_sequence, hf_index, ett_ftam_F_GROUP_CHANGE_ATTRIB_response);

  return offset;
}


static const ber_sequence_t F_SELECT_ANOTHER_request_sequence[] = {
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_SELECT_ANOTHER_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_SELECT_ANOTHER_request_sequence, hf_index, ett_ftam_F_SELECT_ANOTHER_request);

  return offset;
}


static const ber_sequence_t F_SELECT_ANOTHER_response_sequence[] = {
  { &hf_ftam_state_result   , BER_CLASS_APP, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_State_Result },
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_last_member_indicator, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_BOOLEAN },
  { &hf_ftam_referent_indicator, BER_CLASS_APP, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Referent_Indicator },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_SELECT_ANOTHER_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_SELECT_ANOTHER_response_sequence, hf_index, ett_ftam_F_SELECT_ANOTHER_response);

  return offset;
}


static const ber_sequence_t F_CREATE_DIRECTORY_request_sequence[] = {
  { &hf_ftam_initial_attributes, BER_CLASS_APP, 12, BER_FLAGS_NOOWNTAG, dissect_ftam_Create_Attributes },
  { &hf_ftam_create_password, BER_CLASS_APP, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Password },
  { &hf_ftam_requested_access, BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_ftam_Access_Request },
  { &hf_ftam_shared_ASE_infonnation, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_account        , BER_CLASS_APP, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Account },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_CREATE_DIRECTORY_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_CREATE_DIRECTORY_request_sequence, hf_index, ett_ftam_F_CREATE_DIRECTORY_request);

  return offset;
}


static const ber_sequence_t F_CREATE_DIRECTORY_response_sequence[] = {
  { &hf_ftam_state_result   , BER_CLASS_APP, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_State_Result },
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_initial_attributes, BER_CLASS_APP, 12, BER_FLAGS_NOOWNTAG, dissect_ftam_Create_Attributes },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_CREATE_DIRECTORY_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_CREATE_DIRECTORY_response_sequence, hf_index, ett_ftam_F_CREATE_DIRECTORY_response);

  return offset;
}


static const ber_sequence_t F_LINK_request_sequence[] = {
  { &hf_ftam_initial_attributes, BER_CLASS_APP, 12, BER_FLAGS_NOOWNTAG, dissect_ftam_Create_Attributes },
  { &hf_ftam_target_object  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ftam_Pathname_Attribute },
  { &hf_ftam_create_password, BER_CLASS_APP, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Password },
  { &hf_ftam_requested_access, BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_ftam_Access_Request },
  { &hf_ftam_access_passwords, BER_CLASS_APP, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Access_Passwords },
  { &hf_ftam_path_access_passwords, BER_CLASS_APP, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Path_Access_Passwords },
  { &hf_ftam_concurrency_control, BER_CLASS_APP, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Concurrency_Control },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_account        , BER_CLASS_APP, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Account },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_LINK_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_LINK_request_sequence, hf_index, ett_ftam_F_LINK_request);

  return offset;
}


static const ber_sequence_t F_LINK_response_sequence[] = {
  { &hf_ftam_state_result   , BER_CLASS_APP, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_State_Result },
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_initial_attributes, BER_CLASS_APP, 12, BER_FLAGS_NOOWNTAG, dissect_ftam_Create_Attributes },
  { &hf_ftam_target_Object  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ftam_Pathname_Attribute },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_LINK_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_LINK_response_sequence, hf_index, ett_ftam_F_LINK_response);

  return offset;
}


static const ber_sequence_t F_UNLINK_request_sequence[] = {
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_UNLINK_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_UNLINK_request_sequence, hf_index, ett_ftam_F_UNLINK_request);

  return offset;
}


static const ber_sequence_t F_UNLINK_response_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_shared_ASE_information, BER_CLASS_APP, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Shared_ASE_Information },
  { &hf_ftam_charging       , BER_CLASS_APP, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Charging },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_UNLINK_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_UNLINK_response_sequence, hf_index, ett_ftam_F_UNLINK_response);

  return offset;
}


static const ber_sequence_t F_READ_LINK_ATTRIB_request_sequence[] = {
  { &hf_ftam_attribute_names, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ftam_Attribute_Names },
  { &hf_ftam_attribute_extension_names, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_Attribute_Extension_Names },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_READ_LINK_ATTRIB_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_READ_LINK_ATTRIB_request_sequence, hf_index, ett_ftam_F_READ_LINK_ATTRIB_request);

  return offset;
}


static const ber_sequence_t F_READ_LINK_ATTRIB_response_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_read_link_attributes, BER_CLASS_APP, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Read_Attributes },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_READ_LINK_ATTRIB_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_READ_LINK_ATTRIB_response_sequence, hf_index, ett_ftam_F_READ_LINK_ATTRIB_response);

  return offset;
}


static const ber_sequence_t F_CHANGE_LINK_ATTRIB_request_sequence[] = {
  { &hf_ftam_attributes     , BER_CLASS_APP, 8, BER_FLAGS_NOOWNTAG, dissect_ftam_Change_Attributes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_CHANGE_LINK_ATTRIB_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_CHANGE_LINK_ATTRIB_request_sequence, hf_index, ett_ftam_F_CHANGE_LINK_ATTRIB_request);

  return offset;
}


static const ber_sequence_t F_CHANGE_LINK_ATTRIB_response_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_attributes     , BER_CLASS_APP, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Change_Attributes },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_CHANGE_LINK_ATTRIB_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_CHANGE_LINK_ATTRIB_response_sequence, hf_index, ett_ftam_F_CHANGE_LINK_ATTRIB_response);

  return offset;
}


static const ber_sequence_t F_MOVE_request_sequence[] = {
  { &hf_ftam_destination_file_directory, BER_CLASS_APP, 24, BER_FLAGS_NOOWNTAG, dissect_ftam_Destination_File_Directory },
  { &hf_ftam_override       , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_Override },
  { &hf_ftam_create_password, BER_CLASS_APP, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Password },
  { &hf_ftam_access_passwords, BER_CLASS_APP, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Access_Passwords },
  { &hf_ftam_path_access_passwords, BER_CLASS_APP, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Path_Access_Passwords },
  { &hf_ftam_attributes     , BER_CLASS_APP, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Change_Attributes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_MOVE_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_MOVE_request_sequence, hf_index, ett_ftam_F_MOVE_request);

  return offset;
}


static const ber_sequence_t F_MOVE_response_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_destination_file_directory, BER_CLASS_APP, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Destination_File_Directory },
  { &hf_ftam_attributes     , BER_CLASS_APP, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Change_Attributes },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_MOVE_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_MOVE_response_sequence, hf_index, ett_ftam_F_MOVE_response);

  return offset;
}


static const ber_sequence_t F_COPY_request_sequence[] = {
  { &hf_ftam_destination_file_directory, BER_CLASS_APP, 24, BER_FLAGS_NOOWNTAG, dissect_ftam_Destination_File_Directory },
  { &hf_ftam_override       , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ftam_Override },
  { &hf_ftam_create_password, BER_CLASS_APP, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Password },
  { &hf_ftam_access_passwords, BER_CLASS_APP, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Access_Passwords },
  { &hf_ftam_path_access_passwords, BER_CLASS_APP, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Path_Access_Passwords },
  { &hf_ftam_attributes     , BER_CLASS_APP, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Change_Attributes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_COPY_request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_COPY_request_sequence, hf_index, ett_ftam_F_COPY_request);

  return offset;
}


static const ber_sequence_t F_COPY_response_sequence[] = {
  { &hf_ftam_action_result  , BER_CLASS_APP, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Action_Result },
  { &hf_ftam_destination_file_directory, BER_CLASS_APP, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Destination_File_Directory },
  { &hf_ftam_attributes     , BER_CLASS_APP, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Change_Attributes },
  { &hf_ftam_diagnostic     , BER_CLASS_APP, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ftam_Diagnostic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_F_COPY_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   F_COPY_response_sequence, hf_index, ett_ftam_F_COPY_response);

  return offset;
}


static const value_string ftam_FSM_PDU_vals[] = {
  {  41, "f-Change-prefix-request" },
  {  42, "f-Change-prefix-response" },
  {  43, "f-list-request" },
  {  44, "f-list-response" },
  {  45, "f-group-select-request" },
  {  46, "f-group-select-response" },
  {  47, "f-group-delete-request" },
  {  48, "f-group-delete-response" },
  {  49, "f-group-move-request" },
  {  50, "f-group-move-response" },
  {  51, "f-group-copy-request" },
  {  52, "f-group-copy-response" },
  {  53, "f-group-list-request" },
  {  54, "f-group-list-response" },
  {  55, "f-group-Change-attrib-request" },
  {  56, "f-group-Change-attrib-response" },
  {  57, "f-select-another-request" },
  {  58, "f-select-another-response" },
  {  59, "f-create-directory-request" },
  {  60, "f-create-directory-response" },
  {  61, "f-link-request" },
  {  62, "f-link-response" },
  {  63, "f-unlink-request" },
  {  64, "f-unlink-response" },
  {  65, "f-read-link-attrib-request" },
  {  66, "f-read-link-attrib-response" },
  {  67, "f-Change-link-attrib-request" },
  {  68, "f-Change-Iink-attrib-response" },
  {  69, "f-move-request" },
  {  70, "f-move-response" },
  {  71, "f-copy-request" },
  {  72, "f-copy-response" },
  { 0, NULL }
};

static const ber_choice_t FSM_PDU_choice[] = {
  {  41, &hf_ftam_f_Change_prefix_request, BER_CLASS_CON, 41, BER_FLAGS_IMPLTAG, dissect_ftam_F_CHANGE_PREFIX_request },
  {  42, &hf_ftam_f_Change_prefix_response, BER_CLASS_CON, 42, BER_FLAGS_IMPLTAG, dissect_ftam_F_CHANGE_PREFIX_response },
  {  43, &hf_ftam_f_list_request , BER_CLASS_CON, 43, BER_FLAGS_IMPLTAG, dissect_ftam_F_LIST_request },
  {  44, &hf_ftam_f_list_response, BER_CLASS_CON, 44, BER_FLAGS_IMPLTAG, dissect_ftam_F_LIST_response },
  {  45, &hf_ftam_f_group_select_request, BER_CLASS_CON, 45, BER_FLAGS_IMPLTAG, dissect_ftam_F_GROUP_SELECT_request },
  {  46, &hf_ftam_f_group_select_response, BER_CLASS_CON, 46, BER_FLAGS_IMPLTAG, dissect_ftam_F_GROUP_SELECT_response },
  {  47, &hf_ftam_f_group_delete_request, BER_CLASS_CON, 47, BER_FLAGS_IMPLTAG, dissect_ftam_F_GROUP_DELETE_request },
  {  48, &hf_ftam_f_group_delete_response, BER_CLASS_CON, 48, BER_FLAGS_IMPLTAG, dissect_ftam_F_GROUP_DELETE_response },
  {  49, &hf_ftam_f_group_move_request, BER_CLASS_CON, 49, BER_FLAGS_IMPLTAG, dissect_ftam_F_GROUP_MOVE_request },
  {  50, &hf_ftam_f_group_move_response, BER_CLASS_CON, 50, BER_FLAGS_IMPLTAG, dissect_ftam_F_GROUP_MOVE_response },
  {  51, &hf_ftam_f_group_copy_request, BER_CLASS_CON, 51, BER_FLAGS_IMPLTAG, dissect_ftam_F_GROUP_COPY_request },
  {  52, &hf_ftam_f_group_copy_response, BER_CLASS_CON, 52, BER_FLAGS_IMPLTAG, dissect_ftam_F_GROUP_COPY_response },
  {  53, &hf_ftam_f_group_list_request, BER_CLASS_CON, 53, BER_FLAGS_IMPLTAG, dissect_ftam_F_GROUP_LIST_request },
  {  54, &hf_ftam_f_group_list_response, BER_CLASS_CON, 54, BER_FLAGS_IMPLTAG, dissect_ftam_F_GROUP_LIST_response },
  {  55, &hf_ftam_f_group_Change_attrib_request, BER_CLASS_CON, 55, BER_FLAGS_IMPLTAG, dissect_ftam_F_GROUP_CHANGE_ATTRIB_request },
  {  56, &hf_ftam_f_group_Change_attrib_response, BER_CLASS_CON, 56, BER_FLAGS_IMPLTAG, dissect_ftam_F_GROUP_CHANGE_ATTRIB_response },
  {  57, &hf_ftam_f_select_another_request, BER_CLASS_CON, 57, BER_FLAGS_IMPLTAG, dissect_ftam_F_SELECT_ANOTHER_request },
  {  58, &hf_ftam_f_select_another_response, BER_CLASS_CON, 58, BER_FLAGS_IMPLTAG, dissect_ftam_F_SELECT_ANOTHER_response },
  {  59, &hf_ftam_f_create_directory_request, BER_CLASS_CON, 59, BER_FLAGS_IMPLTAG, dissect_ftam_F_CREATE_DIRECTORY_request },
  {  60, &hf_ftam_f_create_directory_response, BER_CLASS_CON, 60, BER_FLAGS_IMPLTAG, dissect_ftam_F_CREATE_DIRECTORY_response },
  {  61, &hf_ftam_f_link_request , BER_CLASS_CON, 61, BER_FLAGS_IMPLTAG, dissect_ftam_F_LINK_request },
  {  62, &hf_ftam_f_link_response, BER_CLASS_CON, 62, BER_FLAGS_IMPLTAG, dissect_ftam_F_LINK_response },
  {  63, &hf_ftam_f_unlink_request, BER_CLASS_CON, 63, BER_FLAGS_IMPLTAG, dissect_ftam_F_UNLINK_request },
  {  64, &hf_ftam_f_unlink_response, BER_CLASS_CON, 64, BER_FLAGS_IMPLTAG, dissect_ftam_F_UNLINK_response },
  {  65, &hf_ftam_f_read_link_attrib_request, BER_CLASS_CON, 65, BER_FLAGS_IMPLTAG, dissect_ftam_F_READ_LINK_ATTRIB_request },
  {  66, &hf_ftam_f_read_link_attrib_response, BER_CLASS_CON, 66, BER_FLAGS_IMPLTAG, dissect_ftam_F_READ_LINK_ATTRIB_response },
  {  67, &hf_ftam_f_Change_link_attrib_request, BER_CLASS_CON, 67, BER_FLAGS_IMPLTAG, dissect_ftam_F_CHANGE_LINK_ATTRIB_request },
  {  68, &hf_ftam_f_Change_Iink_attrib_response, BER_CLASS_CON, 68, BER_FLAGS_IMPLTAG, dissect_ftam_F_CHANGE_LINK_ATTRIB_response },
  {  69, &hf_ftam_f_move_request , BER_CLASS_CON, 69, BER_FLAGS_IMPLTAG, dissect_ftam_F_MOVE_request },
  {  70, &hf_ftam_f_move_response, BER_CLASS_CON, 70, BER_FLAGS_IMPLTAG, dissect_ftam_F_MOVE_response },
  {  71, &hf_ftam_f_copy_request , BER_CLASS_CON, 71, BER_FLAGS_IMPLTAG, dissect_ftam_F_COPY_request },
  {  72, &hf_ftam_f_copy_response, BER_CLASS_CON, 72, BER_FLAGS_IMPLTAG, dissect_ftam_F_COPY_response },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_FSM_PDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int branch_taken;

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 FSM_PDU_choice, hf_index, ett_ftam_FSM_PDU,
                                 &branch_taken);


  if( (branch_taken!=-1) && ftam_FSM_PDU_vals[branch_taken].strptr ){
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s:", ftam_FSM_PDU_vals[branch_taken].strptr);
  }



  return offset;
}


static const ber_choice_t PDU_choice[] = {
  { -1/*choice*/, &hf_ftam_fTAM_Regime_PDU, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_ftam_FTAM_Regime_PDU },
  { -1/*choice*/, &hf_ftam_file_PDU       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_ftam_File_PDU },
  { -1/*choice*/, &hf_ftam_bulk_Data_PDU  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_ftam_Bulk_Data_PDU },
  { -1/*choice*/, &hf_ftam_fSM_PDU        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_ftam_FSM_PDU },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ftam_PDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PDU_choice, hf_index, ett_ftam_PDU,
                                 NULL);

  return offset;
}


/*
* Dissect FTAM unstructured text
*/
static int
dissect_ftam_unstructured_text(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, void* data _U_)
{
	proto_tree_add_item (parent_tree, hf_ftam_unstructured_text, tvb, 0, tvb_reported_length_remaining(tvb, 0), ENC_ASCII);
	return tvb_captured_length(tvb);
}

/*
* Dissect FTAM unstructured binary
*/
static int
dissect_ftam_unstructured_binary(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, void* data _U_)
{
	proto_tree_add_item (parent_tree, hf_ftam_unstructured_binary, tvb, 0, tvb_reported_length_remaining(tvb, 0), ENC_NA);
	return tvb_captured_length(tvb);
}

/*
* Dissect FTAM PDUs inside a PPDU.
*/
static int
dissect_ftam(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
	int offset = 0;
	int old_offset;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_ftam, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_ftam);
	}
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "FTAM");
  	col_clear(pinfo->cinfo, COL_INFO);

	while (tvb_reported_length_remaining(tvb, offset) > 0){
		old_offset=offset;
		offset=dissect_ftam_PDU(false, tvb, offset, &asn1_ctx, tree, -1);
		if(offset == old_offset){
			proto_tree_add_expert(tree, pinfo, &ei_ftam_zero_pdu, tvb, offset, -1);
			break;
		}
	}
	return tvb_captured_length(tvb);
}


/*--- proto_register_ftam -------------------------------------------*/
void proto_register_ftam(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
     { &hf_ftam_unstructured_text,
       { "ISO FTAM unstructured text", "ftam.unstructured_text", FT_STRING,
          BASE_NONE, NULL, 0x0, NULL, HFILL } },
     { &hf_ftam_unstructured_binary,
       { "ISO FTAM unstructured binary", "ftam.unstructured_binary", FT_BYTES,
          BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_ftam_fTAM_Regime_PDU,
      { "fTAM-Regime-PDU", "ftam.fTAM_Regime_PDU",
        FT_UINT32, BASE_DEC, VALS(ftam_FTAM_Regime_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_ftam_file_PDU,
      { "file-PDU", "ftam.file_PDU",
        FT_UINT32, BASE_DEC, VALS(ftam_File_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_ftam_bulk_Data_PDU,
      { "bulk-Data-PDU", "ftam.bulk_Data_PDU",
        FT_UINT32, BASE_DEC, VALS(ftam_Bulk_Data_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_ftam_fSM_PDU,
      { "fSM-PDU", "ftam.fSM_PDU",
        FT_UINT32, BASE_DEC, VALS(ftam_FSM_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_ftam_f_initialize_request,
      { "f-initialize-request", "ftam.f_initialize_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_initialize_response,
      { "f-initialize-response", "ftam.f_initialize_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_terminate_request,
      { "f-terminate-request", "ftam.f_terminate_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_terminate_response,
      { "f-terminate-response", "ftam.f_terminate_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_u_abort_request,
      { "f-u-abort-request", "ftam.f_u_abort_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_p_abort_request,
      { "f-p-abort-request", "ftam.f_p_abort_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_protocol_Version,
      { "protocol-Version", "ftam.protocol_Version",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_implementation_information,
      { "implementation-information", "ftam.implementation_information",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_presentation_tontext_management,
      { "presentation-tontext-management", "ftam.presentation_tontext_management",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ftam_service_class,
      { "service-class", "ftam.service_class",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_functional_units,
      { "functional-units", "ftam.functional_units",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_attribute_groups,
      { "attribute-groups", "ftam.attribute_groups",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_shared_ASE_information,
      { "shared-ASE-information", "ftam.shared_ASE_information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_ftam_quality_of_Service,
      { "ftam-quality-of-Service", "ftam.ftam_quality_of_Service",
        FT_INT32, BASE_DEC, VALS(ftam_FTAM_Quality_of_Service_U_vals), 0,
        NULL, HFILL }},
    { &hf_ftam_contents_type_list,
      { "contents-type-list", "ftam.contents_type_list",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_initiator_identity,
      { "initiator-identity", "ftam.initiator_identity",
        FT_STRING, BASE_NONE, NULL, 0,
        "User_Identity", HFILL }},
    { &hf_ftam_account,
      { "account", "ftam.account",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_filestore_password,
      { "filestore-password", "ftam.filestore_password",
        FT_UINT32, BASE_DEC, VALS(ftam_Password_U_vals), 0,
        "Password", HFILL }},
    { &hf_ftam_checkpoint_window,
      { "checkpoint-window", "ftam.checkpoint_window",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ftam_state_result,
      { "state-result", "ftam.state_result",
        FT_INT32, BASE_DEC, VALS(ftam_State_Result_U_vals), 0,
        NULL, HFILL }},
    { &hf_ftam_action_result,
      { "action-result", "ftam.action_result",
        FT_INT32, BASE_DEC, VALS(ftam_Action_Result_U_vals), 0,
        NULL, HFILL }},
    { &hf_ftam_diagnostic,
      { "diagnostic", "ftam.diagnostic",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam__untag_item,
      { "_untag item", "ftam._untag_item",
        FT_UINT32, BASE_DEC, VALS(ftam_Contents_Type_List_item_vals), 0,
        "Contents_Type_List_item", HFILL }},
    { &hf_ftam_document_type_name,
      { "document-type-name", "ftam.document_type_name",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_abstract_Syntax_name,
      { "abstract-Syntax-name", "ftam.abstract_Syntax_name",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_charging,
      { "charging", "ftam.charging",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_select_request,
      { "f-select-request", "ftam.f_select_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_select_response,
      { "f-select-response", "ftam.f_select_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_deselect_request,
      { "f-deselect-request", "ftam.f_deselect_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_deselect_response,
      { "f-deselect-response", "ftam.f_deselect_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_create_request,
      { "f-create-request", "ftam.f_create_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_create_response,
      { "f-create-response", "ftam.f_create_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_delete_request,
      { "f-delete-request", "ftam.f_delete_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_delete_response,
      { "f-delete-response", "ftam.f_delete_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_read_attrib_request,
      { "f-read-attrib-request", "ftam.f_read_attrib_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_read_attrib_response,
      { "f-read-attrib-response", "ftam.f_read_attrib_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_Change_attrib_reques,
      { "f-Change-attrib-reques", "ftam.f_Change_attrib_reques_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "F_CHANGE_ATTRIB_request", HFILL }},
    { &hf_ftam_f_Change_attrib_respon,
      { "f-Change-attrib-respon", "ftam.f_Change_attrib_respon_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "F_CHANGE_ATTRIB_response", HFILL }},
    { &hf_ftam_f_open_request,
      { "f-open-request", "ftam.f_open_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_open_response,
      { "f-open-response", "ftam.f_open_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_close_request,
      { "f-close-request", "ftam.f_close_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_close_response,
      { "f-close-response", "ftam.f_close_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_begin_group_request,
      { "f-begin-group-request", "ftam.f_begin_group_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_begin_group_response,
      { "f-begin-group-response", "ftam.f_begin_group_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_end_group_request,
      { "f-end-group-request", "ftam.f_end_group_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_end_group_response,
      { "f-end-group-response", "ftam.f_end_group_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_recover_request,
      { "f-recover-request", "ftam.f_recover_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_recover_response,
      { "f-recover-response", "ftam.f_recover_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_locate_request,
      { "f-locate-request", "ftam.f_locate_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_locate_response,
      { "f-locate-response", "ftam.f_locate_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_erase_request,
      { "f-erase-request", "ftam.f_erase_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_erase_response,
      { "f-erase-response", "ftam.f_erase_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_select_attributes,
      { "attributes", "ftam.attributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Select_Attributes", HFILL }},
    { &hf_ftam_requested_access,
      { "requested-access", "ftam.requested_access",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Access_Request", HFILL }},
    { &hf_ftam_access_passwords,
      { "access-passwords", "ftam.access_passwords_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_path_access_passwords,
      { "path-access-passwords", "ftam.path_access_passwords",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_concurrency_control,
      { "concurrency-control", "ftam.concurrency_control_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_referent_indicator,
      { "referent-indicator", "ftam.referent_indicator",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_override,
      { "override", "ftam.override",
        FT_INT32, BASE_DEC, VALS(ftam_Override_vals), 0,
        NULL, HFILL }},
    { &hf_ftam_initial_attributes,
      { "initial-attributes", "ftam.initial_attributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Create_Attributes", HFILL }},
    { &hf_ftam_create_password,
      { "create-password", "ftam.create_password",
        FT_UINT32, BASE_DEC, VALS(ftam_Password_U_vals), 0,
        "Password", HFILL }},
    { &hf_ftam_attribute_names,
      { "attribute-names", "ftam.attribute_names",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_attribute_extension_names,
      { "attribute-extension-names", "ftam.attribute_extension_names",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_read_attributes,
      { "attributes", "ftam.attributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Read_Attributes", HFILL }},
    { &hf_ftam_attributes,
      { "attributes", "ftam.attributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Change_Attributes", HFILL }},
    { &hf_ftam_processing_mode,
      { "processing-mode", "ftam.processing_mode",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_open_contents_type,
      { "contents-type", "ftam.contents_type",
        FT_UINT32, BASE_DEC, VALS(ftam_T_open_contents_type_vals), 0,
        "T_open_contents_type", HFILL }},
    { &hf_ftam_unknown,
      { "unknown", "ftam.unknown_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_proposed,
      { "proposed", "ftam.proposed",
        FT_UINT32, BASE_DEC, VALS(ftam_Contents_Type_Attribute_vals), 0,
        "Contents_Type_Attribute", HFILL }},
    { &hf_ftam_enable_fadu_locking,
      { "enable-fadu-locking", "ftam.enable_fadu_locking",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ftam_activity_identifier,
      { "activity-identifier", "ftam.activity_identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_request_recovery_mode,
      { "recovery-mode", "ftam.recovery_mode",
        FT_INT32, BASE_DEC, VALS(ftam_T_request_recovery_mode_vals), 0,
        "T_request_recovery_mode", HFILL }},
    { &hf_ftam_remove_contexts,
      { "remove-contexts", "ftam.remove_contexts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Abstract_Syntax_Name", HFILL }},
    { &hf_ftam_remove_contexts_item,
      { "Abstract-Syntax-Name", "ftam.Abstract_Syntax_Name",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_define_contexts,
      { "define-contexts", "ftam.define_contexts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Abstract_Syntax_Name", HFILL }},
    { &hf_ftam_define_contexts_item,
      { "Abstract-Syntax-Name", "ftam.Abstract_Syntax_Name",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_degree_of_overlap,
      { "degree-of-overlap", "ftam.degree_of_overlap",
        FT_INT32, BASE_DEC, VALS(ftam_Degree_Of_Overlap_U_vals), 0,
        NULL, HFILL }},
    { &hf_ftam_transfer_window,
      { "transfer-window", "ftam.transfer_window",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ftam_contents_type,
      { "contents-type", "ftam.contents_type",
        FT_UINT32, BASE_DEC, VALS(ftam_Contents_Type_Attribute_vals), 0,
        "Contents_Type_Attribute", HFILL }},
    { &hf_ftam_response_recovery_mode,
      { "recovery-mode", "ftam.recovery_mode",
        FT_INT32, BASE_DEC, VALS(ftam_T_response_recovery_mode_vals), 0,
        "T_response_recovery_mode", HFILL }},
    { &hf_ftam_presentation_action,
      { "presentation-action", "ftam.presentation_action",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ftam_threshold,
      { "threshold", "ftam.threshold",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ftam_bulk_transfer_number,
      { "bulk-transfer-number", "ftam.bulk_transfer_number",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ftam_recovefy_Point,
      { "recovefy-Point", "ftam.recovefy_Point",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ftam_concurrent_bulk_transfer_number,
      { "concurrent-bulk-transfer-number", "ftam.concurrent_bulk_transfer_number",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ftam_concurrent_recovery_point,
      { "concurrent-recovery-point", "ftam.concurrent_recovery_point",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ftam_last_transfer_end_read_response,
      { "last-transfer-end-read-response", "ftam.last_transfer_end_read_response",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ftam_last_transfer_end_write_response,
      { "last-transfer-end-write-response", "ftam.last_transfer_end_write_response",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ftam_recovety_Point,
      { "recovety-Point", "ftam.recovety_Point",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ftam_last_transfer_end_read_request,
      { "last-transfer-end-read-request", "ftam.last_transfer_end_read_request",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ftam_last_transfer_end_write_request,
      { "last-transfer-end-write-request", "ftam.last_transfer_end_write_request",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ftam_file_access_data_unit_identity,
      { "file-access-data-unit-identity", "ftam.file_access_data_unit_identity",
        FT_UINT32, BASE_DEC, VALS(ftam_FADU_Identity_U_vals), 0,
        "FADU_Identity", HFILL }},
    { &hf_ftam_fadu_lock,
      { "fadu-lock", "ftam.fadu_lock",
        FT_INT32, BASE_DEC, VALS(ftam_FADU_Lock_U_vals), 0,
        NULL, HFILL }},
    { &hf_ftam_f_read_request,
      { "f-read-request", "ftam.f_read_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_write_request,
      { "f-write-request", "ftam.f_write_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_data_end_request,
      { "f-data-end-request", "ftam.f_data_end_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_transfer_end_request,
      { "f-transfer-end-request", "ftam.f_transfer_end_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_transfer_end_response,
      { "f-transfer-end-response", "ftam.f_transfer_end_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_cancel_request,
      { "f-cancel-request", "ftam.f_cancel_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_cancel_response,
      { "f-cancel-response", "ftam.f_cancel_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_restart_request,
      { "f-restart-request", "ftam.f_restart_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_restart_response,
      { "f-restart-response", "ftam.f_restart_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_read_access_context,
      { "access-context", "ftam.access_context_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_transfer_number,
      { "transfer-number", "ftam.transfer_number",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ftam_file_access_data_unit_Operation,
      { "file-access-data-unit-Operation", "ftam.file_access_data_unit_Operation",
        FT_INT32, BASE_DEC, VALS(ftam_T_file_access_data_unit_Operation_vals), 0,
        "T_file_access_data_unit_Operation", HFILL }},
    { &hf_ftam_request_type,
      { "request-type", "ftam.request_type",
        FT_INT32, BASE_DEC, VALS(ftam_Request_Type_U_vals), 0,
        NULL, HFILL }},
    { &hf_ftam_checkpoint_identifier,
      { "checkpoint-identifier", "ftam.checkpoint_identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ftam_access_context,
      { "access-context", "ftam.access_context",
        FT_INT32, BASE_DEC, VALS(ftam_T_access_context_vals), 0,
        NULL, HFILL }},
    { &hf_ftam_level_number,
      { "level-number", "ftam.level_number",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ftam_read_password,
      { "read-password", "ftam.read_password",
        FT_UINT32, BASE_DEC, VALS(ftam_Password_U_vals), 0,
        "Password", HFILL }},
    { &hf_ftam_insert_password,
      { "insert-password", "ftam.insert_password",
        FT_UINT32, BASE_DEC, VALS(ftam_Password_U_vals), 0,
        "Password", HFILL }},
    { &hf_ftam_replace_password,
      { "replace-password", "ftam.replace_password",
        FT_UINT32, BASE_DEC, VALS(ftam_Password_U_vals), 0,
        "Password", HFILL }},
    { &hf_ftam_extend_password,
      { "extend-password", "ftam.extend_password",
        FT_UINT32, BASE_DEC, VALS(ftam_Password_U_vals), 0,
        "Password", HFILL }},
    { &hf_ftam_erase_password,
      { "erase-password", "ftam.erase_password",
        FT_UINT32, BASE_DEC, VALS(ftam_Password_U_vals), 0,
        "Password", HFILL }},
    { &hf_ftam_read_attribute_password,
      { "read-attribute-password", "ftam.read_attribute_password",
        FT_UINT32, BASE_DEC, VALS(ftam_Password_U_vals), 0,
        "Password", HFILL }},
    { &hf_ftam_change_attribute_password,
      { "change-attribute-password", "ftam.change_attribute_password",
        FT_UINT32, BASE_DEC, VALS(ftam_Password_U_vals), 0,
        "Password", HFILL }},
    { &hf_ftam_delete_password,
      { "delete-password", "ftam.delete_password",
        FT_UINT32, BASE_DEC, VALS(ftam_Password_U_vals), 0,
        "Password", HFILL }},
    { &hf_ftam_pass_passwords,
      { "pass-passwords", "ftam.pass_passwords",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_link_password,
      { "link-password", "ftam.link_password",
        FT_UINT32, BASE_DEC, VALS(ftam_Password_U_vals), 0,
        "Password", HFILL }},
    { &hf_ftam_pathname,
      { "pathname", "ftam.pathname",
        FT_UINT32, BASE_DEC, VALS(ftam_Pathname_Attribute_vals), 0,
        "Pathname_Attribute", HFILL }},
    { &hf_ftam_storage_account,
      { "storage-account", "ftam.storage_account",
        FT_UINT32, BASE_DEC, VALS(ftam_Account_Attribute_vals), 0,
        "Account_Attribute", HFILL }},
    { &hf_ftam_object_availability,
      { "object-availability", "ftam.object_availability",
        FT_UINT32, BASE_DEC, VALS(ftam_Object_Availability_Attribute_vals), 0,
        "Object_Availability_Attribute", HFILL }},
    { &hf_ftam_future_Object_size,
      { "future-Object-size", "ftam.future_Object_size",
        FT_UINT32, BASE_DEC, VALS(ftam_Object_Size_Attribute_vals), 0,
        "Object_Size_Attribute", HFILL }},
    { &hf_ftam_change_attributes_access_control,
      { "access-control", "ftam.access_control",
        FT_UINT32, BASE_DEC, VALS(ftam_Access_Control_Change_Attribute_vals), 0,
        "Access_Control_Change_Attribute", HFILL }},
    { &hf_ftam_change_path_access_control,
      { "path-access-control", "ftam.path_access_control",
        FT_UINT32, BASE_DEC, VALS(ftam_Access_Control_Change_Attribute_vals), 0,
        "Access_Control_Change_Attribute", HFILL }},
    { &hf_ftam_legal_qualification,
      { "legal-qualification", "ftam.legal_qualification",
        FT_UINT32, BASE_DEC, VALS(ftam_Legal_Qualification_Attribute_vals), 0,
        "Legal_Qualification_Attribute", HFILL }},
    { &hf_ftam_private_use,
      { "private-use", "ftam.private_use",
        FT_UINT32, BASE_DEC, VALS(ftam_Private_Use_Attribute_vals), 0,
        "Private_Use_Attribute", HFILL }},
    { &hf_ftam_attribute_extensions,
      { "attribute-extensions", "ftam.attribute_extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam__untag_item_01,
      { "_untag item", "ftam._untag_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Charging_item", HFILL }},
    { &hf_ftam_resource_identifier,
      { "resource-identifier", "ftam.resource_identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "GraphicString", HFILL }},
    { &hf_ftam_charging_unit,
      { "charging-unit", "ftam.charging_unit",
        FT_STRING, BASE_NONE, NULL, 0,
        "GraphicString", HFILL }},
    { &hf_ftam_charging_value,
      { "charging-value", "ftam.charging_value",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ftam_read,
      { "read", "ftam.read",
        FT_INT32, BASE_DEC, VALS(ftam_Lock_vals), 0,
        "Lock", HFILL }},
    { &hf_ftam_insert,
      { "insert", "ftam.insert",
        FT_INT32, BASE_DEC, VALS(ftam_Lock_vals), 0,
        "Lock", HFILL }},
    { &hf_ftam_replace,
      { "replace", "ftam.replace",
        FT_INT32, BASE_DEC, VALS(ftam_Lock_vals), 0,
        "Lock", HFILL }},
    { &hf_ftam_extend,
      { "extend", "ftam.extend",
        FT_INT32, BASE_DEC, VALS(ftam_Lock_vals), 0,
        "Lock", HFILL }},
    { &hf_ftam_erase,
      { "erase", "ftam.erase",
        FT_INT32, BASE_DEC, VALS(ftam_Lock_vals), 0,
        "Lock", HFILL }},
    { &hf_ftam_read_attribute,
      { "read-attribute", "ftam.read_attribute",
        FT_INT32, BASE_DEC, VALS(ftam_Lock_vals), 0,
        "Lock", HFILL }},
    { &hf_ftam_change_attribute,
      { "change-attribute", "ftam.change_attribute",
        FT_INT32, BASE_DEC, VALS(ftam_Lock_vals), 0,
        "Lock", HFILL }},
    { &hf_ftam_delete_Object,
      { "delete-Object", "ftam.delete_Object",
        FT_INT32, BASE_DEC, VALS(ftam_Lock_vals), 0,
        "Lock", HFILL }},
    { &hf_ftam_object_type,
      { "object-type", "ftam.object_type",
        FT_INT32, BASE_DEC, VALS(ftam_Object_Type_Attribute_vals), 0,
        "Object_Type_Attribute", HFILL }},
    { &hf_ftam_permitted_actions,
      { "permitted-actions", "ftam.permitted_actions",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Permitted_Actions_Attribute", HFILL }},
    { &hf_ftam_access_control,
      { "access-control", "ftam.access_control",
        FT_UINT32, BASE_DEC, VALS(ftam_Access_Control_Attribute_vals), 0,
        "Access_Control_Attribute", HFILL }},
    { &hf_ftam_path_access_control,
      { "path-access-control", "ftam.path_access_control",
        FT_UINT32, BASE_DEC, VALS(ftam_Access_Control_Attribute_vals), 0,
        "Access_Control_Attribute", HFILL }},
    { &hf_ftam__untag_item_02,
      { "_untag item", "ftam._untag_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Diagnostic_item", HFILL }},
    { &hf_ftam_diagnostic_type,
      { "diagnostic-type", "ftam.diagnostic_type",
        FT_INT32, BASE_DEC, VALS(ftam_T_diagnostic_type_vals), 0,
        NULL, HFILL }},
    { &hf_ftam_error_identifier,
      { "error-identifier", "ftam.error_identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ftam_error_observer,
      { "error-observer", "ftam.error_observer",
        FT_INT32, BASE_DEC, VALS(ftam_Entity_Reference_vals), 0,
        "Entity_Reference", HFILL }},
    { &hf_ftam_error_Source,
      { "error-Source", "ftam.error_Source",
        FT_INT32, BASE_DEC, VALS(ftam_Entity_Reference_vals), 0,
        "Entity_Reference", HFILL }},
    { &hf_ftam_suggested_delay,
      { "suggested-delay", "ftam.suggested_delay",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ftam_further_details,
      { "further-details", "ftam.further_details",
        FT_STRING, BASE_NONE, NULL, 0,
        "GraphicString", HFILL }},
    { &hf_ftam_first_last,
      { "first-last", "ftam.first_last",
        FT_INT32, BASE_DEC, VALS(ftam_T_first_last_vals), 0,
        "T_first_last", HFILL }},
    { &hf_ftam_relative,
      { "relative", "ftam.relative",
        FT_INT32, BASE_DEC, VALS(ftam_T_relative_vals), 0,
        NULL, HFILL }},
    { &hf_ftam_begin_end,
      { "begin-end", "ftam.begin_end",
        FT_INT32, BASE_DEC, VALS(ftam_T_begin_end_vals), 0,
        NULL, HFILL }},
    { &hf_ftam_single_name,
      { "single-name", "ftam.single_name_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Node_Name", HFILL }},
    { &hf_ftam_name_list,
      { "name-list", "ftam.name_list",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Node_Name", HFILL }},
    { &hf_ftam_name_list_item,
      { "Node-Name", "ftam.Node_Name_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_fadu_number,
      { "fadu-number", "ftam.fadu_number",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ftam_graphicString,
      { "graphicString", "ftam.graphicString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_octetString,
      { "octetString", "ftam.octetString",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_ftam_linked_Object,
      { "linked-Object", "ftam.linked_Object",
        FT_UINT32, BASE_DEC, VALS(ftam_Pathname_Attribute_vals), 0,
        "Pathname_Attribute", HFILL }},
    { &hf_ftam_child_objects,
      { "child-objects", "ftam.child_objects",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Child_Objects_Attribute", HFILL }},
    { &hf_ftam_primaty_pathname,
      { "primaty-pathname", "ftam.primaty_pathname",
        FT_UINT32, BASE_DEC, VALS(ftam_Pathname_Attribute_vals), 0,
        "Pathname_Attribute", HFILL }},
    { &hf_ftam_date_and_time_of_creation,
      { "date-and-time-of-creation", "ftam.date_and_time_of_creation",
        FT_UINT32, BASE_DEC, VALS(ftam_Date_and_Time_Attribute_vals), 0,
        "Date_and_Time_Attribute", HFILL }},
    { &hf_ftam_date_and_time_of_last_modification,
      { "date-and-time-of-last-modification", "ftam.date_and_time_of_last_modification",
        FT_UINT32, BASE_DEC, VALS(ftam_Date_and_Time_Attribute_vals), 0,
        "Date_and_Time_Attribute", HFILL }},
    { &hf_ftam_date_and_time_of_last_read_access,
      { "date-and-time-of-last-read-access", "ftam.date_and_time_of_last_read_access",
        FT_UINT32, BASE_DEC, VALS(ftam_Date_and_Time_Attribute_vals), 0,
        "Date_and_Time_Attribute", HFILL }},
    { &hf_ftam_date_and_time_of_last_attribute_modification,
      { "date-and-time-of-last-attribute-modification", "ftam.date_and_time_of_last_attribute_modification",
        FT_UINT32, BASE_DEC, VALS(ftam_Date_and_Time_Attribute_vals), 0,
        "Date_and_Time_Attribute", HFILL }},
    { &hf_ftam_identity_of_creator,
      { "identity-of-creator", "ftam.identity_of_creator",
        FT_UINT32, BASE_DEC, VALS(ftam_User_Identity_Attribute_vals), 0,
        "User_Identity_Attribute", HFILL }},
    { &hf_ftam_identity_of_last_modifier,
      { "identity-of-last-modifier", "ftam.identity_of_last_modifier",
        FT_UINT32, BASE_DEC, VALS(ftam_User_Identity_Attribute_vals), 0,
        "User_Identity_Attribute", HFILL }},
    { &hf_ftam_identity_of_last_reader,
      { "identity-of-last-reader", "ftam.identity_of_last_reader",
        FT_UINT32, BASE_DEC, VALS(ftam_User_Identity_Attribute_vals), 0,
        "User_Identity_Attribute", HFILL }},
    { &hf_ftam_identity_last_attribute_modifier,
      { "identity-last-attribute-modifier", "ftam.identity_last_attribute_modifier",
        FT_UINT32, BASE_DEC, VALS(ftam_User_Identity_Attribute_vals), 0,
        "User_Identity_Attribute", HFILL }},
    { &hf_ftam_object_size,
      { "object-size", "ftam.object_size",
        FT_UINT32, BASE_DEC, VALS(ftam_Object_Size_Attribute_vals), 0,
        "Object_Size_Attribute", HFILL }},
    { &hf_ftam_no_value_available,
      { "no-value-available", "ftam.no_value_available_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_actual_values3,
      { "actual-values", "ftam.actual_values3",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Access_Control_Element", HFILL }},
    { &hf_ftam_actual_values3_item,
      { "Access-Control-Element", "ftam.Access_Control_Element_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_actual_values1,
      { "actual-values", "ftam.actual_values1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_actual_values1", HFILL }},
    { &hf_ftam_insert_values,
      { "insert-values", "ftam.insert_values",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Access_Control_Element", HFILL }},
    { &hf_ftam_insert_values_item,
      { "Access-Control-Element", "ftam.Access_Control_Element_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_delete_values,
      { "delete-values", "ftam.delete_values",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Access_Control_Element", HFILL }},
    { &hf_ftam_delete_values_item,
      { "Access-Control-Element", "ftam.Access_Control_Element_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_action_list,
      { "action-list", "ftam.action_list",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Access_Request", HFILL }},
    { &hf_ftam_concurrency_access,
      { "concurrency-access", "ftam.concurrency_access_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_identity,
      { "identity", "ftam.identity",
        FT_STRING, BASE_NONE, NULL, 0,
        "User_Identity", HFILL }},
    { &hf_ftam_passwords,
      { "passwords", "ftam.passwords_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Access_Passwords", HFILL }},
    { &hf_ftam_location,
      { "location", "ftam.location",
        FT_UINT32, BASE_DEC, VALS(acse_AE_title_vals), 0,
        "Application_Entity_Title", HFILL }},
    { &hf_ftam_read_key,
      { "read", "ftam.read_key",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Concurrency_Key", HFILL }},
    { &hf_ftam_insert_key,
      { "insert", "ftam.insert_key",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Concurrency_Key", HFILL }},
    { &hf_ftam_replace_key,
      { "replace", "ftam.replace_key",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Concurrency_Key", HFILL }},
    { &hf_ftam_extend_key,
      { "extend", "ftam.extend_key",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Concurrency_Key", HFILL }},
    { &hf_ftam_erase_key,
      { "erase", "ftam.erase_key",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Concurrency_Key", HFILL }},
    { &hf_ftam_read_attribute_key,
      { "read-attribute", "ftam.read_attribute_key",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Concurrency_Key", HFILL }},
    { &hf_ftam_change_attribute_key,
      { "change-attribute", "ftam.change_attribute_key",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Concurrency_Key", HFILL }},
    { &hf_ftam_delete_Object_key,
      { "delete-Object", "ftam.delete_Object_key",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Concurrency_Key", HFILL }},
    { &hf_ftam_actual_values2,
      { "actual-values", "ftam.actual_values2",
        FT_STRING, BASE_NONE, NULL, 0,
        "Account", HFILL }},
    { &hf_ftam_document_type,
      { "document-type", "ftam.document_type_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_document_type", HFILL }},
    { &hf_ftam_parameter,
      { "parameter", "ftam.parameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_constraint_set_and_abstract_Syntax,
      { "constraint-set-and-abstract-Syntax", "ftam.constraint_set_and_abstract_Syntax_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_constraint_set_and_abstract_Syntax", HFILL }},
    { &hf_ftam_constraint_set_name,
      { "constraint-set-name", "ftam.constraint_set_name",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_actual_values5,
      { "actual-values", "ftam.actual_values5",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_ftam_actual_values8,
      { "actual-values", "ftam.actual_values8",
        FT_INT32, BASE_DEC, VALS(ftam_T_actual_values8_vals), 0,
        "T_actual_values8", HFILL }},
    { &hf_ftam_incomplete_pathname,
      { "incomplete-pathname", "ftam.incomplete_pathname",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Pathname", HFILL }},
    { &hf_ftam_complete_pathname,
      { "complete-pathname", "ftam.complete_pathname",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Pathname", HFILL }},
    { &hf_ftam_actual_values7,
      { "actual-values", "ftam.actual_values7",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ftam_actual_values9,
      { "actual-values", "ftam.actual_values9",
        FT_STRING, BASE_NONE, NULL, 0,
        "GraphicString", HFILL }},
    { &hf_ftam_abstract_Syntax_not_supported,
      { "abstract-Syntax-not-supported", "ftam.abstract_Syntax_not_supported_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_actual_values4,
      { "actual-values", "ftam.actual_values4_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_ftam_actual_values6,
      { "actual-values", "ftam.actual_values6",
        FT_STRING, BASE_NONE, NULL, 0,
        "User_Identity", HFILL }},
    { &hf_ftam_Child_Objects_Attribute_item,
      { "Child-Objects-Attribute item", "ftam.Child_Objects_Attribute_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "GraphicString", HFILL }},
    { &hf_ftam_f_Change_prefix_request,
      { "f-Change-prefix-request", "ftam.f_Change_prefix_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_Change_prefix_response,
      { "f-Change-prefix-response", "ftam.f_Change_prefix_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_list_request,
      { "f-list-request", "ftam.f_list_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_list_response,
      { "f-list-response", "ftam.f_list_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_group_select_request,
      { "f-group-select-request", "ftam.f_group_select_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_group_select_response,
      { "f-group-select-response", "ftam.f_group_select_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_group_delete_request,
      { "f-group-delete-request", "ftam.f_group_delete_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_group_delete_response,
      { "f-group-delete-response", "ftam.f_group_delete_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_group_move_request,
      { "f-group-move-request", "ftam.f_group_move_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_group_move_response,
      { "f-group-move-response", "ftam.f_group_move_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_group_copy_request,
      { "f-group-copy-request", "ftam.f_group_copy_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_group_copy_response,
      { "f-group-copy-response", "ftam.f_group_copy_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_group_list_request,
      { "f-group-list-request", "ftam.f_group_list_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_group_list_response,
      { "f-group-list-response", "ftam.f_group_list_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_group_Change_attrib_request,
      { "f-group-Change-attrib-request", "ftam.f_group_Change_attrib_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_group_Change_attrib_response,
      { "f-group-Change-attrib-response", "ftam.f_group_Change_attrib_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_select_another_request,
      { "f-select-another-request", "ftam.f_select_another_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_select_another_response,
      { "f-select-another-response", "ftam.f_select_another_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_create_directory_request,
      { "f-create-directory-request", "ftam.f_create_directory_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_create_directory_response,
      { "f-create-directory-response", "ftam.f_create_directory_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_link_request,
      { "f-link-request", "ftam.f_link_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_link_response,
      { "f-link-response", "ftam.f_link_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_unlink_request,
      { "f-unlink-request", "ftam.f_unlink_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_unlink_response,
      { "f-unlink-response", "ftam.f_unlink_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_read_link_attrib_request,
      { "f-read-link-attrib-request", "ftam.f_read_link_attrib_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_read_link_attrib_response,
      { "f-read-link-attrib-response", "ftam.f_read_link_attrib_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_Change_link_attrib_request,
      { "f-Change-link-attrib-request", "ftam.f_Change_link_attrib_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_Change_Iink_attrib_response,
      { "f-Change-Iink-attrib-response", "ftam.f_Change_Iink_attrib_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "F_CHANGE_LINK_ATTRIB_response", HFILL }},
    { &hf_ftam_f_move_request,
      { "f-move-request", "ftam.f_move_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_move_response,
      { "f-move-response", "ftam.f_move_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_copy_request,
      { "f-copy-request", "ftam.f_copy_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_f_copy_response,
      { "f-copy-response", "ftam.f_copy_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_reset,
      { "reset", "ftam.reset",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ftam_destination_file_directory,
      { "destination-file-directory", "ftam.destination_file_directory",
        FT_UINT32, BASE_DEC, VALS(ftam_Pathname_Attribute_vals), 0,
        NULL, HFILL }},
    { &hf_ftam_attribute_value_asset_tions,
      { "attribute-value-asset-tions", "ftam.attribute_value_asset_tions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Attribute_Value_Assertions", HFILL }},
    { &hf_ftam_scope,
      { "scope", "ftam.scope",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_objects_attributes_list,
      { "objects-attributes-list", "ftam.objects_attributes_list",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_attribute_value_assertions,
      { "attribute-value-assertions", "ftam.attribute_value_assertions",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_maximum_set_size,
      { "maximum-set-size", "ftam.maximum_set_size",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ftam_request_Operation_result,
      { "request-Operation-result", "ftam.request_Operation_result",
        FT_INT32, BASE_DEC, VALS(ftam_Request_Operation_Result_U_vals), 0,
        NULL, HFILL }},
    { &hf_ftam_operation_result,
      { "operation-result", "ftam.operation_result",
        FT_UINT32, BASE_DEC, VALS(ftam_Operation_Result_U_vals), 0,
        NULL, HFILL }},
    { &hf_ftam_error_action,
      { "error-action", "ftam.error_action",
        FT_INT32, BASE_DEC, VALS(ftam_Error_Action_vals), 0,
        NULL, HFILL }},
    { &hf_ftam_last_member_indicator,
      { "last-member-indicator", "ftam.last_member_indicator",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ftam_shared_ASE_infonnation,
      { "shared-ASE-infonnation", "ftam.shared_ASE_infonnation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Shared_ASE_Information", HFILL }},
    { &hf_ftam_target_object,
      { "target-object", "ftam.target_object",
        FT_UINT32, BASE_DEC, VALS(ftam_Pathname_Attribute_vals), 0,
        "Pathname_Attribute", HFILL }},
    { &hf_ftam_target_Object,
      { "target-Object", "ftam.target_Object",
        FT_UINT32, BASE_DEC, VALS(ftam_Pathname_Attribute_vals), 0,
        "Pathname_Attribute", HFILL }},
    { &hf_ftam_read_link_attributes,
      { "attributes", "ftam.attributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Read_Attributes", HFILL }},
    { &hf_ftam_Attribute_Extension_Names_item,
      { "Attribute-Extension-Set-Name", "ftam.Attribute_Extension_Set_Name_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_extension_set_identifier,
      { "extension-set-identifier", "ftam.extension_set_identifier",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_extension_attribute_names,
      { "extension-attribute-names", "ftam.extension_attribute_names",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension_Attribute_identifier", HFILL }},
    { &hf_ftam_extension_attribute_names_item,
      { "Extension-Attribute-identifier", "ftam.Extension_Attribute_identifier",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Extensions_item,
      { "Attribute-Extension-Set", "ftam.Attribute_Extension_Set_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_extension_set_attributes,
      { "extension-set-attributes", "ftam.extension_set_attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension_Attribute", HFILL }},
    { &hf_ftam_extension_set_attributes_item,
      { "Extension-Attribute", "ftam.Extension_Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_extension_attribute_identifier,
      { "extension-attribute-identifier", "ftam.extension_attribute_identifier",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_extension_attribute,
      { "extension-attribute", "ftam.extension_attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam__untag_item_03,
      { "_untag item", "ftam._untag_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_root_directory,
      { "root-directory", "ftam.root_directory",
        FT_UINT32, BASE_DEC, VALS(ftam_Pathname_Attribute_vals), 0,
        "Pathname_Attribute", HFILL }},
    { &hf_ftam_retrieval_scope,
      { "retrieval-scope", "ftam.retrieval_scope",
        FT_INT32, BASE_DEC, VALS(ftam_T_retrieval_scope_vals), 0,
        NULL, HFILL }},
    { &hf_ftam_OR_Set_item,
      { "AND-Set", "ftam.AND_Set",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_AND_Set_item,
      { "AND-Set item", "ftam.AND_Set_item",
        FT_UINT32, BASE_DEC, VALS(ftam_AND_Set_item_vals), 0,
        NULL, HFILL }},
    { &hf_ftam_pathname_Pattern,
      { "pathname-Pattern", "ftam.pathname_Pattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_object_type_Pattern,
      { "object-type-Pattern", "ftam.object_type_Pattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Integer_Pattern", HFILL }},
    { &hf_ftam_permitted_actions_Pattern,
      { "permitted-actions-Pattern", "ftam.permitted_actions_Pattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Bitstring_Pattern", HFILL }},
    { &hf_ftam_contents_type_Pattern,
      { "contents-type-Pattern", "ftam.contents_type_Pattern",
        FT_UINT32, BASE_DEC, VALS(ftam_Contents_Type_Pattern_vals), 0,
        NULL, HFILL }},
    { &hf_ftam_linked_Object_Pattern,
      { "linked-Object-Pattern", "ftam.linked_Object_Pattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Pathname_Pattern", HFILL }},
    { &hf_ftam_child_objects_Pattern,
      { "child-objects-Pattern", "ftam.child_objects_Pattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Pathname_Pattern", HFILL }},
    { &hf_ftam_primaty_pathname_Pattern,
      { "primaty-pathname-Pattern", "ftam.primaty_pathname_Pattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Pathname_Pattern", HFILL }},
    { &hf_ftam_storage_account_Pattern,
      { "storage-account-Pattern", "ftam.storage_account_Pattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "String_Pattern", HFILL }},
    { &hf_ftam_date_and_time_of_creation_Pattern,
      { "date-and-time-of-creation-Pattern", "ftam.date_and_time_of_creation_Pattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Date_and_Time_Pattern", HFILL }},
    { &hf_ftam_date_and_time_of_last_modification_Pattern,
      { "date-and-time-of-last-modification-Pattern", "ftam.date_and_time_of_last_modification_Pattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Date_and_Time_Pattern", HFILL }},
    { &hf_ftam_date_and_time_of_last_read_access_Pattern,
      { "date-and-time-of-last-read-access-Pattern", "ftam.date_and_time_of_last_read_access_Pattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Date_and_Time_Pattern", HFILL }},
    { &hf_ftam_date_and_time_of_last_attribute_modification_Pattern,
      { "date-and-time-of-last-attribute-modification-Pattern", "ftam.date_and_time_of_last_attribute_modification_Pattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Date_and_Time_Pattern", HFILL }},
    { &hf_ftam_identity_of_creator_Pattern,
      { "identity-of-creator-Pattern", "ftam.identity_of_creator_Pattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "User_Identity_Pattern", HFILL }},
    { &hf_ftam_identity_of_last_modifier_Pattern,
      { "identity-of-last-modifier-Pattern", "ftam.identity_of_last_modifier_Pattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "User_Identity_Pattern", HFILL }},
    { &hf_ftam_identity_of_last_reader_Pattern,
      { "identity-of-last-reader-Pattern", "ftam.identity_of_last_reader_Pattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "User_Identity_Pattern", HFILL }},
    { &hf_ftam_identity_of_last_attribute_modifier_Pattern,
      { "identity-of-last-attribute-modifier-Pattern", "ftam.identity_of_last_attribute_modifier_Pattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "User_Identity_Pattern", HFILL }},
    { &hf_ftam_object_availabiiity_Pattern,
      { "object-availabiiity-Pattern", "ftam.object_availabiiity_Pattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Boolean_Pattern", HFILL }},
    { &hf_ftam_object_size_Pattern,
      { "object-size-Pattern", "ftam.object_size_Pattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Integer_Pattern", HFILL }},
    { &hf_ftam_future_object_size_Pattern,
      { "future-object-size-Pattern", "ftam.future_object_size_Pattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Integer_Pattern", HFILL }},
    { &hf_ftam_legal_quailfication_Pattern,
      { "legal-quailfication-Pattern", "ftam.legal_quailfication_Pattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "String_Pattern", HFILL }},
    { &hf_ftam_attribute_extensions_pattern,
      { "attribute-extensions-pattern", "ftam.attribute_extensions_pattern",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_equality_comparision,
      { "equality-comparision", "ftam.equality_comparision",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_pathname_value,
      { "pathname-value", "ftam.pathname_value",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_pathname_value_item,
      { "pathname-value item", "ftam.pathname_value_item",
        FT_UINT32, BASE_DEC, VALS(ftam_T_pathname_value_item_vals), 0,
        NULL, HFILL }},
    { &hf_ftam_string_match,
      { "string-match", "ftam.string_match_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "String_Pattern", HFILL }},
    { &hf_ftam_any_match,
      { "any-match", "ftam.any_match_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_string_value,
      { "string-value", "ftam.string_value",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_string_value_item,
      { "string-value item", "ftam.string_value_item",
        FT_UINT32, BASE_DEC, VALS(ftam_T_string_value_item_vals), 0,
        NULL, HFILL }},
    { &hf_ftam_substring_match,
      { "substring-match", "ftam.substring_match",
        FT_STRING, BASE_NONE, NULL, 0,
        "GraphicString", HFILL }},
    { &hf_ftam_number_of_characters_match,
      { "number-of-characters-match", "ftam.number_of_characters_match",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ftam_match_bitstring,
      { "match-bitstring", "ftam.match_bitstring",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_ftam_significance_bitstring,
      { "significance-bitstring", "ftam.significance_bitstring",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_ftam_relational_camparision,
      { "relational-camparision", "ftam.relational_camparision",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Equality_Comparision", HFILL }},
    { &hf_ftam_time_and_date_value,
      { "time-and-date-value", "ftam.time_and_date_value",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_ftam_relational_comparision,
      { "relational-comparision", "ftam.relational_comparision",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_integer_value,
      { "integer-value", "ftam.integer_value",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ftam_object_identifier_value,
      { "object-identifier-value", "ftam.object_identifier_value",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_ftam_boolean_value,
      { "boolean-value", "ftam.boolean_value",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ftam_document_type_Pattern,
      { "document-type-Pattern", "ftam.document_type_Pattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Object_Identifier_Pattern", HFILL }},
    { &hf_ftam_constraint_set_abstract_Syntax_Pattern,
      { "constraint-set-abstract-Syntax-Pattern", "ftam.constraint_set_abstract_Syntax_Pattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_constraint_set_abstract_Syntax_Pattern", HFILL }},
    { &hf_ftam_constraint_Set_Pattern,
      { "constraint-Set-Pattern", "ftam.constraint_Set_Pattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Object_Identifier_Pattern", HFILL }},
    { &hf_ftam_abstract_Syntax_Pattern,
      { "abstract-Syntax-Pattern", "ftam.abstract_Syntax_Pattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Object_Identifier_Pattern", HFILL }},
    { &hf_ftam_Attribute_Extensions_Pattern_item,
      { "Attribute-Extensions-Pattern item", "ftam.Attribute_Extensions_Pattern_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_extension_set_attribute_Patterns,
      { "extension-set-attribute-Patterns", "ftam.extension_set_attribute_Patterns",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_extension_set_attribute_Patterns", HFILL }},
    { &hf_ftam_extension_set_attribute_Patterns_item,
      { "extension-set-attribute-Patterns item", "ftam.extension_set_attribute_Patterns_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_extension_set_attribute_Patterns_item", HFILL }},
    { &hf_ftam_attribute_extension_attribute_identifier,
      { "extension-attribute-identifier", "ftam.extension_attribute_identifier",
        FT_OID, BASE_NONE, NULL, 0,
        "T_attribute_extension_attribute_identifier", HFILL }},
    { &hf_ftam_extension_attribute_Pattern,
      { "extension-attribute-Pattern", "ftam.extension_attribute_Pattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam__untag_item_04,
      { "Read-Attributes", "ftam.Read_Attributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_success_Object_count,
      { "success-Object-count", "ftam.success_Object_count",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ftam_success_Object_names,
      { "success-Object-names", "ftam.success_Object_names",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Pathname", HFILL }},
    { &hf_ftam_success_Object_names_item,
      { "Pathname", "ftam.Pathname",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ftam_Pathname_item,
      { "Pathname item", "ftam.Pathname_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "GraphicString", HFILL }},
    { &hf_ftam_Pass_Passwords_item,
      { "Password", "ftam.Password",
        FT_UINT32, BASE_DEC, VALS(ftam_Password_U_vals), 0,
        NULL, HFILL }},
    { &hf_ftam__untag_item_05,
      { "_untag item", "ftam._untag_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Path_Access_Passwords_item", HFILL }},
    { &hf_ftam_ap,
      { "ap", "ftam.ap",
        FT_UINT32, BASE_DEC, VALS(acse_AP_title_vals), 0,
        "AP_title", HFILL }},
    { &hf_ftam_ae,
      { "ae", "ftam.ae",
        FT_UINT32, BASE_DEC, VALS(acse_ASO_qualifier_vals), 0,
        "AE_qualifier", HFILL }},
    { &hf_ftam_Protocol_Version_U_version_1,
      { "version-1", "ftam.Protocol.Version.U.version.1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ftam_Protocol_Version_U_version_2,
      { "version-2", "ftam.Protocol.Version.U.version.2",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ftam_Service_Class_U_unconstrained_class,
      { "unconstrained-class", "ftam.Service.Class.U.unconstrained.class",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ftam_Service_Class_U_management_class,
      { "management-class", "ftam.Service.Class.U.management.class",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ftam_Service_Class_U_transfer_class,
      { "transfer-class", "ftam.Service.Class.U.transfer.class",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ftam_Service_Class_U_transfer_and_management_class,
      { "transfer-and-management-class", "ftam.Service.Class.U.transfer.and.management.class",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ftam_Service_Class_U_access_class,
      { "access-class", "ftam.Service.Class.U.access.class",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_ftam_Functional_Units_U_spare_bit0,
      { "spare_bit0", "ftam.Functional.Units.U.spare.bit0",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ftam_Functional_Units_U_spare_bit1,
      { "spare_bit1", "ftam.Functional.Units.U.spare.bit1",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ftam_Functional_Units_U_read,
      { "read", "ftam.Functional.Units.U.read",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ftam_Functional_Units_U_write,
      { "write", "ftam.Functional.Units.U.write",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ftam_Functional_Units_U_file_access,
      { "file-access", "ftam.Functional.Units.U.file.access",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_ftam_Functional_Units_U_limited_file_management,
      { "limited-file-management", "ftam.Functional.Units.U.limited.file.management",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_ftam_Functional_Units_U_enhanced_file_management,
      { "enhanced-file-management", "ftam.Functional.Units.U.enhanced.file.management",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_ftam_Functional_Units_U_grouping,
      { "grouping", "ftam.Functional.Units.U.grouping",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_ftam_Functional_Units_U_fadu_locking,
      { "fadu-locking", "ftam.Functional.Units.U.fadu.locking",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ftam_Functional_Units_U_recovery,
      { "recovery", "ftam.Functional.Units.U.recovery",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ftam_Functional_Units_U_restart_data_transfer,
      { "restart-data-transfer", "ftam.Functional.Units.U.restart.data.transfer",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ftam_Functional_Units_U_limited_filestore_management,
      { "limited-filestore-management", "ftam.Functional.Units.U.limited.filestore.management",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ftam_Functional_Units_U_enhanced_filestore_management,
      { "enhanced-filestore-management", "ftam.Functional.Units.U.enhanced.filestore.management",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_ftam_Functional_Units_U_object_manipulation,
      { "object-manipulation", "ftam.Functional.Units.U.object.manipulation",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_ftam_Functional_Units_U_group_manipulation,
      { "group-manipulation", "ftam.Functional.Units.U.group.manipulation",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_ftam_Functional_Units_U_consecutive_access,
      { "consecutive-access", "ftam.Functional.Units.U.consecutive.access",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_ftam_Functional_Units_U_concurrent_access,
      { "concurrent-access", "ftam.Functional.Units.U.concurrent.access",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Groups_U_storage,
      { "storage", "ftam.Attribute.Groups.U.storage",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Groups_U_security,
      { "security", "ftam.Attribute.Groups.U.security",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Groups_U_private,
      { "private", "ftam.Attribute.Groups.U.private",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Groups_U_extension,
      { "extension", "ftam.Attribute.Groups.U.extension",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ftam_T_processing_mode_f_read,
      { "f-read", "ftam.T.processing.mode.f.read",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ftam_T_processing_mode_f_insert,
      { "f-insert", "ftam.T.processing.mode.f.insert",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ftam_T_processing_mode_f_replace,
      { "f-replace", "ftam.T.processing.mode.f.replace",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ftam_T_processing_mode_f_extend,
      { "f-extend", "ftam.T.processing.mode.f.extend",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ftam_T_processing_mode_f_erase,
      { "f-erase", "ftam.T.processing.mode.f.erase",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_ftam_Access_Request_U_read,
      { "read", "ftam.Access.Request.U.read",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ftam_Access_Request_U_insert,
      { "insert", "ftam.Access.Request.U.insert",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ftam_Access_Request_U_replace,
      { "replace", "ftam.Access.Request.U.replace",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ftam_Access_Request_U_extend,
      { "extend", "ftam.Access.Request.U.extend",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ftam_Access_Request_U_erase,
      { "erase", "ftam.Access.Request.U.erase",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_ftam_Access_Request_U_read_attribute,
      { "read-attribute", "ftam.Access.Request.U.read.attribute",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_ftam_Access_Request_U_change_attribute,
      { "change-attribute", "ftam.Access.Request.U.change.attribute",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_ftam_Access_Request_U_delete_Object,
      { "delete-Object", "ftam.Access.Request.U.delete.Object",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_ftam_Concurrency_Key_not_required,
      { "not-required", "ftam.Concurrency.Key.not.required",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ftam_Concurrency_Key_shared,
      { "shared", "ftam.Concurrency.Key.shared",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ftam_Concurrency_Key_exclusive,
      { "exclusive", "ftam.Concurrency.Key.exclusive",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ftam_Concurrency_Key_no_access,
      { "no-access", "ftam.Concurrency.Key.no.access",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ftam_Permitted_Actions_Attribute_read,
      { "read", "ftam.Permitted.Actions.Attribute.read",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ftam_Permitted_Actions_Attribute_insert,
      { "insert", "ftam.Permitted.Actions.Attribute.insert",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ftam_Permitted_Actions_Attribute_replace,
      { "replace", "ftam.Permitted.Actions.Attribute.replace",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ftam_Permitted_Actions_Attribute_extend,
      { "extend", "ftam.Permitted.Actions.Attribute.extend",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ftam_Permitted_Actions_Attribute_erase,
      { "erase", "ftam.Permitted.Actions.Attribute.erase",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_ftam_Permitted_Actions_Attribute_read_attribute,
      { "read-attribute", "ftam.Permitted.Actions.Attribute.read.attribute",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_ftam_Permitted_Actions_Attribute_change_attribute,
      { "change-attribute", "ftam.Permitted.Actions.Attribute.change.attribute",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_ftam_Permitted_Actions_Attribute_delete_Object,
      { "delete-Object", "ftam.Permitted.Actions.Attribute.delete.Object",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_ftam_Permitted_Actions_Attribute_traversal,
      { "traversal", "ftam.Permitted.Actions.Attribute.traversal",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ftam_Permitted_Actions_Attribute_reverse_traversal,
      { "reverse-traversal", "ftam.Permitted.Actions.Attribute.reverse.traversal",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ftam_Permitted_Actions_Attribute_random_Order,
      { "random-Order", "ftam.Permitted.Actions.Attribute.random.Order",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ftam_Permitted_Actions_Attribute_pass,
      { "pass", "ftam.Permitted.Actions.Attribute.pass",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ftam_Permitted_Actions_Attribute_link,
      { "link", "ftam.Permitted.Actions.Attribute.link",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_ftam_Equality_Comparision_no_value_available_matches,
      { "no-value-available-matches", "ftam.Equality.Comparision.no.value.available.matches",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ftam_Equality_Comparision_equals_matches,
      { "equals-matches", "ftam.Equality.Comparision.equals.matches",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ftam_Relational_Comparision_no_value_available_matches,
      { "no-value-available-matches", "ftam.Relational.Comparision.no.value.available.matches",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ftam_Relational_Comparision_equals_matches,
      { "equals-matches", "ftam.Relational.Comparision.equals.matches",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ftam_Relational_Comparision_less_than_matches,
      { "less-than-matches", "ftam.Relational.Comparision.less.than.matches",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ftam_Relational_Comparision_greater_than_matches,
      { "greater-than-matches", "ftam.Relational.Comparision.greater.than.matches",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Names_read_pathname,
      { "read-pathname", "ftam.Attribute.Names.read.pathname",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Names_read_permitted_actions,
      { "read-permitted-actions", "ftam.Attribute.Names.read.permitted.actions",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Names_read_contents_type,
      { "read-contents-type", "ftam.Attribute.Names.read.contents.type",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Names_read_storage_account,
      { "read-storage-account", "ftam.Attribute.Names.read.storage.account",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Names_read_date_and_time_of_creation,
      { "read-date-and-time-of-creation", "ftam.Attribute.Names.read.date.and.time.of.creation",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Names_read_date_and_time_of_last_modification,
      { "read-date-and-time-of-last-modification", "ftam.Attribute.Names.read.date.and.time.of.last.modification",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Names_read_date_and_time_of_last_read_access,
      { "read-date-and-time-of-last-read-access", "ftam.Attribute.Names.read.date.and.time.of.last.read.access",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Names_read_date_and_time_of_last_attribute_modification,
      { "read-date-and-time-of-last-attribute-modification", "ftam.Attribute.Names.read.date.and.time.of.last.attribute.modification",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Names_read_identity_of_creator,
      { "read-identity-of-creator", "ftam.Attribute.Names.read.identity.of.creator",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Names_read_identity_of_last_modifier,
      { "read-identity-of-last-modifier", "ftam.Attribute.Names.read.identity.of.last.modifier",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Names_read_identity_of_last_reader,
      { "read-identity-of-last-reader", "ftam.Attribute.Names.read.identity.of.last.reader",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Names_read_identity_of_last_attribute_modifier,
      { "read-identity-of-last-attribute-modifier", "ftam.Attribute.Names.read.identity.of.last.attribute.modifier",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Names_read_Object_availability,
      { "read-Object-availability", "ftam.Attribute.Names.read.Object.availability",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Names_read_Object_size,
      { "read-Object-size", "ftam.Attribute.Names.read.Object.size",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Names_read_future_Object_size,
      { "read-future-Object-size", "ftam.Attribute.Names.read.future.Object.size",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Names_read_access_control,
      { "read-access-control", "ftam.Attribute.Names.read.access.control",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Names_read_l8gal_qualifiCatiOnS,
      { "read-l8gal-qualifiCatiOnS", "ftam.Attribute.Names.read.l8gal.qualifiCatiOnS",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Names_read_private_use,
      { "read-private-use", "ftam.Attribute.Names.read.private.use",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Names_read_Object_type,
      { "read-Object-type", "ftam.Attribute.Names.read.Object.type",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Names_read_linked_Object,
      { "read-linked-Object", "ftam.Attribute.Names.read.linked.Object",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Names_read_primary_pathname,
      { "read-primary-pathname", "ftam.Attribute.Names.read.primary.pathname",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Names_read_path_access_control,
      { "read-path-access-control", "ftam.Attribute.Names.read.path.access.control",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Names_spare_bit22,
      { "spare_bit22", "ftam.Attribute.Names.spare.bit22",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_ftam_Attribute_Names_read_Child_objects,
      { "read-Child-objects", "ftam.Attribute.Names.read.Child.objects",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_ftam,
    &ett_ftam_PDU,
    &ett_ftam_FTAM_Regime_PDU,
    &ett_ftam_F_INITIALIZE_request,
    &ett_ftam_F_INITIALIZE_response,
    &ett_ftam_Protocol_Version_U,
    &ett_ftam_Service_Class_U,
    &ett_ftam_Functional_Units_U,
    &ett_ftam_Attribute_Groups_U,
    &ett_ftam_Contents_Type_List_U,
    &ett_ftam_Contents_Type_List_item,
    &ett_ftam_F_TERMINATE_request,
    &ett_ftam_F_TERMINATE_response,
    &ett_ftam_F_U_ABORT_request,
    &ett_ftam_F_P_ABORT_request,
    &ett_ftam_File_PDU,
    &ett_ftam_F_SELECT_request,
    &ett_ftam_F_SELECT_response,
    &ett_ftam_F_DESELECT_request,
    &ett_ftam_F_DESELECT_response,
    &ett_ftam_F_CREATE_request,
    &ett_ftam_F_CREATE_response,
    &ett_ftam_F_DELETE_request,
    &ett_ftam_F_DELETE_response,
    &ett_ftam_F_READ_ATTRIB_request,
    &ett_ftam_F_READ_ATTRIB_response,
    &ett_ftam_F_CHANGE_ATTRIB_request,
    &ett_ftam_F_CHANGE_ATTRIB_response,
    &ett_ftam_F_OPEN_request,
    &ett_ftam_T_processing_mode,
    &ett_ftam_T_open_contents_type,
    &ett_ftam_SET_OF_Abstract_Syntax_Name,
    &ett_ftam_F_OPEN_response,
    &ett_ftam_F_CLOSE_request,
    &ett_ftam_F_CLOSE_response,
    &ett_ftam_F_BEGIN_GROUP_request,
    &ett_ftam_F_BEGIN_GROUP_response,
    &ett_ftam_F_END_GROUP_request,
    &ett_ftam_F_END_GROUP_response,
    &ett_ftam_F_RECOVER_request,
    &ett_ftam_F_RECOVER_response,
    &ett_ftam_F_LOCATE_request,
    &ett_ftam_F_LOCATE_response,
    &ett_ftam_F_ERASE_request,
    &ett_ftam_F_ERASE_response,
    &ett_ftam_Bulk_Data_PDU,
    &ett_ftam_F_READ_request,
    &ett_ftam_F_WRITE_request,
    &ett_ftam_F_DATA_END_request,
    &ett_ftam_F_TRANSFER_END_request,
    &ett_ftam_F_TRANSFER_END_response,
    &ett_ftam_F_CANCEL_request,
    &ett_ftam_F_CANCEL_response,
    &ett_ftam_F_RESTART_request,
    &ett_ftam_F_RESTART_response,
    &ett_ftam_Access_Context_U,
    &ett_ftam_Access_Passwords_U,
    &ett_ftam_Access_Request_U,
    &ett_ftam_Change_Attributes_U,
    &ett_ftam_Charging_U,
    &ett_ftam_Charging_item,
    &ett_ftam_Concurrency_Control_U,
    &ett_ftam_Create_Attributes_U,
    &ett_ftam_Diagnostic_U,
    &ett_ftam_Diagnostic_item,
    &ett_ftam_FADU_Identity_U,
    &ett_ftam_SEQUENCE_OF_Node_Name,
    &ett_ftam_Password_U,
    &ett_ftam_Read_Attributes_U,
    &ett_ftam_Select_Attributes_U,
    &ett_ftam_Access_Control_Attribute,
    &ett_ftam_SET_OF_Access_Control_Element,
    &ett_ftam_Access_Control_Change_Attribute,
    &ett_ftam_T_actual_values1,
    &ett_ftam_Access_Control_Element,
    &ett_ftam_Concurrency_Access,
    &ett_ftam_Concurrency_Key,
    &ett_ftam_Account_Attribute,
    &ett_ftam_Contents_Type_Attribute,
    &ett_ftam_T_document_type,
    &ett_ftam_T_constraint_set_and_abstract_Syntax,
    &ett_ftam_Date_and_Time_Attribute,
    &ett_ftam_Object_Availability_Attribute,
    &ett_ftam_Pathname_Attribute,
    &ett_ftam_Object_Size_Attribute,
    &ett_ftam_Legal_Qualification_Attribute,
    &ett_ftam_Permitted_Actions_Attribute,
    &ett_ftam_Private_Use_Attribute,
    &ett_ftam_User_Identity_Attribute,
    &ett_ftam_Child_Objects_Attribute,
    &ett_ftam_FSM_PDU,
    &ett_ftam_F_CHANGE_PREFIX_request,
    &ett_ftam_F_CHANGE_PREFIX_response,
    &ett_ftam_F_LIST_request,
    &ett_ftam_F_LIST_response,
    &ett_ftam_F_GROUP_SELECT_request,
    &ett_ftam_F_GROUP_SELECT_response,
    &ett_ftam_F_GROUP_DELETE_request,
    &ett_ftam_F_GROUP_DELETE_response,
    &ett_ftam_F_GROUP_MOVE_request,
    &ett_ftam_F_GROUP_MOVE_response,
    &ett_ftam_F_GROUP_COPY_request,
    &ett_ftam_F_GROUP_COPY_response,
    &ett_ftam_F_GROUP_LIST_request,
    &ett_ftam_F_GROUP_LIST_response,
    &ett_ftam_F_GROUP_CHANGE_ATTRIB_request,
    &ett_ftam_F_GROUP_CHANGE_ATTRIB_response,
    &ett_ftam_F_SELECT_ANOTHER_request,
    &ett_ftam_F_SELECT_ANOTHER_response,
    &ett_ftam_F_CREATE_DIRECTORY_request,
    &ett_ftam_F_CREATE_DIRECTORY_response,
    &ett_ftam_F_LINK_request,
    &ett_ftam_F_LINK_response,
    &ett_ftam_F_UNLINK_request,
    &ett_ftam_F_UNLINK_response,
    &ett_ftam_F_READ_LINK_ATTRIB_request,
    &ett_ftam_F_READ_LINK_ATTRIB_response,
    &ett_ftam_F_CHANGE_LINK_ATTRIB_request,
    &ett_ftam_F_CHANGE_LINK_ATTRIB_response,
    &ett_ftam_F_MOVE_request,
    &ett_ftam_F_MOVE_response,
    &ett_ftam_F_COPY_request,
    &ett_ftam_F_COPY_response,
    &ett_ftam_Attribute_Extension_Names,
    &ett_ftam_Attribute_Extension_Set_Name,
    &ett_ftam_SEQUENCE_OF_Extension_Attribute_identifier,
    &ett_ftam_Attribute_Extensions,
    &ett_ftam_Attribute_Extension_Set,
    &ett_ftam_SEQUENCE_OF_Extension_Attribute,
    &ett_ftam_Extension_Attribute,
    &ett_ftam_Scope_U,
    &ett_ftam_T__untag_item,
    &ett_ftam_OR_Set,
    &ett_ftam_AND_Set,
    &ett_ftam_AND_Set_item,
    &ett_ftam_Equality_Comparision,
    &ett_ftam_Relational_Comparision,
    &ett_ftam_Pathname_Pattern,
    &ett_ftam_T_pathname_value,
    &ett_ftam_T_pathname_value_item,
    &ett_ftam_String_Pattern,
    &ett_ftam_T_string_value,
    &ett_ftam_T_string_value_item,
    &ett_ftam_Bitstring_Pattern,
    &ett_ftam_Date_and_Time_Pattern,
    &ett_ftam_Integer_Pattern,
    &ett_ftam_Object_Identifier_Pattern,
    &ett_ftam_Boolean_Pattern,
    &ett_ftam_Contents_Type_Pattern,
    &ett_ftam_T_constraint_set_abstract_Syntax_Pattern,
    &ett_ftam_Attribute_Extensions_Pattern,
    &ett_ftam_Attribute_Extensions_Pattern_item,
    &ett_ftam_T_extension_set_attribute_Patterns,
    &ett_ftam_T_extension_set_attribute_Patterns_item,
    &ett_ftam_SEQUENCE_OF_Read_Attributes,
    &ett_ftam_Operation_Result_U,
    &ett_ftam_SEQUENCE_OF_Pathname,
    &ett_ftam_Pathname,
    &ett_ftam_Pass_Passwords,
    &ett_ftam_Path_Access_Passwords_U,
    &ett_ftam_Path_Access_Passwords_item,
    &ett_ftam_Attribute_Names,
    &ett_ftam_AE_title,
  };
  static ei_register_info ei[] = {
    { &ei_ftam_zero_pdu, { "ftam.zero_pdu", PI_PROTOCOL, PI_ERROR, "Internal error, zero-byte FTAM PDU", EXPFILL }},
  };

  expert_module_t* expert_ftam;

  /* Register protocol */
  proto_ftam = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("ftam", dissect_ftam, proto_ftam);
  /* Register fields and subtrees */
  proto_register_field_array(proto_ftam, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_ftam = expert_register_protocol(proto_ftam);
  expert_register_field_array(expert_ftam, ei, array_length(ei));

}


/*--- proto_reg_handoff_ftam --- */
void proto_reg_handoff_ftam(void) {
	register_ber_oid_dissector("1.0.8571.1.1", dissect_ftam, proto_ftam,"iso-ftam(1)");
	register_ber_oid_dissector("1.0.8571.2.1", dissect_ftam, proto_ftam,"ftam-pci(1)");
	register_ber_oid_dissector("1.3.14.5.2.2", dissect_ftam, proto_ftam,"NIST file directory entry abstract syntax");

	/* Unstructured text file document type FTAM-1 */
	register_ber_oid_dissector("1.0.8571.5.1", dissect_ftam_unstructured_text, proto_ftam,"ISO FTAM unstructured text");
	oid_add_from_string("ISO FTAM sequential text","1.0.8571.5.2");
	oid_add_from_string("FTAM unstructured text abstract syntax","1.0.8571.2.3");
	oid_add_from_string("FTAM simple-hierarchy","1.0.8571.2.5");
	oid_add_from_string("FTAM hierarchical file model","1.0.8571.3.1");
	oid_add_from_string("FTAM unstructured constraint set","1.0.8571.4.1");

	/* Unstructured binary file document type FTAM-3 */
	register_ber_oid_dissector("1.0.8571.5.3", dissect_ftam_unstructured_binary, proto_ftam,"ISO FTAM unstructured binary");
	oid_add_from_string("FTAM unstructured binary abstract syntax","1.0.8571.2.4");

	/* Filedirectory file document type NBS-9 */
	oid_add_from_string("NBS-9 FTAM file directory file","1.3.14.5.5.9");

	/* Filedirectory file document type NBS-9 (WITH OLD NIST OIDs)*/
	oid_add_from_string("NBS-9-OLD FTAM file directory file","1.3.9999.1.5.9");
	oid_add_from_string("NIST file directory entry abstract syntax","1.3.9999.1.2.2");
}
