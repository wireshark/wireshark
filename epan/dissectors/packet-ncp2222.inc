#define FAKE_TREE_IS_VISIBLE 1
/* fake that the tree is visible so that proto.c will not try to
 "fake" generation of finfo values/nodes.
  Thus this means netware dissector is slower than it has to, but it wont crash.
  once the dissector is refactored to avoid calling fvalue_ functions directly this faking of whether the tree is visible or not can be removed.
*/


/* packet-ncp2222.inc
 *
 * Routines for NetWare Core Protocol. This C code gets #include'd
 * into packet-ncp2222.c, which is generated from ncp2222.py. It's
 * #include'd instead of being in a separate compilation unit so
 * that all the data tables in packet-ncp2222.c can remain static.
 *
 * Gilbert Ramirez <gram@alumni.rice.edu>
 * Modified to decode NDS packets by Greg Morris <gmorris@novell.com>
 *
 * Portions Copyright (c) Gilbert Ramirez 2000-2002
 * Portions Copyright (c) Novell, Inc. 2000-2003
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

gboolean    nds_defragment  = TRUE;
gboolean    nds_echo_eid    = TRUE;
gboolean    ncp_echo_err    = TRUE;
gboolean    ncp_echo_conn   = FALSE;
gboolean    ncp_echo_server = TRUE;
gboolean    ncp_echo_file   = FALSE;
gboolean    ncp_newstyle    = TRUE;

extern dissector_handle_t nds_data_handle;
typedef struct {
    guint32     nds_frag_verb;
    guint32     nds_frag_version;
    guint32     nds_frag_flags;
    guint32     nds_frag_prot_flags;
    guint32     nds_length;
    guint32     nds_frag;
    gboolean    nds_fragmented;
    guint8      sequence;
} frag_info;

static frag_info           frags[100];
static char    mv_resolve_name_string[128];

static const fragment_items nds_frag_items = {
    &ett_nds_segment,
    &ett_nds_segments,
    &hf_nds_segments,
    &hf_nds_segment,
    &hf_nds_segment_overlap,
    &hf_nds_segment_overlap_conflict,
    &hf_nds_segment_multiple_tails,
    &hf_nds_segment_too_long_segment,
    &hf_nds_segment_error,
    &hf_nds_segment_count,
    NULL,
    &hf_nds_reassembled_length,
    /* Reassembled data field */
    NULL,
    "segments"
};

/* Table for reassembly of fragments. */
static reassembly_table nds_reassembly_table;

#define NDS_TAG_NO_SUCH_ENTRY           0x00000000
#define NDS_TAG_LOCAL_ENTRY             0x00000001
#define NDS_TAG_REMOTE_ENTRY            0x00000002
#define NDS_TAG_ALIAS_ENTRY             0x00000003
#define NDS_TAG_REFERRAL_INFORMATION    0x00000004
#define NDS_TAG_ENTRY_AND_REFERRALS     0x00000006

/* Search objects */
#define NDS_SEARCH_ENTRY                         0
#define NDS_SEARCH_SUBORDINATES                  1
#define NDS_SEARCH_SUBTREE                       2
#define NDS_SEARCH_PARTITION                     3

/* Search Referral Types */
#define NDS_ALIAS_REFERRAL                       0
#define NDS_PARTITION_REFERRAL                   1

/* Search Filter Types */
#define NDS_SEARCH_ITEM                          0
#define NDS_SEARCH_OR                            1
#define NDS_SEARCH_AND                           2
#define NDS_SEARCH_NOT                           3

/* Search Operators */
#define NDS_SEARCH_EQUAL                         7
#define NDS_SEARCH_GREATER_OR_EQUAL              8
#define NDS_SEARCH_LESS_OR_EQUAL                 9
#define NDS_SEARCH_APPROX                       10
#define NDS_SEARCH_PRESENT                      15
#define NDS_SEARCH_RDN                          16
#define NDS_SEARCH_BASE_CLASS                   17
#define NDS_SEARCH_MODIFICATION_GE              18  /* Deprecated, use DS_SEARCH_ENTRY_MTS_GE */
#define NDS_SEARCH_VALUE_TIME_GE                19  /* Deprecated, use DS_SEARCH_VALUE_MTS_GE */
#define NDS_SEARCH_REFERENCES                   20
#define NDS_SEARCH_DN_IN_VALUE                  21
#define NDS_SEARCH_SCHEMA_IN_VALUE              22
#define NDS_SEARCH_ENTRY_FLAGS                  23
#define NDS_SEARCH_ENTRY_HAS_FLAG               24
#define NDS_SEARCH_VALUE_FLAGS                  25
#define NDS_SEARCH_VALUE_HAS_FLAG               26
#define NDS_SEARCH_ATTR_FLAGS                   27
#define NDS_SEARCH_ATTR_HAS_FLAG                28
#define NDS_SEARCH_EID                          29

#define NDS_SEARCH_ENTRY_MTS_GE                 18
#define NDS_SEARCH_ENTRY_MTS_G                  30
#define NDS_SEARCH_ENTRY_MTS_LE                 31
#define NDS_SEARCH_ENTRY_MTS_L                  32
#define NDS_SEARCH_ENTRY_MTS_EQ                 33
#define NDS_SEARCH_ENTRY_MTS_EQ_APPROX          34
#define NDS_SEARCH_VALUE_MTS_GE                 19
#define NDS_SEARCH_VALUE_MTS_G                  35
#define NDS_SEARCH_VALUE_MTS_LE                 36
#define NDS_SEARCH_VALUE_MTS_L                  37
#define NDS_SEARCH_VALUE_MTS_EQ                 38
#define NDS_SEARCH_VALUE_MTS_EQ_APPROX          39

#define NDS_SEARCH_ENTRY_CTS_GE                 40
#define NDS_SEARCH_ENTRY_CTS_G                  41
#define NDS_SEARCH_ENTRY_CTS_LE                 42
#define NDS_SEARCH_ENTRY_CTS_L                  43
#define NDS_SEARCH_ENTRY_CTS_EQ                 44
#define NDS_SEARCH_ENTRY_CTS_EQ_APPROX          45
#define NDS_SEARCH_VALUE_CTS_GE                 46
#define NDS_SEARCH_VALUE_CTS_G                  47
#define NDS_SEARCH_VALUE_CTS_LE                 48
#define NDS_SEARCH_VALUE_CTS_L                  49
#define NDS_SEARCH_VALUE_CTS_EQ                 50
#define NDS_SEARCH_VALUE_CTS_EQ_APPROX          51
#define NDS_SEARCH_EXTENSIBLE                   52
#define NDS_SEARCH_ENTRY_SUBCOUNT_GE            53
#define NDS_SEARCH_ENTRY_SUBCOUNT_G             54
#define NDS_SEARCH_ENTRY_SUBCOUNT_LE            55
#define NDS_SEARCH_ENTRY_SUBCOUNT_L             56
#define NDS_SEARCH_ENTRY_SUBCOUNT_EQ            57

#define DCS_OPS                         0x10000000L
#define DCS_MOD_GE_WITH_ATTR            DCS_OPS + NDS_SEARCH_MODIFICATION_GE
#define DCS_VALUE_GE_WITH_ATTR          DCS_OPS + NDS_SEARCH_VALUE_TIME_GE
#define DCS_MASK                        ~DCS_OPS

/* Iterator verbs */
#define IT_CLEAR                                 1
#define IT_COPY                                  2
#define IT_COUNT                                 3
#define IT_CREATE                                4
#define IT_CURRENT                               5
#define IT_DESTROY                               6
#define IT_DONE                                  7
#define IT_FIRST                                 8
#define IT_GETPOSITION                           9
#define IT_LAST                                 10
#define IT_NEXT                                 11
#define IT_PREV                                 12
#define IT_POSITION                             13
#define IT_POSITION_IT                          14
#define IT_SETINDEX                             15
#define IT_SETFILTER                            16
#define IT_SKIP                                 17
#define IT_TYPEDOWN                             18
#define IT_ATFIRST                              19
#define IT_ATEOF                                20
#define IT_GETINDEX                             21
#define IT_ISPOSITIONABLE                       22
#define IT_ATBOF                                23
#define IT_ATLAST                               24

/* Iteration information flags */
#define DSI_OUTPUT_FIELDS               0x00000001U
#define DSI_ENTRY_ID                    0x00000002U
#define DSI_ENTRY_FLAGS                 0x00000004U
#define DSI_SUBORDINATE_COUNT           0x00000008U
#define DSI_MODIFICATION_TIME           0x00000010U
#define DSI_MODIFICATION_TIMESTAMP      0x00000020U
#define DSI_CREATION_TIMESTAMP          0x00000040U
#define DSI_PARTITION_ROOT_ID           0x00000080U
#define DSI_PARENT_ID                   0x00000100U
#define DSI_REVISION_COUNT              0x00000200U
#define DSI_REPLICA_TYPE                0x00000400U
#define DSI_BASE_CLASS                  0x00000800U
#define DSI_ENTRY_RDN                   0x00001000U
#define DSI_ENTRY_DN                    0x00002000U
#define DSI_PARTITION_ROOT_DN           0x00004000U
#define DSI_PARENT_DN                   0x00008000U
#define DSI_PURGE_TIME                  0x00010000U
#define DSI_DEREFERENCED_BASE_CLASS     0x00020000
#define DSI_REPLICA_NUMBER              0x00040000
#define DSI_REPLICA_STATE               0x00080000
#define DSI_FEDERATION_BOUNDARY         0x00100000
#define DSI_SCHEMA_BOUNDARY             0x00200000
#define DSI_FEDERATION_BOUNDARY_ID      0x00400000
#define DSI_SCHEMA_BOUNDARY_ID          0x00800000
#define DSI_CUR_SUBCOUNT                0x01000000
#define DSI_LOCAL_ENTRY_FLAGS           0x02000000

static const value_string zensearchenum[] = {
    { 0, "[Root]" },
    { 1, "Object Container" },
    { 2, "Associated Container" },
    { 3, "Selected Container" },
    {0, NULL }
};

static const value_string itersearchenum[] = {
    { NDS_SEARCH_ITEM, "Search Item" },
    { NDS_SEARCH_OR, "OR" },
    { NDS_SEARCH_AND, "AND" },
    { NDS_SEARCH_NOT, "NOT" },
    { NDS_SEARCH_EQUAL, "Equals" },
    { NDS_SEARCH_GREATER_OR_EQUAL, "Greater or Equals" },
    { NDS_SEARCH_LESS_OR_EQUAL, "Less or Equals" },
    { NDS_SEARCH_APPROX, "Approximately" },
    { NDS_SEARCH_PRESENT, "Present" },
    { NDS_SEARCH_RDN, "Relative Distinguished Name" },
    { NDS_SEARCH_BASE_CLASS, "Base Class" },
    { NDS_SEARCH_MODIFICATION_GE, "Modification Greater or Equal" },
    { NDS_SEARCH_VALUE_TIME_GE, "Time Value Greater or Equal" },
    { NDS_SEARCH_REFERENCES, "References" },
    { NDS_SEARCH_DN_IN_VALUE, "Designated Name in Value" },
    { NDS_SEARCH_SCHEMA_IN_VALUE, "Schema in Value" },
    { NDS_SEARCH_ENTRY_FLAGS, "Entry Flags" },
    { NDS_SEARCH_ENTRY_HAS_FLAG, "Entry has Flags" },
    { NDS_SEARCH_VALUE_FLAGS, "Value Flags" },
    { NDS_SEARCH_VALUE_HAS_FLAG, "Value has Flags" },
    { NDS_SEARCH_ATTR_FLAGS, "Attribute Flags" },
    { NDS_SEARCH_ATTR_HAS_FLAG, "Attribute has Flags" },
    { NDS_SEARCH_EID, "Entry ID" },
    { NDS_SEARCH_ENTRY_MTS_GE, "Entry Modification Timestamp Greater or Equal" },
    { NDS_SEARCH_ENTRY_MTS_G, "Entry Modification Timestamp Greater" },
    { NDS_SEARCH_ENTRY_MTS_LE, "Entry Modification Timestamp Less or Equals" },
    { NDS_SEARCH_ENTRY_MTS_L, "Entry Modification Timestamp Less" },
    { NDS_SEARCH_ENTRY_MTS_EQ, "Entry Modification Timestamp Equals" },
    { NDS_SEARCH_ENTRY_MTS_EQ_APPROX, "Entry Modification Timestamp Equals Approximately" },
    { NDS_SEARCH_VALUE_MTS_GE, "Value Modification Timestamp Greater or Equal" },
    { NDS_SEARCH_VALUE_MTS_G, "Value Modification Timestamp Greater" },
    { NDS_SEARCH_VALUE_MTS_LE, "Value Modification Timestamp Less or Equals" },
    { NDS_SEARCH_VALUE_MTS_L, "Value Modification Timestamp Less" },
    { NDS_SEARCH_VALUE_MTS_EQ, "Value Modification Timestamp Equals" },
    { NDS_SEARCH_VALUE_MTS_EQ_APPROX, "Value Modification Timestamp Equals Approximately" },
    { NDS_SEARCH_ENTRY_CTS_GE, "Entry Creation Timestamp Greater or Equals" },
    { NDS_SEARCH_ENTRY_CTS_G, "Entry Creation Timestamp Greater" },
    { NDS_SEARCH_ENTRY_CTS_LE, "Entry Creation Timestamp Less or Equals" },
    { NDS_SEARCH_ENTRY_CTS_L, "Entry Creation Timestamp Less" },
    { NDS_SEARCH_ENTRY_CTS_EQ, "Entry Creation Timestamp Equals" },
    { NDS_SEARCH_ENTRY_CTS_EQ_APPROX, "Entry Creation Timestamp Equals Approximately" },
    { NDS_SEARCH_VALUE_CTS_GE, "Value Creation Timestamp Greater or Equals" },
    { NDS_SEARCH_VALUE_CTS_G, "Value Creation Timestamp Greater" },
    { NDS_SEARCH_VALUE_CTS_LE, "Value Creation Timestamp Less or Equals" },
    { NDS_SEARCH_VALUE_CTS_L, "Value Creation Timestamp Less" },
    { NDS_SEARCH_VALUE_CTS_EQ, "Value Creation Timestamp Equals" },
    { NDS_SEARCH_VALUE_CTS_EQ_APPROX, "Value Creation Timestamp Equals Approximately" },
    { NDS_SEARCH_EXTENSIBLE, "Extensible" },
    { NDS_SEARCH_ENTRY_SUBCOUNT_GE, "Entry SubCount Greater or Equals" },
    { NDS_SEARCH_ENTRY_SUBCOUNT_G, "Entry SubCount Greater" },
    { NDS_SEARCH_ENTRY_SUBCOUNT_LE, "Entry SubCount Less or Equals" },
    { NDS_SEARCH_ENTRY_SUBCOUNT_L, "Entry SubCount Less" },
    { NDS_SEARCH_ENTRY_SUBCOUNT_EQ, "Entry SubCount Equals" },
    {0, NULL }
};

static const value_string iterator_subverbs[] = {
    { IT_CLEAR, "Clear" },
    { IT_COPY, "Copy" },
    { IT_COUNT, "Count" },
    { IT_CREATE, "Create" },
    { IT_CURRENT, "Current" },
    { IT_DESTROY, "Destroy" },
    { IT_DONE, "Done" },
    { IT_FIRST, "First" },
    { IT_GETPOSITION, "Get Position" },
    { IT_LAST, "Last" },
    { IT_NEXT, "Next" },
    { IT_PREV, "Previous" },
    { IT_POSITION, "Position" },
    { IT_POSITION_IT, "Position Iterator" },
    { IT_SETINDEX, "Set Index" },
    { IT_SETFILTER, "Set Filter" },
    { IT_SKIP, "Skip" },
    { IT_TYPEDOWN, "Type Down" },
    { IT_ATFIRST, "At First" },
    { IT_ATEOF, "At End of File" },
    { IT_GETINDEX, "Get Index" },
    { IT_ISPOSITIONABLE, "Is Positionable" },
    { IT_ATBOF, "At Beginning of File" },
    { IT_ATLAST, "At Last" },
    { 0, NULL }
};


static const value_string nds_tuned_tags[] = {
    { 0, "RDN Hint" },
    { 1, "RDN History" },
    {0, NULL }
};

#if 0
static const value_string nds_scope_vals[] = {
    { 0, "Search Scope: 0x0000 - Examine base object only" },
    { 1, "Search Scope: 0x0001 - Search the immediate subordinates of the base object" },
    { 2, "Search Scope: 0x0002 - Search the base object and all of its subordinates" },
    { 3, "Search Scope: 0x0003 - Search the base objects and all objects in its partition (NDS version 8 or higher)" },
    {0, NULL }
};
#endif

static const value_string nds_tuned_item_tags[] = {
    { 0, "Single Item" },
    { 1, "Multiple Items" },
    {0, NULL }
};

static const value_string nds_tags[] = {
    { NDS_TAG_NO_SUCH_ENTRY,        "No Such Entry" },
    { NDS_TAG_LOCAL_ENTRY,          "Local Entry" },
    { NDS_TAG_REMOTE_ENTRY,         "Remote Entry" },
    { NDS_TAG_ALIAS_ENTRY,          "Alias Entry" },
    { NDS_TAG_REFERRAL_INFORMATION, "Referral Information" },
    { NDS_TAG_ENTRY_AND_REFERRALS,  "Entry and Referrals" },
    { 0, NULL }
};

static const range_string nds_info_type[] = {
    { 0x00000000, 0x00000000, "Attribute Names Only / " },
    { 0x00000001, 0x00000001, "Attribute Name & Value / " },
    { 0x00000002, 0x00000002, "Effective Privileges / " },
    { 0x00000003, 0x00000003, "Value Information / " },
    { 0x00000004, 0x00000004, "Abbreviated Value / " },
    { 0x00000005, 0xFFFFFFFF, "No Info Type Set" },
    { 0, 0, NULL }
};

static const value_string nds_kind_of_changes[] = {
    { 0x00000000, "Add Attribute" },
    { 0x00000001, "Remove Attribute" },
    { 0x00000002, "Add Value" },
    { 0x00000003, "Remove Value" },
    { 0x00000004, "Add Additional Value" },
    { 0x00000005, "Overwrite Value" },
    { 0x00000006, "Clear Attribute" },
    { 0x00000007, "Clear Value" },
    { 0, NULL }
};

static const value_string es_type[] = {
    { 0x00000000, "No type is specified" },
    { 0x00000001, "Unicode string" },
    { 0x00000002, "Partial name" },
    { 0x00000003, "Referrals" },
    { 0x00000004, "Tuned name" },
    { 0x00000005, "GUID attribute" },
    { 0x00000006, "Local entry ID" },
    { 0x00000007, "Number of defined entry specifiers" },
    { 0, NULL }
};

static const value_string ncp_rights_vals[] = {
    { 0x00, "No Rights"},
    { 0x01, "Read"},
    { 0x02, "Write"},
    { 0x03, "Read, Write"},
    { 0x04, "Deny Read"},
    { 0x05, "Read, Deny Read"},
    { 0x06, "Write, Deny Read"},
    { 0x07, "Read, Write, Deny Read"},
    { 0x08, "Deny Write"},
    { 0x09, "Read, Deny Write"},
    { 0x0a, "Write, Deny Write"},
    { 0x0b, "Read, Write, Deny Write"},
    { 0x0c, "Deny Read, Deny Write"},
    { 0x0d, "Read, Deny Read, Deny Write"},
    { 0x0e, "Write, Deny Read, Deny Write"},
    { 0x0f, "Read, Write, Deny Read, Deny Write"},
    { 0x10, "Compatibility"},
    { 0x11, "Read, Compatibility"},
    { 0x12, "Write, Compatibility"},
    { 0x13, "Read, Write, Compatibility"},
    { 0x14, "Deny Read, Compatibility"},
    { 0x15, "Read, Deny Read, Compatibility"},
    { 0x16, "Write, Deny Read, Compatibility"},
    { 0x17, "Read, Write, Deny Read, Compatibility"},
    { 0x18, "Deny Write, Compatibility"},
    { 0x19, "Read, Deny Write, Compatibility"},
    { 0x1a, "Write, Deny Write, Compatibility"},
    { 0x1b, "Read, Write, Deny Write, Compatibility"},
    { 0x1c, "Deny Read, Deny Write, Compatibility"},
    { 0x1d, "Read, Deny Read, Deny Write, Compatibility"},
    { 0x1e, "Write, Deny Read, Deny Write, Compatibility"},
    { 0x1f, "Read, Write, Deny Read, Deny Write, Compatibility"},
    { 0x40, "File Write Through"},
    { 0x41, "Read, File Write Through"},
    { 0x42, "Write, File Write Through"},
    { 0x43, "Read, Write, File Write Through"},
    { 0x44, "Deny Read, File Write Through"},
    { 0x45, "Read, Deny Read, File Write Through"},
    { 0x46, "Write, Deny Read, File Write Through"},
    { 0x47, "Read, Write, Deny Read, File Write Through"},
    { 0x48, "Deny Write, File Write Through"},
    { 0x49, "Read, Deny Write, File Write Through"},
    { 0x4a, "Write, Deny Write, File Write Through"},
    { 0x4b, "Read, Write, Deny Write, File Write Through"},
    { 0x4c, "Deny Read, Deny Write, File Write Through"},
    { 0x4d, "Read, Deny Read, Deny Write, File Write Through"},
    { 0x4e, "Write, Deny Read, Deny Write, File Write Through"},
    { 0x4f, "Read, Write, Deny Read, Deny Write, File Write Through"},
    { 0x50, "Compatibility, File Write Through"},
    { 0x51, "Read, Compatibility, File Write Through"},
    { 0x52, "Write, Compatibility, File Write Through"},
    { 0x53, "Read, Write, Compatibility, File Write Through"},
    { 0x54, "Deny Read, Compatibility, File Write Through"},
    { 0x55, "Read, Deny Read, Compatibility, File Write Through"},
    { 0x56, "Write, Deny Read, Compatibility, File Write Through"},
    { 0x57, "Read, Write, Deny Read, Compatibility, File Write Through"},
    { 0x58, "Deny Write, Compatibility, File Write Through"},
    { 0x59, "Read, Deny Write, Compatibility, File Write Through"},
    { 0x5a, "Write, Deny Write, Compatibility, File Write Through"},
    { 0x5b, "Read, Write, Deny Write, Compatibility, File Write Through"},
    { 0x5c, "Deny Read, Deny Write, Compatibility, File Write Through"},
    { 0x5d, "Read, Deny Read, Deny Write, Compatibility, File Write Through"},
    { 0x5e, "Write, Deny Read, Deny Write, Compatibility, File Write Through"},
    { 0x5f, "Read, Write, Deny Read, Deny Write, Compatibility, File Write Through"},
    { 0,    NULL }
};

static const value_string open_create_mode_vals[] = {
    { 0x01, "Open"},
    { 0x02, "Replace"},
    { 0x03, "Open, Replace"},
    { 0x08, "Create"},
    { 0x09, "Open, Create"},
    { 0x0a, "Replace, Create"},
    { 0x0b, "Open, Replace, Create"},
    { 0x20, "64-bit"},
    { 0x21, "Open, 64-bit"},
    { 0x22, "Replace, 64-bit"},
    { 0x23, "Open, Replace, 64-bit"},
    { 0x28, "Create, 64-bit"},
    { 0x29, "Open, Create, 64-bit"},
    { 0x2a, "Replace, Create, 64-bit"},
    { 0x2b, "Open, Replace, Create, 64-bit"},
    { 0x40, "Read Only"},
    { 0x41, "Open, Read Only"},
    { 0x42, "Replace, Read Only"},
    { 0x43, "Open, Replace, Read Only"},
    { 0x48, "Create, Read Only"},
    { 0x49, "Open, Create, Read Only"},
    { 0x4a, "Replace, Create, Read Only"},
    { 0x4b, "Open, Replace, Create, Read Only"},
    { 0x60, "64-bit, Read Only"},
    { 0x61, "Open, 64-bit, Read Only"},
    { 0x62, "Replace, 64-bit, Read Only"},
    { 0x63, "Open, Replace, 64-bit, Read Only"},
    { 0x68, "Create, 64-bit, Read Only"},
    { 0x69, "Open, Create, 64-bit, Read Only"},
    { 0x6a, "Replace, Create, 64-bit, Read Only"},
    { 0x6b, "Open, Replace, Create, 64-bit, Read Only"},
    { 0x80, "Op-Lock"},
    { 0x81, "Open, Op-Lock"},
    { 0x82, "Replace, Op-Lock"},
    { 0x83, "Open, Replace, Op-Lock"},
    { 0x88, "Create, Op-Lock"},
    { 0x89, "Open, Create, Op-Lock"},
    { 0x8a, "Replace, Create, Op-Lock"},
    { 0x8b, "Open, Replace, Create, Op-Lock"},
    { 0xa0, "64-bit, Op-Lock"},
    { 0xa1, "Open, 64-bit, Op-Lock"},
    { 0xa2, "Replace, 64-bit, Op-Lock"},
    { 0xa3, "Open, Replace, 64-bit, Op-Lock"},
    { 0xa8, "Create, 64-bit, Op-Lock"},
    { 0xa9, "Open, Create, 64-bit, Op-Lock"},
    { 0xaa, "Replace, Create, 64-bit, Op-Lock"},
    { 0xab, "Open, Replace, Create, 64-bit, Op-Lock"},
    { 0xc0, "Read Only, Op-Lock"},
    { 0xc1, "Open, Read Only, Op-Lock"},
    { 0xc2, "Replace, Read Only, Op-Lock"},
    { 0xc3, "Open, Replace, Read Only, Op-Lock"},
    { 0xc8, "Create, Read Only, Op-Lock"},
    { 0xc9, "Open, Create, Read Only, Op-Lock"},
    { 0xca, "Replace, Create, Read Only, Op-Lock"},
    { 0xcb, "Open, Replace, Create, Read Only, Op-Lock"},
    { 0xe0, "64-bit, Read Only, Op-Lock"},
    { 0xe1, "Open, 64-bit, Read Only, Op-Lock"},
    { 0xe2, "Replace, 64-bit, Read Only, Op-Lock"},
    { 0xe3, "Open, Replace, 64-bit, Read Only, Op-Lock"},
    { 0xe8, "Create, 64-bit, Read Only, Op-Lock"},
    { 0xe9, "Open, Create, 64-bit, Read Only, Op-Lock"},
    { 0xea, "Replace, Create, 64-bit, Read Only, Op-Lock"},
    { 0xeb, "Open, Replace, Create, 64-bit, Read Only, Op-Lock"},
    { 0,    NULL }
};

static const value_string open_create_action_vals[] = {
    { 0x01, "Opened"},
    { 0x02, "Created"},
    { 0x03, "Opened, Created"},
    { 0x04, "Replaced"},
    { 0x05, "Opened, Replaced"},
    { 0x06, "Created, Replaced"},
    { 0x07, "Opened, Created, Replaced"},
    { 0x08, "Compressed"},
    { 0x09, "Opened, Compressed"},
    { 0x0a, "Created, Compressed"},
    { 0x0b, "Opened, Created, Compressed"},
    { 0x0c, "Replaced, Compressed"},
    { 0x0d, "Opened, Replaced, Compressed"},
    { 0x0e, "Created, Replaced, Compressed"},
    { 0x0f, "Opened, Created, Replaced, Compressed"},
    { 0x80, "Read Only"},
    { 0x81, "Opened, Read Only"},
    { 0x82, "Created, Read Only"},
    { 0x83, "Opened, Created, Read Only"},
    { 0x84, "Replaced, Read Only"},
    { 0x85, "Opened, Replaced, Read Only"},
    { 0x86, "Created, Replaced, Read Only"},
    { 0x87, "Opened, Created, Replaced, Read Only"},
    { 0x88, "Compressed, Read Only"},
    { 0x89, "Opened, Compressed, Read Only"},
    { 0x8a, "Created, Compressed, Read Only"},
    { 0x8b, "Opened, Created, Compressed, Read Only"},
    { 0x8c, "Replaced, Compressed, Read Only"},
    { 0x8d, "Opened, Replaced, Compressed, Read Only"},
    { 0x8e, "Created, Replaced, Compressed, Read Only"},
    { 0x8f, "Opened, Created, Replaced, Compressed, Read Only"},
    { 0,    NULL }
};

static const value_string access_rights_vals[] = {
    { 0x0000, "No Rights"},
    { 0x0001, "Read"},
    { 0x0002, "Write"},
    { 0x0003, "Read, Write"},
    { 0x0004, "Open"},
    { 0x0005, "Read, Open"},
    { 0x0006, "Write, Open"},
    { 0x0007, "Read, Write, Open"},
    { 0x0008, "Create"},
    { 0x0009, "Read, Create"},
    { 0x000a, "Write, Create"},
    { 0x000b, "Read, Write, Create"},
    { 0x000c, "Open, Create"},
    { 0x000d, "Read, Open, Create"},
    { 0x000e, "Write, Open, Create"},
    { 0x000f, "Read, Write, Open, Create"},
    { 0x0010, "Delete"},
    { 0x0011, "Read, Delete"},
    { 0x0012, "Write, Delete"},
    { 0x0013, "Read, Write, Delete"},
    { 0x0014, "Open, Delete"},
    { 0x0015, "Read, Open, Delete"},
    { 0x0016, "Write, Open, Delete"},
    { 0x0017, "Read, Write, Open, Delete"},
    { 0x0018, "Create, Delete"},
    { 0x0019, "Read, Create, Delete"},
    { 0x001a, "Write, Create, Delete"},
    { 0x001b, "Read, Write, Create, Delete"},
    { 0x001c, "Open, Create, Delete"},
    { 0x001d, "Read, Open, Create, Delete"},
    { 0x001e, "Write, Open, Create, Delete"},
    { 0x001f, "Read, Write, Open, Create, Delete"},
    { 0x0020, "Parental"},
    { 0x0021, "Read, Parental"},
    { 0x0022, "Write, Parental"},
    { 0x0023, "Read, Write, Parental"},
    { 0x0024, "Open, Parental"},
    { 0x0025, "Read, Open, Parental"},
    { 0x0026, "Write, Open, Parental"},
    { 0x0027, "Read, Write, Open, Parental"},
    { 0x0028, "Create, Parental"},
    { 0x0029, "Read, Create, Parental"},
    { 0x002a, "Write, Create, Parental"},
    { 0x002b, "Read, Write, Create, Parental"},
    { 0x002c, "Open, Create, Parental"},
    { 0x002d, "Read, Open, Create, Parental"},
    { 0x002e, "Write, Open, Create, Parental"},
    { 0x002f, "Read, Write, Open, Create, Parental"},
    { 0x0030, "Delete, Parental"},
    { 0x0031, "Read, Delete, Parental"},
    { 0x0032, "Write, Delete, Parental"},
    { 0x0033, "Read, Write, Delete, Parental"},
    { 0x0034, "Open, Delete, Parental"},
    { 0x0035, "Read, Open, Delete, Parental"},
    { 0x0036, "Write, Open, Delete, Parental"},
    { 0x0037, "Read, Write, Open, Delete, Parental"},
    { 0x0038, "Create, Delete, Parental"},
    { 0x0039, "Read, Create, Delete, Parental"},
    { 0x003a, "Write, Create, Delete, Parental"},
    { 0x003b, "Read, Write, Create, Delete, Parental"},
    { 0x003c, "Open, Create, Delete, Parental"},
    { 0x003d, "Read, Open, Create, Delete, Parental"},
    { 0x003e, "Write, Open, Create, Delete, Parental"},
    { 0x003f, "Read, Write, Open, Create, Delete, Parental"},
    { 0x0040, "Search"},
    { 0x0041, "Read, Search"},
    { 0x0042, "Write, Search"},
    { 0x0043, "Read, Write, Search"},
    { 0x0044, "Open, Search"},
    { 0x0045, "Read, Open, Search"},
    { 0x0046, "Write, Open, Search"},
    { 0x0047, "Read, Write, Open, Search"},
    { 0x0048, "Create, Search"},
    { 0x0049, "Read, Create, Search"},
    { 0x004a, "Write, Create, Search"},
    { 0x004b, "Read, Write, Create, Search"},
    { 0x004c, "Open, Create, Search"},
    { 0x004d, "Read, Open, Create, Search"},
    { 0x004e, "Write, Open, Create, Search"},
    { 0x004f, "Read, Write, Open, Create, Search"},
    { 0x0050, "Delete, Search"},
    { 0x0051, "Read, Delete, Search"},
    { 0x0052, "Write, Delete, Search"},
    { 0x0053, "Read, Write, Delete, Search"},
    { 0x0054, "Open, Delete, Search"},
    { 0x0055, "Read, Open, Delete, Search"},
    { 0x0056, "Write, Open, Delete, Search"},
    { 0x0057, "Read, Write, Open, Delete, Search"},
    { 0x0058, "Create, Delete, Search"},
    { 0x0059, "Read, Create, Delete, Search"},
    { 0x005a, "Write, Create, Delete, Search"},
    { 0x005b, "Read, Write, Create, Delete, Search"},
    { 0x005c, "Open, Create, Delete, Search"},
    { 0x005d, "Read, Open, Create, Delete, Search"},
    { 0x005e, "Write, Open, Create, Delete, Search"},
    { 0x005f, "Read, Write, Open, Create, Delete, Search"},
    { 0x0060, "Parental, Search"},
    { 0x0061, "Read, Parental, Search"},
    { 0x0062, "Write, Parental, Search"},
    { 0x0063, "Read, Write, Parental, Search"},
    { 0x0064, "Open, Parental, Search"},
    { 0x0065, "Read, Open, Parental, Search"},
    { 0x0066, "Write, Open, Parental, Search"},
    { 0x0067, "Read, Write, Open, Parental, Search"},
    { 0x0068, "Create, Parental, Search"},
    { 0x0069, "Read, Create, Parental, Search"},
    { 0x006a, "Write, Create, Parental, Search"},
    { 0x006b, "Read, Write, Create, Parental, Search"},
    { 0x006c, "Open, Create, Parental, Search"},
    { 0x006d, "Read, Open, Create, Parental, Search"},
    { 0x006e, "Write, Open, Create, Parental, Search"},
    { 0x006f, "Read, Write, Open, Create, Parental, Search"},
    { 0x0070, "Delete, Parental, Search"},
    { 0x0071, "Read, Delete, Parental, Search"},
    { 0x0072, "Write, Delete, Parental, Search"},
    { 0x0073, "Read, Write, Delete, Parental, Search"},
    { 0x0074, "Open, Delete, Parental, Search"},
    { 0x0075, "Read, Open, Delete, Parental, Search"},
    { 0x0076, "Write, Open, Delete, Parental, Search"},
    { 0x0077, "Read, Write, Open, Delete, Parental, Search"},
    { 0x0078, "Create, Delete, Parental, Search"},
    { 0x0079, "Read, Create, Delete, Parental, Search"},
    { 0x007a, "Write, Create, Delete, Parental, Search"},
    { 0x007b, "Read, Write, Create, Delete, Parental, Search"},
    { 0x007c, "Open, Create, Delete, Parental, Search"},
    { 0x007d, "Read, Open, Create, Delete, Parental, Search"},
    { 0x007e, "Write, Open, Create, Delete, Parental, Search"},
    { 0x007f, "Read, Write, Open, Create, Delete, Parental, Search"},
    { 0x0080, "Modify"},
    { 0x0081, "Read, Modify"},
    { 0x0082, "Write, Modify"},
    { 0x0083, "Read, Write, Modify"},
    { 0x0084, "Open, Modify"},
    { 0x0085, "Read, Open, Modify"},
    { 0x0086, "Write, Open, Modify"},
    { 0x0087, "Read, Write, Open, Modify"},
    { 0x0088, "Create, Modify"},
    { 0x0089, "Read, Create, Modify"},
    { 0x008a, "Write, Create, Modify"},
    { 0x008b, "Read, Write, Create, Modify"},
    { 0x008c, "Open, Create, Modify"},
    { 0x008d, "Read, Open, Create, Modify"},
    { 0x008e, "Write, Open, Create, Modify"},
    { 0x008f, "Read, Write, Open, Create, Modify"},
    { 0x0090, "Delete, Modify"},
    { 0x0091, "Read, Delete, Modify"},
    { 0x0092, "Write, Delete, Modify"},
    { 0x0093, "Read, Write, Delete, Modify"},
    { 0x0094, "Open, Delete, Modify"},
    { 0x0095, "Read, Open, Delete, Modify"},
    { 0x0096, "Write, Open, Delete, Modify"},
    { 0x0097, "Read, Write, Open, Delete, Modify"},
    { 0x0098, "Create, Delete, Modify"},
    { 0x0099, "Read, Create, Delete, Modify"},
    { 0x009a, "Write, Create, Delete, Modify"},
    { 0x009b, "Read, Write, Create, Delete, Modify"},
    { 0x009c, "Open, Create, Delete, Modify"},
    { 0x009d, "Read, Open, Create, Delete, Modify"},
    { 0x009e, "Write, Open, Create, Delete, Modify"},
    { 0x009f, "Read, Write, Open, Create, Delete, Modify"},
    { 0x00a0, "Parental, Modify"},
    { 0x00a1, "Read, Parental, Modify"},
    { 0x00a2, "Write, Parental, Modify"},
    { 0x00a3, "Read, Write, Parental, Modify"},
    { 0x00a4, "Open, Parental, Modify"},
    { 0x00a5, "Read, Open, Parental, Modify"},
    { 0x00a6, "Write, Open, Parental, Modify"},
    { 0x00a7, "Read, Write, Open, Parental, Modify"},
    { 0x00a8, "Create, Parental, Modify"},
    { 0x00a9, "Read, Create, Parental, Modify"},
    { 0x00aa, "Write, Create, Parental, Modify"},
    { 0x00ab, "Read, Write, Create, Parental, Modify"},
    { 0x00ac, "Open, Create, Parental, Modify"},
    { 0x00ad, "Read, Open, Create, Parental, Modify"},
    { 0x00ae, "Write, Open, Create, Parental, Modify"},
    { 0x00af, "Read, Write, Open, Create, Parental, Modify"},
    { 0x00b0, "Delete, Parental, Modify"},
    { 0x00b1, "Read, Delete, Parental, Modify"},
    { 0x00b2, "Write, Delete, Parental, Modify"},
    { 0x00b3, "Read, Write, Delete, Parental, Modify"},
    { 0x00b4, "Open, Delete, Parental, Modify"},
    { 0x00b5, "Read, Open, Delete, Parental, Modify"},
    { 0x00b6, "Write, Open, Delete, Parental, Modify"},
    { 0x00b7, "Read, Write, Open, Delete, Parental, Modify"},
    { 0x00b8, "Create, Delete, Parental, Modify"},
    { 0x00b9, "Read, Create, Delete, Parental, Modify"},
    { 0x00ba, "Write, Create, Delete, Parental, Modify"},
    { 0x00bb, "Read, Write, Create, Delete, Parental, Modify"},
    { 0x00bc, "Open, Create, Delete, Parental, Modify"},
    { 0x00bd, "Read, Open, Create, Delete, Parental, Modify"},
    { 0x00be, "Write, Open, Create, Delete, Parental, Modify"},
    { 0x00bf, "Read, Write, Open, Create, Delete, Parental, Modify"},
    { 0x00c0, "Search, Modify"},
    { 0x00c1, "Read, Search, Modify"},
    { 0x00c2, "Write, Search, Modify"},
    { 0x00c3, "Read, Write, Search, Modify"},
    { 0x00c4, "Open, Search, Modify"},
    { 0x00c5, "Read, Open, Search, Modify"},
    { 0x00c6, "Write, Open, Search, Modify"},
    { 0x00c7, "Read, Write, Open, Search, Modify"},
    { 0x00c8, "Create, Search, Modify"},
    { 0x00c9, "Read, Create, Search, Modify"},
    { 0x00ca, "Write, Create, Search, Modify"},
    { 0x00cb, "Read, Write, Create, Search, Modify"},
    { 0x00cc, "Open, Create, Search, Modify"},
    { 0x00cd, "Read, Open, Create, Search, Modify"},
    { 0x00ce, "Write, Open, Create, Search, Modify"},
    { 0x00cf, "Read, Write, Open, Create, Search, Modify"},
    { 0x00d0, "Delete, Search, Modify"},
    { 0x00d1, "Read, Delete, Search, Modify"},
    { 0x00d2, "Write, Delete, Search, Modify"},
    { 0x00d3, "Read, Write, Delete, Search, Modify"},
    { 0x00d4, "Open, Delete, Search, Modify"},
    { 0x00d5, "Read, Open, Delete, Search, Modify"},
    { 0x00d6, "Write, Open, Delete, Search, Modify"},
    { 0x00d7, "Read, Write, Open, Delete, Search, Modify"},
    { 0x00d8, "Create, Delete, Search, Modify"},
    { 0x00d9, "Read, Create, Delete, Search, Modify"},
    { 0x00da, "Write, Create, Delete, Search, Modify"},
    { 0x00db, "Read, Write, Create, Delete, Search, Modify"},
    { 0x00dc, "Open, Create, Delete, Search, Modify"},
    { 0x00dd, "Read, Open, Create, Delete, Search, Modify"},
    { 0x00de, "Write, Open, Create, Delete, Search, Modify"},
    { 0x00df, "Read, Write, Open, Create, Delete, Search, Modify"},
    { 0x00e0, "Parental, Search, Modify"},
    { 0x00e1, "Read, Parental, Search, Modify"},
    { 0x00e2, "Write, Parental, Search, Modify"},
    { 0x00e3, "Read, Write, Parental, Search, Modify"},
    { 0x00e4, "Open, Parental, Search, Modify"},
    { 0x00e5, "Read, Open, Parental, Search, Modify"},
    { 0x00e6, "Write, Open, Parental, Search, Modify"},
    { 0x00e7, "Read, Write, Open, Parental, Search, Modify"},
    { 0x00e8, "Create, Parental, Search, Modify"},
    { 0x00e9, "Read, Create, Parental, Search, Modify"},
    { 0x00ea, "Write, Create, Parental, Search, Modify"},
    { 0x00eb, "Read, Write, Create, Parental, Search, Modify"},
    { 0x00ec, "Open, Create, Parental, Search, Modify"},
    { 0x00ed, "Read, Open, Create, Parental, Search, Modify"},
    { 0x00ee, "Write, Open, Create, Parental, Search, Modify"},
    { 0x00ef, "Read, Write, Open, Create, Parental, Search, Modify"},
    { 0x00f0, "Delete, Parental, Search, Modify"},
    { 0x00f1, "Read, Delete, Parental, Search, Modify"},
    { 0x00f2, "Write, Delete, Parental, Search, Modify"},
    { 0x00f3, "Read, Write, Delete, Parental, Search, Modify"},
    { 0x00f4, "Open, Delete, Parental, Search, Modify"},
    { 0x00f5, "Read, Open, Delete, Parental, Search, Modify"},
    { 0x00f6, "Write, Open, Delete, Parental, Search, Modify"},
    { 0x00f7, "Read, Write, Open, Delete, Parental, Search, Modify"},
    { 0x00f8, "Create, Delete, Parental, Search, Modify"},
    { 0x00f9, "Read, Create, Delete, Parental, Search, Modify"},
    { 0x00fa, "Write, Create, Delete, Parental, Search, Modify"},
    { 0x00fb, "Read, Write, Create, Delete, Parental, Search, Modify"},
    { 0x00fc, "Open, Create, Delete, Parental, Search, Modify"},
    { 0x00fd, "Read, Open, Create, Delete, Parental, Search, Modify"},
    { 0x00fe, "Write, Open, Create, Delete, Parental, Search, Modify"},
    { 0x00ff, "Read, Write, Open, Create, Delete, Parental, Search, Modify"},
    { 0x0100, "Supervisor"},
    { 0x0101, "Read, Supervisor"},
    { 0x0102, "Write, Supervisor"},
    { 0x0103, "Read, Write, Supervisor"},
    { 0x0104, "Open, Supervisor"},
    { 0x0105, "Read, Open, Supervisor"},
    { 0x0106, "Write, Open, Supervisor"},
    { 0x0107, "Read, Write, Open, Supervisor"},
    { 0x0108, "Create, Supervisor"},
    { 0x0109, "Read, Create, Supervisor"},
    { 0x010a, "Write, Create, Supervisor"},
    { 0x010b, "Read, Write, Create, Supervisor"},
    { 0x010c, "Open, Create, Supervisor"},
    { 0x010d, "Read, Open, Create, Supervisor"},
    { 0x010e, "Write, Open, Create, Supervisor"},
    { 0x010f, "Read, Write, Open, Create, Supervisor"},
    { 0x0110, "Delete, Supervisor"},
    { 0x0111, "Read, Delete, Supervisor"},
    { 0x0112, "Write, Delete, Supervisor"},
    { 0x0113, "Read, Write, Delete, Supervisor"},
    { 0x0114, "Open, Delete, Supervisor"},
    { 0x0115, "Read, Open, Delete, Supervisor"},
    { 0x0116, "Write, Open, Delete, Supervisor"},
    { 0x0117, "Read, Write, Open, Delete, Supervisor"},
    { 0x0118, "Create, Delete, Supervisor"},
    { 0x0119, "Read, Create, Delete, Supervisor"},
    { 0x011a, "Write, Create, Delete, Supervisor"},
    { 0x011b, "Read, Write, Create, Delete, Supervisor"},
    { 0x011c, "Open, Create, Delete, Supervisor"},
    { 0x011d, "Read, Open, Create, Delete, Supervisor"},
    { 0x011e, "Write, Open, Create, Delete, Supervisor"},
    { 0x011f, "Read, Write, Open, Create, Delete, Supervisor"},
    { 0x0120, "Parental, Supervisor"},
    { 0x0121, "Read, Parental, Supervisor"},
    { 0x0122, "Write, Parental, Supervisor"},
    { 0x0123, "Read, Write, Parental, Supervisor"},
    { 0x0124, "Open, Parental, Supervisor"},
    { 0x0125, "Read, Open, Parental, Supervisor"},
    { 0x0126, "Write, Open, Parental, Supervisor"},
    { 0x0127, "Read, Write, Open, Parental, Supervisor"},
    { 0x0128, "Create, Parental, Supervisor"},
    { 0x0129, "Read, Create, Parental, Supervisor"},
    { 0x012a, "Write, Create, Parental, Supervisor"},
    { 0x012b, "Read, Write, Create, Parental, Supervisor"},
    { 0x012c, "Open, Create, Parental, Supervisor"},
    { 0x012d, "Read, Open, Create, Parental, Supervisor"},
    { 0x012e, "Write, Open, Create, Parental, Supervisor"},
    { 0x012f, "Read, Write, Open, Create, Parental, Supervisor"},
    { 0x0130, "Delete, Parental, Supervisor"},
    { 0x0131, "Read, Delete, Parental, Supervisor"},
    { 0x0132, "Write, Delete, Parental, Supervisor"},
    { 0x0133, "Read, Write, Delete, Parental, Supervisor"},
    { 0x0134, "Open, Delete, Parental, Supervisor"},
    { 0x0135, "Read, Open, Delete, Parental, Supervisor"},
    { 0x0136, "Write, Open, Delete, Parental, Supervisor"},
    { 0x0137, "Read, Write, Open, Delete, Parental, Supervisor"},
    { 0x0138, "Create, Delete, Parental, Supervisor"},
    { 0x0139, "Read, Create, Delete, Parental, Supervisor"},
    { 0x013a, "Write, Create, Delete, Parental, Supervisor"},
    { 0x013b, "Read, Write, Create, Delete, Parental, Supervisor"},
    { 0x013c, "Open, Create, Delete, Parental, Supervisor"},
    { 0x013d, "Read, Open, Create, Delete, Parental, Supervisor"},
    { 0x013e, "Write, Open, Create, Delete, Parental, Supervisor"},
    { 0x013f, "Read, Write, Open, Create, Delete, Parental, Supervisor"},
    { 0x0140, "Search, Supervisor"},
    { 0x0141, "Read, Search, Supervisor"},
    { 0x0142, "Write, Search, Supervisor"},
    { 0x0143, "Read, Write, Search, Supervisor"},
    { 0x0144, "Open, Search, Supervisor"},
    { 0x0145, "Read, Open, Search, Supervisor"},
    { 0x0146, "Write, Open, Search, Supervisor"},
    { 0x0147, "Read, Write, Open, Search, Supervisor"},
    { 0x0148, "Create, Search, Supervisor"},
    { 0x0149, "Read, Create, Search, Supervisor"},
    { 0x014a, "Write, Create, Search, Supervisor"},
    { 0x014b, "Read, Write, Create, Search, Supervisor"},
    { 0x014c, "Open, Create, Search, Supervisor"},
    { 0x014d, "Read, Open, Create, Search, Supervisor"},
    { 0x014e, "Write, Open, Create, Search, Supervisor"},
    { 0x014f, "Read, Write, Open, Create, Search, Supervisor"},
    { 0x0150, "Delete, Search, Supervisor"},
    { 0x0151, "Read, Delete, Search, Supervisor"},
    { 0x0152, "Write, Delete, Search, Supervisor"},
    { 0x0153, "Read, Write, Delete, Search, Supervisor"},
    { 0x0154, "Open, Delete, Search, Supervisor"},
    { 0x0155, "Read, Open, Delete, Search, Supervisor"},
    { 0x0156, "Write, Open, Delete, Search, Supervisor"},
    { 0x0157, "Read, Write, Open, Delete, Search, Supervisor"},
    { 0x0158, "Create, Delete, Search, Supervisor"},
    { 0x0159, "Read, Create, Delete, Search, Supervisor"},
    { 0x015a, "Write, Create, Delete, Search, Supervisor"},
    { 0x015b, "Read, Write, Create, Delete, Search, Supervisor"},
    { 0x015c, "Open, Create, Delete, Search, Supervisor"},
    { 0x015d, "Read, Open, Create, Delete, Search, Supervisor"},
    { 0x015e, "Write, Open, Create, Delete, Search, Supervisor"},
    { 0x015f, "Read, Write, Open, Create, Delete, Search, Supervisor"},
    { 0x0160, "Parental, Search, Supervisor"},
    { 0x0161, "Read, Parental, Search, Supervisor"},
    { 0x0162, "Write, Parental, Search, Supervisor"},
    { 0x0163, "Read, Write, Parental, Search, Supervisor"},
    { 0x0164, "Open, Parental, Search, Supervisor"},
    { 0x0165, "Read, Open, Parental, Search, Supervisor"},
    { 0x0166, "Write, Open, Parental, Search, Supervisor"},
    { 0x0167, "Read, Write, Open, Parental, Search, Supervisor"},
    { 0x0168, "Create, Parental, Search, Supervisor"},
    { 0x0169, "Read, Create, Parental, Search, Supervisor"},
    { 0x016a, "Write, Create, Parental, Search, Supervisor"},
    { 0x016b, "Read, Write, Create, Parental, Search, Supervisor"},
    { 0x016c, "Open, Create, Parental, Search, Supervisor"},
    { 0x016d, "Read, Open, Create, Parental, Search, Supervisor"},
    { 0x016e, "Write, Open, Create, Parental, Search, Supervisor"},
    { 0x016f, "Read, Write, Open, Create, Parental, Search, Supervisor"},
    { 0x0170, "Delete, Parental, Search, Supervisor"},
    { 0x0171, "Read, Delete, Parental, Search, Supervisor"},
    { 0x0172, "Write, Delete, Parental, Search, Supervisor"},
    { 0x0173, "Read, Write, Delete, Parental, Search, Supervisor"},
    { 0x0174, "Open, Delete, Parental, Search, Supervisor"},
    { 0x0175, "Read, Open, Delete, Parental, Search, Supervisor"},
    { 0x0176, "Write, Open, Delete, Parental, Search, Supervisor"},
    { 0x0177, "Read, Write, Open, Delete, Parental, Search, Supervisor"},
    { 0x0178, "Create, Delete, Parental, Search, Supervisor"},
    { 0x0179, "Read, Create, Delete, Parental, Search, Supervisor"},
    { 0x017a, "Write, Create, Delete, Parental, Search, Supervisor"},
    { 0x017b, "Read, Write, Create, Delete, Parental, Search, Supervisor"},
    { 0x017c, "Open, Create, Delete, Parental, Search, Supervisor"},
    { 0x017d, "Read, Open, Create, Delete, Parental, Search, Supervisor"},
    { 0x017e, "Write, Open, Create, Delete, Parental, Search, Supervisor"},
    { 0x017f, "Read, Write, Open, Create, Delete, Parental, Search, Supervisor"},
    { 0x0180, "Modify, Supervisor"},
    { 0x0181, "Read, Modify, Supervisor"},
    { 0x0182, "Write, Modify, Supervisor"},
    { 0x0183, "Read, Write, Modify, Supervisor"},
    { 0x0184, "Open, Modify, Supervisor"},
    { 0x0185, "Read, Open, Modify, Supervisor"},
    { 0x0186, "Write, Open, Modify, Supervisor"},
    { 0x0187, "Read, Write, Open, Modify, Supervisor"},
    { 0x0188, "Create, Modify, Supervisor"},
    { 0x0189, "Read, Create, Modify, Supervisor"},
    { 0x018a, "Write, Create, Modify, Supervisor"},
    { 0x018b, "Read, Write, Create, Modify, Supervisor"},
    { 0x018c, "Open, Create, Modify, Supervisor"},
    { 0x018d, "Read, Open, Create, Modify, Supervisor"},
    { 0x018e, "Write, Open, Create, Modify, Supervisor"},
    { 0x018f, "Read, Write, Open, Create, Modify, Supervisor"},
    { 0x0190, "Delete, Modify, Supervisor"},
    { 0x0191, "Read, Delete, Modify, Supervisor"},
    { 0x0192, "Write, Delete, Modify, Supervisor"},
    { 0x0193, "Read, Write, Delete, Modify, Supervisor"},
    { 0x0194, "Open, Delete, Modify, Supervisor"},
    { 0x0195, "Read, Open, Delete, Modify, Supervisor"},
    { 0x0196, "Write, Open, Delete, Modify, Supervisor"},
    { 0x0197, "Read, Write, Open, Delete, Modify, Supervisor"},
    { 0x0198, "Create, Delete, Modify, Supervisor"},
    { 0x0199, "Read, Create, Delete, Modify, Supervisor"},
    { 0x019a, "Write, Create, Delete, Modify, Supervisor"},
    { 0x019b, "Read, Write, Create, Delete, Modify, Supervisor"},
    { 0x019c, "Open, Create, Delete, Modify, Supervisor"},
    { 0x019d, "Read, Open, Create, Delete, Modify, Supervisor"},
    { 0x019e, "Write, Open, Create, Delete, Modify, Supervisor"},
    { 0x019f, "Read, Write, Open, Create, Delete, Modify, Supervisor"},
    { 0x01a0, "Parental, Modify, Supervisor"},
    { 0x01a1, "Read, Parental, Modify, Supervisor"},
    { 0x01a2, "Write, Parental, Modify, Supervisor"},
    { 0x01a3, "Read, Write, Parental, Modify, Supervisor"},
    { 0x01a4, "Open, Parental, Modify, Supervisor"},
    { 0x01a5, "Read, Open, Parental, Modify, Supervisor"},
    { 0x01a6, "Write, Open, Parental, Modify, Supervisor"},
    { 0x01a7, "Read, Write, Open, Parental, Modify, Supervisor"},
    { 0x01a8, "Create, Parental, Modify, Supervisor"},
    { 0x01a9, "Read, Create, Parental, Modify, Supervisor"},
    { 0x01aa, "Write, Create, Parental, Modify, Supervisor"},
    { 0x01ab, "Read, Write, Create, Parental, Modify, Supervisor"},
    { 0x01ac, "Open, Create, Parental, Modify, Supervisor"},
    { 0x01ad, "Read, Open, Create, Parental, Modify, Supervisor"},
    { 0x01ae, "Write, Open, Create, Parental, Modify, Supervisor"},
    { 0x01af, "Read, Write, Open, Create, Parental, Modify, Supervisor"},
    { 0x01b0, "Delete, Parental, Modify, Supervisor"},
    { 0x01b1, "Read, Delete, Parental, Modify, Supervisor"},
    { 0x01b2, "Write, Delete, Parental, Modify, Supervisor"},
    { 0x01b3, "Read, Write, Delete, Parental, Modify, Supervisor"},
    { 0x01b4, "Open, Delete, Parental, Modify, Supervisor"},
    { 0x01b5, "Read, Open, Delete, Parental, Modify, Supervisor"},
    { 0x01b6, "Write, Open, Delete, Parental, Modify, Supervisor"},
    { 0x01b7, "Read, Write, Open, Delete, Parental, Modify, Supervisor"},
    { 0x01b8, "Create, Delete, Parental, Modify, Supervisor"},
    { 0x01b9, "Read, Create, Delete, Parental, Modify, Supervisor"},
    { 0x01ba, "Write, Create, Delete, Parental, Modify, Supervisor"},
    { 0x01bb, "Read, Write, Create, Delete, Parental, Modify, Supervisor"},
    { 0x01bc, "Open, Create, Delete, Parental, Modify, Supervisor"},
    { 0x01bd, "Read, Open, Create, Delete, Parental, Modify, Supervisor"},
    { 0x01be, "Write, Open, Create, Delete, Parental, Modify, Supervisor"},
    { 0x01bf, "Read, Write, Open, Create, Delete, Parental, Modify, Supervisor"},
    { 0x01c0, "Search, Modify, Supervisor"},
    { 0x01c1, "Read, Search, Modify, Supervisor"},
    { 0x01c2, "Write, Search, Modify, Supervisor"},
    { 0x01c3, "Read, Write, Search, Modify, Supervisor"},
    { 0x01c4, "Open, Search, Modify, Supervisor"},
    { 0x01c5, "Read, Open, Search, Modify, Supervisor"},
    { 0x01c6, "Write, Open, Search, Modify, Supervisor"},
    { 0x01c7, "Read, Write, Open, Search, Modify, Supervisor"},
    { 0x01c8, "Create, Search, Modify, Supervisor"},
    { 0x01c9, "Read, Create, Search, Modify, Supervisor"},
    { 0x01ca, "Write, Create, Search, Modify, Supervisor"},
    { 0x01cb, "Read, Write, Create, Search, Modify, Supervisor"},
    { 0x01cc, "Open, Create, Search, Modify, Supervisor"},
    { 0x01cd, "Read, Open, Create, Search, Modify, Supervisor"},
    { 0x01ce, "Write, Open, Create, Search, Modify, Supervisor"},
    { 0x01cf, "Read, Write, Open, Create, Search, Modify, Supervisor"},
    { 0x01d0, "Delete, Search, Modify, Supervisor"},
    { 0x01d1, "Read, Delete, Search, Modify, Supervisor"},
    { 0x01d2, "Write, Delete, Search, Modify, Supervisor"},
    { 0x01d3, "Read, Write, Delete, Search, Modify, Supervisor"},
    { 0x01d4, "Open, Delete, Search, Modify, Supervisor"},
    { 0x01d5, "Read, Open, Delete, Search, Modify, Supervisor"},
    { 0x01d6, "Write, Open, Delete, Search, Modify, Supervisor"},
    { 0x01d7, "Read, Write, Open, Delete, Search, Modify, Supervisor"},
    { 0x01d8, "Create, Delete, Search, Modify, Supervisor"},
    { 0x01d9, "Read, Create, Delete, Search, Modify, Supervisor"},
    { 0x01da, "Write, Create, Delete, Search, Modify, Supervisor"},
    { 0x01db, "Read, Write, Create, Delete, Search, Modify, Supervisor"},
    { 0x01dc, "Open, Create, Delete, Search, Modify, Supervisor"},
    { 0x01dd, "Read, Open, Create, Delete, Search, Modify, Supervisor"},
    { 0x01de, "Write, Open, Create, Delete, Search, Modify, Supervisor"},
    { 0x01df, "Read, Write, Open, Create, Delete, Search, Modify, Supervisor"},
    { 0x01e0, "Parental, Search, Modify, Supervisor"},
    { 0x01e1, "Read, Parental, Search, Modify, Supervisor"},
    { 0x01e2, "Write, Parental, Search, Modify, Supervisor"},
    { 0x01e3, "Read, Write, Parental, Search, Modify, Supervisor"},
    { 0x01e4, "Open, Parental, Search, Modify, Supervisor"},
    { 0x01e5, "Read, Open, Parental, Search, Modify, Supervisor"},
    { 0x01e6, "Write, Open, Parental, Search, Modify, Supervisor"},
    { 0x01e7, "Read, Write, Open, Parental, Search, Modify, Supervisor"},
    { 0x01e8, "Create, Parental, Search, Modify, Supervisor"},
    { 0x01e9, "Read, Create, Parental, Search, Modify, Supervisor"},
    { 0x01ea, "Write, Create, Parental, Search, Modify, Supervisor"},
    { 0x01eb, "Read, Write, Create, Parental, Search, Modify, Supervisor"},
    { 0x01ec, "Open, Create, Parental, Search, Modify, Supervisor"},
    { 0x01ed, "Read, Open, Create, Parental, Search, Modify, Supervisor"},
    { 0x01ee, "Write, Open, Create, Parental, Search, Modify, Supervisor"},
    { 0x01ef, "Read, Write, Open, Create, Parental, Search, Modify, Supervisor"},
    { 0x01f0, "Delete, Parental, Search, Modify, Supervisor"},
    { 0x01f1, "Read, Delete, Parental, Search, Modify, Supervisor"},
    { 0x01f2, "Write, Delete, Parental, Search, Modify, Supervisor"},
    { 0x01f3, "Read, Write, Delete, Parental, Search, Modify, Supervisor"},
    { 0x01f4, "Open, Delete, Parental, Search, Modify, Supervisor"},
    { 0x01f5, "Read, Open, Delete, Parental, Search, Modify, Supervisor"},
    { 0x01f6, "Write, Open, Delete, Parental, Search, Modify, Supervisor"},
    { 0x01f7, "Read, Write, Open, Delete, Parental, Search, Modify, Supervisor"},
    { 0x01f8, "Create, Delete, Parental, Search, Modify, Supervisor"},
    { 0x01f9, "Read, Create, Delete, Parental, Search, Modify, Supervisor"},
    { 0x01fa, "Write, Create, Delete, Parental, Search, Modify, Supervisor"},
    { 0x01fb, "Read, Write, Create, Delete, Parental, Search, Modify, Supervisor"},
    { 0x01fc, "Open, Create, Delete, Parental, Search, Modify, Supervisor"},
    { 0x01fd, "Read, Open, Create, Delete, Parental, Search, Modify, Supervisor"},
    { 0x01fe, "Write, Open, Create, Delete, Parental, Search, Modify, Supervisor"},
    { 0x01ff, "Read, Write, Open, Create, Delete, Parental, Search, Modify, Supervisor"},
    { 0,    NULL }
};


static const value_string nds_reply_errors[] = {
    { 0xffffffff, "(-1) Insufficient Space" },
    { 0xffffff89, "(-119) Buffer too Small" },
    { 0xffffff88, "(-120) RR Volume Flag Not Set" },
    { 0xffffff87, "(-121) No Items Found" },
    { 0xffffff86, "(-122) Connection Already Temporary" },
    { 0xffffff85, "(-123) Connection Already Logged In" },
    { 0xffffff84, "(-124) Connection Not Authenticated" },
    { 0xffffff83, "(-125) Connection Not Logged In" },
    { 0xffffff82, "(-126) NCP Boundary Check Failed" },
    { 0xffffff81, "(-127) Lock Waiting" },
    { 0xffffff80, "(-128) Lock Fail" },
    { 0xffffff7f, "(-129) Out of Handles" },
    { 0xffffff7e, "(-130) No Open Privilege" },
    { 0xffffff7d, "(-131) Hard IO Error" },
    { 0xffffff7c, "(-132) No Create Privilege" },
    { 0xffffff7b, "(-133) No Create Delete Privilege" },
    { 0xffffff7a, "(-134) Create Duplicate When Read Only" },
    { 0xffffff79, "(-135) Create File with Invalid Name" },
    { 0xffffff78, "(-136) Invalid File Handle" },
    { 0xffffff77, "(-137) No Search Privilege"   },
    { 0xffffff76, "(-138) No Delete Privilege" },
    { 0xffffff75, "(-139) No Rename Privilege" },
    { 0xffffff74, "(-140) No Set Privilege" },
    { 0xffffff73, "(-141) Some File in Use" },
    { 0xffffff72, "(-142) All File in Use" },
    { 0xffffff71, "(-143) Some Read Only" },
    { 0xffffff70, "(-144) All Read Only" },
    { 0xffffff6f, "(-145) Some names Exist" },
    { 0xffffff6e, "(-146) All Names Exist" },
    { 0xffffff6d, "(-147) No Read Privilege" },
    { 0xffffff6c, "(-148) No Write Privilege" },
    { 0xffffff6b, "(-149) File Detached" },
    { 0xffffff6a, "(-150) No Alloc Space/Target Not a Subdirectory/Insuffficient Memory" },
    { 0xffffff69, "(-151) No Spool Space" },
    { 0xffffff68, "(-152) Invalid Volume" },
    { 0xffffff67, "(-153) Directory Full" },
    { 0xffffff66, "(-154) Rename Across Volume" },
    { 0xffffff65, "(-155) Bad Directory Handle" },
    { 0xffffff64, "(-156) Invalid Path/No Such Extension" },
    { 0xffffff63, "(-157) No Directory Handles" },
    { 0xffffff62, "(-158) Bad File Name" },
    { 0xffffff61, "(-159) Directory Active" },
    { 0xffffff60, "(-160) Directory Not Empty" },
    { 0xffffff5f, "(-161) Directory IO Error" },
    { 0xffffff5e, "(-162) IO Locked" },
    { 0xffffff5d, "(-163) Transaction Restarted" },
    { 0xffffff5c, "(-164) Rename Directory Invalid" },
    { 0xffffff5b, "(-165) Invalid Open/Create Mode" },
    { 0xffffff5a, "(-166) Already in Use" },
    { 0xffffff59, "(-167) Invalid Resource Tag" },
    { 0xffffff58, "(-168) Access Denied" },
    { 0xffffff44, "(-188) Login Signing Required" },
    { 0xffffff43, "(-189) Login Encryption Required" },
    { 0xffffff42, "(-190) Invalid Data Stream" },
    { 0xffffff41, "(-191) Invalid Name Space" },
    { 0xffffff40, "(-192) No Accounting Privileges" },
    { 0xffffff3f, "(-193) No Account Balance" },
    { 0xffffff3e, "(-194) Credit Limit Exceeded" },
    { 0xffffff3d, "(-195) Too Many Holds" },
    { 0xffffff3c, "(-196) Accounting Disabled" },
    { 0xffffff3b, "(-197) Intruder Login Lockout" },
    { 0xffffff3a, "(-198) No Console Rights" },
    { 0xffffff30, "(-208) Queue IO Failure" },
    { 0xffffff2f, "(-209) No Queue" },
    { 0xffffff2e, "(-210) No Queue Server" },
    { 0xffffff2d, "(-211) No Queue Rights" },
    { 0xffffff2c, "(-212) Queue Full" },
    { 0xffffff2b, "(-213) No Queue Job" },
    { 0xffffff2a, "(-214) No Queue Job Rights/Unencrypted Not Allowed" },
    { 0xffffff29, "(-215) Queue In Service/Duplicate Password" },
    { 0xffffff28, "(-216) Queue Not Active/Password Too Short" },
    { 0xffffff27, "(-217) Queue Station Not Server/Maximum Logins Exceeded" },
    { 0xffffff26, "(-218) Queue Halted/Bad Login Time" },
    { 0xffffff25, "(-219) Queue Maximum Servers/Node Address Violation" },
    { 0xffffff24, "(-220) Login Account Expired" },
    { 0xffffff22, "(-222) Bad Password" },
    { 0xffffff21, "(-223) Password Expired" },
    { 0xffffff20, "(-224) No Login Connection Available" },
    { 0xffffff18, "(-232) Write to Group Property" },
    { 0xffffff17, "(-233) Member Already Exists" },
    { 0xffffff16, "(-234) No Such Member" },
    { 0xffffff15, "(-235) Property Not Group" },
    { 0xffffff14, "(-236) No Such Value Set" },
    { 0xffffff13, "(-237) Property Already Exists" },
    { 0xffffff12, "(-238) Object Already Exists" },
    { 0xffffff11, "(-239) Illegal Name" },
    { 0xffffff10, "(-240) Illegal Wildcard" },
    { 0xffffff0f, "(-241) Bindery Security" },
    { 0xffffff0e, "(-242) No Object Read Rights" },
    { 0xffffff0d, "(-243) No Object Rename Rights" },
    { 0xffffff0c, "(-244) No Object Delete Rights" },
    { 0xffffff0b, "(-245) No Object Create Rights" },
    { 0xffffff0a, "(-246) No Property Delete Rights" },
    { 0xffffff09, "(-247) No Property Create Rights" },
    { 0xffffff08, "(-248) No Property Write Rights" },
    { 0xffffff07, "(-249) No Property Read Rights" },
    { 0xffffff06, "(-250) Temp Remap" },
    { 0xffffff05, "(-251) Unknown Request/No Such Property" },
    { 0xffffff04, "(-252) Message Queue Full/Target Already Has Message/No Such Object" },
    { 0xffffff03, "(-253) Bad Station Number" },
    { 0xffffff02, "(-254) Bindery Locked/Directory Locked/Spool Delete/Trustee not Found/Timeout" },
    { 0xffffff01, "(-255) Hard Failure" },
    { 0xfffffed3, "(-301) Not Enough Memory" },
    { 0xfffffed2, "(-302) Bad Key" },
    { 0xfffffed1, "(-303) Bad Context" },
    { 0xfffffed0, "(-304) Buffer Full" },
    { 0xfffffecf, "(-305) List Empty" },
    { 0xfffffece, "(-306) Bad Syntax"   },
    { 0xfffffecd, "(-307) Buffer Empty" },
    { 0xfffffecc, "(-308) Bad Verb" },
    { 0xfffffecb, "(-309) Expected Identifier" },
    { 0xfffffeca, "(-310) Expected Equals" },
    { 0xfffffec9, "(-311) Attribute Type Expected" },
    { 0xfffffec8, "(-312) Attribute Type Not Expected" },
    { 0xfffffec7, "(-313) Filter Tree Empty" },
    { 0xfffffec6, "(-314) Invalid Object Name" },
    { 0xfffffec5, "(-315) Expected RDN Delimiter" },
    { 0xfffffec4, "(-316) Too Many Tokens" },
    { 0xfffffec3, "(-317) Inconsistent MultiAVA" },
    { 0xfffffec2, "(-318) Country Name Too Long" },
    { 0xfffffec1, "(-319) Internal Error" },
    { 0xfffffec0, "(-320) Can't Add Root" },
    { 0xfffffebf, "(-321) Unable to Attach" },
    { 0xfffffebe, "(-322) Invalid Iteration Handle" },
    { 0xfffffebd, "(-323) Buffer Zero Length" },
    { 0xfffffebc, "(-324) Invalid Replica Type" },
    { 0xfffffebb, "(-325) Invalid Attribute Syntax" },
    { 0xfffffeba, "(-326) Invalid Filter Syntax" },
    { 0xfffffeb8, "(-328) Unicode Error during Context Creation" },
    { 0xfffffeb7, "(-329) Invalid Union Tag" },
    { 0xfffffeb6, "(-330) Invalid Server Response" },
    { 0xfffffeb5, "(-331) Null Pointer" },
    { 0xfffffeb4, "(-332) No Server Found" },
    { 0xfffffeb3, "(-333) No Connection" },
    { 0xfffffeb2, "(-334) RDN Too Long" },
    { 0xfffffeb1, "(-335) Duplicate Type" },
    { 0xfffffeb0, "(-336) Data Store Failure" },
    { 0xfffffeaf, "(-337) Not Logged In" },
    { 0xfffffeae, "(-338) Invalid Password Characters" },
    { 0xfffffead, "(-339) Failed Server Authentication" },
    { 0xfffffeac, "(-340) Transport Failed" },
    { 0xfffffeab, "(-341) No Such Syntax" },
    { 0xfffffeaa, "(-342) Invalid DS Name" },
    { 0xfffffea9, "(-343) Attribute Name Too Long" },
    { 0xfffffea8, "(-344) Invalid TDS" },
    { 0xfffffea7, "(-345) Invalid DS Version" },
    { 0xfffffea6, "(-346) Unicode Translation" },
    { 0xfffffea5, "(-347) Schema Name Too Long" },
    { 0xfffffea4, "(-348) Unicode File Not Found" },
    { 0xfffffea3, "(-349) Unicode Already Loaded" },
    { 0xfffffea2, "(-350) Not Context Owner" },
    { 0xfffffea1, "(-351) Attempt to Authenticate" },
    { 0xfffffea0, "(-352) No Writable Replicas" },
    { 0xfffffe9f, "(-353) DN Too Long" },
    { 0xfffffe9e, "(-354) Rename Not Allowed" },
    { 0xfffffe9d, "(-355) Not NDS for NT" },
    { 0xfffffe9c, "(-356) NDS for NT - No Domain" },
    { 0xfffffe9b, "(-357) NDS for NT - Sync Disabled" },
    { 0xfffffe9a, "(-358) Iterator Invalid Handle" },
    { 0xfffffe99, "(-359) Iterator Invalid Position" },
    { 0xfffffe98, "(-360) Iterator Invalid Search Data" },
    { 0xfffffe97, "(-361) Iterator Invalid Scope" },
    { 0xfffffda7, "(-601) No Such Entry" },
    { 0xfffffda6, "(-602) No Such Value" },
    { 0xfffffda5, "(-603) No Such Attribute" },
    { 0xfffffda4, "(-604) No Such Class" },
    { 0xfffffda3, "(-605) No Such Partition" },
    { 0xfffffda2, "(-606) Entry Already Exists" },
    { 0xfffffda1, "(-607) Not Effective Class" },
    { 0xfffffda0, "(-608) Illegal Attribute" },
    { 0xfffffd9f, "(-609) Missing Mandatory" },
    { 0xfffffd9e, "(-610) Illegal DS Name" },
    { 0xfffffd9d, "(-611) Illegal Containment" },
    { 0xfffffd9c, "(-612) Can't Have Multiple Values" },
    { 0xfffffd9b, "(-613) Syntax Violation" },
    { 0xfffffd9a, "(-614) Duplicate Value" },
    { 0xfffffd99, "(-615) Attribute Already Exists" },
    { 0xfffffd98, "(-616) Maximum Entries Exist" },
    { 0xfffffd97, "(-617) Database Format" },
    { 0xfffffd96, "(-618) Inconsistent Database" },
    { 0xfffffd95, "(-619) Invalid Comparison" },
    { 0xfffffd94, "(-620) Comparison Failed" },
    { 0xfffffd93, "(-621) Transaction Tracking Disabled" },
    { 0xfffffd92, "(-622) Invalid Transport" },
    { 0xfffffd91, "(-623) Syntax Invalid in Name" },
    { 0xfffffd90, "(-624) Replica Already Exists" },
    { 0xfffffd8f, "(-625) Transport Failure" },
    { 0xfffffd8e, "(-626) All Referrals Failed" },
    { 0xfffffd8d, "(-627) Can't Remove Naming Value" },
    { 0xfffffd8c, "(-628) Object Class Violation" },
    { 0xfffffd8b, "(-629) Entry is Not Leaf" },
    { 0xfffffd8a, "(-630) Different Tree" },
    { 0xfffffd89, "(-631) Illegal Replica Type" },
    { 0xfffffd88, "(-632) System Failure" },
    { 0xfffffd87, "(-633) Invalid Entry for Root" },
    { 0xfffffd86, "(-634) No Referrals" },
    { 0xfffffd85, "(-635) Remote Failure" },
    { 0xfffffd84, "(-636) Unreachable Server" },
    { 0xfffffd83, "(-637) Previous Move in Progress" },
    { 0xfffffd82, "(-638) No Character Mapping" },
    { 0xfffffd81, "(-639) Incomplete Authentication" },
    { 0xfffffd80, "(-640) Invalid Certificate" },
    { 0xfffffd7f, "(-641) Invalid Request" },
    { 0xfffffd7e, "(-642) Invalid Iteration" },
    { 0xfffffd7d, "(-643) Schema is Non-removable" },
    { 0xfffffd7c, "(-644) Schema is in Use" },
    { 0xfffffd7b, "(-645) Class Already Exists" },
    { 0xfffffd7a, "(-646) Bad Naming Attributes" },
    { 0xfffffd79, "(-647) Not Root Partition" },
    { 0xfffffd78, "(-648) Insufficient Stack" },
    { 0xfffffd77, "(-649) Insufficient Buffer" },
    { 0xfffffd76, "(-650) Ambiguous Containment" },
    { 0xfffffd75, "(-651) Ambiguous Naming" },
    { 0xfffffd74, "(-652) Duplicate Mandatory" },
    { 0xfffffd73, "(-653) Duplicate Optional" },
    { 0xfffffd72, "(-654) Partition Busy" },
    { 0xfffffd71, "(-655) Multiple Replicas" },
    { 0xfffffd70, "(-656) Crucial Replica" },
    { 0xfffffd6f, "(-657) Schema Sync in Progress" },
    { 0xfffffd6e, "(-658) Skulk in Progress" },
    { 0xfffffd6d, "(-659) Time Not Synchronized" },
    { 0xfffffd6c, "(-660) Record in Use" },
    { 0xfffffd6b, "(-661) DS Volume Not Mounted" },
    { 0xfffffd6a, "(-662) DS Volume IO Failure" },
    { 0xfffffd69, "(-663) DS Locked" },
    { 0xfffffd68, "(-664) Old Epoch" },
    { 0xfffffd67, "(-665) New Epoch" },
    { 0xfffffd66, "(-666) Incompatible DS Version" },
    { 0xfffffd65, "(-667) Partition Root" },
    { 0xfffffd64, "(-668) Entry Not Container" },
    { 0xfffffd63, "(-669) Failed Authentication" },
    { 0xfffffd62, "(-670) Invalid Context" },
    { 0xfffffd61, "(-671) No Such Parent" },
    { 0xfffffd60, "(-672) No Access" },
    { 0xfffffd5f, "(-673) Replica Not On" },
    { 0xfffffd5e, "(-674) Invalid Name Service" },
    { 0xfffffd5d, "(-675) Invalid Task" },
    { 0xfffffd5c, "(-676) Invalide Connection Handle" },
    { 0xfffffd5b, "(-677) Invalid Identity" },
    { 0xfffffd5a, "(-678) Duplicate ACL" },
    { 0xfffffd59, "(-679) Partition Already Exists" },
    { 0xfffffd58, "(-680) Transport Modified" },
    { 0xfffffd57, "(-681) Alias of an Alias" },
    { 0xfffffd56, "(-682) Auditing Failed" },
    { 0xfffffd55, "(-683) Invalid API Version" },
    { 0xfffffd54, "(-684) Secure NCP Violation" },
    { 0xfffffd53, "(-685) Move in Progress" },
    { 0xfffffd52, "(-686) Not a Leaf Partition" },
    { 0xfffffd51, "(-687) Cannot Abort" },
    { 0xfffffd50, "(-688) Cache Overflow" },
    { 0xfffffd4f, "(-689) Invalid Subordinate Count" },
    { 0xfffffd4e, "(-690) Invalid RDN" },
    { 0xfffffd4d, "(-691) Modification Time Not Current" },
    { 0xfffffd4c, "(-692) Incorrect Base Class" },
    { 0xfffffd4b, "(-693) Missing Reference" },
    { 0xfffffd4a, "(-694) Lost Entry" },
    { 0xfffffd49, "(-695) Agent Already Registered" },
    { 0xfffffd48, "(-696) DS Loader Busy" },
    { 0xfffffd47, "(-697) DS Cannot Reload" },
    { 0xfffffd46, "(-698) Replica in Skulk" },
    { 0xfffffd45, "(-699) Fatal" },
    { 0xfffffd44, "(-700) Obsolete API" },
    { 0xfffffd43, "(-701) Synchronization Disabled" },
    { 0xfffffd42, "(-702) Invalid Parameter" },
    { 0xfffffd41, "(-703) Duplicate Template" },
    { 0xfffffd40, "(-704) No Master Replica" },
    { 0xfffffd3f, "(-705) Duplicate Containment" },
    { 0xfffffd3e, "(-706) Not a Sibling" },
    { 0xfffffd3d, "(-707) Invalid Signature" },
    { 0xfffffd3c, "(-708) Invalid Response" },
    { 0xfffffd3b, "(-709) Insufficient Sockets" },
    { 0xfffffd3a, "(-710) Database Read Fail" },
    { 0xfffffd39, "(-711) Invalid Code Page" },
    { 0xfffffd38, "(-712) Invalid Escape Character" },
    { 0xfffffd37, "(-713) Invalide Delimiters" },
    { 0xfffffd36, "(-714) Not Implemented" },
    { 0xfffffd35, "(-715) Checksum Failure" },
    { 0xfffffd34, "(-716) Checksumming Not Supported" },
    { 0xfffffd33, "(-717) CRC Failure" },
    { 0xfffffd32, "(-718) Invalid Entry Handle" },
    { 0xfffffd31, "(-719) Invalid Value Handle" },
    { 0xfffffd30, "(-720) Connection Denied" },
    { 0xfffffd2f, "(-721) No Such Federation Link" },
    { 0xfffffd2e, "(-722) Operetational Schema Mismatch" },
    { 0xfffffd2d, "(-723) Stream Not Found" },
    { 0xfffffd2c, "(-724) DClient Unavailable" },
    { 0xfffffd2b, "(-725) MASV No Access" },
    { 0xfffffd2a, "(-726) MASV Invalid Request" },
    { 0xfffffd29, "(-727) MASV Failure" },
    { 0xfffffd28, "(-728) MASV Already Exists" },
    { 0xfffffd27, "(-729) MASV Not Found" },
    { 0xfffffd26, "(-730) MASV Bad Range" },
    { 0xfffffd25, "(-731) Value Data" },
    { 0xfffffd24, "(-732) Database Locked" },
    { 0xfffffd21, "(-735) Nothing to Abort" },
    { 0xfffffd20, "(-736) End of Stream" },
    { 0xfffffd1f, "(-737) No Such Template" },
    { 0xfffffd1e, "(-738) SAS Locked" },
    { 0xfffffd1d, "(-739) Invalid SAS Version" },
    { 0xfffffd1c, "(-740) SAS Already Registered" },
    { 0xfffffd1b, "(-741) Name Type Not Supported" },
    { 0xfffffd1a, "(-742) Wrong DS Version" },
    { 0xfffffd19, "(-743) Invalid Control Function" },
    { 0xfffffd18, "(-744) Invalid Control State" },
    { 0xfffffd17, "(-745) Cache in Use" },
    { 0xfffffd16, "(-746) Zero Creation Time" },
    { 0xfffffd15, "(-747) Would Block" },
    { 0xfffffd14, "(-748) Connection Timeout" },
    { 0xfffffd13, "(-749) Too Many Referrals" },
    { 0xfffffd12, "(-750) Operation Cancelled" },
    { 0xfffffd11, "(-751) Unknown Target" },
    { 0xfffffd10, "(-752) GUID Failure" },
    { 0xfffffd0f, "(-753) Incompatible OS" },
    { 0xfffffd0e, "(-754) Callback Cancel" },
    { 0xfffffd0d, "(-755) Invalid Synchronization Data" },
    { 0xfffffd0c, "(-756) Stream Exists" },
    { 0xfffffd0b, "(-757) Auxiliary Has Containment" },
    { 0xfffffd0a, "(-758) Auxiliary Not Container" },
    { 0xfffffd09, "(-759) Auxiliary Not Effective" },
    { 0xfffffd08, "(-760) Auxiliary On Alias" },
    { 0xfffffd07, "(-761) Have Seen State" },
    { 0xfffffd06, "(-762) Verb Locked" },
    { 0xfffffd05, "(-763) Verb Exceeds Table Length" },
    { 0xfffffd04, "(-764) BOF Hit" },
    { 0xfffffd03, "(-765) EOF Hit" },
    { 0xfffffd02, "(-766) Incompatible Replica Version" },
    { 0xfffffd01, "(-767) Query Timeout" },
    { 0xfffffd00, "(-768) Query Maximum Count" },
    { 0xfffffcff, "(-769) Duplicate Naming" },
    { 0xfffffcfe, "(-770) No Transaction Active" },
    { 0xfffffcfd, "(-771) Transaction Active" },
    { 0xfffffcfc, "(-772) Illegal Transaction Operation" },
    { 0xfffffcfb, "(-773) Iterator Syntax" },
    { 0xfffffcfa, "(-774) Repairing DIB" },
    { 0xfffffcf9, "(-775) Invalid OID Format" },
    { 0xfffffcf8, "(-776) Attempted to perform an NDS operation, and the DS agent on this server is closing" },
    { 0xfffffcf7, "(-777) Attempted to modify an object's attribute that is not stored on the sparse replica" },
    { 0xfffffcf6, "(-778) VpVector and VpvUser which must be correlated, are out of sync" },
    { 0xfffffcf5, "(-779) Error Cannot Go Remote" },
    { 0xfffffcf4, "(-780) Request not Supported" },
    { 0xfffffcf3, "(-781) Entry Not Local" },
    { 0xfffffcf2, "(-782) Root Unreachable" },
    { 0xfffffcf1, "(-783) VRDIM Not Initialized" },
    { 0xfffffcf0, "(-784) Wait Timeout" },
    { 0xfffffcef, "(-785) DIB Error" },
    { 0xfffffcee, "(-786) DIB IO Failure" },
    { 0xfffffced, "(-787) Illegal Schema Attribute" },
    { 0xfffffcec, "(-788) Error Schema Partition" },
    { 0xfffffceb, "(-789) Invalid Template" },
    { 0xfffffcea, "(-790) Error Opening File" },
    { 0xfffffce9, "(-791) Error Direct Opening File" },
    { 0xfffffce8, "(-792) Error Creating File" },
    { 0xfffffce7, "(-793) Error Direct Creating File" },
    { 0xfffffce6, "(-794) Error Reading File" },
    { 0xfffffce5, "(-795) Error Direct Reading File" },
    { 0xfffffce4, "(-796) Error Writing File" },
    { 0xfffffce3, "(-797) Error Direct Writing File" },
    { 0xfffffce2, "(-798) Error Positioning in File" },
    { 0xfffffce1, "(-799) Error Getting File Size" },
    { 0xffffe88f, "(-6001) Error Truncating File" },
    { 0xffffe88e, "(-6002) Error Parsing File Name" },
    { 0xffffe88d, "(-6003) Error Closing File" },
    { 0xffffe88c, "(-6004) Error Getting File Info" },
    { 0xffffe88b, "(-6005) Error Expanding File" },
    { 0xffffe88a, "(-6006) Error Getting Free Blocks" },
    { 0xffffe889, "(-6007) Error Checking File Existence" },
    { 0xffffe888, "(-6008) Error Deleting File" },
    { 0xffffe887, "(-6009) Error Renaming File" },
    { 0xffffe886, "(-6010) Error Initializing IO System" },
    { 0xffffe885, "(-6011) Error Flushing File" },
    { 0xffffe884, "(-6012) Error Setting Up for Read" },
    { 0xffffe883, "(-6013) Error Setting up for Write" },
    { 0xffffe882, "(-6014) Error Old View" },
    { 0xffffe881, "(-6015) Server in Skulk" },
    { 0xffffe880, "(-6016) Error Returning Partial Results" },
    { 0xffffe87f, "(-6017) No Such Schema" },
    { 0xffffe87e, "(-6018) Serial Number Mismatch" },
    { 0xffffe87d, "(-6019) Bad Referal Database Serial Number" },
    { 0xffffe87c, "(-6020) Bad Referal Serial Number" },
    { 0xffffe87b, "(-6021) Invalid File Sequence" },
    { 0xffffe87a, "(-6022) Error Referal Trans Gap" },
    { 0xffffe879, "(-6023) Bad Referal File Number" },
    { 0xffffe878, "(-6024) Referal File Not Found" },
    { 0xffffe877, "(-6025) Error Backup Active" },
    { 0xffffe876, "(-6026) Referal Device Full" },
    { 0xffffe875, "(-6027) Unsupported Version" },
    { 0xffffe874, "(-6028) Error Must Wait Checkpoint" },
    { 0xffffe873, "(-6029) Attribute Maintenance in Progress" },
    { 0xffffe872, "(-6030) Error Abort Transaction" },
    { 0xffff0000, "Ok" },
    { 0x0000, "Ok" },
    { 0, NULL }
};

#define NDS_PTYPE_IPX           0x00000000
#define NDS_PTYPE_IP            0x00000001
#define NDS_PTYPE_SDLC          0x00000002
#define NDS_PTYPE_TR_ON_ETH     0x00000003
#define NDS_PTYPE_OSI           0x00000004
#define NDS_PTYPE_APPLETALK     0x00000005
#define NDS_PTYPE_NETBEUI       0x00000006
#define NDS_PTYPE_SOCKETADDRESS 0x00000007
#define NDS_PTYPE_UDP           0x00000008
#define NDS_PTYPE_TCP           0x00000009
#define NDS_PTYPE_UDPv6         0x0000000a
#define NDS_PTYPE_TCPv6         0x0000000b
#define NDS_PTYPE_INTERNAL      0x0000000c
#define NDS_PTYPE_URL           0x0000000d
#define NDS_PTYPE_DNS           0x0000000e
#define NDS_PTYPE_CNT           0x0000000f

static const value_string nds_protocol_type[] = {
    { NDS_PTYPE_IPX,           "(IPX Protocol)" },
    { NDS_PTYPE_IP,            "(IP Protocol)" },
    { NDS_PTYPE_SDLC,          "(SDLC Protocol)" },
    { NDS_PTYPE_TR_ON_ETH,     "(TokenRing on Ethernet Protocol)" },
    { NDS_PTYPE_OSI,           "(OSI Protocol)" },
    { NDS_PTYPE_APPLETALK,     "(AppleTalk Protocol)" },
    { NDS_PTYPE_NETBEUI,       "(NetBEUI Protocol)" },
    { NDS_PTYPE_SOCKETADDRESS, "(Socket Address Protocol)" },
    { NDS_PTYPE_UDP,           "(UDP Protocol)" },
    { NDS_PTYPE_TCP,           "(TCP Protocol)" },
    { NDS_PTYPE_UDPv6,         "(UDP v6 Protocol)" },
    { NDS_PTYPE_TCPv6,         "(TCP v6 Protocol)" },
    { NDS_PTYPE_INTERNAL,      "(Internal Protocol)" },
    { NDS_PTYPE_URL,           "(URL Protocol)" },
    { NDS_PTYPE_DNS,           "(DNS Protocol)" },
    { NDS_PTYPE_CNT,           "(Number of protocol types defined)" },
    { 0, NULL }
};


static const value_string nds_syntax[] = {
    { 0x00000000, "Unknown Syntax" },
    { 0x00000001, "Distinguished Name" },
    { 0x00000002, "Case Sensitive Unicode String" },
    { 0x00000003, "Non Case Sensitive Unicode String" },
    { 0x00000004, "Printable String" },
    { 0x00000005, "Numeric String" },
    { 0x00000006, "Case Insensitive List" },
    { 0x00000007, "Boolean" },
    { 0x00000008, "Signed Integer" },
    { 0x00000009, "Binary String" },
    { 0x0000000a, "Telephone Number" },
    { 0x0000000b, "Fax Number" },
    { 0x0000000c, "Network Address" },
    { 0x0000000d, "Binary String List" },
    { 0x0000000e, "Email Address" },
    { 0x0000000f, "File System Path" },
    { 0x00000010, "Replica Pointer" },
    { 0x00000011, "Object ACL" },
    { 0x00000012, "Postal Address" },
    { 0x00000013, "Time Stamp" },
    { 0x00000014, "Class Name" },
    { 0x00000015, "Stream" },
    { 0x00000016, "Counter" },
    { 0x00000017, "Back Link" },
    { 0x00000018, "Time" },
    { 0x00000019, "Typed Name" },
    { 0x0000001a, "Hold" },
    { 0x0000001b, "Interval" },
    { 0, NULL }
};

static const value_string name_space_type[] = {
    { 0x00000000, "DOS Name Space" },
    { 0x00000001, "MAC Name Space" },
    { 0x00000002, "NFS Name Space" },
    { 0x00000003, "FTAM Name Space" },
    { 0x00000004, "OS/2, Long Name Space" },
    { 0, NULL }
};


static const value_string nds_replica_state[] = {
    { 0x0000, "On" },
    { 0x0001, "New" },
    { 0x0002, "Dying" },
    { 0x0003, "Locked" },
    { 0x0004, "Create Master State 0" },
    { 0x0005, "Create Master State 1" },
    { 0x0006, "Transition On" },
    { 0x0007, "Dead Replica" },
    { 0x0008, "Begin Add" },
    { 0x000b, "Master Start" },
    { 0x000c, "Master Done" },
    { 0x0017, "Federated" },
    { 0x0030, "Split State 0" },
    { 0x0031, "Split State 1" },
    { 0x0040, "Join State 0" },
    { 0x0041, "Join State 1" },
    { 0x0042, "Join State 2" },
    { 0x0050, "Move Subtree State 0" },
    { 0x0051, "Move Subtree State 1" },
    { 0, NULL }
};

static const value_string nds_replica_type[] = {
    { 0x0000, "Master" },
    { 0x0001, "Secondary" },
    { 0x0002, "Read Only" },
    { 0x0003, "Sub Ref" },
    { 0, NULL }
};

static const value_string class_def_type[] = {
    { 0x0000, "Return Class Name" },
    { 0x0001, "Return Class Name, Flag, and Definition" },
    { 0x0002, "Return Class Name, Flag, Definition, and Super Class" },
    { 0x0003, "Return Class Name, Flag, and ASN.1 identifier" },
    { 0x0004, "Return Class Name, Flag, Definition, Super Class, and ACL" },
    { 0x0005, "Return Class Name, Flag, Creation Timestamp, Modification Timestamp, Definition, and ACL" },
    { 0, NULL }
};

static const range_string nds_search_scope[] = {
    { 0x0000, 0x0000, "Examine the base object only" },
    { 0x0001, 0x0001, "Search the immediate subordinates of the base object" },
    { 0x0002, 0x0002, "Search the base object and all its subordinates" },
    { 0x0003, 0x0003, "Search the base objects and all objects in its partition (Implemented in NDS 8)" },
    { 0x0004, 0xFFFF, "No Search Scope Defined" },
    { 0, 0, NULL }
};

static const value_string nds_verb2b_flag_vals[] = {
    { 0, "Request Flags (0x0000) - Retain old object name" },
    { 1, "Request Flags (0x0001) - Delete old object name" },
    { 0,  NULL }
};

static const value_string serv_type_vals[] = {
    { 0, "NetWare" },
    { 1, "OES" },
    { 0,  NULL }
};

static const value_string kernel_type_vals[] = {
    { 0, "NetWare" },
    { 1, "Linux" },
    { 0,  NULL }
};

static const int * ncp_pingflags1[] = {
    &hf_bit1pingflags1,
    &hf_bit2pingflags1,
    &hf_bit3pingflags1,
    &hf_bit4pingflags1,
    &hf_bit5pingflags1,
    &hf_bit6pingflags1,
    &hf_bit7pingflags1,
    &hf_bit8pingflags1,
    &hf_bit9pingflags1,
    &hf_bit10pingflags1,
    &hf_bit11pingflags1,
    &hf_bit12pingflags1,
    &hf_bit13pingflags1,
    &hf_bit14pingflags1,
    &hf_bit15pingflags1,
    &hf_bit16pingflags1,
    NULL
};

static const int * ncp_pingflags2[] = {
    &hf_bit1pingflags2,
    &hf_bit2pingflags2,
    &hf_bit3pingflags2,
    &hf_bit4pingflags2,
    &hf_bit5pingflags2,
    &hf_bit6pingflags2,
    &hf_bit7pingflags2,
    &hf_bit8pingflags2,
    &hf_bit9pingflags2,
    &hf_bit10pingflags2,
    &hf_bit11pingflags2,
    &hf_bit12pingflags2,
    &hf_bit13pingflags2,
    &hf_bit14pingflags2,
    &hf_bit15pingflags2,
    &hf_bit16pingflags2,
    NULL
};

static const int * ncp_pingvflags1[] = {
    &hf_bit1pingvflags1,
    &hf_bit2pingvflags1,
    &hf_bit3pingvflags1,
    &hf_bit4pingvflags1,
    &hf_bit5pingvflags1,
    &hf_bit6pingvflags1,
    &hf_bit7pingvflags1,
    &hf_bit8pingvflags1,
    &hf_bit9pingvflags1,
    &hf_bit10pingvflags1,
    &hf_bit11pingvflags1,
    &hf_bit12pingvflags1,
    &hf_bit13pingvflags1,
    &hf_bit14pingvflags1,
    &hf_bit15pingvflags1,
    &hf_bit16pingvflags1,
    NULL
};

static const int * ncp_pingpflags1[] = {
    &hf_bit1pingpflags1,
    &hf_bit2pingpflags1,
    &hf_bit3pingpflags1,
    &hf_bit4pingpflags1,
    &hf_bit5pingpflags1,
    &hf_bit6pingpflags1,
    &hf_bit7pingpflags1,
    &hf_bit8pingpflags1,
    &hf_bit9pingpflags1,
    &hf_bit10pingpflags1,
    &hf_bit11pingpflags1,
    &hf_bit12pingpflags1,
    &hf_bit13pingpflags1,
    &hf_bit14pingpflags1,
    &hf_bit15pingpflags1,
    &hf_bit16pingpflags1,
    NULL
};

static const int * ndsprotflags[] = {
    &hf_ndsprot1flag,
    &hf_ndsprot2flag,
    &hf_ndsprot3flag,
    &hf_ndsprot4flag,
    &hf_ndsprot5flag,
    &hf_ndsprot6flag,
    &hf_ndsprot7flag,
    &hf_ndsprot8flag,
    &hf_ndsprot9flag,
    &hf_ndsprot10flag,
    &hf_ndsprot11flag,
    &hf_ndsprot12flag,
    &hf_ndsprot13flag,
    &hf_ndsprot14flag,
    &hf_ndsprot15flag,
    &hf_ndsprot16flag,
    NULL
};

static const int * ncp_infoflagsl[] = {
    &hf_bit1infoflagsl,
    &hf_bit2infoflagsl,
    &hf_bit3infoflagsl,
    &hf_bit4infoflagsl,
    &hf_bit5infoflagsl,
    &hf_bit6infoflagsl,
    &hf_bit7infoflagsl,
    &hf_bit8infoflagsl,
    &hf_bit9infoflagsl,
    &hf_bit10infoflagsl,
    &hf_bit11infoflagsl,
    &hf_bit12infoflagsl,
    &hf_bit13infoflagsl,
    &hf_bit14infoflagsl,
    &hf_bit15infoflagsl,
    &hf_bit16infoflagsl,
    NULL
};

static const int * ncp_infoflagsh[] = {
    &hf_bit1infoflagsh,
    &hf_bit2infoflagsh,
    &hf_bit3infoflagsh,
    &hf_bit4infoflagsh,
    &hf_bit5infoflagsh,
    &hf_bit6infoflagsh,
    &hf_bit7infoflagsh,
    &hf_bit8infoflagsh,
    &hf_bit9infoflagsh,
    &hf_bit10infoflagsh,
    &hf_bit11infoflagsh,
    &hf_bit12infoflagsh,
    &hf_bit13infoflagsh,
    &hf_bit14infoflagsh,
    &hf_bit15infoflagsh,
    &hf_bit16infoflagsh,
    NULL
};

static const int * ncp_retinfoflagsh[] = {
    &hf_bit1retinfoflagsh,
    &hf_bit2retinfoflagsh,
    &hf_bit3retinfoflagsh,
    &hf_bit4retinfoflagsh,
    &hf_bit5retinfoflagsh,
    &hf_bit6retinfoflagsh,
    &hf_bit7retinfoflagsh,
    &hf_bit8retinfoflagsh,
    &hf_bit9retinfoflagsh,
    &hf_bit10retinfoflagsh,
    &hf_bit11retinfoflagsh,
    &hf_bit12retinfoflagsh,
    &hf_bit13retinfoflagsh,
    &hf_bit14retinfoflagsh,
    &hf_bit15retinfoflagsh,
    &hf_bit16retinfoflagsh,
    NULL
};

static const int * ncp_acflags[] = {
    &hf_bit1acflags,
    &hf_bit2acflags,
    &hf_bit3acflags,
    &hf_bit4acflags,
    &hf_bit5acflags,
    &hf_bit6acflags,
    &hf_bit7acflags,
    &hf_bit8acflags,
    &hf_bit9acflags,
    &hf_bit10acflags,
    &hf_bit11acflags,
    &hf_bit12acflags,
    &hf_bit13acflags,
    &hf_bit14acflags,
    &hf_bit15acflags,
    &hf_bit16acflags,
    NULL
};

static const int * ncp_eflags[] = {
    &hf_bit1eflags,
    &hf_bit2eflags,
    &hf_bit3eflags,
    &hf_bit4eflags,
    &hf_bit5eflags,
    &hf_bit6eflags,
    &hf_bit7eflags,
    &hf_bit8eflags,
    &hf_bit9eflags,
    &hf_bit10eflags,
    &hf_bit11eflags,
    &hf_bit12eflags,
    &hf_bit13eflags,
    &hf_bit14eflags,
    &hf_bit15eflags,
    &hf_bit16eflags,
    NULL
};

static const int * ncp_cflags[] = {
    &hf_bit1cflags,
    &hf_bit2cflags,
    &hf_bit3cflags,
    &hf_bit4cflags,
    &hf_bit5cflags,
    &hf_bit6cflags,
    &hf_bit7cflags,
    &hf_bit8cflags,
    &hf_bit9cflags,
    &hf_bit10cflags,
    &hf_bit11cflags,
    &hf_bit12cflags,
    &hf_bit13cflags,
    &hf_bit14cflags,
    &hf_bit15cflags,
    &hf_bit16cflags,
    NULL
};

static const int * ncp_lflags[] = {
    &hf_bit1lflags,
    &hf_bit2lflags,
    &hf_bit3lflags,
    &hf_bit4lflags,
    &hf_bit5lflags,
    &hf_bit6lflags,
    &hf_bit7lflags,
    &hf_bit8lflags,
    &hf_bit9lflags,
    &hf_bit10lflags,
    &hf_bit11lflags,
    &hf_bit12lflags,
    &hf_bit13lflags,
    &hf_bit14lflags,
    &hf_bit15lflags,
    &hf_bit16lflags,
    NULL
};

static const int * ncp_nflags[] = {
    &hf_bit1nflags,
    &hf_bit2nflags,
    &hf_bit3nflags,
    &hf_bit4nflags,
    &hf_bit5nflags,
    &hf_bit6nflags,
    &hf_bit7nflags,
    &hf_bit8nflags,
    &hf_bit9nflags,
    &hf_bit10nflags,
    &hf_bit11nflags,
    &hf_bit12nflags,
    &hf_bit13nflags,
    &hf_bit14nflags,
    &hf_bit15nflags,
    &hf_bit16nflags,
    NULL
};

static const int * ncp_rflags[] = {
    &hf_bit1rflags,
    &hf_bit2rflags,
    &hf_bit3rflags,
    &hf_bit4rflags,
    &hf_bit5rflags,
    &hf_bit6rflags,
    &hf_bit7rflags,
    &hf_bit8rflags,
    &hf_bit9rflags,
    &hf_bit10rflags,
    &hf_bit11rflags,
    &hf_bit12rflags,
    &hf_bit13rflags,
    &hf_bit14rflags,
    &hf_bit15rflags,
    &hf_bit16rflags,
    NULL
};

static const int * ncp_outflags[] = {
    &hf_bit1outflags,
    &hf_bit2outflags,
    &hf_bit3outflags,
    &hf_bit4outflags,
    &hf_bit5outflags,
    &hf_bit6outflags,
    &hf_bit7outflags,
    &hf_bit8outflags,
    &hf_bit9outflags,
    &hf_bit10outflags,
    &hf_bit11outflags,
    &hf_bit12outflags,
    &hf_bit13outflags,
    &hf_bit14outflags,
    &hf_bit15outflags,
    &hf_bit16outflags,
    NULL
};

static const int * ncp_siflags[] = {
    &hf_bit1siflags,
    &hf_bit2siflags,
    &hf_bit3siflags,
    &hf_bit4siflags,
    &hf_bit5siflags,
    &hf_bit6siflags,
    &hf_bit7siflags,
    &hf_bit8siflags,
    &hf_bit9siflags,
    &hf_bit10siflags,
    &hf_bit11siflags,
    &hf_bit12siflags,
    &hf_bit13siflags,
    &hf_bit14siflags,
    &hf_bit15siflags,
    &hf_bit16siflags,
    NULL
};

static const int * ncp_vflags[] = {
    &hf_bit1vflags,
    &hf_bit2vflags,
    &hf_bit3vflags,
    &hf_bit4vflags,
    &hf_bit5vflags,
    &hf_bit6vflags,
    &hf_bit7vflags,
    &hf_bit8vflags,
    &hf_bit9vflags,
    &hf_bit10vflags,
    &hf_bit11vflags,
    &hf_bit12vflags,
    &hf_bit13vflags,
    &hf_bit14vflags,
    &hf_bit15vflags,
    &hf_bit16vflags,
    NULL
};

static const int * nds_bitflags[] = {
    &hf_nds_bit1,
    &hf_nds_bit2,
    &hf_nds_bit3,
    &hf_nds_bit4,
    &hf_nds_bit5,
    &hf_nds_bit6,
    &hf_nds_bit7,
    &hf_nds_bit8,
    &hf_nds_bit9,
    &hf_nds_bit10,
    &hf_nds_bit11,
    &hf_nds_bit12,
    &hf_nds_bit13,
    &hf_nds_bit14,
    &hf_nds_bit15,
    &hf_nds_bit16,
    NULL
};

static const int * ncp_l1flagsl[] = {
    &hf_bit1l1flagsl,
    &hf_bit2l1flagsl,
    &hf_bit3l1flagsl,
    &hf_bit4l1flagsl,
    &hf_bit5l1flagsl,
    &hf_bit6l1flagsl,
    &hf_bit7l1flagsl,
    &hf_bit8l1flagsl,
    &hf_bit9l1flagsl,
    &hf_bit10l1flagsl,
    &hf_bit11l1flagsl,
    &hf_bit12l1flagsl,
    &hf_bit13l1flagsl,
    &hf_bit14l1flagsl,
    &hf_bit15l1flagsl,
    &hf_bit16l1flagsl,
    NULL
};

static const int * ncp_l1flagsh[] = {
    &hf_bit1l1flagsh,
    &hf_bit2l1flagsh,
    &hf_bit3l1flagsh,
    &hf_bit4l1flagsh,
    &hf_bit5l1flagsh,
    &hf_bit6l1flagsh,
    &hf_bit7l1flagsh,
    &hf_bit8l1flagsh,
    &hf_bit9l1flagsh,
    &hf_bit10l1flagsh,
    &hf_bit11l1flagsh,
    &hf_bit12l1flagsh,
    &hf_bit13l1flagsh,
    &hf_bit14l1flagsh,
    &hf_bit15l1flagsh,
    &hf_bit16l1flagsh,
    NULL
};

static void
process_ptvc_record(ptvcursor_t *ptvc, packet_info *pinfo, const ptvc_record *rec,
                    gboolean *req_cond_results, gboolean really_decode,
                    const ncp_record *ncp_rec, gboolean request);

/* NCP packets come in request/reply pairs. The request packets tell the type
 * of NCP request and give a sequence ID. The response, unfortunately, only
 * identifies itself via the sequence ID; you have to know what type of NCP
 * request the request packet contained in order to successfully parse the NCP
 * response. A global method for doing this does not exist in wireshark yet
 * (NFS also requires it), so for now the NCP section will keep its own hash
 * table keeping track of NCP packet types.
 *
 * We construct a conversation specified by the client and server
 * addresses and the connection number; the key representing the unique
 * NCP request then is composed of the pointer to the conversation
 * structure, cast to a "guint" (which may throw away the upper 32
 * bits of the pointer on a P64 platform, but the low-order 32 bits
 * are more likely to differ between conversations than the upper 32 bits),
 * and the sequence number.
 *
 * The value stored in the hash table is the ncp_req_hash_value pointer. This
 * struct tells us the NCP type and gives the ncp2222_record pointer, if
 * ncp_type == 0x2222.
 */
typedef struct {
    conversation_t  *conversation;
    guint32           nw_sequence_long;
} ncp_req_hash_key;


typedef struct {
    guint32          nw_eid;
} ncp_req_eid_hash_key;

typedef struct {
    ncp_req_eid_hash_key    *nds_eid;
    char                    object_name[256];
} ncp_req_eid_hash_value;

static GHashTable *ncp_req_hash = NULL;
static GHashTable *ncp_req_eid_hash = NULL;

/* Hash Functions */
static gboolean
ncp_equal(gconstpointer v, gconstpointer v2)
{
    const ncp_req_hash_key *val1 = (const ncp_req_hash_key*)v;
    const ncp_req_hash_key *val2 = (const ncp_req_hash_key*)v2;

    if (val1->conversation == val2->conversation &&
        val1->nw_sequence_long  == val2->nw_sequence_long ) {
        return TRUE;
    }
    return FALSE;
}

static gboolean
ncp_eid_equal(gconstpointer v, gconstpointer v2)
{
    const ncp_req_eid_hash_key *val1 = (const ncp_req_eid_hash_key*)v;
    const ncp_req_eid_hash_key *val2 = (const ncp_req_eid_hash_key*)v2;

    if (val1->nw_eid == val2->nw_eid ) {
        return TRUE;
    }
    return FALSE;
}

static guint
ncp_hash(gconstpointer v)
{
    const ncp_req_hash_key *ncp_key = (const ncp_req_hash_key*)v;
    return GPOINTER_TO_UINT(ncp_key->conversation) + ncp_key->nw_sequence_long;
}

static guint
ncp_eid_hash(gconstpointer v)
{
    const ncp_req_eid_hash_key *ncp_eid_key = (const ncp_req_eid_hash_key*)v;
    return GPOINTER_TO_UINT(ncp_eid_key->nw_eid);
}

/* Initializes the hash table and the mem_chunk area each time a new
 * file is loaded or re-loaded in wireshark */
static void
ncp_init_protocol(void)
{
    int i;

    /* fragment */
    reassembly_table_init(&nds_reassembly_table,
                          &addresses_reassembly_table_functions);

    for (i = 0; i < 99; i++) {
        frags[i].nds_frag = 0xfffffff0;
    }

    if (ncp_req_hash) {
        g_hash_table_destroy(ncp_req_hash);
    }
    if (ncp_req_eid_hash) {
        g_hash_table_destroy(ncp_req_eid_hash);
    }

    ncp_req_hash = g_hash_table_new(ncp_hash, ncp_equal);
    ncp_req_eid_hash = g_hash_table_new(ncp_eid_hash, ncp_eid_equal);
}

/* After the sequential run, we don't need the ncp_request hash and keys
 * anymore; the lookups have already been done and the vital info
 * saved in the reply-packets' private_data in the frame_data struct. */
static void
ncp_postseq_cleanup(void)
{
#if 0 /* XXX: ?? */
    if (ncp_req_hash) {
        /* Destroy the hash, but don't clean up request_condition data. */
        g_hash_table_destroy(ncp_req_hash);
        ncp_req_hash = NULL;
    }
#endif
    /* Don't free the ncp_req_hash_values or EID_hash_table, as they're
     * needed during random-access processing of the proto_tree.*/
}

/* NCP sequence numbers are from 0 - 255. After reaching 255 the
 * sequence number wraps back to 0. Change nw_sequence to nw_sequence_long
 * and use upper bits to make sequence numbers unique. This way
 * future attempts to locate initiating packet will succeed.
 */
static ncp_req_hash_value*
ncp_hash_insert(conversation_t *conversation, guint8 nw_sequence,
                const ncp_record *ncp_rec, guint32 pkt_num)
{
    ncp_req_hash_key    *request_key;
    ncp_req_hash_value  *request_value;

    /* Now remember the request, so we can find it if we later
       a reply to it. */
    request_key = wmem_new(wmem_file_scope(), ncp_req_hash_key);
    request_key->conversation = conversation;
    /* Make sequence number unique */
    request_key->nw_sequence_long = (0x10000 + ((pkt_num/16)<<16)) | nw_sequence;

    request_value = wmem_new0(wmem_file_scope(), ncp_req_hash_value);
    request_value->ncp_rec = ncp_rec;
    request_value->req_cond_results = NULL;
    request_value->req_nds_flags = 0;
    request_value->nds_request_verb = 0;
    request_value->nds_version = 0;
    g_strlcpy(request_value->object_name, " ", 256);
    request_value->nds_frag = TRUE;

    g_hash_table_insert(ncp_req_hash, request_key, request_value);

    return request_value;
}

static ncp_req_eid_hash_value*
ncp_eid_hash_insert(guint32 nw_eid)
{
    ncp_req_eid_hash_key    *request_eid_key;
    ncp_req_eid_hash_value  *request_eid_value;

    /* Now remember the request, so we can find it if we later
       a reply to it. */
    request_eid_key = wmem_new(wmem_file_scope(), ncp_req_eid_hash_key);
    request_eid_key->nw_eid = nw_eid;

    request_eid_value = wmem_new0(wmem_file_scope(), ncp_req_eid_hash_value);
    g_strlcpy(request_eid_value->object_name, " ", 256);

    g_hash_table_insert(ncp_req_eid_hash, request_eid_key, request_eid_value);

    return request_eid_value;
}

/* Returns the ncp_rec*, or NULL if not found. */
static ncp_req_hash_value*
ncp_hash_lookup(conversation_t *conversation, guint8 nw_sequence, guint32 pkt_num)
{
    ncp_req_hash_key  request_key;
    ncp_req_hash_value *temp_value;

    request_key.conversation = conversation;
    /* Find unique sequence number */
    request_key.nw_sequence_long = (0x10000+((pkt_num/16)<<16)) | nw_sequence;

    /* Since masking of sequence number utilizes the packet number as
     * part of it's algorythm it is possible for a packet to sit right
     * on the boundary and fail. (depending on number of packets in trace)
     * Loop through all the previous sequence numbers in the hash to see
     * if the original request packet can be found.
     */
    temp_value = (ncp_req_hash_value *)g_hash_table_lookup(ncp_req_hash, &request_key);
    while(!temp_value)
    {
       request_key.nw_sequence_long = request_key.nw_sequence_long-0x10000;
       if((request_key.nw_sequence_long & 0xffff0000) == 0){
            break;
       }
       temp_value = (ncp_req_hash_value *)g_hash_table_lookup(ncp_req_hash, &request_key);
    }
    return temp_value;
}

/* Returns the value_rec* for needed EID, or NULL if not found. */
static ncp_req_eid_hash_value*
ncp_eid_hash_lookup(conversation_t *conversation _U_, guint32 nw_eid)
{
    ncp_req_eid_hash_key  request_eid_key;

    request_eid_key.nw_eid = nw_eid;

    return (ncp_req_eid_hash_value *)g_hash_table_lookup(ncp_req_eid_hash, &request_eid_key);
}

/* Does NCP func require a subfunction code? */
static gboolean
ncp_requires_subfunc(guint8 func)
{
    const guint8 *ncp_func_requirement = ncp_func_requires_subfunc;

    while (*ncp_func_requirement != 0) {
        if (*ncp_func_requirement == func) {
            return TRUE;
        }
        ncp_func_requirement++;
    }
    return FALSE;
}

/* Does the NCP func have a length parameter? */
static gboolean
ncp_has_length_parameter(guint8 func)
{
    const guint8 *ncp_func_requirement = ncp_func_has_no_length_parameter;

    while (*ncp_func_requirement != 0) {
        if (*ncp_func_requirement == func) {
            return FALSE;
        }
        ncp_func_requirement++;
    }
    return TRUE;
}


/* Return a ncp_record* based on func and possibly subfunc */
static const ncp_record *
ncp_record_find(guint8 func, guint8 subfunc)
{
    const ncp_record *ncp_rec = ncp_packets;

    while(ncp_rec->func != 0 || ncp_rec->subfunc != 0 ||
          ncp_rec->name != NULL ) {
        if (ncp_rec->func == func) {
            if (ncp_rec->has_subfunc) {
                if (ncp_rec->subfunc == subfunc) {
                    return ncp_rec;
                }
            }
            else {
                return ncp_rec;
            }
        }
        ncp_rec++;
    }
    return NULL;
}

#define NW_UNI_MAX 1024

#define VTYPE_NONE                       0  /* no value */
#define VTYPE_UINT8                      1
#define VTYPE_UINT16                     2
#define VTYPE_UINT32                     3
#define VTYPE_STRING                     4
#define VTYPE_BITFIELD                   5
#define VTYPE_MULTIVALUE_UINT32          6
#define VTYPE_BYTES                      7
#define VTYPE_BOOLEAN                    8
#define VTYPE_ITEM                       9

#define MVTYPE_ATTR_REQUEST              1
#define MVTYPE_ATTR_REPLY                2
#define MVTYPE_ATTR_REQUEST2             3
#define MVTYPE_READ_CLASS_REQ            4
#define MVTYPE_READ_REPLICAS             5
#define MVTYPE_MODIFY_ATTR_REQUEST       6
#define MVTYPE_ADDR_REFERRAL_REQUEST     7
#define MVTYPE_ADDR_REFERRAL_REPLY       8
#define MVTYPE_LOC_ADDR_REFERRAL_REPLY   9
#define MVTYPE_PROC_ENTRY_SPECIFIERS    10
#define MVTYPE_PRINT_TIMESTAMP          11
#define MVTYPE_LIST_PARTITIONS          12
#define MVTYPE_CLASS_NAMES              13
#define MVTYPE_MODIFY_CLASS             14
#define MVTYPE_ADD_ATTR_REQUEST         15
#define MVTYPE_PROCESS_TAGS             16
#define MVTYPE_PROCESS_ITERATOR         17

typedef struct {
    guint8          vtype;
    guint32         vvalue;
    const char*     vstring;
    const char*     vdesc;
    guint32         vlength;
    guint32         voffset;
    guint32         hfname;
    const char*     bit1;
    guint32         bit1hfname;
    const char*     bit2;
    guint32         bit2hfname;
    const char*     bit3;
    guint32         bit3hfname;
    const char*     bit4;
    guint32         bit4hfname;
    const char*     bit5;
    guint32         bit5hfname;
    const char*     bit6;
    guint32         bit6hfname;
    const char*     bit7;
    guint32         bit7hfname;
    const char*     bit8;
    guint32         bit8hfname;
    const char*     bit9;
    guint32         bit9hfname;
    const char*     bit10;
    guint32         bit10hfname;
    const char*     bit11;
    guint32         bit11hfname;
    const char*     bit12;
    guint32         bit12hfname;
    const char*     bit13;
    guint32         bit13hfname;
    const char*     bit14;
    guint32         bit14hfname;
    const char*     bit15;
    guint32         bit15hfname;
    const char*     bit16;
    guint32         bit16hfname;
    guint8          mvtype;
    guint32         vflags;
    guint32         nds_version;
    guint32         pflags; /* NDS Protocol Flags */
} nds_val;

static proto_item*
add_ptvc_field(packet_info* pinfo, ptvcursor_t *ptvc, const ptvc_record *rec, gboolean request, gboolean repeat, guint* ret_value)
{
    header_field_info* hinfo = proto_registrar_get_nth(*rec->hf_ptr);

    if (!repeat && request && rec->req_info_str)
        col_set_str(pinfo->cinfo, COL_INFO, "C ");

    /* We may want integer values regardless of whether or not the value is displayed in INFO column */
    if (IS_FT_UINT(hinfo->type) || IS_FT_INT(hinfo->type)) {
        guint32 value32 = 0;
        guint64 value64 = 0;

        switch(rec->length)
        {
        case 1:
            value32 = tvb_get_guint8(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
            *ret_value = value32;
            break;
        case 2:
            value32 = tvb_get_guint16(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc), rec->endianness);
            *ret_value = value32;
            break;
        case 3:
            value32 = tvb_get_guint24(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc), rec->endianness);
            *ret_value = value32;
            break;
        case 4:
            value32 = tvb_get_guint32(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc), rec->endianness);
            *ret_value = value32;
            break;
        case 5:
            value64 = tvb_get_guint40(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc), rec->endianness);
            break;
        case 6:
            value64 = tvb_get_guint48(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc), rec->endianness);
            break;
        case 7:
            value64 = tvb_get_guint56(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc), rec->endianness);
            break;
        case 8:
            value64 = tvb_get_guint64(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc), rec->endianness);
            break;
        default:
            DISSECTOR_ASSERT(FALSE);
            break;
        }

        if (request && rec->req_info_str) {
            if (rec->length <= 4) {
                col_append_fstr(pinfo->cinfo, COL_INFO,
                        (const gchar*)(repeat ? rec->req_info_str->repeat_string : rec->req_info_str->first_string),
                        value32);
            } else {
                col_append_fstr(pinfo->cinfo, COL_INFO,
                        (const gchar*)(repeat ? rec->req_info_str->repeat_string : rec->req_info_str->first_string),
                        value64);

            }
        }
    } else if (request && rec->req_info_str) {
        if (hinfo->type == FT_STRING) {
            col_append_fstr(pinfo->cinfo, COL_INFO,
                                (const gchar*)(repeat ? rec->req_info_str->repeat_string : rec->req_info_str->first_string),
                                 tvb_get_string_enc(wmem_packet_scope(), ptvcursor_tvbuff(ptvc),
                                     ptvcursor_current_offset(ptvc), rec->length, ENC_ASCII));
        } else if (hinfo->type == FT_STRINGZ) {
            gint length;
            col_append_fstr(pinfo->cinfo, COL_INFO,
                                (const gchar*)(repeat ? rec->req_info_str->repeat_string : rec->req_info_str->first_string),
                                tvb_get_stringz_enc(wmem_packet_scope(), ptvcursor_tvbuff(ptvc),
                                    ptvcursor_current_offset(ptvc), &length, ENC_ASCII));
        } else if (hinfo->type == FT_UINT_STRING) {
            guint32 length = 0;

            switch(rec->length)
            {
            case 1:
                length = tvb_get_guint8(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
                break;
            case 2:
                length = tvb_get_guint16(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc), rec->endianness);
                break;
            case 3:
                length = tvb_get_guint24(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc), rec->endianness);
                break;
            case 4:
                length = tvb_get_guint32(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc), rec->endianness);
                break;
            default:
                DISSECTOR_ASSERT(FALSE);
                break;
            }

            col_append_fstr(pinfo->cinfo, COL_INFO,
                                (const gchar*)(repeat ? rec->req_info_str->repeat_string : rec->req_info_str->first_string),
                                tvb_get_string_enc(wmem_packet_scope(), ptvcursor_tvbuff(ptvc),
                                    ptvcursor_current_offset(ptvc)+rec->length, length, ENC_ASCII));
        } else if (hinfo->type == FT_BYTES) {
            col_append_fstr(pinfo->cinfo, COL_INFO,
                                (const gchar*)(repeat ? rec->req_info_str->repeat_string : rec->req_info_str->first_string),
                                tvb_bytes_to_str(wmem_packet_scope(), ptvcursor_tvbuff(ptvc),
                                    ptvcursor_current_offset(ptvc), rec->length));
        }
    }

    return ptvcursor_add(ptvc, *rec->hf_ptr,
                      rec->length,
                      rec->endianness);
}

/*
 * XXX - are these just DOS-format dates and times?
 *
 * Should we put code to understand various date and time formats (UNIX,
 * DOS, SMB weird mutant UNIX, NT, Mac, etc. into libwireshark, and have
 * the "display" member of an HF_ABSOLUTE_TIME field specify whether
 * it's DOS date/DOS time, DOS time/DOS date, NT time, UNIX time_t,
 * UNIX "struct timeval", NFSv3/NFSv4 seconds/nanoseconds, Mac, etc.?
 *
 * What about hijacking the "bitmask" field to specify the precision of
 * the time stamp, or putting a combination of precision and format
 * into the "display" member?
 *
 * What about relative times?  Should they have units (seconds, milliseconds,
 * microseconds, nanoseconds, etc.), precision, and format in there?
 */
static void
padd_date( gchar *result, guint32 date_value )
{
    g_snprintf( result, ITEM_LABEL_LENGTH, "%04u/%02u/%02u", ((date_value & 0xfe00) >> 9) + 1980, (date_value & 0x01e0) >> 5, date_value & 0x001f);
}

static void
padd_time( gchar *result, guint32 time_value )
{
    g_snprintf( result, ITEM_LABEL_LENGTH, "%02u:%02u:%02u", ((time_value & 0xf800) >> 11), ((time_value & 0x07e0) >> 5), (time_value & 0x001f) * 2);
}

/* Add a value for a ptvc_record, and process the sub-ptvc_record
 * that it points to. */
static void
process_bitfield_sub_ptvc_record(ptvcursor_t *ptvc, const ptvc_record *rec,
                                 gboolean really_decode)
{
    proto_item          *item;
    proto_tree          *sub_tree;
    const ptvc_record   *sub_rec;
    int                 current_offset;
    gint                ett;
    ptvcursor_t         *sub_ptvc;

    if (really_decode) {
        /* Save the current offset */
        current_offset = ptvcursor_current_offset(ptvc);

        /* Add the item */
        item = ptvcursor_add(ptvc, *rec->hf_ptr, rec->length,
                             rec->endianness);

        ett = *rec->sub_ptvc_rec->ett;

        /* Make a new protocol sub-tree */
        sub_tree = proto_item_add_subtree(item, ett);

        /* Make a new ptvcursor */
        sub_ptvc = ptvcursor_new(sub_tree, ptvcursor_tvbuff(ptvc),
                                 current_offset);

        /* Use it */
        sub_rec = rec->sub_ptvc_rec->ptvc_rec;
        while(sub_rec->hf_ptr != NULL) {
            DISSECTOR_ASSERT(!sub_rec->sub_ptvc_rec);
            ptvcursor_add_no_advance(sub_ptvc, *sub_rec->hf_ptr,
                                     sub_rec->length,
                                     sub_rec->endianness);
            sub_rec++;
        }

        /* Free it. */
        ptvcursor_free(sub_ptvc);
    }
    else {
        DISSECTOR_ASSERT(rec->length > 0 &&
                         proto_registrar_get_nth(*rec->hf_ptr)->type != FT_UINT_STRING);
        ptvcursor_advance(ptvc, rec->length);
    }
}

/* Process a sub-ptvc_record that points to a "struct" ptvc_record. */
static void
process_struct_sub_ptvc_record(ptvcursor_t *ptvc, packet_info *pinfo, const ptvc_record *rec,
                               gboolean *req_cond_results, gboolean really_decode,
                               const ncp_record *ncp_rec, gboolean request)
{
    const ptvc_record   *sub_rec;
    gint                ett;
    proto_tree          *old_tree=NULL, *new_tree;
    proto_item          *item=NULL;
    gint                offset=0;

    /* Create a sub-proto_tree? */
    if (rec->sub_ptvc_rec->descr) {
        ett = *rec->sub_ptvc_rec->ett;
        old_tree = ptvcursor_tree(ptvc);
        offset = ptvcursor_current_offset(ptvc);
        new_tree = proto_tree_add_subtree(old_tree, ptvcursor_tvbuff(ptvc), offset, -1,
                                          ett, &item, rec->sub_ptvc_rec->descr);
        ptvcursor_set_tree(ptvc, new_tree);
    }

    /* Get the ptvc_record for the struct and call our caller
     * to process it. */
    sub_rec = rec->sub_ptvc_rec->ptvc_rec;
    process_ptvc_record(ptvc, pinfo, sub_rec, req_cond_results, really_decode, ncp_rec, request);

    /* Re-set the tree */
    if (rec->sub_ptvc_rec->descr) {
        if (ptvcursor_current_offset(ptvc) <= offset)
            THROW(ReportedBoundsError);

        proto_item_set_len(item, ptvcursor_current_offset(ptvc) - offset);
        ptvcursor_set_tree(ptvc, old_tree);
    }
}

/* Run through the table of ptvc_record's and add info to the tree. This
 * is the work-horse of process_ptvc_record(). */
static void
_process_ptvc_record(ptvcursor_t *ptvc, packet_info *pinfo, const ptvc_record *rec,
                     gboolean *req_cond_results, gboolean really_decode,
                     const ncp_record *ncp_rec, gboolean request)
{
    guint       i, repeat_count, repeat_value;

    if (rec->sub_ptvc_rec) {
        /* Repeat this? */
        if (rec->repeat_index >= NO_REPEAT) {
            if (rec->hf_ptr == PTVC_STRUCT) {
                process_struct_sub_ptvc_record(ptvc, pinfo, rec,
                                               req_cond_results, really_decode,
                                               ncp_rec, request);
            }
            else {
                process_bitfield_sub_ptvc_record(ptvc, rec,
                                                 really_decode);
            }
        }
        else {
            repeat_count = repeat_vars[rec->repeat_index];
            for (i = 0; i < repeat_count; i++ ) {
                if (rec->hf_ptr == PTVC_STRUCT) {
                    process_struct_sub_ptvc_record(ptvc, pinfo, rec,
                                                   req_cond_results, really_decode,
                                                   ncp_rec, request);
                }
                else {
                    process_bitfield_sub_ptvc_record(ptvc, rec,
                                                     really_decode);
                }
            }
        }
    }
    else {
        /* If we can't repeat this field, we might use it
         * to set a 'var'. */
        if (rec->repeat_index == NO_REPEAT) {
            if (really_decode) {
                repeat_value = 0;
                add_ptvc_field(pinfo, ptvc, rec, request, FALSE, &repeat_value);

                /* Set the value as a 'var' ? */
                if (rec->var_index != NO_VAR) {
                    repeat_vars[rec->var_index] = repeat_value;
                }
            }
            else {
                /* If we don't decode the field, we
                 * better not use the value to set a var.
                 * Actually, we could, as long as we don't
                 * *use* that var; for now keep this assert in
                 * place. */
                DISSECTOR_ASSERT(rec->var_index == NO_VAR);

                /* This had better not be variable-length,
                 * either. */
                DISSECTOR_ASSERT(rec->length > 0 &&
                                 proto_registrar_get_nth(*rec->hf_ptr)->type != FT_UINT_STRING);
                ptvcursor_advance(ptvc, rec->length);
            }
        }
        else {
            /* We do repeat this field. */
            repeat_count = repeat_vars[rec->repeat_index];
            if (really_decode) {
                for (i = 0; i < repeat_count; i++ ) {
                    add_ptvc_field(pinfo, ptvc, rec, request, i != 0, &repeat_value);
                }
            }
            else {
                for (i = 0; i < repeat_count; i++ ) {
                    DISSECTOR_ASSERT(rec->length > 0 &&
                                     proto_registrar_get_nth(*rec->hf_ptr)->type != FT_UINT_STRING);
                    ptvcursor_advance(ptvc, rec->length);
                }
            }
        }
    }
}

/* Run through the table of ptvc_record's and add info to the tree.
 * Honor a request condition result. */
static void
process_ptvc_record(ptvcursor_t *ptvc, packet_info *pinfo, const ptvc_record *rec,
                    gboolean *req_cond_results, gboolean really_decode,
                    const ncp_record *ncp_rec, gboolean request)
{
    gboolean decode;
    ptvcursor_t *expert_ptvc;
    proto_tree* expert_tree = ptvcursor_tree(ptvc);
    tvbuff_t* expert_tvb = ptvcursor_tvbuff(ptvc);
    gint expert_offset = ptvcursor_current_offset(ptvc);

    while(rec->hf_ptr != NULL) {
        decode = really_decode;
        /* If we're supposed to decode, check the request condition
         * results to see if we should override this and *not* decode. */
        if (decode && req_cond_results) {
            if (rec->req_cond_index != NO_REQ_COND) {
                if (req_cond_results[rec->req_cond_index] == FALSE) {
                    decode = FALSE;
                }
            }
        }
        if (decode || ncp_rec->req_cond_size_type == REQ_COND_SIZE_CONSTANT) {
            _process_ptvc_record(ptvc, pinfo, rec, req_cond_results, decode, ncp_rec, request);
        }
        rec++;
    }

    /* Collect any potential expert info that would have been collected over
       these records */
    if (ncp_rec->expert_handler_func)
    {
        expert_ptvc = ptvcursor_new(expert_tree, expert_tvb, expert_offset);
        ncp_rec->expert_handler_func(expert_ptvc, pinfo, ncp_rec, request);
        ptvcursor_free(expert_ptvc);
    }
}



/* Clear the repeat_vars array. */
static void
clear_repeat_vars(void)
{
    guint i;

    for (i = 0 ; i < NUM_REPEAT_VARS; i++ ) {
        repeat_vars[i] = 0;
    }
}


/* Given an error_equivalency table and a completion code, return
 * the string representing the error. */
static const char*
ncp_error_string(const error_equivalency *errors, guint8 completion_code)
{

    while (errors->ncp_error_index != -1) {
        if (errors->error_in_packet == completion_code) {
            return ncp_errors[errors->ncp_error_index];
        }
        errors++;
    }

    return "Unknown Error Code";
}

static const ncp_record ncp1111_request =
{ 0x1, 0x00, NO_SUBFUNC, "Create Connection Service", NCP_GROUP_CONNECTION,
  NULL, NULL, ncp_0x2_errors, NULL, NO_REQ_COND_SIZE, NULL };

static const ncp_record ncp5555_request =
{ 0x5, 0x00, NO_SUBFUNC, "Destroy Connection Service", NCP_GROUP_CONNECTION,
  NULL, NULL, ncp_0x2_errors, NULL, NO_REQ_COND_SIZE, NULL };

static const ncp_record ncpbbbb_request =
{ 0xb, 0x00, NO_SUBFUNC, "Server Broadcast Message", NCP_GROUP_CONNECTION,
  NULL, NULL, ncp_0x2_errors, NULL, NO_REQ_COND_SIZE, NULL };

static const ncp_record ncplip_echo =
{ 0x1f, 0x00, NO_SUBFUNC, "LIP Echo Packet", NCP_GROUP_CONNECTION,
  NULL, NULL, ncp_0x2_errors, NULL, NO_REQ_COND_SIZE, NULL };

/* Wrapper around proto_tree_free() */
static void free_proto_tree(void *tree)
{
    if (tree) {
        proto_tree_free((proto_tree*) tree);
    }
}

static guint32
align_4(tvbuff_t *tvb, guint32 aoffset)
{
    if(tvb_captured_length_remaining(tvb, aoffset) > 4 )
    {
        return (aoffset%4);
    }
    return 0;
}

static const char *
get_string(tvbuff_t* tvb, guint offset, guint str_length)
{
    char *dest_buf;
    gint i;
    guint16 c_char;
    gint length_remaining = 0;
    gint max_length = (str_length < NW_UNI_MAX) ? str_length : NW_UNI_MAX;

    length_remaining = tvb_captured_length_remaining(tvb, offset);
    if((gint)str_length > length_remaining)
    {
        THROW(ReportedBoundsError);
    }

    if(str_length == 0)
    {
        return "";
    }

    dest_buf = (char *)wmem_alloc(wmem_packet_scope(), max_length + 1);
    dest_buf[0] = '\0';

    for ( i = 0; i < (gint)str_length; i++ )
    {
        c_char = tvb_get_guint8(tvb, offset );
        if (c_char<0x20 || c_char>0x7e)
        {
            if (c_char != 0x00)
            {
                c_char = '.';
                dest_buf[i] = c_char & 0xff;
            }
            else
            {
                i--;
                str_length--;
            }
        }
        else
        {
            dest_buf[i] = c_char & 0xff;
        }
        offset++;
        length_remaining--;

        if(length_remaining==1)
        {
            dest_buf[i+1] = '\0';
            return dest_buf;
        }
        if (i >= 1023) { /* Don't process beyond the size of our variable */
            break;       /* If string is too long just return the first 1K. */
        }
    }
    if (i < 0) {
        i = 0;
    }
    dest_buf[i] = '\0';
    return dest_buf;
}

/* Echo the NDS EID and name for NCP 22,51 replies to expert tap */
static void ncp1633_reply_expert_func(ptvcursor_t *ptvc, packet_info *pinfo, const ncp_record *ncp_rec _U_, gboolean request)
{
    if (nds_echo_eid && !request) {
        guint32 object_id;
        guint8  volume_name_len;
        gchar*  volume_name;

        object_id = tvb_get_letohl(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc)+126);
        ptvcursor_advance(ptvc, 134);
        volume_name_len = tvb_get_guint8(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
        ptvcursor_advance(ptvc, 1);
        volume_name = tvb_get_string_enc(wmem_packet_scope(), ptvcursor_tvbuff(ptvc),
                                ptvcursor_current_offset(ptvc), volume_name_len, ENC_ASCII);

        expert_add_info_format(pinfo, NULL, &ei_ncp_eid,
                                    "EID (%08x) = %s", object_id, volume_name);
    }
}

/* The following allows for specific NCP server info to be echoed to the expert tap. */
static void ncp1711_reply_expert_func(ptvcursor_t *ptvc, packet_info *pinfo, const ncp_record *ncp_rec _U_, gboolean request)
{
    if (ncp_echo_server && !request) {
        guint8* fsname;
        guint8 maj_ver, min_ver, os_lang, serv_type, kernel;
        guint16 prod_rev;

        fsname = tvb_get_string_enc(wmem_packet_scope(), ptvcursor_tvbuff(ptvc),
                                ptvcursor_current_offset(ptvc), 48, ENC_ASCII);
        ptvcursor_advance(ptvc, 48);
        maj_ver = tvb_get_guint8(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
        ptvcursor_advance(ptvc, 1);
        min_ver = tvb_get_guint8(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
        ptvcursor_advance(ptvc, 25); /* Skip unimportant fields */
        prod_rev = tvb_get_ntohs(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
        ptvcursor_advance(ptvc, 2);
        os_lang = tvb_get_guint8(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
        ptvcursor_advance(ptvc, 2);
        serv_type = tvb_get_guint8(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
        ptvcursor_advance(ptvc, 1);
        kernel = tvb_get_guint8(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
        ptvcursor_advance(ptvc, 1);

        expert_add_info_format(pinfo, NULL, &ei_ncp_server, "Server %s, version %d.%d, support pack %d, language %d, server type %s, kernel %s", fsname,
                                maj_ver, min_ver, prod_rev, os_lang, val_to_str(serv_type & 0x01, serv_type_vals, "Unknown: %d"),
                                val_to_str(kernel & 0x01, kernel_type_vals, "Unknown: %d") );
    }
}

/* The following allows for Update file handle rights echoed to expert tap. */
static void ncp42_request_expert_func(ptvcursor_t *ptvc, packet_info *pinfo, const ncp_record *ncp_rec _U_, gboolean request)
{
    if (ncp_echo_file && request) {
        gchar* filehandle = tvb_bytes_to_str(wmem_packet_scope(), ptvcursor_tvbuff(ptvc),
                                                ptvcursor_current_offset(ptvc)+1, 6);

        expert_add_info_format(pinfo, NULL, &ei_ncp_file_handle, "Close file handle %s", filehandle);
    }
}

/* The following allows for oplock level 1 file opens echoed to expert tap. */
static void file_rights_expert_func(ptvcursor_t *ptvc, packet_info *pinfo, const ncp_record *ncp_rec, gboolean request)
{
    if (ncp_echo_file) {
        if (request) {
            guint8 oaction = 0, path_count = 0;
            guint16 rights = 0;
            gchar* filename = "";

            if (ncp_rec->func == 87) {
                switch(ncp_rec->subfunc)
                {
                case 1:
                case 32:
                    oaction = tvb_get_guint8(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc)+1);
                    ptvcursor_advance(ptvc, 12);
                    rights = tvb_get_ntohs(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
                    ptvcursor_advance(ptvc, 8);
                    path_count = tvb_get_guint8(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
                    ptvcursor_advance(ptvc, 1);
                    filename = tvb_get_string_enc(wmem_packet_scope(), ptvcursor_tvbuff(ptvc),
                                ptvcursor_current_offset(ptvc), path_count, ENC_ASCII);
                    break;
                case 33:
                case 30:
                    oaction = tvb_get_guint8(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc)+2);
                    ptvcursor_advance(ptvc, 16);
                    rights = tvb_get_ntohs(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
                    ptvcursor_advance(ptvc, 8);
                    path_count = tvb_get_guint8(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
                    ptvcursor_advance(ptvc, 1);
                    filename = tvb_get_string_enc(wmem_packet_scope(), ptvcursor_tvbuff(ptvc),
                                    ptvcursor_current_offset(ptvc), path_count, ENC_ASCII);
                    break;
                }
            } else if (ncp_rec->func == 89) {
                switch(ncp_rec->subfunc)
                {
                case 1:
                case 32:
                    oaction = tvb_get_guint8(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc)+1);
                    ptvcursor_advance(ptvc, 12);
                    rights = tvb_get_ntohs(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
                    ptvcursor_advance(ptvc, 14);
                    path_count = tvb_get_guint8(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
                    ptvcursor_advance(ptvc, 1);
                    filename = tvb_get_string_enc(wmem_packet_scope(), ptvcursor_tvbuff(ptvc),
                                    ptvcursor_current_offset(ptvc), path_count, ENC_ASCII);
                    break;
                case 33:
                case 30:
                    oaction = tvb_get_guint8(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc)+2);
                    ptvcursor_advance(ptvc, 16);
                    rights = tvb_get_ntohs(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
                    ptvcursor_advance(ptvc, 14);
                    path_count = tvb_get_guint8(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
                    ptvcursor_advance(ptvc, 1);
                    filename = tvb_get_string_enc(wmem_packet_scope(), ptvcursor_tvbuff(ptvc),
                                    ptvcursor_current_offset(ptvc), path_count, ENC_ASCII);
                    break;
                }
            }

            expert_add_info_format(pinfo, NULL, &ei_ncp_file_rights,
                                "Op-lock open, mode %s for filename %s with rights %s",
                                val_to_str(oaction & 0xeb, open_create_mode_vals, "Unknown: %d"),
                                filename,
                                val_to_str(rights & 0x5f, ncp_rights_vals, "Unknown: %d"));
        } else {
            if ((ncp_rec->func == 89 || ncp_rec->func == 87) && (ncp_rec->subfunc == 32 || ncp_rec->subfunc == 1)) {
                guint8 oaction, oplockflg;
                gchar* filehandle;

                filehandle = tvb_bytes_to_str(wmem_packet_scope(), ptvcursor_tvbuff(ptvc),
                                                ptvcursor_current_offset(ptvc), 4);
                ptvcursor_advance(ptvc, 4);
                oaction = tvb_get_guint8(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));

                if (ncp_rec->subfunc == 1) {
                    expert_add_info_format(pinfo, NULL, &ei_ncp_file_handle, "%s - File handle %s",
                                           val_to_str(oaction & 0x8f, open_create_action_vals, "Unknown: %d"),
                                           filehandle);
                }
                else
                {
                    ptvcursor_advance(ptvc, 1);
                    oplockflg = tvb_get_guint8(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
                    expert_add_info_format(pinfo, NULL, &ei_ncp_file_handle, "%s - File handle %s, %s",
                                           val_to_str(oaction & 0x8f, open_create_action_vals, "Unknown: %d"),
                                           filehandle,
                                           val_to_str(oplockflg, ncp_o_c_ret_flags_vals, "Unknown: %d"));
                }
            }
        }
    }
}

/* The following allows for oplock ack's and level 2 request echoed to expert tap. */
static void ncp5722_request_expert_func(ptvcursor_t *ptvc, packet_info *pinfo, const ncp_record *ncp_rec _U_, gboolean request)
{
    if (ncp_echo_file && request) {
        guint32 filehandle;
        guint8 cc_function;

        filehandle = tvb_get_ntohl(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
        ptvcursor_advance(ptvc, 4);
        cc_function = tvb_get_guint8(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));

        expert_add_info_format(pinfo, NULL, &ei_ncp_op_lock_handle, "Op-lock on handle %08x - %s", filehandle,
                                val_to_str(cc_function, ncp_cc_function_vals, "Unknown: %d"));
    }
}

/* The following allows for Update file handle rights echoed to expert tap. */
static void ncp572c_expert_func(ptvcursor_t *ptvc, packet_info *pinfo, const ncp_record *ncp_rec _U_, gboolean request)
{
    if (ncp_echo_file) {
        gchar* filehandle;

        if (request) {
            guint16 access_rights, new_rights;

            access_rights = tvb_get_ntohs(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc)+8);
            ptvcursor_advance(ptvc, 10);
            new_rights = tvb_get_ntohs(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
            ptvcursor_advance(ptvc, 2);
            filehandle = tvb_bytes_to_str(wmem_packet_scope(), ptvcursor_tvbuff(ptvc),
                                                    ptvcursor_current_offset(ptvc), 4);

            expert_add_info_format(pinfo, NULL, &ei_ncp_file_rights_change, "Change handle %s rights from:(%s) to:(%s)",
                                   filehandle,
                                   val_to_str(access_rights & 0x1ff, access_rights_vals, "Unknown: %d"),
                                   val_to_str(new_rights & 0x1ff, access_rights_vals, "Unknown: %d"));

        } else {
            guint32 rights;

            filehandle = tvb_bytes_to_str(wmem_packet_scope(), ptvcursor_tvbuff(ptvc),
                                                    ptvcursor_current_offset(ptvc), 4);
            ptvcursor_advance(ptvc, 4);
            rights = tvb_get_ntohl(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc)+8);

            expert_add_info_format(pinfo, NULL, &ei_ncp_effective_rights, "Handle %s effective rights:(%s)", filehandle,
                                    val_to_str(rights & 0x1ff, access_rights_vals, "Unknown: %d"));
        }
    }
}

static void
print_nds_values(proto_tree *vtree, packet_info* pinfo, tvbuff_t *tvb, guint32 syntax_type, nds_val *vvalues)
{
    guint32         value1 = 0;
    guint32         value2 = 0;
    guint32         value3 = 0;
    guint32         value4 = 0;
    guint32         value5 = 0;
    guint32         voffset = 0, oldvoffset;
    guint32         icounter;
    guint32         number_of_values = 0;
    guint32         number_of_items = 0;
    guint32         r;
    proto_item      *vitem;
    proto_tree      *nvtree;
    proto_item      *aditem;
    proto_tree      *adtree;
    const char      *valuestr = NULL;
    gint            length_remaining;
    nstime_t        ns;
    gboolean        entry_rights = FALSE;

    voffset = vvalues->voffset;
#if 0
    if(tvb_get_guint8(tvb, voffset) == 0x00)
    {
        voffset = voffset+2;
    }
#endif

    number_of_values = tvb_get_letohl(tvb, voffset);

    vitem = proto_tree_add_uint_format(vtree, hf_nds_uint32value, tvb, voffset,
                                       4, number_of_values, "Number of Values: %u", number_of_values);

    nvtree = proto_item_add_subtree(vitem, ett_nds);

    oldvoffset = voffset;
    voffset = voffset + 4;

    for (icounter = 1 ; icounter <= number_of_values; icounter++ )
    {
        if (oldvoffset >= voffset) {
            proto_tree_add_expert_format(nvtree, pinfo, &ei_ncp_invalid_offset, tvb, 0, 0, "Invalid offset: %u", voffset);
            THROW(ReportedBoundsError);
        }
        oldvoffset = voffset;
        switch(syntax_type)
        {
        case 0x00000006:        /* Case Insensitive List */
        case 0x00000012:        /* Postal Address */
            voffset += align_4(tvb, voffset);
            voffset = voffset+4;
            number_of_items = tvb_get_letohl(tvb, voffset);
            voffset = voffset+4;
            for (r=1; r<=number_of_items; r++)
            {
                value1 = tvb_get_letohl(tvb, voffset);
                voffset = voffset + 4;
                vvalues->vstring = get_string(tvb, voffset, value1);
                proto_tree_add_string(nvtree, hf_value_string, tvb, voffset,
                                      value1, vvalues->vstring);
                voffset = voffset + value1;
                voffset += align_4(tvb, voffset);
            }
            break;
        case 0x00000007:        /* Boolean */
            voffset+=4;                            /* this is always just a parameter count of 1, so ignore */
            value1 = tvb_get_guint8(tvb, voffset); /* Boolean value */
            if (value1==0)
            {
                vvalues->vstring = "False";
            }
            else
            {
                vvalues->vstring = "True";
            }
            proto_tree_add_string(nvtree, hf_value_string, tvb, voffset,
                                  1, vvalues->vstring);
            voffset=voffset+1;
            voffset += align_4(tvb, voffset);
            break;
        case 0x00000009:        /* Binary String */
            value1 = tvb_get_letohl(tvb, voffset); /* length of field */
            length_remaining = tvb_captured_length_remaining(tvb, voffset);
            if(length_remaining == -1 || value1 > (guint32) length_remaining)
            {
                break;
            }
            voffset += 4;
            proto_tree_add_item(nvtree, hf_value_bytes, tvb, voffset, value1, ENC_NA);
            voffset += value1;
            voffset += (value1%2);
            break;
        case 0x0000000d:        /* Binary String List */
            value1 = tvb_get_letohl(tvb, voffset); /* Overall length of field list */
            length_remaining = tvb_captured_length_remaining(tvb, voffset);
            if(length_remaining == -1 || value1 > (guint32) length_remaining)
            {
                break;
            }
            voffset += 4;
            tvb_ensure_bytes_exist(tvb, voffset, value1);
            number_of_items = tvb_get_letohl(tvb, voffset);
            voffset = voffset+4;
            for (r=1; r<=number_of_items; r++)
            {
                value1 = tvb_get_letohl(tvb, voffset); /* length of field */
                length_remaining = tvb_captured_length_remaining(tvb, voffset);
                if(length_remaining == -1 || value1 > (guint32) length_remaining)
                {
                    break;
                }
                voffset += 4;
                proto_tree_add_item(nvtree, hf_value_bytes, tvb, voffset, value1, ENC_NA);
                voffset += value1;
                voffset += (value1%2);
            }
            break;
        case 0x00000015:        /* Stream */
            value1 = tvb_get_letohl(tvb, voffset); /* length of field */
            length_remaining = tvb_captured_length_remaining(tvb, voffset);
            if(length_remaining == -1 || value1 > (guint32) length_remaining)
            {
                break;
            }
            proto_tree_add_uint_format(nvtree, hf_nds_uint32value, tvb, voffset, 4, value1, "No value, Open stream file for data.");
            voffset += 4;
            voffset += value1;
            voffset += (value1%2);
            break;
        case 0x00000008:        /* Signed Integer */
        case 0x00000016:        /* Counter */
        case 0x0000001b:        /* Interval */
            value1 = tvb_get_letohl(tvb, voffset); /* length of field */
            voffset = voffset+4;
            value2 = tvb_get_letohl(tvb, voffset); /* Value */
            if (strcmp(vvalues->vstring, "zendmSearchType")==0) {
                proto_tree_add_uint_format(nvtree, hf_nds_uint32value, tvb, voffset,
                                           value1, value2,
                                           "Value (%d) = %s", value2,
                                           val_to_str(value2, zensearchenum, "Unknown: %d"));
            }
            else
            {
                proto_tree_add_uint_format(nvtree, hf_nds_uint32value, tvb, voffset,
                                           value1, value2, "Value %d", value2);
            }
            voffset = voffset+4;
            break;
        case 0x0000000b:        /* Fax Number */
            value1 = tvb_get_letohl(tvb, voffset); /* length of field */
            voffset = voffset+4;
            vvalues->vstring = get_string(tvb, voffset, value1);
            proto_tree_add_string(nvtree, hf_value_string, tvb, voffset,
                                  value1, vvalues->vstring);
            voffset = voffset + value1;
            voffset += align_4(tvb, voffset);
            break;
        case 0x0000000c:        /* Network Address */
            value1 = tvb_get_letohl(tvb, voffset); /* length of field */
            voffset = voffset + 4;
            value2 = tvb_get_letohl(tvb, voffset); /* type of Protocol */
            valuestr = val_to_str_const(value2, nds_protocol_type, "(Undefined Protocol)");
            proto_tree_add_uint_format(nvtree, hf_nds_uint32value, tvb, voffset,
                                       value1, value2, valuestr, value2);
            voffset = voffset+4;
            value3 = tvb_get_letohl(tvb, voffset); /* length of address */
            voffset = voffset+4;
            switch (value2)
            {
            case NDS_PTYPE_IPX:
                proto_tree_add_item(nvtree, hf_nds_net, tvb, voffset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(nvtree, hf_nds_node, tvb, voffset+4, 6, ENC_NA);
                proto_tree_add_item(nvtree, hf_nds_socket, tvb, voffset+10, 2, ENC_BIG_ENDIAN);
                break;
            case NDS_PTYPE_IP:
                if (value3 > 4) {
                    proto_tree_add_item(nvtree, hf_nds_port, tvb, voffset, 2, ENC_BIG_ENDIAN);
                    voffset += 2;
                }
                proto_tree_add_item(nvtree, hf_add_ref_ip, tvb, voffset, 4, ENC_BIG_ENDIAN);
                break;
            case NDS_PTYPE_UDP:
                if (value3 > 4) {
                    proto_tree_add_item(nvtree, hf_nds_port, tvb, voffset, 2, ENC_BIG_ENDIAN);
                    voffset += 2;
                }
                proto_tree_add_item(nvtree, hf_add_ref_udp, tvb, voffset, 4, ENC_BIG_ENDIAN);
                break;
            case NDS_PTYPE_TCP:
                proto_tree_add_item(nvtree, hf_nds_port, tvb, voffset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(nvtree, hf_add_ref_tcp, tvb, voffset+2, 4, ENC_BIG_ENDIAN);
                break;
            case NDS_PTYPE_URL:
            case NDS_PTYPE_DNS:
                vvalues->vstring = get_string(tvb, voffset, value3);
                proto_tree_add_string(nvtree, hf_value_string, tvb, voffset,
                                      value3, vvalues->vstring);
                break;
            default:
                break;
            }
            voffset = voffset + value3;
            voffset += align_4(tvb, voffset);
            break;
        case 0x0000000f:        /* File System Path */
            /*value1 = tvb_get_letohl(tvb, voffset);*/ /* length of field */
            voffset = voffset + 4;
            value2 = tvb_get_letohl(tvb, voffset); /* Name Space */
            valuestr = val_to_str_const(value2, name_space_type, "Unknown Name Space");
            proto_tree_add_string(nvtree, hf_value_string, tvb, voffset,
                                  4, valuestr);
            voffset = voffset+4;
            value3 = tvb_get_letohl(tvb, voffset); /* Length of Volume name */
            voffset = voffset+4;
            vvalues->vstring = get_string(tvb, voffset, value3);
            proto_tree_add_string(nvtree, hf_value_string, tvb, voffset,
                                  value3, vvalues->vstring);
            voffset = voffset+value3;
            voffset += align_4(tvb, voffset);
            value4 = tvb_get_letohl(tvb, voffset); /* Length of Path name */
            voffset = voffset+4;
            vvalues->vstring = get_string(tvb, voffset, value4);
            proto_tree_add_string(nvtree, hf_value_string, tvb, voffset,
                                  value4, vvalues->vstring);
            voffset = voffset+value4;
            voffset += align_4(tvb, voffset);
            break;
        case 0x00000010:        /* Replica Pointer */
            /*value1 = tvb_get_letohl(tvb, voffset);*/ /* length of field */
            voffset = voffset + 4;
            value2 = tvb_get_letohl(tvb, voffset); /* Length of Server name */
            voffset = voffset+4;
            vvalues->vstring = get_string(tvb, voffset, value2);
            proto_tree_add_string(nvtree, hf_value_string, tvb, voffset,
                                  value2, vvalues->vstring);
            voffset = voffset+value2;
            voffset += align_4(tvb, voffset);
            proto_tree_add_item(nvtree, hf_replica_type, tvb, voffset, 2, ENC_LITTLE_ENDIAN);
            voffset = voffset+2;
            proto_tree_add_item(nvtree, hf_replica_state, tvb, voffset, 2, ENC_LITTLE_ENDIAN);
            voffset = voffset+2;
            proto_tree_add_item(nvtree, hf_replica_number, tvb, voffset, 4, ENC_LITTLE_ENDIAN);
            voffset = voffset+4;
            if((vvalues->pflags & 0x8000) | (vvalues->pflags & 0x4000))
            {
                /* If this request flag is set then this is a server. Server structures
                 * include the RootID as part of the replica data. */
                proto_tree_add_item(nvtree, hf_nds_partition_root_id, tvb, voffset, 4, ENC_BIG_ENDIAN);
                voffset += 4;
            }
            number_of_items = tvb_get_letohl(tvb, voffset);  /* Number of Addresses */
            aditem = proto_tree_add_uint_format(nvtree, hf_nds_uint32value, tvb, voffset,
                                                4, number_of_items, "Number of Addresses: %u", number_of_items);

            adtree = proto_item_add_subtree(aditem, ett_nds);
            voffset = voffset+4;
            for (r=1; r <= number_of_items; r++)
            {
                /* Trap for end of packet */
                if(tvb_captured_length_remaining(tvb, voffset)<12)
                {
                    THROW(ReportedBoundsError);
                }
                voffset += align_4(tvb, voffset);
                value4 = tvb_get_letohl(tvb, voffset); /* type of Protocol */
                valuestr = val_to_str_const(value4, nds_protocol_type, "(Undefined Protocol)");
                proto_tree_add_uint_format(adtree, hf_nds_uint32value, tvb, voffset,
                                           4, value4, valuestr, value4);
                voffset = voffset+4;
                value5 = tvb_get_letohl(tvb, voffset); /* length of address */
                voffset = voffset+4;
                switch (value4)
                {
                case NDS_PTYPE_IPX:
                    proto_tree_add_item(adtree, hf_nds_net, tvb, voffset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(adtree, hf_nds_node, tvb, voffset+4, 6, ENC_NA);
                    proto_tree_add_item(adtree, hf_nds_socket, tvb, voffset+10, 2, ENC_BIG_ENDIAN);
                    break;
                case NDS_PTYPE_IP:
                    proto_tree_add_item(adtree, hf_nds_port, tvb, voffset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(adtree, hf_add_ref_ip, tvb, voffset+2, 4, ENC_BIG_ENDIAN);
                    break;
                case NDS_PTYPE_UDP:
                    proto_tree_add_item(adtree, hf_nds_port, tvb, voffset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(adtree, hf_add_ref_udp, tvb, voffset+2, 4, ENC_BIG_ENDIAN);
                    break;
                case NDS_PTYPE_TCP:
                    proto_tree_add_item(adtree, hf_nds_port, tvb, voffset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(adtree, hf_add_ref_tcp, tvb, voffset+2, 4, ENC_BIG_ENDIAN);
                    break;
                case NDS_PTYPE_URL:
                case NDS_PTYPE_DNS:
                    vvalues->vstring = get_string(tvb, voffset, value5);
                    proto_tree_add_string(adtree, hf_value_string, tvb, voffset,
                                          value5, vvalues->vstring);
                    break;
                default:
                    break;
                }
                voffset = voffset + value5;
            }
            voffset += align_4(tvb, voffset);
            break;
        case 0x00000011:        /* Object ACL */
            /*value1 = tvb_get_letohl(tvb, voffset);*/ /* Length of Field */
            voffset = voffset + 4;
            value2 = tvb_get_letohl(tvb, voffset);
            voffset = voffset + 4;
            vvalues->vstring = get_string(tvb, voffset, value2); /* Unicode String */
            proto_tree_add_string(nvtree, hf_value_string, tvb, voffset,
                                  value2, vvalues->vstring);
            if (strcmp(vvalues->vstring, "[Entry Rights]")) {
                entry_rights=TRUE;
            }
            else
            {
                entry_rights=FALSE;
            }
            voffset = voffset + value2;
            voffset += align_4(tvb, voffset);
            value3 = tvb_get_letohl(tvb, voffset);
            voffset = voffset + 4;
            vvalues->vstring = get_string(tvb, voffset, value3); /* Unicode Subject Name */
            proto_tree_add_string(nvtree, hf_value_string, tvb, voffset,
                                  value3, vvalues->vstring);
            voffset = voffset + value3;
            voffset += align_4(tvb, voffset);
            /* Entry or Attribute Privileges */
            if (entry_rights) {
                /* if Entries then use these bits */
                static const int * entries[] = {
                    &hf_nds_compare_attributes,
                    &hf_nds_read_attribute,
                    &hf_nds_write_add_delete_attribute,
                    &hf_nds_add_delete_self,
                    &hf_nds_privilege_not_defined,
                    &hf_nds_supervisor,
                    &hf_nds_inheritance_control,
                    &hf_bit8vflags,
                    &hf_bit9vflags,
                    &hf_bit10vflags,
                    &hf_bit11vflags,
                    &hf_bit12vflags,
                    &hf_bit13vflags,
                    &hf_bit14vflags,
                    &hf_bit15vflags,
                    &hf_bit16vflags,
                    NULL
                };

                proto_tree_add_bitmask(nvtree, tvb, voffset, hf_nds_privileges, ett_ncp, entries, ENC_LITTLE_ENDIAN);
            }
            else
            {
                /* if attribute rights then do these bits */
                static const int * rights[] = {
                    &hf_nds_browse_entry,
                    &hf_nds_add_entry,
                    &hf_nds_delete_entry,
                    &hf_nds_rename_entry,
                    &hf_nds_supervisor_entry,
                    &hf_nds_entry_privilege_not_defined,
                    &hf_nds_inheritance_control,
                    &hf_bit8vflags,
                    &hf_bit9vflags,
                    &hf_bit10vflags,
                    &hf_bit11vflags,
                    &hf_bit12vflags,
                    &hf_bit13vflags,
                    &hf_bit14vflags,
                    &hf_bit15vflags,
                    &hf_bit16vflags,
                    NULL
                };

                proto_tree_add_bitmask(nvtree, tvb, voffset, hf_nds_privileges, ett_ncp, rights, ENC_LITTLE_ENDIAN);
            }
            voffset = voffset+4;
            voffset += align_4(tvb, voffset);
            break;
        case 0x00000013:        /* Time Stamp */
            value1 = tvb_get_letohl(tvb, voffset);         /* Seconds */
            proto_tree_add_uint_format(nvtree, hf_nds_uint32value, tvb, voffset,
                                       4, value1, "Length of Record: %u", value1);
            voffset = voffset+4;
            ns.secs = tvb_get_letohl(tvb, voffset);
            ns.nsecs = 0;
            proto_tree_add_time_format(nvtree, hf_nds_ds_time, tvb, voffset, 4,
                &ns, "Timestamp: %s", abs_time_secs_to_str(wmem_packet_scope(), ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
            voffset = voffset + 4;
            proto_tree_add_item(nvtree, hf_nds_rnum, tvb, voffset, 2, ENC_LITTLE_ENDIAN);
            voffset = voffset+2;
            proto_tree_add_item(nvtree, hf_nds_revent, tvb, voffset, 2, ENC_LITTLE_ENDIAN);
            voffset = voffset+2;
            voffset += align_4(tvb, voffset);
            break;
        case 0x00000017:        /* Back Link */
            value1 = tvb_get_letohl(tvb, voffset);         /* Length */
            proto_tree_add_uint_format(nvtree, hf_nds_uint32value, tvb, voffset,
                                       4, value1, "Length of Record %08x", value1);
            voffset = voffset+4;
            value2 = tvb_get_letohl(tvb, voffset);         /* Remote ID */
            proto_tree_add_uint_format(nvtree, hf_nds_uint32value, tvb, voffset,
                                       4, value2, "Remote ID %08x", value2);
            voffset = voffset+4;
            value3 = tvb_get_letohl(tvb, voffset);         /* Length of string */
            voffset = voffset+4;
            vvalues->vstring = get_string(tvb, voffset, value3);
            proto_tree_add_string_format(nvtree, hf_value_string, tvb, voffset,
                                         value3, vvalues->vstring,
                                         "Server Distinguished Name - %s", vvalues->vstring);
            voffset = voffset+value3;
            voffset += align_4(tvb, voffset);
            break;
        case 0x00000018:        /* Time */
            voffset += 4; /* This is the length of the time data no need to decode, always 4 bytes */
            ns.secs = tvb_get_letohl(tvb, voffset);
            ns.nsecs = 0;
            proto_tree_add_time_format(nvtree, hf_nds_ds_time, tvb, voffset, 4,
                &ns, "Time: %s", abs_time_secs_to_str(wmem_packet_scope(), ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
            voffset = voffset + 4;
            break;
        case 0x00000019:        /* Typed Name */
            value1 = tvb_get_letohl(tvb, voffset);         /* Length */
            proto_tree_add_uint_format(nvtree, hf_nds_uint32value, tvb, voffset,
                                       4, value1, "Length of Record %08x", value1);
            voffset = voffset+4;
            value2 = tvb_get_letohl(tvb, voffset);         /* Level */
            proto_tree_add_uint_format(nvtree, hf_nds_uint32value, tvb, voffset,
                                       4, value2, "Level %d", value2);
            voffset = voffset+4;
            value3 = tvb_get_letohl(tvb, voffset);         /* Interval */
            proto_tree_add_uint_format(nvtree, hf_nds_uint32value, tvb, voffset,
                                       4, value3, "Interval %d", value3);
            voffset = voffset+4;
            value4 = tvb_get_letohl(tvb, voffset);         /* Distinguished Name */
            voffset = voffset+4;
            vvalues->vstring = get_string(tvb, voffset, value4);
            proto_tree_add_string_format(nvtree, hf_value_string, tvb, voffset,
                                         value4, vvalues->vstring,
                                         "Distinguished Name - %s", vvalues->vstring);
            voffset = voffset+value4;
            voffset += align_4(tvb, voffset);
            break;
        case 0x0000001a:        /* Hold */
            value1 = tvb_get_letohl(tvb, voffset);         /* Length */
            proto_tree_add_uint_format(nvtree, hf_nds_uint32value, tvb, voffset,
                                       4, value1, "Length of Record %08x", value1);
            voffset = voffset+4;
            value2 = tvb_get_letohl(tvb, voffset);         /* Amount */
            proto_tree_add_uint_format(nvtree, hf_nds_uint32value, tvb, voffset,
                                       4, value2, "Amount %d", value2);
            voffset = voffset+4;
            value3 = tvb_get_letohl(tvb, voffset);         /* Subject */
            voffset = voffset+4;
            vvalues->vstring = get_string(tvb, voffset, value3);
            proto_tree_add_string_format(nvtree, hf_value_string, tvb, voffset,
                                         value3, vvalues->vstring,
                                         "Subject - %s", vvalues->vstring);
            voffset = voffset+value3;
            voffset += align_4(tvb, voffset);
            break;
        case 0x00000001:        /* Distinguished Name */
        case 0x00000002:        /* Case Sensitive Unicode String */
        case 0x00000003:        /* Non Case Sensitive Unicode String */
        case 0x00000004:        /* Printable String */
        case 0x00000005:        /* Numeric String */
        case 0x0000000a:        /* Telephone Number */
        case 0x0000000e:        /* Email Address */
        case 0x00000014:        /* Class Name */
        default:
            value1 = tvb_get_letohl(tvb, voffset);
            voffset = voffset + 4;
            if (strcmp(vvalues->vstring, "zendmSearchOrder")==0) {
                vvalues->vstring = get_string(tvb, voffset, value1);
                if (strcmp(vvalues->vstring, "0")==0) {
                    vvalues->vstring = "Value (0) = Object";
                }
                else if (strcmp(vvalues->vstring, "1")==0) {
                    vvalues->vstring = "Value (1) = Group";
                }
                else if (strcmp(vvalues->vstring, "2")==0) {
                    vvalues->vstring = "Value (2) = Container";
                }
                else if (strcmp(vvalues->vstring, "01")==0) {
                    vvalues->vstring = "Value (01) = Object, Group";
                }
                else if (strcmp(vvalues->vstring, "02")==0) {
                    vvalues->vstring = "Value (02) = Object, Container";
                }
                else if (strcmp(vvalues->vstring, "10")==0) {
                    vvalues->vstring = "Value (10) = Group, Object";
                }
                else if (strcmp(vvalues->vstring, "12")==0) {
                    vvalues->vstring = "Value (12) = Group, Container";
                }
                else if (strcmp(vvalues->vstring, "20")==0) {
                    vvalues->vstring = "Value (20) = Container, Object";
                }
                else if (strcmp(vvalues->vstring, "21")==0) {
                    vvalues->vstring = "Value (21) = Container, Group";
                }
                else if (strcmp(vvalues->vstring, "012")==0) {
                    vvalues->vstring = "Value (012) = Object, Group, Container";
                }
                else if (strcmp(vvalues->vstring, "021")==0) {
                    vvalues->vstring = "Value (021) = Object, Container, Group";
                }
                else if (strcmp(vvalues->vstring, "102")==0) {
                    vvalues->vstring = "Value (102) = Group, Object, Container";
                }
                else if (strcmp(vvalues->vstring, "120")==0) {
                    vvalues->vstring = "Value (120) = Group, Container, Object";
                }
                else if (strcmp(vvalues->vstring, "201")==0) {
                    vvalues->vstring = "Value (201) = Container, Object, Group";
                }
                else if (strcmp(vvalues->vstring, "210")==0) {
                    vvalues->vstring = "Value (210) = Container, Group, Object";
                }
            }
            else
            {
                vvalues->vstring = get_string(tvb, voffset, value1);
            }
            proto_tree_add_string(nvtree, hf_value_string, tvb, voffset,
                                  value1, vvalues->vstring);
            voffset = voffset + value1;
            voffset += align_4(tvb, voffset);
            break;
        }
        voffset += align_4(tvb, voffset);
    }
    vvalues->voffset=voffset;
    return;
}

static guint32
print_es_type(proto_tree *estree, tvbuff_t *tvb, nds_val *values, guint32 vtype, guint32 ioffset)
{
    guint32         value1;
    guint32         value2;
    guint32         value3;
    guint32         value4;
    guint32         value5;
    guint32         number_of_referrals;
    guint32         r;
    guint32         i;
    proto_tree      *nestree;
    proto_item      *nesitem;
    proto_tree      *sub1tree;
    proto_item      *sub1item;
    proto_tree      *sub2tree;
    const char      *vstring="";
    nstime_t        ns;

    switch (vtype)
    {
    case 0: /* No Specifier Type */
        /* ES Type */
        proto_tree_add_item(estree, hf_es_value, tvb, ioffset,
                            4, ENC_LITTLE_ENDIAN);
        ioffset = ioffset + 4;
        break;
    case 1: /* Unicode String */
        value1 = tvb_get_letohl(tvb, ioffset);   /* Delimiter Set */
        ioffset = ioffset + 4;
        values->vstring = get_string(tvb, ioffset, value1);
        proto_tree_add_string_format(estree, hf_mv_string, tvb, ioffset,
                                     value1, values->vstring, "Delimiter ->%s", values->vstring);
        ioffset=ioffset + value1;
        ioffset += align_4(tvb, ioffset);
        value2 = tvb_get_letohl(tvb, ioffset);
        ioffset = ioffset + 4;
        values->vstring = get_string(tvb, ioffset, value2);
        proto_tree_add_string(estree, hf_mv_string, tvb, ioffset,
                              value2, values->vstring);
        values->voffset=ioffset + value2;
        ioffset = values->voffset;
        ioffset += align_4(tvb, ioffset);
        break;
    case 2: /* Based */
        value1 = tvb_get_letohl(tvb, ioffset);   /* ES Type */
        vstring = val_to_str_const(value1, es_type, "No ES Type Found");
        nesitem = proto_tree_add_string_format(estree, hf_es_type, tvb, ioffset,
                                               4, vstring, "Base Context Type - %s", vstring);
        nestree = proto_item_add_subtree(nesitem, ett_nds);
        ioffset = ioffset + 4;
        switch (value1)
        {
        case 0: /* No Specifier Type */
            /* ES Type */
            proto_tree_add_item(nestree, hf_es_value, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
            ioffset = ioffset + 4;
            break;
        case 1: /* Unicode String */
            value2 = tvb_get_letohl(tvb, ioffset);   /* Delimiter Set */
            ioffset = ioffset + 4;
            values->vstring = get_string(tvb, ioffset, value2);
            proto_tree_add_string_format(nestree, hf_mv_string, tvb, ioffset,
                                         value2, values->vstring, "Delimiter ->%s", values->vstring);
            ioffset=ioffset + value2;
            ioffset += align_4(tvb, ioffset);
            value3 = tvb_get_letohl(tvb, ioffset);
            ioffset = ioffset + 4;
            values->vstring = get_string(tvb, ioffset, value3);
            proto_tree_add_string(nestree, hf_mv_string, tvb, ioffset,
                                  value3, values->vstring);
            values->voffset=ioffset + value3;
            ioffset = values->voffset;
            ioffset += align_4(tvb, ioffset);
            break;
        case 2: /* Based */
            break;
        case 3: /* Hinted */
            break;
        case 4: /* Tuned */
            value2 = tvb_get_letohl(tvb, ioffset);   /* Count */
            proto_tree_add_item(nestree, hf_es_rdn_count, tvb, ioffset,
                                4, ENC_LITTLE_ENDIAN);
            ioffset = ioffset + 4;
            for (r = 1 ; r <= value2; r++ )
            {
                ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                ns.nsecs = 0;
                proto_tree_add_time_format(nestree, hf_es_seconds, tvb, ioffset,
                                           4, &ns, "Timestamp: %s",
                                           abs_time_secs_to_str(wmem_packet_scope(), ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                ioffset = ioffset + 4;
                proto_tree_add_item(nestree, hf_nds_replica_num, tvb, ioffset,
                                    2, ENC_LITTLE_ENDIAN);
                ioffset = ioffset + 2;
                proto_tree_add_item(nestree, hf_nds_event_num, tvb, ioffset,
                                    2, ENC_LITTLE_ENDIAN);
                ioffset = ioffset + 2;
            }
            value4 = tvb_get_letohl(tvb, ioffset);   /* Delimiter Set */
            ioffset = ioffset + 4;
            values->vstring = get_string(tvb, ioffset, value4);
            proto_tree_add_string(nestree, hf_mv_string, tvb, ioffset,
                                  value4, values->vstring);
            ioffset=ioffset + value4;
            ioffset += align_4(tvb, ioffset);
            value5 = tvb_get_letohl(tvb, ioffset);   /* RDN */
            ioffset = ioffset + 4;
            values->vstring = get_string(tvb, ioffset, value5);
            proto_tree_add_string(nestree, hf_rdn_string, tvb, ioffset,
                                  value5, values->vstring);
            ioffset=ioffset + value5;
            ioffset += align_4(tvb, ioffset);
            break;
        case 5: /* GUID */
        case 6: /* ID32 */
        case 7: /* Count */
        default:
            /* ES Type */
            /* XXX: nestree rather than estree ?? */
            proto_tree_add_item(estree, hf_es_value, tvb, ioffset,
                                4, ENC_LITTLE_ENDIAN);
            ioffset = ioffset + 4;
            break;
        }
        value1 = tvb_get_letohl(tvb, ioffset);   /* ES Type */
        vstring = val_to_str_const(value1, es_type, "No ES Type Found");
        nesitem = proto_tree_add_string_format(estree, hf_es_type, tvb, ioffset,
                                               4, vstring, "Object Name Type - %s", vstring);
        nestree = proto_item_add_subtree(nesitem, ett_nds);
        ioffset = ioffset + 4;
        switch (value1)
        {
        case 0: /* No Specifier Type */
            /* ES Type */
            proto_tree_add_item(nestree, hf_es_value, tvb, ioffset,
                                4, ENC_LITTLE_ENDIAN);
            ioffset = ioffset + 4;
            break;
        case 1: /* Unicode String */
            value2 = tvb_get_letohl(tvb, ioffset);   /* Delimiter Set */
            ioffset = ioffset + 4;
            values->vstring = get_string(tvb, ioffset, value2);
            proto_tree_add_string_format(nestree, hf_mv_string, tvb, ioffset,
                                         value2, values->vstring, "Delimiter ->%s", values->vstring);
            ioffset=ioffset + value2;
            ioffset += align_4(tvb, ioffset);
            value3 = tvb_get_letohl(tvb, ioffset);
            ioffset = ioffset + 4;
            values->vstring = get_string(tvb, ioffset, value3);
            proto_tree_add_string(nestree, hf_mv_string, tvb, ioffset,
                                  value3, values->vstring);
            values->voffset=ioffset + value3;
            ioffset = values->voffset;
            ioffset += align_4(tvb, ioffset);
            break;
        case 2: /* Based */
            break;
        case 3: /* Hinted */
            break;
        case 4: /* Tuned */
            /* Count */
            proto_tree_add_item_ret_uint(nestree, hf_es_rdn_count, tvb, ioffset,
                                4, ENC_LITTLE_ENDIAN, &value2);
            ioffset = ioffset + 4;
            for (r = 1 ; r <= value2; r++ )
            {
                ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                ns.nsecs = 0;
                proto_tree_add_time_format(nestree, hf_es_seconds, tvb, ioffset,
                                           4, &ns, "Timestamp: %s",
                                           abs_time_secs_to_str(wmem_packet_scope(), ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                ioffset = ioffset + 4;
                proto_tree_add_item(nestree, hf_nds_replica_num, tvb, ioffset,
                                    2, ENC_LITTLE_ENDIAN);
                ioffset = ioffset + 2;
                proto_tree_add_item(nestree, hf_nds_event_num, tvb, ioffset,
                                    2, ENC_LITTLE_ENDIAN);
                ioffset = ioffset + 2;
            }
            value4 = tvb_get_letohl(tvb, ioffset);   /* Delimiter Set */
            ioffset = ioffset + 4;
            values->vstring = get_string(tvb, ioffset, value4);
            proto_tree_add_string(nestree, hf_mv_string, tvb, ioffset,
                                  value4, values->vstring);
            ioffset=ioffset + value4;
            ioffset += align_4(tvb, ioffset);
            value5 = tvb_get_letohl(tvb, ioffset);   /* RDN */
            ioffset = ioffset + 4;
            values->vstring = get_string(tvb, ioffset, value5);
            proto_tree_add_string(nestree, hf_rdn_string, tvb, ioffset,
                                  value5, values->vstring);
            ioffset=ioffset + value5;
            ioffset += align_4(tvb, ioffset);
            break;
        case 5: /* GUID */
        case 6: /* ID32 */
        case 7: /* Count */
        default:
            /* ES Type */
            /* XXX: nestree rather than estree ?? */
            proto_tree_add_item(estree, hf_es_value, tvb, ioffset,
                                4, ENC_LITTLE_ENDIAN);
            ioffset = ioffset + 4;
            break;
        }
        break;
    case 3: /* Hinted */
        number_of_referrals = tvb_get_letohl(tvb, ioffset);

        for (r = 1 ; r <= number_of_referrals; r++ )
        {
            sub1item = proto_tree_add_uint_format(estree, hf_referral_record, tvb, 6, 0,
                                                  r, "NDS Referral Record #%u", r);
            sub1tree = proto_item_add_subtree(sub1item, ett_nds);

            proto_tree_add_item_ret_uint(sub1tree, hf_referral_addcount, tvb, ioffset, 4, ENC_LITTLE_ENDIAN, &value1);

            ioffset = ioffset + 4;
            for (i = 1 ; i <= value1; i++ )
            {
                value2 = tvb_get_letohl(tvb, ioffset);
                values->vstring = val_to_str_const(value2, nds_protocol_type, "(Undefined Protocol)");
                proto_tree_add_uint_format(sub1tree, hf_nds_uint32value, tvb, ioffset,
                                           4, value2, vstring, value2);
                ioffset = ioffset+4;
                value3 = tvb_get_letohl(tvb, ioffset);
                ioffset = ioffset+4;
                switch (value2)
                {
                case NDS_PTYPE_IPX:
                    proto_tree_add_item(sub1tree, hf_nds_net, tvb, ioffset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(sub1tree, hf_nds_node, tvb, ioffset+4, 6, ENC_NA);
                    proto_tree_add_item(sub1tree, hf_nds_socket, tvb, ioffset+10, 2, ENC_BIG_ENDIAN);
                    break;
                case NDS_PTYPE_IP:
                    proto_tree_add_item(sub1tree, hf_nds_port, tvb, ioffset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(sub1tree, hf_add_ref_ip, tvb, ioffset+2, 4, ENC_BIG_ENDIAN);
                    break;
                case NDS_PTYPE_UDP:
                    proto_tree_add_item(sub1tree, hf_nds_port, tvb, ioffset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(sub1tree, hf_add_ref_udp, tvb, ioffset+2, 4, ENC_BIG_ENDIAN);
                    break;
                case NDS_PTYPE_TCP:
                    proto_tree_add_item(sub1tree, hf_nds_port, tvb, ioffset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(sub1tree, hf_add_ref_tcp, tvb, ioffset+2, 4, ENC_BIG_ENDIAN);
                    break;
                case NDS_PTYPE_URL:
                case NDS_PTYPE_DNS:
                    values->vstring = get_string(tvb, ioffset, value3);
                    proto_tree_add_string(sub1tree, hf_value_string, tvb, ioffset,
                                          value3, values->vstring);
                    break;
                default:
                    break;
                }
                ioffset = ioffset + value3;
                ioffset += align_4(tvb, ioffset);
            }

        }
        value1 = tvb_get_letohl(tvb, ioffset);   /* ES Type */
        vstring = val_to_str_const(value1, es_type, "No ES Type Found");
        nesitem = proto_tree_add_string_format(estree, hf_es_type, tvb, ioffset,
                                               4, vstring, "Object Name Type - %s", vstring);
        nestree = proto_item_add_subtree(nesitem, ett_nds);
        ioffset = ioffset + 4;
        switch (value1)
        {
        case 0: /* No Specifier Type */
            /* ES Type */
            proto_tree_add_item(nestree, hf_es_value, tvb, ioffset,
                                4, ENC_LITTLE_ENDIAN);
            ioffset = ioffset + 4;
            break;
        case 1: /* Unicode String */
            value2 = tvb_get_letohl(tvb, ioffset);   /* Delimiter Set */
            ioffset = ioffset + 4;
            values->vstring = get_string(tvb, ioffset, value2);
            proto_tree_add_string_format(nestree, hf_mv_string, tvb, ioffset,
                                         value2, values->vstring, "Delimiter ->%s", values->vstring);
            ioffset=ioffset + value2;
            ioffset += align_4(tvb, ioffset);
            value3 = tvb_get_letohl(tvb, ioffset);
            ioffset = ioffset + 4;
            values->vstring = get_string(tvb, ioffset, value3);
            proto_tree_add_string(nestree, hf_mv_string, tvb, ioffset,
                                  value3, values->vstring);
            values->voffset=ioffset + value3;
            ioffset = values->voffset;
            ioffset += align_4(tvb, ioffset);
            break;
        case 2: /* Based */
            break;
        case 3: /* Hinted */
            break;
        case 4: /* Tuned */
            /* Count */
            proto_tree_add_item_ret_uint(nestree, hf_es_rdn_count, tvb, ioffset,
                                4, ENC_LITTLE_ENDIAN, &value2);
            ioffset = ioffset + 4;
            for (r = 1 ; r <= value2; r++ )
            {
                ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                ns.nsecs = 0;
                proto_tree_add_time_format(nestree, hf_es_seconds, tvb, ioffset,
                                           4, &ns, "Timestamp: %s",
                                           abs_time_secs_to_str(wmem_packet_scope(), ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                ioffset = ioffset + 4;
                proto_tree_add_item(nestree, hf_nds_replica_num, tvb, ioffset,
                                    2, ENC_LITTLE_ENDIAN);
                ioffset = ioffset + 2;
                proto_tree_add_item(nestree, hf_nds_event_num, tvb, ioffset,
                                    2, ENC_LITTLE_ENDIAN);
                ioffset = ioffset + 2;
            }
            value4 = tvb_get_letohl(tvb, ioffset);   /* Delimiter Set */
            ioffset = ioffset + 4;
            values->vstring = get_string(tvb, ioffset, value4);
            proto_tree_add_string(nestree, hf_mv_string, tvb, ioffset,
                                  value4, values->vstring);
            ioffset=ioffset + value4;
            ioffset += align_4(tvb, ioffset);
            value5 = tvb_get_letohl(tvb, ioffset);   /* RDN */
            ioffset = ioffset + 4;
            values->vstring = get_string(tvb, ioffset, value5);
            proto_tree_add_string(nestree, hf_rdn_string, tvb, ioffset,
                                  value5, values->vstring);
            ioffset=ioffset + value5;
            ioffset += align_4(tvb, ioffset);
            break;
        case 5: /* GUID */
        case 6: /* ID32 */
        case 7: /* Count */
        default:
            /* ES Type */
            /* XXX: nestree rather than estree ?? */
            proto_tree_add_item(estree, hf_es_value, tvb, ioffset,
                                4, ENC_LITTLE_ENDIAN);
            ioffset = ioffset + 4;
            break;
        }
        break;
    case 4: /* Tuned */
        value1 = tvb_get_letohl(tvb, ioffset);
        sub1item = proto_tree_add_uint_format(estree, hf_es_rdn_count, tvb, ioffset,
                                              4, value1, "Number of RDN Items %u", value1);
        sub1tree = proto_item_add_subtree(sub1item, ett_nds);
        ioffset = ioffset + 4;
        for (r = 1 ; r <= value1; r++ )
        {
            sub2tree = proto_tree_add_subtree_format(sub1tree, tvb, ioffset, 10, ett_nds, NULL, "Item %u", r);

            ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
            ns.nsecs = 0;
            proto_tree_add_time_format(sub2tree, hf_es_seconds, tvb, ioffset,
                                       4, &ns, "Timestamp: %s",
                                       abs_time_secs_to_str(wmem_packet_scope(), ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
            ioffset = ioffset + 4;
            proto_tree_add_item(sub2tree, hf_nds_replica_num, tvb, ioffset,
                                2, ENC_LITTLE_ENDIAN);
            ioffset = ioffset + 2;
            proto_tree_add_item(sub2tree, hf_nds_event_num, tvb, ioffset,
                                2, ENC_LITTLE_ENDIAN);
            ioffset = ioffset + 2;
        }
        value3 = tvb_get_letohl(tvb, ioffset);   /* Delimiter Set */
        ioffset = ioffset + 4;
        values->vstring = get_string(tvb, ioffset, value3);
        proto_tree_add_string(sub1tree, hf_mv_string, tvb, ioffset,
                              value3, values->vstring);
        ioffset=ioffset + value3;
        ioffset += align_4(tvb, ioffset);
        value4 = tvb_get_letohl(tvb, ioffset);   /* RDN */
        ioffset = ioffset + 4;
        values->vstring = get_string(tvb, ioffset, value4);
        proto_tree_add_string(sub1tree, hf_rdn_string, tvb, ioffset,
                              value4, values->vstring);
        ioffset=ioffset + value4;
        ioffset += align_4(tvb, ioffset);
        break;
    case 5: /* GUID */
    case 6: /* ID32 */
    case 7: /* Count */
    default:
        /* ES Type */
        proto_tree_add_item(estree, hf_es_value, tvb, ioffset,
                            4, ENC_LITTLE_ENDIAN);
        ioffset = ioffset + 4;
        break;
    }
    return ioffset;
}


static void process_set_filter(proto_tree* , tvbuff_t*, packet_info*, nds_val*);

static void
process_search_expression(proto_tree *it_tree, tvbuff_t *tvb, nds_val *values)
{
    guint32     search_tag, ioffset;
    const char *search_string;

    ioffset = values->voffset;
    search_tag = tvb_get_letohl(tvb, ioffset); /* Get next search operation tag */
    search_string = val_to_str_const(search_tag, itersearchenum, "(No Search Operation Type Found!)");
    proto_tree_add_uint_format(it_tree, hf_iter_search, tvb, ioffset, 4,
                               search_tag, "Search Operation Type: %d, (0x%04x), %s",
                               search_tag, search_tag, search_string);
    ioffset += 4;
    switch (search_tag)
    {
    case NDS_SEARCH_EQUAL:
    case NDS_SEARCH_GREATER_OR_EQUAL:
    case NDS_SEARCH_LESS_OR_EQUAL:
    case NDS_SEARCH_APPROX:
    case NDS_SEARCH_ATTR_FLAGS:
    case NDS_SEARCH_ATTR_HAS_FLAG:
        /* start of DCWPutAttribute */
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        ioffset = ioffset + 4;
        values->vstring = get_string(tvb, ioffset, values->vvalue);
        proto_tree_add_string(it_tree, hf_mv_string, tvb, ioffset,
                              values->vvalue, values->vstring);
        ioffset += values->vvalue;
        /* end of DCWPutAttribute */

        ioffset += align_4(tvb, ioffset);

        /* start of DCWPutValue */
        proto_tree_add_item(it_tree, hf_nds_syntax, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
        ioffset = ioffset + 4;
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        ioffset = ioffset + 4;
        values->vstring = get_string(tvb, ioffset, values->vvalue);
        proto_tree_add_string(it_tree, hf_mv_string, tvb, ioffset,
                              values->vvalue, values->vstring);
        ioffset += values->vvalue;
        /* end of DCWPutValue */

        break;
    case NDS_SEARCH_PRESENT:
        /* start of DCWPutAttribute */
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        ioffset = ioffset + 4;
        values->vstring = get_string(tvb, ioffset, values->vvalue);
        proto_tree_add_string(it_tree, hf_mv_string, tvb, ioffset,
                              values->vvalue, values->vstring);
        ioffset = ioffset + values->vvalue;
        /* end of DCWPutAttribute */
        break;

    case NDS_SEARCH_RDN:
        /* print the relative distinguished name. This includes context info... */
#if 0
        if (err = DCWPutRDN(context, cur, limit, item->data))
            return err;
#endif

        values->vvalue = tvb_get_letohl(tvb, ioffset);
        ioffset = ioffset + 4;
        values->vstring = get_string(tvb, ioffset, values->vvalue);
        proto_tree_add_string(it_tree, hf_mv_string, tvb, ioffset,
                              values->vvalue, values->vstring);
        ioffset += values->vvalue;
        break;
    case NDS_SEARCH_BASE_CLASS:
    case NDS_SEARCH_ENTRY_FLAGS:
    case NDS_SEARCH_ENTRY_HAS_FLAG:
    case NDS_SEARCH_VALUE_FLAGS:
    case NDS_SEARCH_VALUE_HAS_FLAG:
        /* start of DCWPutValue */
#if 0
        proto_tree_add_item(it_tree, hf_nds_syntax, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
        ioffset = ioffset + 4;
#endif
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        ioffset = ioffset + 4;
        values->vstring = get_string(tvb, ioffset, values->vvalue);
        proto_tree_add_string(it_tree, hf_mv_string, tvb, ioffset,
                              values->vvalue, values->vstring);
        ioffset += values->vvalue;
        /* end of DCWPutValue */
        break;
    case DCS_VALUE_GE_WITH_ATTR:        /* Deprecated, use DS_SEARCH_VALUE_MTS_GE */
    case NDS_SEARCH_VALUE_MTS_GE:
    case NDS_SEARCH_VALUE_MTS_G:
    case NDS_SEARCH_VALUE_MTS_LE:
    case NDS_SEARCH_VALUE_MTS_L:
    case NDS_SEARCH_VALUE_MTS_EQ:
    case NDS_SEARCH_VALUE_MTS_EQ_APPROX:
    case NDS_SEARCH_VALUE_CTS_GE:
    case NDS_SEARCH_VALUE_CTS_G:
    case NDS_SEARCH_VALUE_CTS_LE:
    case NDS_SEARCH_VALUE_CTS_L:
    case NDS_SEARCH_VALUE_CTS_EQ:
    case NDS_SEARCH_VALUE_CTS_EQ_APPROX:
        /* start of DCWPutAttribute */
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        ioffset = ioffset + 4;
        values->vstring = get_string(tvb, ioffset, values->vvalue);
        proto_tree_add_string(it_tree, hf_mv_string, tvb, ioffset,
                              values->vvalue, values->vstring);
        ioffset += values->vvalue;
        /* end of DCWPutAttribute */

        ioffset += align_4(tvb, ioffset);

        /* start of DCWPutValue */
        proto_tree_add_item(it_tree, hf_nds_syntax, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
        ioffset = ioffset + 4;
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        ioffset = ioffset + 4;
        values->vstring = get_string(tvb, ioffset, values->vvalue);
        proto_tree_add_string(it_tree, hf_mv_string, tvb, ioffset,
                              values->vvalue, values->vstring);
        ioffset += values->vvalue;
        /* end of DCWPutValue */
        break;
    case DCS_MOD_GE_WITH_ATTR:        /* Deprecated, use DS_SEARCH_ENTRY_MTS */
    case NDS_SEARCH_ENTRY_MTS_GE:
    case NDS_SEARCH_ENTRY_MTS_G:
    case NDS_SEARCH_ENTRY_MTS_LE:
    case NDS_SEARCH_ENTRY_MTS_L:
    case NDS_SEARCH_ENTRY_MTS_EQ:
    case NDS_SEARCH_ENTRY_MTS_EQ_APPROX:
    case NDS_SEARCH_ENTRY_CTS_GE:
    case NDS_SEARCH_ENTRY_CTS_G:
    case NDS_SEARCH_ENTRY_CTS_LE:
    case NDS_SEARCH_ENTRY_CTS_L:
    case NDS_SEARCH_ENTRY_CTS_EQ:
    case NDS_SEARCH_ENTRY_CTS_EQ_APPROX:
        /* start of DCWPutAttribute */
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        ioffset = ioffset + 4;
        values->vstring = get_string(tvb, ioffset, values->vvalue);
        proto_tree_add_string(it_tree, hf_mv_string, tvb, ioffset,
                              values->vvalue, values->vstring);
        ioffset += values->vvalue;
        /* end of DCWPutAttribute */

        ioffset += align_4(tvb, ioffset);

        /* start of DCWPutValue */
        proto_tree_add_item(it_tree, hf_nds_syntax, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
        ioffset = ioffset + 4;
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        ioffset = ioffset + 4;
        values->vstring = get_string(tvb, ioffset, values->vvalue);
        proto_tree_add_string(it_tree, hf_mv_string, tvb, ioffset,
                              values->vvalue, values->vstring);
        ioffset += values->vvalue;
        /* end of DCWPutValue */

        break;
    case NDS_SEARCH_EID:
    case NDS_SEARCH_ENTRY_SUBCOUNT_GE:
    case NDS_SEARCH_ENTRY_SUBCOUNT_G:
    case NDS_SEARCH_ENTRY_SUBCOUNT_LE:
    case NDS_SEARCH_ENTRY_SUBCOUNT_L:
    case NDS_SEARCH_ENTRY_SUBCOUNT_EQ:
        /* start of DCWPutValue */
        proto_tree_add_item(it_tree, hf_nds_syntax, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
        ioffset = ioffset + 4;
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        ioffset = ioffset + 4;
        values->vstring = get_string(tvb, ioffset, values->vvalue);
        proto_tree_add_string(it_tree, hf_mv_string, tvb, ioffset,
                              values->vvalue, values->vstring);
        ioffset += values->vvalue;
        /* end of DCWPutValue */

        break;

    default: /* Unknown Iteration search Item type */
        if (tvb_captured_length_remaining(tvb, ioffset) < 4) {
                THROW(ReportedBoundsError);
        }
        break;
    }
    ioffset += align_4(tvb, ioffset);
    values->voffset = ioffset;
    return;
}

static void
process_search_subexpression(proto_tree *it_tree, tvbuff_t *tvb, packet_info *pinfo, nds_val *values)
{
    proto_tree  *it_subtree, *it_subtree1;
    proto_item  *it_subitem;
    guint32     i, ioffset, number_of_items;

    ioffset = values->voffset;
    if (values->vvalue != NDS_SEARCH_NOT) {
        number_of_items = tvb_get_letohl(tvb, ioffset);
        it_subitem = proto_tree_add_item(it_tree, hf_this_count, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
        it_subtree = proto_item_add_subtree(it_subitem, ett_nds);
        ioffset += 4;
        for (i = 0; i < number_of_items; i++)
        {
            it_subtree1 = proto_tree_add_subtree_format(it_subtree, tvb, ioffset, -1, ett_nds, NULL, "Item #: %u", i+1);

            values->voffset = ioffset;
            process_set_filter(it_subtree1, tvb, pinfo, values);
            ioffset = values->voffset;

            if (tvb_captured_length_remaining(tvb, ioffset) < 4) {
                THROW(ReportedBoundsError);
                break;
            }

        }
    }
    values->voffset = ioffset;
    return;
}

static void
process_search_match(proto_tree *it_tree, tvbuff_t *tvb, nds_val *values)
{
    guint32     ioffset;

    ioffset = values->voffset;

    values->vvalue = tvb_get_letohl(tvb, ioffset);
    ioffset += 4;
    proto_tree_add_item(it_tree, hf_nds_oid, tvb, ioffset, values->vvalue, ENC_NA);
    ioffset += values->vvalue;

    ioffset += align_4(tvb, ioffset);

    proto_tree_add_item(it_tree, hf_iter_ans, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
    ioffset += 4;

    ioffset += align_4(tvb, ioffset);

    /* start of DCWPutAttribute */
    values->vvalue = tvb_get_letohl(tvb, ioffset);
    ioffset = ioffset + 4;
    values->vstring = get_string(tvb, ioffset, values->vvalue);
    proto_tree_add_string(it_tree, hf_mv_string, tvb, ioffset,
            values->vvalue, values->vstring);
    ioffset = ioffset + values->vvalue;
    /* end of DCWPutAttribute */

    ioffset += align_4(tvb, ioffset);

    /* start of DCWPutValue */
    proto_tree_add_item(it_tree, hf_nds_syntax, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
    ioffset = ioffset + 4;
    values->vvalue = tvb_get_letohl(tvb, ioffset);
    ioffset = ioffset + 4;
    values->vstring = get_string(tvb, ioffset, values->vvalue);
    proto_tree_add_string(it_tree, hf_mv_string, tvb, ioffset,
                          values->vvalue, values->vstring);
    ioffset += values->vvalue;
    /* end of DCWPutValue */

    ioffset += align_4(tvb, ioffset);

    values->voffset = ioffset;
    return;
}

static void
process_set_filter(proto_tree *it_tree, tvbuff_t *tvb, packet_info *pinfo, nds_val *values)
{
    guint32     search_tag, ioffset = values->voffset;
    const char *search_string;

    search_tag = tvb_get_letohl(tvb, ioffset);
    search_string = val_to_str_const(search_tag, itersearchenum, "(No Search Tag Found)");
    proto_tree_add_uint_format(it_tree, hf_iter_search, tvb, ioffset, 4,
        search_tag, "Type of Search: Tag = %d, (0x%04x), %s",
        search_tag, search_tag, search_string);
    ioffset += 4;
    values->voffset = ioffset;

    switch (search_tag)
    {
    case NDS_SEARCH_ITEM:
        /* DCWPutSearchExp */
        process_search_expression(it_tree, tvb, values);
        break;

    case NDS_SEARCH_EXTENSIBLE:
#if 0
        err = DCWPutSearchExtMatch(context, syncFormat, cur, limit, sexp->u.extMatch);
#endif
        process_search_match(it_tree, tvb, values);
        break;

    case NDS_SEARCH_OR:
    case NDS_SEARCH_AND:
    case NDS_SEARCH_NOT:
        /* DCWPutSearchSubExp = process_search_subexpression */
        process_search_subexpression(it_tree, tvb, pinfo, values);
        break;
    default: /* Unknown Iteration search type */
        if (tvb_captured_length_remaining(tvb, ioffset) < 4) {
            THROW(ReportedBoundsError);
        }
        break;
    }
    /*ioffset = values->voffset;*/
    return;
}

static void
process_entry_info(proto_tree *it_tree, tvbuff_t *tvb, nds_val *values)
{
    guint32     iter_flags, ioffset = values->voffset;
    nstime_t    ns;

    values->vstring = NULL;
    ioffset += align_4(tvb, ioffset);
    iter_flags = tvb_get_letohl(tvb, ioffset);


    if (iter_flags & DSI_OUTPUT_FIELDS) { /* Output Flags */
        proto_tree_add_bitmask(it_tree, tvb, ioffset, hf_retinfoflagsl, ett_ncp, ncp_infoflagsl, ENC_LITTLE_ENDIAN);
        ioffset = ioffset+2;
        proto_tree_add_bitmask(it_tree, tvb, ioffset, hf_retinfoflagsh, ett_ncp, ncp_retinfoflagsh, ENC_LITTLE_ENDIAN);
        ioffset = ioffset+2;
    }
    if (iter_flags & DSI_ENTRY_ID) { /* Entry ID */
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        proto_tree_add_uint_format(it_tree, hf_nds_eid, tvb, ioffset,
                4, values->vvalue, "Entry ID 0x%08x", values->vvalue);
        ioffset = ioffset + 4;
    }
    if (iter_flags & DSI_ENTRY_FLAGS) { /* Entry Flags */
        proto_tree_add_bitmask(it_tree, tvb, ioffset, hf_eflags, ett_ncp, ncp_eflags, ENC_LITTLE_ENDIAN);
        ioffset = ioffset+4;
    }
    if (iter_flags & DSI_SUBORDINATE_COUNT) { /* Subordinate Count */
        proto_tree_add_item(it_tree, hf_sub_count, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
        ioffset += 4;
    }
    if (iter_flags & DSI_MODIFICATION_TIME) { /* Modification Time */
        ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
        ns.nsecs = 0;
        proto_tree_add_time_format(it_tree, hf_es_seconds, tvb, ioffset,
                4, &ns, "Modification Time: %s",
                abs_time_secs_to_str(wmem_packet_scope(), ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
        ioffset = ioffset + 4;
    }
    if (iter_flags & DSI_MODIFICATION_TIMESTAMP) { /* Modification Timestamp */
        ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
        ns.nsecs = 0;
        proto_tree_add_time_format(it_tree, hf_es_seconds, tvb, ioffset,
                4, &ns, "Modification Timestamp: %s",
                abs_time_secs_to_str(wmem_packet_scope(), ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
        ioffset = ioffset + 4;
        proto_tree_add_item(it_tree, hf_nds_replica_num, tvb, ioffset,
                2, ENC_LITTLE_ENDIAN);
        ioffset = ioffset + 2;
        proto_tree_add_item(it_tree, hf_nds_event_num, tvb, ioffset,
                2, ENC_LITTLE_ENDIAN);
        ioffset = ioffset + 2;
    }
    if (iter_flags & DSI_CREATION_TIMESTAMP) { /* Creation Timestamp */
        ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
        ns.nsecs = 0;
        proto_tree_add_time_format(it_tree, hf_es_seconds, tvb, ioffset,
                4, &ns, "Creation Timestamp: %s",
                abs_time_secs_to_str(wmem_packet_scope(), ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
        ioffset = ioffset + 4;
        proto_tree_add_item(it_tree, hf_nds_replica_num, tvb, ioffset,
                2, ENC_LITTLE_ENDIAN);
        ioffset = ioffset + 2;
        proto_tree_add_item(it_tree, hf_nds_event_num, tvb, ioffset,
                2, ENC_LITTLE_ENDIAN);
        ioffset = ioffset + 2;
    }
    if (iter_flags & DSI_PARTITION_ROOT_ID) { /* Partition Root ID */
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        proto_tree_add_uint_format(it_tree, hf_nds_local_partition, tvb, ioffset,
                4, values->vvalue, "Partition Root ID %08x", values->vvalue);
        ioffset = ioffset + 4;
    }
    if (iter_flags & DSI_PARENT_ID) { /* Parent ID */
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        proto_tree_add_uint_format(it_tree, hf_nds_local_partition, tvb, ioffset,
                4, values->vvalue, "Parent ID %08x", values->vvalue);
        ioffset = ioffset + 4;
    }
    if (iter_flags & DSI_REVISION_COUNT) { /* Revision Count */
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        proto_tree_add_uint_format(it_tree, hf_nds_local_partition, tvb, ioffset,
                4, values->vvalue, "Revision count %08x", values->vvalue);
        ioffset = ioffset + 4;
    }
    if (iter_flags & DSI_REPLICA_TYPE) { /* Replica Type */
        values->vvalue = tvb_get_letohl(tvb, ioffset) & 0x00ff;
        proto_tree_add_uint(it_tree, hf_replica_type, tvb, ioffset, 4, values->vvalue);
        values->vvalue = tvb_get_letohl(tvb, ioffset) & 0xff00;
        proto_tree_add_uint(it_tree, hf_replica_state, tvb, ioffset, 4, values->vvalue);
        ioffset = ioffset + 4;
    }
    if (iter_flags & DSI_BASE_CLASS) { /* Base Class */
        values->vvalue = tvb_get_letohl(tvb, ioffset);         /* Length of string */
        ioffset = ioffset+4;
        values->vstring = get_string(tvb, ioffset, values->vvalue);
        proto_tree_add_string_format(it_tree, hf_value_string, tvb, ioffset,
                values->vvalue, values->vstring,
                "Base Class: - %s", values->vstring);
        ioffset = ioffset+values->vvalue;
        ioffset += align_4(tvb, ioffset);
    }
    if (iter_flags & DSI_ENTRY_RDN) { /* Relative Distinguished Name */
        values->vvalue = tvb_get_letohl(tvb, ioffset);         /* Length of string */
        ioffset = ioffset+4;
        values->vstring = get_string(tvb, ioffset, values->vvalue);
        proto_tree_add_string_format(it_tree, hf_value_string, tvb, ioffset,
                 values->vvalue, values->vstring,
                 "Relative Distinguished Name - %s", values->vstring);
        ioffset = ioffset+values->vvalue;
        ioffset += align_4(tvb, ioffset);
    }
    if (iter_flags & DSI_ENTRY_DN) { /* Distinguished Name */
        values->vvalue = tvb_get_letohl(tvb, ioffset);         /* Length of string */
        ioffset = ioffset+4;
        values->vstring = get_string(tvb, ioffset, values->vvalue);
        proto_tree_add_string_format(it_tree, hf_value_string, tvb, ioffset,
                 values->vvalue, values->vstring,
                 "Distinguished Name - %s", values->vstring);
        ioffset = ioffset+values->vvalue;
        ioffset += align_4(tvb, ioffset);
    }
    if (iter_flags & DSI_PARTITION_ROOT_DN) { /* Root Distinguished Name */
        values->vvalue = tvb_get_letohl(tvb, ioffset);         /* Length of string */
        ioffset = ioffset+4;
        values->vstring = get_string(tvb, ioffset, values->vvalue);
        proto_tree_add_string_format(it_tree, hf_value_string, tvb, ioffset,
                 values->vvalue, values->vstring,
                 "Root Distinguished Name - %s", values->vstring);
        ioffset = ioffset+values->vvalue;
        ioffset += align_4(tvb, ioffset);
    }
    if (iter_flags & DSI_PARENT_DN) { /* Parent Distinguished Name */
        values->vvalue = tvb_get_letohl(tvb, ioffset);         /* Length of string */
        ioffset = ioffset+4;
        values->vstring = get_string(tvb, ioffset, values->vvalue);
        proto_tree_add_string_format(it_tree, hf_value_string, tvb, ioffset,
                 values->vvalue, values->vstring,
                 "Parent Distinguished Name - %s", values->vstring);
        ioffset = ioffset+values->vvalue;
        ioffset += align_4(tvb, ioffset);
    }
    if (iter_flags & DSI_PURGE_TIME) { /* Purge Time */
        ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
        ns.nsecs = 0;
        proto_tree_add_time(it_tree, hf_nds_purge, tvb, ioffset, 4, &ns);
        ioffset = ioffset + 4;
    }
    if (iter_flags & DSI_DEREFERENCED_BASE_CLASS) { /* Dereference Base Class */
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        ioffset = ioffset + 4;
        values->vstring = get_string(tvb, ioffset, values->vvalue);
        proto_tree_add_string(it_tree, hf_deref_base, tvb, ioffset,
                values->vvalue, values->vstring);
        ioffset = ioffset + values->vvalue;
    }
    if (iter_flags & DSI_REPLICA_NUMBER) { /* Replica Number */
        proto_tree_add_item_ret_uint(it_tree, hf_replica_number, tvb, ioffset,
                 4, ENC_LITTLE_ENDIAN, &values->vvalue);
        ioffset = ioffset+4;
    }
    if (iter_flags & DSI_REPLICA_STATE) { /* Replica State */
        values->vvalue = tvb_get_letohl(tvb, ioffset) & 0xff00;
        values->vstring = val_to_str_const(values->vvalue, nds_replica_state, "No Replica State Found");
        proto_tree_add_uint(it_tree, hf_replica_state, tvb, ioffset, 4, values->vvalue);
        ioffset = ioffset + 2;
    }
    if (iter_flags & DSI_FEDERATION_BOUNDARY) { /* Federation Boundary */
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        proto_tree_add_uint_format(it_tree, hf_nds_uint32value, tvb, ioffset,
                4, values->vvalue, "Federation Boundary %d", values->vvalue);
        ioffset = ioffset+4;
    }
    if (iter_flags & DSI_SCHEMA_BOUNDARY) { /* Schema Boundary */
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        proto_tree_add_uint_format(it_tree, hf_nds_uint32value, tvb, ioffset,
                4, values->vvalue, "Schema Boundary %d", values->vvalue);
        ioffset = ioffset+4;
    }
    if (iter_flags & DSI_FEDERATION_BOUNDARY_ID) { /* Federation Boundary ID */
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        proto_tree_add_uint_format(it_tree, hf_nds_uint32value, tvb, ioffset,
                4, values->vvalue, "Federation Boundary ID %d", values->vvalue);
        ioffset = ioffset+4;
    }
    if (iter_flags & DSI_SCHEMA_BOUNDARY_ID) { /* Schema Boundary ID*/
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        proto_tree_add_uint_format(it_tree, hf_nds_uint32value, tvb, ioffset,
                4, values->vvalue, "Schema Boundary ID %d", values->vvalue);
        ioffset = ioffset+4;
    }
    if (iter_flags & DSI_CUR_SUBCOUNT) { /* Current Subcount */
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        proto_tree_add_uint_format(it_tree, hf_nds_uint32value, tvb, ioffset,
                4, values->vvalue, "Current Subcount %d", values->vvalue);
        ioffset = ioffset+4;
    }
    if (iter_flags & DSI_LOCAL_ENTRY_FLAGS) { /* Local Entry Flags */
        proto_tree_add_bitmask(it_tree, tvb, ioffset, hf_eflags, ett_ncp, ncp_eflags, ENC_LITTLE_ENDIAN);
        ioffset = ioffset+4;
    }
    values->voffset = ioffset;
    return;
}

static void
dissect_nds_iterator(proto_tree *it_tree, tvbuff_t *tvb, packet_info *pinfo, guint32 it_verb, guint32 request_flags, guint32 ioffset, gboolean request_reply)
{
    guint32     rcode, i, number_of_items, number_to_get;
    const char  *error_string;
    nds_val     values;
    proto_tree  *it_subtree, *it_subtree1;
    proto_item  *it_subitem;
    proto_item  *expert_item;

    values.vtype = 0;
    values.vvalue = 0;
    values.vlength = 0;
    values.voffset = 0;
    values.hfname = 0;
    values.vdesc = "";
    values.vstring = NULL;
    values.mvtype = 0;
    values.vflags = 0;


    while (TRUE) {
        it_subitem = proto_tree_add_uint(it_tree, hf_ncp_nds_iterverb, tvb, ioffset-4, 4, it_verb);

        it_subtree = proto_item_add_subtree(it_subitem, ett_nds);

        if (request_reply) { /* Request packets */
            switch (it_verb) {
            case IT_ATFIRST:
            case IT_ATEOF:
            case IT_ATLAST:
            case IT_ATBOF:
            case IT_CLEAR:
            case IT_COPY:
                break;
            case IT_COUNT:
                proto_tree_add_item(it_subtree, hf_timelimit, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset += 4;
                proto_tree_add_item(it_subtree, hf_max_entries, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset += 4;
                proto_tree_add_item(it_subtree, hf_move_position, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset += 4;
                break;
            case IT_CREATE:
            case IT_CURRENT:
            case IT_DESTROY:
            case IT_DONE:
                break;
            case IT_FIRST:
                proto_tree_add_item(it_subtree, hf_timelimit, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset += 4;
                break;
            case IT_GETPOSITION:
            case IT_ISPOSITIONABLE:
                break;
            case IT_LAST:
                proto_tree_add_item(it_subtree, hf_timelimit, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset += 4;
                break;
            case IT_NEXT:
            case IT_PREV:
                proto_tree_add_item(it_subtree, hf_timelimit, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset += 4;
                proto_tree_add_item(it_subtree, hf_num_to_get, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset += 4;
                break;
            case IT_POSITION:
                proto_tree_add_item(it_subtree, hf_iter_position, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset += 4;
                proto_tree_add_item(it_subtree, hf_timelimit, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset += 4;
                break;
            case IT_POSITION_IT:
                proto_tree_add_item(it_subtree, hf_iter_other, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset += 4;
                break;
            case IT_SETINDEX:
                proto_tree_add_item(it_subtree, hf_nds_number_of_items, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                number_of_items = tvb_get_letohl(tvb, ioffset);
                ioffset += 4;
                for (i=0; i < number_of_items; i++) {
                    /* Process the attribute tag */
#if 0
                    proto_tree_add_item(it_subtree, hf_nds_tag_string, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
#endif
                    proto_tree_add_item(it_subtree, hf_iter_index, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                    ioffset = ioffset + 4;

                    /* start of DCWPutAttribute */
#if 0
                    values.vvalue = tvb_get_letohl(tvb, ioffset);
                    ioffset = ioffset + 4;
                    values.vstring = get_string(tvb, ioffset, values.vvalue);
                    proto_tree_add_string(it_subtree, hf_mv_string, tvb, ioffset,
                            values.vvalue, values.vstring);
                    ioffset = ioffset + values.vvalue;
#endif
                    /* end of DCWPutAttribute */

#if 0
                    ioffset += align_4(tvb, ioffset);
#endif
                    if (tvb_captured_length_remaining(tvb, ioffset) < 4) {
                        THROW(ReportedBoundsError);
                        return;
                    }
                }
                break;
            case IT_SETFILTER:

                values.voffset = ioffset;

                /* DCWPutSearchExp  = process_set_filter() */
                process_set_filter(it_subtree, tvb, pinfo, &values);

                ioffset = values.voffset;
                ioffset += align_4(tvb, ioffset);
                break;
            case IT_SKIP:
                proto_tree_add_item(it_subtree, hf_timelimit, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset += 4;
                proto_tree_add_item(it_subtree, hf_num_to_skip, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset += 4;
                break;
            case IT_TYPEDOWN:
                proto_tree_add_item(it_subtree, hf_num_to_get, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                number_to_get = tvb_get_letohl(tvb, ioffset);
                ioffset += 4;
                if (number_to_get == 0) {
                    proto_tree_add_item(it_tree, hf_nds_tag_string, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                    ioffset = ioffset + 4;

                }
                values.vvalue = tvb_get_letohl(tvb, ioffset);
                ioffset = ioffset + 4;
                values.vstring = get_string(tvb, ioffset, values.vvalue);
                proto_tree_add_string(it_subtree, hf_mv_string, tvb, ioffset,
                        values.vvalue, values.vstring);
                ioffset = ioffset + values.vvalue;
                ioffset += align_4(tvb, ioffset);
                break;
            default:
                if (tvb_captured_length_remaining(tvb, ioffset) < 4) {
                    THROW(ReportedBoundsError);
                }
                return;
            }
        }
        else    /* Reply Packets */
        {                                           /* All replies include a completion code first */
            expert_item = proto_tree_add_item_ret_uint(it_subtree, hf_iter_verb_completion_code, tvb, ioffset,
                    4, ENC_LITTLE_ENDIAN, &rcode);
            error_string = val_to_str_const(rcode, nds_reply_errors, "Unknown Interation Verb Completion Code");

            if (rcode != 0 && ncp_echo_err) {
                expert_add_info_format(pinfo, expert_item, &ei_iter_verb_completion_code, "Iteration Verb Error: 0x%08x %s", rcode, error_string);
            }
            ioffset += 4;

            switch (it_verb) {
            case IT_ATFIRST:
            case IT_ATEOF:
            case IT_ATLAST:
            case IT_ATBOF:
                proto_tree_add_item(it_subtree, hf_iter_ans, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset += 4;
                break;
            case IT_CLEAR:
                break;
            case IT_COPY:
                proto_tree_add_item(it_subtree, hf_iter_copy, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset += 4;
                break;
            case IT_COUNT:
                proto_tree_add_item(it_subtree, hf_this_count, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset += 4;
                break;
            case IT_CREATE:
                proto_tree_add_item(it_subtree, hf_nds_iterator, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset += 4;
                break;
            case IT_CURRENT:
            case IT_NEXT:
            case IT_PREV:
            case IT_FIRST:
            case IT_LAST:
                proto_tree_add_item(it_subtree, hf_nds_info_type, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset = ioffset + 4;
                proto_tree_add_item(it_subtree, hf_data_size, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset += 4;
                number_of_items = tvb_get_letohl(tvb, ioffset);
                proto_tree_add_item(it_subtree, hf_this_count, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset += 4;
                for (i = 0; i < number_of_items; i++)
                {
                    it_subtree1 = proto_tree_add_subtree_format(it_subtree, tvb, ioffset, -1, ett_nds, NULL, "Item #: %u", i+1);

                    ioffset += align_4(tvb, ioffset);

                    /* Start WGetAndBufferEntryInfo = process_entry_info() */
                    values.voffset = ioffset;
                    values.vflags = request_flags;
                    process_entry_info(it_subtree1, tvb, &values);
                    ioffset = values.voffset;
                    /* End WGetAndBufferEntryInfo */

                    ioffset += align_4(tvb, ioffset);

                    /* WGetReadBuffer - This seems to be a count and then size field (2 * guint32) */
                    /* For now we will just skip this offset. NEED TO ADD LOGIC TO HANDLE */
                    ioffset += 8;

                    if (tvb_captured_length_remaining(tvb, ioffset) < 4) {
                        break;
                    }
                }
                break;
            case IT_DESTROY:
            case IT_DONE:
                break;
            case IT_GETPOSITION:
                proto_tree_add_item(it_subtree, hf_iter_position, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset += 4;
                break;
            case IT_ISPOSITIONABLE:
                proto_tree_add_item(it_subtree, hf_positionable, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset += 4;
                break;
            case IT_POSITION:
            case IT_POSITION_IT:
            case IT_SETFILTER:
            case IT_TYPEDOWN:
                break;
            case IT_SETINDEX:
                proto_tree_add_item(it_subtree, hf_iter_index, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset += 4;
                break;
            case IT_SKIP:
                proto_tree_add_item(it_subtree, hf_num_skipped, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset += 4;
                break;
            default:
                if (tvb_captured_length_remaining(tvb, ioffset) < 4) {
                    THROW(ReportedBoundsError);
                }
                return;
            }
        }
        it_verb = tvb_get_letohl(tvb, ioffset);
        ioffset += 4;
        if (it_verb == IT_DONE || tvb_captured_length_remaining(tvb, ioffset) < 4) {
            proto_tree_add_uint(it_tree, hf_ncp_nds_iterverb, tvb, ioffset-4, 4, it_verb);
            break;
        }
    }
    return;
}


static void
process_multivalues(proto_tree *ncp_tree, tvbuff_t *tvb, packet_info *pinfo, nds_val *values)
{
    guint32         i;
    guint32         r;
    guint32         ioffset = 0, oldioffset;
    guint32         value1 = 0;
    guint32         value2 = 0;
    guint8          value3 = 0;
    guint32         value4 = 0;
    gint            value5 = 0;
    guint32         value6 = 0;
    guint32         value7 = 0;
    const char      *valuestr = "";
    proto_tree      *ntree;
    proto_tree      *atree;
    proto_item      *nitem;
    proto_item      *aitem;
    guint32         number_of_referrals = 0;
    proto_tree      *estree;
    proto_item      *esitem;
    guint32         bvalue=0;
    nds_val         temp_values;
    proto_tree      *sub1tree;
    proto_item      *sub1item;
    proto_tree      *sub2tree;
    proto_item      *sub2item;
    gint            length_remaining;
    nstime_t        ns;

    mv_resolve_name_string[0] = '\0';
    values->vstring = "";

    /* Is the value passed a string or UINT32? */
    if(values->mvtype != MVTYPE_LIST_PARTITIONS && values->mvtype != MVTYPE_PROCESS_TAGS)
    {
        nitem = proto_tree_add_uint_format(ncp_tree, values->hfname, tvb, values->voffset+ioffset,
                                           values->vlength, values->vvalue, values->vdesc, values->vvalue);
    }
    else
    {
        nitem = proto_tree_add_string_format(ncp_tree, values->hfname, tvb, values->voffset+ioffset,
                                             values->vlength, values->vdesc, "%s", values->vdesc);
    }
    ioffset = (values->voffset+4);

    ntree = proto_item_add_subtree(nitem, ett_nds);

    switch (values->mvtype)
    {
    case MVTYPE_ATTR_REQUEST:   /* Attribute Request */
        for (i = 1 ; i <= values->vvalue; i++ )
        {
            ioffset += align_4(tvb, ioffset);
            value1 = tvb_get_letohl(tvb, ioffset);
            ioffset = ioffset + 4;
            values->vstring = get_string(tvb, ioffset, value1);
            proto_tree_add_string(ntree, hf_mv_string, tvb, ioffset,
                                  value1, values->vstring);
            ioffset = ioffset + value1;
        }
        break;

    case MVTYPE_ATTR_REPLY:     /* Attribute Reply */
        switch(values->vflags)
        {
        case 0:
            for (i = 1 ; i <= values->vvalue; i++ )
            {
                ioffset += align_4(tvb, ioffset);
                value1 = tvb_get_letohl(tvb, ioffset);
                ioffset = ioffset + 4;
                values->vstring = get_string(tvb, ioffset, value1);
                proto_tree_add_string(ntree, hf_mv_string, tvb, ioffset,
                                      value1, values->vstring);
                ioffset = ioffset + value1;
            }
            break;
        case 1:
            for (i = 1 ; i <= values->vvalue; i++ )
            {
                proto_tree_add_item(ntree, hf_nds_syntax, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset = ioffset + 4;
                value2 = tvb_get_letohl(tvb, ioffset);
                ioffset = ioffset + 4;
                values->vstring = get_string(tvb, ioffset, value2);
                proto_tree_add_string(ntree, hf_mv_string, tvb, ioffset,
                                      value2, values->vstring);
                ioffset += value2;
                ioffset += align_4(tvb, ioffset);
                values->voffset = ioffset;

                print_nds_values(ntree, pinfo, tvb, value1, values);
                ioffset = values->voffset;
            }
            break;
        case 2:
            for (i = 1 ; i <= values->vvalue; i++ )
            {
                proto_tree_add_item(ntree, hf_nds_syntax, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset = ioffset + 4;
                value2 = tvb_get_letohl(tvb, ioffset);
                ioffset = ioffset + 4;
                values->vstring = get_string(tvb, ioffset, value2);
                proto_tree_add_string(ntree, hf_mv_string, tvb, ioffset,
                                      value2, values->vstring);
                values->voffset=ioffset + value2;
                ioffset += value2;
                ioffset += align_4(tvb, ioffset);
                value3 = tvb_get_letohl(tvb, ioffset);

                proto_tree_add_uint_format(ntree, hf_nds_uint32value, tvb, ioffset, 4,
                                           value3, "Number of Values - %u", value3);

                ioffset = ioffset + 4;
                for (r = 1 ; r <= value3; r++ )
                {
                    ioffset += 4;   /* Length = 4 */
                    proto_tree_add_item(ntree, hf_nds_privileges, tvb, ioffset,
                                        values->vlength, ENC_LITTLE_ENDIAN);

                    ioffset = ioffset+4;
                }
            }
            break;
        case 3:
            for (i = 1 ; i <= values->vvalue; i++ )
            {
                proto_tree_add_item(ntree, hf_nds_syntax, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset = ioffset + 4;
                value2 = tvb_get_letohl(tvb, ioffset);
                ioffset = ioffset + 4;
                values->vstring = get_string(tvb, ioffset, value2);
                proto_tree_add_string(ntree, hf_mv_string, tvb, ioffset,
                                      value2, values->vstring);
                ioffset = ioffset + value2;
                ioffset += align_4(tvb, ioffset);
                value3 = tvb_get_letohl(tvb, ioffset);

                aitem = proto_tree_add_uint_format(ntree, hf_nds_uint32value, tvb, ioffset, 4,
                                                   value3, "Number of Values - %u", value3);

                atree = proto_item_add_subtree(aitem, ett_nds);

                ioffset = ioffset + 4;
                for (r = 1 ; r <= value3; r++ )
                {
                    ioffset += align_4(tvb, ioffset);
                    proto_tree_add_bitmask(atree, tvb, ioffset, hf_vflags, ett_ncp, ncp_vflags, ENC_LITTLE_ENDIAN);
                    ioffset = ioffset + 4;
                    ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                    ns.nsecs = 0;
                    proto_tree_add_time_format(atree, hf_es_seconds, tvb, ioffset,
                                               4, &ns, "Timestamp: %s",
                                               abs_time_secs_to_str(wmem_packet_scope(), ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                    ioffset = ioffset + 4;
                    proto_tree_add_item(atree, hf_nds_replica_num, tvb, ioffset,
                                        2, ENC_LITTLE_ENDIAN);
                    ioffset = ioffset + 2;
                    proto_tree_add_item(atree, hf_nds_event_num, tvb, ioffset,
                                        2, ENC_LITTLE_ENDIAN);
                    ioffset = ioffset + 2;
                    value5 = tvb_get_letohl(tvb, ioffset); /* length of field */
                    if(value5 > tvb_captured_length_remaining(tvb, ioffset))
                    {
                        break;
                    }
                    ioffset += 4;
                    proto_tree_add_item(atree, hf_value_bytes, tvb, ioffset, value5, ENC_NA);
                    ioffset += value5;
                    ioffset += (value5%2);
                }
            }
            break;
        case 4:
            for (i = 1 ; i <= values->vvalue; i++ )
            {
                proto_tree_add_item(ntree, hf_nds_syntax, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                ioffset = ioffset + 4;
                value2 = tvb_get_letohl(tvb, ioffset);
                ioffset = ioffset + 4;
                values->vstring = get_string(tvb, ioffset, value2);
                proto_tree_add_string(ntree, hf_mv_string, tvb, ioffset,
                                      value2, values->vstring);
                ioffset = ioffset + value2;
                value3 = tvb_get_letohl(tvb, ioffset);

                proto_tree_add_uint_format(ntree, hf_nds_uint32value, tvb, ioffset, 4,
                                           value3, "Number of Values - %u", value3);

                ioffset = ioffset + 4;
                for (r = 1 ; r <= value3; r++ )
                {
                    ioffset += align_4(tvb, ioffset);
                    proto_tree_add_bitmask(ntree, tvb, ioffset, hf_vflags, ett_ncp, ncp_vflags, ENC_LITTLE_ENDIAN);
                    ioffset = ioffset + 4;
                    ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                    ns.nsecs = 0;
                    proto_tree_add_time_format(ntree, hf_es_seconds, tvb, ioffset,
                                               4, &ns, "Creation Time: %s",
                                               abs_time_secs_to_str(wmem_packet_scope(), ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                    ioffset = ioffset + 4;
                    proto_tree_add_item(ntree, hf_nds_replica_num, tvb, ioffset,
                                        2, ENC_LITTLE_ENDIAN);
                    ioffset = ioffset + 2;
                    proto_tree_add_item(ntree, hf_nds_event_num, tvb, ioffset,
                                        2, ENC_LITTLE_ENDIAN);
                    ioffset = ioffset + 2;
                    proto_tree_add_item(ntree, hf_nds_value_len, tvb, ioffset,
                                        4, ENC_LITTLE_ENDIAN);
                    ioffset = ioffset + 4;
                }
            }
            break;
        default:
            break;
        }
        break;

    case MVTYPE_ATTR_REQUEST2:    /* Attribute Request */
        oldioffset = 0;
        for (i = 1 ; i <= values->vvalue; i++ )
        {
            if (oldioffset >= ioffset) {
                proto_tree_add_expert_format(ntree, pinfo, &ei_ncp_invalid_offset, tvb, 0, 0, "Invalid offset: %u", ioffset);
                THROW(ReportedBoundsError);
            }
            oldioffset = ioffset;
            ioffset += align_4(tvb, ioffset);
            value1 = tvb_get_letohl(tvb, ioffset);
            proto_tree_add_uint_format(ntree, hf_nds_uint32value, tvb, ioffset,
                                       4, value1, "Value %d", value1);
            ioffset = ioffset + value1;
        }
        break;

    case MVTYPE_ADD_ATTR_REQUEST: /* Add Attribute Request */
        for (i = 1 ; i <= values->vvalue; i++ )
        {
            value1 = tvb_get_letohl(tvb, ioffset);
            ioffset = ioffset + 4;
            values->vstring = get_string(tvb, ioffset, value1);
            proto_tree_add_string(ntree, hf_mv_string, tvb, ioffset,
                                  value1, values->vstring);
            ioffset = ioffset + value1;
            ioffset += align_4(tvb, ioffset);
            values->voffset = ioffset;
            print_nds_values(ntree, pinfo, tvb, 9, values);
            ioffset = values->voffset;
        }
        break;

    case MVTYPE_READ_CLASS_REQ:   /* Read Class Request */
        for (i = 1 ; i <= values->vvalue; i++ )
        {
            ioffset += align_4(tvb, ioffset);
            value1 = tvb_get_letohl(tvb, ioffset);
            ioffset = ioffset + 4;
            values->vstring = get_string(tvb, ioffset, value1);
            proto_tree_add_string(ntree, hf_nds_base, tvb, ioffset,
                                  value1, values->vstring);
            values->mvtype = MVTYPE_ATTR_REQUEST;
            ioffset = ioffset + value1;
        }
        break;

    case MVTYPE_READ_REPLICAS:    /* Read Replicas */
        for (i = 1 ; i <= values->vvalue; i++ )
        {
            bvalue = 0x00000001;

            for (r = 0 ; r < 9; r++ )
            {
                if (values->vflags & bvalue)
                {
                    switch(bvalue)
                    {
                    case 0x00000001:                /*p3values.bit1 = "Output Flags"*/
                        proto_tree_add_bitmask(ntree, tvb, ioffset, hf_outflags, ett_ncp, ncp_outflags, ENC_LITTLE_ENDIAN);
                        ioffset = ioffset + 4;
                        break;
                    case 0x00000002:                /*p3values.bit2 = "Entry ID"*/
                        value1 = tvb_get_letohl(tvb, ioffset);
                        proto_tree_add_uint_format(ntree, hf_nds_eid, tvb, ioffset,
                                                   4, value1, "Entry ID %08x", value1);
                        ioffset = ioffset + 4;
                        break;
                    case 0x00000004:                /*p3values.bit3 = "Replica State"*/
                        proto_tree_add_item_ret_uint(ntree, hf_replica_state, tvb, ioffset,
                                              4, ENC_LITTLE_ENDIAN, &value1);
                        ioffset = ioffset + 4;
                        break;
                    case 0x0000008:                 /*p3values.bit4 = "Modification Timestamp"*/
                        ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                        ns.nsecs = 0;
                        proto_tree_add_time_format(ntree, hf_es_seconds, tvb, ioffset,
                                                   4, &ns, "Modification Timestamp: %s",
                                                   abs_time_secs_to_str(wmem_packet_scope(), ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                        ioffset = ioffset + 4;
                        proto_tree_add_item(ntree, hf_nds_replica_num, tvb, ioffset,
                                            2, ENC_LITTLE_ENDIAN);
                        ioffset = ioffset + 2;
                        proto_tree_add_item(ntree, hf_nds_event_num, tvb, ioffset,
                                            2, ENC_LITTLE_ENDIAN);
                        ioffset = ioffset + 2;
                        break;
                    case 0x00000010:                /*p3values.bit5 = "Purge Time"*/
                        ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                        ns.nsecs = 0;
                        proto_tree_add_time(ntree, hf_nds_purge, tvb, ioffset, 4, &ns);
                        ioffset = ioffset + 4;
                        break;
                    case 0x00000020:                /*p3values.bit6 = "Local Partition ID"*/
                        proto_tree_add_item(ntree, hf_nds_local_partition, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                        ioffset = ioffset + 4;
                        break;
                    case 0x00000040:                /*p3values.bit7 = "Distinguished Name"*/
                        value1 = tvb_get_letohl(tvb, ioffset);
                        ioffset = ioffset + 4;
                        temp_values.vstring = get_string(tvb, ioffset, value1);
                        proto_tree_add_string(ntree, hf_nds_name, tvb, ioffset,
                                              value1, temp_values.vstring);
                        ioffset = ioffset + value1;
                        break;
                    case 0x00000080:                /*p3values.bit8 = "Replica Type & State"*/
                        value1 = tvb_get_letohl(tvb, ioffset);
                        value2 = value1 & 0x00ff;
                        proto_tree_add_uint(ntree, hf_replica_type, tvb, ioffset, 4, value2);
                        value3 = value1 & 0xff00;
                        proto_tree_add_uint(ntree, hf_replica_state, tvb, ioffset, 4, value3);
                        ioffset = ioffset + 4;
                        break;
                    case 0x00000100:                /*p3values.bit9 = "Partition Busy"*/
                        value1 = tvb_get_letohs(tvb, ioffset);
                        proto_tree_add_boolean(ntree, hf_partition_busy, tvb, ioffset, 4, value1);
                        ioffset += 4;
                        break;
                    default:
                        break;
                    }
                }
                bvalue = bvalue*2;
                ioffset += align_4(tvb, ioffset);
                if(tvb_captured_length_remaining(tvb, ioffset) < 4 )
                {
                    break;
                }
            }
            if(tvb_captured_length_remaining(tvb, ioffset) < 4 )
            {
                break;
            }
        }
        break;

    case MVTYPE_MODIFY_ATTR_REQUEST: /* Modify Attribute Request */
        for (i = 0 ; i < values->vvalue; i++ )
        {
            ioffset += align_4(tvb, ioffset);
            value1 = tvb_get_letohl(tvb, ioffset);
            valuestr = val_to_str_const(value1, nds_kind_of_changes, "(Kind Change Not Found)");
            proto_tree_add_uint_format(ntree, hf_nds_uint32value, tvb, ioffset,
                                       values->vlength, value1, valuestr, value1);
            ioffset = ioffset+4;
            value2 = tvb_get_letohl(tvb, ioffset);
            ioffset = ioffset + 4;
            temp_values.vstring = get_string(tvb, ioffset, value2);   /* Name of Attribute */
            proto_tree_add_string(ntree, hf_mv_string, tvb, ioffset,
                                  value2, temp_values.vstring);
            ioffset = ioffset + value2;
            ioffset += align_4(tvb, ioffset);
            if(value1 != 1 && value1 != 6)
            {
                values->voffset = ioffset;
                /* XX: Is values.vstring set properly at this point ?? */
                print_nds_values(ntree, pinfo, tvb, 9, values);
                ioffset = values->voffset;
            }
        }
        break;

    case MVTYPE_ADDR_REFERRAL_REQUEST: /* Address Referral Request */
        for (i = 0 ; i < values->vvalue; i++ )
        {
            value1 = tvb_get_letohl(tvb, ioffset);
            valuestr = val_to_str_const(value1, nds_protocol_type, "(Undefined Protocol)");
            proto_tree_add_uint_format(ntree, hf_nds_uint32value, tvb, ioffset,
                                       values->vlength, value1, valuestr, value1);
            ioffset = ioffset+4;
        }
        break;

    case MVTYPE_ADDR_REFERRAL_REPLY: /* Address Referral Reply */
        number_of_referrals = values->vvalue;

        for (r = 1 ; r <= number_of_referrals; r++ )
        {
            aitem = proto_tree_add_uint_format(ntree, hf_referral_record, tvb, 6, 0,
                                               r, "NDS Referral Record #%u", r);
            atree = proto_item_add_subtree(aitem, ett_nds);

            proto_tree_add_item_ret_uint(atree, hf_referral_addcount, tvb, ioffset, 4, ENC_LITTLE_ENDIAN, &value1);

            ioffset = ioffset + 4;
            for (i = 1 ; i <= value1; i++ )
            {
                value2 = tvb_get_letohl(tvb, ioffset);
                valuestr = val_to_str_const(value2, nds_protocol_type, "(Undefined Protocol)");
                proto_tree_add_uint_format(atree, hf_nds_uint32value, tvb, ioffset,
                                           values->vlength, value2, valuestr, value2);
                ioffset = ioffset+4;
                value3 = tvb_get_letohl(tvb, ioffset);
                ioffset = ioffset+4;
                switch (value2)
                {
                case NDS_PTYPE_IPX:
                    proto_tree_add_item(atree, hf_nds_net, tvb, ioffset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(atree, hf_nds_node, tvb, ioffset+4, 6, ENC_NA);
                    proto_tree_add_item(atree, hf_nds_socket, tvb, ioffset+10, 2, ENC_BIG_ENDIAN);
                    break;
                case NDS_PTYPE_IP:
                    proto_tree_add_item(atree, hf_nds_port, tvb, ioffset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(atree, hf_add_ref_ip, tvb, ioffset+2, 4, ENC_BIG_ENDIAN);
                    break;
                case NDS_PTYPE_UDP:
                    proto_tree_add_item(atree, hf_nds_port, tvb, ioffset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(atree, hf_add_ref_udp, tvb, ioffset+2, 4, ENC_BIG_ENDIAN);
                    break;
                case NDS_PTYPE_TCP:
                    proto_tree_add_item(atree, hf_nds_port, tvb, ioffset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(atree, hf_add_ref_tcp, tvb, ioffset+2, 4, ENC_BIG_ENDIAN);
                    break;
                case NDS_PTYPE_URL:
                case NDS_PTYPE_DNS:
                    values->vstring = get_string(tvb, ioffset, value3);
                    proto_tree_add_string(atree, hf_value_string, tvb, ioffset,
                                          value3, values->vstring);
                    break;
                default:
                    break;
                }
                ioffset = ioffset + value3;
                ioffset += align_4(tvb, ioffset);
            }

        }
        break;

    case MVTYPE_LOC_ADDR_REFERRAL_REPLY: /* Local Address Referral Reply */
        number_of_referrals = values->vvalue;

        for (r = 1 ; r <= number_of_referrals; r++ )
        {
            aitem = proto_tree_add_uint_format(ntree, hf_referral_record, tvb, 6, 0,
                                               r, "NDS Referral Record #%u", r);
            atree = proto_item_add_subtree(aitem, ett_nds);

            value2 = tvb_get_letohl(tvb, ioffset);
            valuestr = val_to_str_const(value2, nds_protocol_type, "(Undefined Protocol)");
            proto_tree_add_uint_format(atree, hf_nds_uint32value, tvb, ioffset,
                                       values->vlength, value2, valuestr, value2);
            ioffset = ioffset+4;
            value3 = tvb_get_letohl(tvb, ioffset);
            ioffset = ioffset+4;

            switch (value2)
            {
            case NDS_PTYPE_IPX:
                proto_tree_add_item(atree, hf_nds_net, tvb, ioffset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(atree, hf_nds_node, tvb, ioffset+4, 6, ENC_NA);
                proto_tree_add_item(atree, hf_nds_socket, tvb, ioffset+10, 2, ENC_BIG_ENDIAN);
                break;
            case NDS_PTYPE_IP:
                proto_tree_add_item(atree, hf_nds_port, tvb, ioffset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(atree, hf_add_ref_ip, tvb, ioffset+2, 4, ENC_BIG_ENDIAN);
                break;
            case NDS_PTYPE_UDP:
                proto_tree_add_item(atree, hf_nds_port, tvb, ioffset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(atree, hf_add_ref_udp, tvb, ioffset+2, 4, ENC_BIG_ENDIAN);
                break;
            case NDS_PTYPE_TCP:
                proto_tree_add_item(atree, hf_nds_port, tvb, ioffset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(atree, hf_add_ref_tcp, tvb, ioffset+2, 4, ENC_BIG_ENDIAN);
                break;
            case NDS_PTYPE_URL:
            case NDS_PTYPE_DNS:
                values->vstring = get_string(tvb, ioffset, value3);
                proto_tree_add_string(atree, hf_value_string, tvb, ioffset,
                                      value3, values->vstring);
                break;
            default:
                break;
            }
            ioffset = ioffset + value3;
            ioffset += align_4(tvb, ioffset);
        }
        break;

    case MVTYPE_PROC_ENTRY_SPECIFIERS: /* Process Entry Specifiers */
        value2 = tvb_get_letohl(tvb, ioffset);   /* ES Type */
        values->vstring = val_to_str_const(value2, es_type, "No ES Type Found");
        esitem = proto_tree_add_string_format(ntree, hf_es_type, tvb, ioffset,
                                              4, values->vstring, "Output Entry Specifier - %s", values->vstring);
        estree = proto_item_add_subtree(esitem, ett_nds);
        ioffset = ioffset + 4;
        ioffset = print_es_type(estree, tvb, values, value2, ioffset);
        value3 = tvb_get_letohl(tvb, ioffset);   /* ES Type */
        values->vstring = val_to_str_const(value3, es_type, "No ES Type Found");
        esitem = proto_tree_add_string_format(ntree, hf_es_type, tvb, ioffset,
                                              4, values->vstring, "Input Entry Specifier - %s", values->vstring);
        estree = proto_item_add_subtree(esitem, ett_nds);
        ioffset = ioffset + 4;
        ioffset = print_es_type(estree, tvb, values, value3, ioffset);
        /* values.vstring is being overwritten. So store the resolve name to a global value */
        g_strlcpy(mv_resolve_name_string, values->vstring, 128);
        value4 = tvb_get_letohl(tvb, ioffset);
        aitem = proto_tree_add_uint_format(ntree, hf_referral_record, tvb, ioffset, 4,
                                           value4, "Referral Protocols - %u", value4);
        atree = proto_item_add_subtree(aitem, ett_nds);
        ioffset += 4;
        for (i = 0 ; i < value4; i++ )
        {
            value5 = tvb_get_letohl(tvb, ioffset);
            valuestr = val_to_str_const(value5, nds_protocol_type, "(Undefined Protocol)");
            proto_tree_add_string_format(atree, hf_value_string, tvb, ioffset,
                                         4, valuestr, "Protocol -> %s", valuestr);
            ioffset = ioffset+4;
        }
        value6 = tvb_get_letohl(tvb, ioffset);
        aitem = proto_tree_add_uint_format(ntree, hf_referral_record, tvb, ioffset, 4,
                                           value6, "Tree Walking Protocols - %u", value6);
        atree = proto_item_add_subtree(aitem, ett_nds);
        ioffset += 4;
        for (i = 0 ; i < value6; i++ )
        {
            value7 = tvb_get_letohl(tvb, ioffset);
            valuestr = val_to_str_const(value7, nds_protocol_type, "(Undefined Protocol)");
            proto_tree_add_string_format(atree, hf_value_string, tvb, ioffset,
                                         4, valuestr, "Protocol -> %s", valuestr);
            ioffset = ioffset+4;
        }
        values->vstring = " ";
        break;

    case MVTYPE_PRINT_TIMESTAMP:  /* Print Timestamp */
        proto_tree_add_item(ncp_tree, hf_nds_replica_num, tvb, ioffset,
                            2, ENC_LITTLE_ENDIAN);
        ioffset = ioffset + 2;
        proto_tree_add_item(ncp_tree, hf_nds_event_num, tvb, ioffset,
                            2, ENC_LITTLE_ENDIAN);
        ioffset = ioffset + 2;
        /* fall through */

    case MVTYPE_LIST_PARTITIONS:  /* List Partitions */
        number_of_referrals = values->vvalue;
        /* A bad packet could put us in a tight loop so trap for anything
         * over 256 referrals.
         */
        if (number_of_referrals > 256) {
            proto_tree_add_expert_format(ntree, pinfo, &ei_ncp_invalid_offset, tvb, 0, 0, "Bad referal at offset: %u", ioffset);
            THROW(ReportedBoundsError);
            break;
        }
        for (i = 0; i < number_of_referrals; i++)
        {
            bvalue = 0x00000001;

            for (r = 0 ; r < 32; r++ )
            {
                /*oldioffset = ioffset;*/
                if (values->vflags & bvalue)
                {
                    switch(bvalue)
                    {
                    case 0x00000001:                /* Information Flags */
                        proto_tree_add_bitmask(ncp_tree, tvb, ioffset, hf_infoflagsl, ett_ncp, ncp_infoflagsl, ENC_LITTLE_ENDIAN);
                        ioffset += 2;
                        proto_tree_add_bitmask(ncp_tree, tvb, ioffset, hf_infoflagsh, ett_ncp, ncp_infoflagsh, ENC_LITTLE_ENDIAN);
                        ioffset += 2;
                        break;
                    case 0x00000002:                /* Entry ID */
                        value1 = tvb_get_letohl(tvb, ioffset);
                        proto_tree_add_uint_format(ntree, hf_nds_eid, tvb, ioffset,
                                                   4, value1, "Entry ID %08x", value1);
                        ioffset = ioffset + 4;
                        break;
                    case 0x00000004:                /* Entry Flags */
                        proto_tree_add_bitmask(ncp_tree, tvb, ioffset, hf_eflags, ett_ncp, ncp_eflags, ENC_LITTLE_ENDIAN);
                        ioffset = ioffset+4;
                        break;
                    case 0x0000008:                 /* Subordinate Count */
                        value1 = tvb_get_letohl(tvb, ioffset);
                        proto_tree_add_uint_format(ntree, hf_sub_count, tvb, ioffset,
                                                   4, value1, "Subordinate Count %u", value1);
                        ioffset = ioffset + 4;
                        break;
                    case 0x0000010:                 /* Modification Time */
                        ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                        ns.nsecs = 0;
                        proto_tree_add_time_format(ntree, hf_es_seconds, tvb, ioffset,
                                                   4, &ns, "Modification Time: %s",
                                                   abs_time_secs_to_str(wmem_packet_scope(), ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                        ioffset = ioffset + 4;
                        break;
                    case 0x0000020:                 /* Modification Timestamp */
                        ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                        ns.nsecs = 0;
                        proto_tree_add_time_format(ntree, hf_es_seconds, tvb, ioffset,
                                                   4, &ns, "Modification Timestamp: %s",
                                                   abs_time_secs_to_str(wmem_packet_scope(), ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                        ioffset = ioffset + 4;
                        proto_tree_add_item(ntree, hf_nds_replica_num, tvb, ioffset,
                                            2, ENC_LITTLE_ENDIAN);
                        ioffset = ioffset + 2;
                        proto_tree_add_item(ntree, hf_nds_event_num, tvb, ioffset,
                                            2, ENC_LITTLE_ENDIAN);
                        ioffset = ioffset + 2;
                        break;
                    case 0x0000040:                 /* Creation Timestamp */
                        ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                        ns.nsecs = 0;
                        proto_tree_add_time_format(ntree, hf_es_seconds, tvb, ioffset,
                                                   4, &ns, "Creation Timestamp: %s",
                                                   abs_time_secs_to_str(wmem_packet_scope(), ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                        ioffset = ioffset + 4;
                        proto_tree_add_item(ntree, hf_nds_replica_num, tvb, ioffset,
                                            2, ENC_LITTLE_ENDIAN);
                        ioffset = ioffset + 2;
                        proto_tree_add_item(ntree, hf_nds_event_num, tvb, ioffset,
                                            2, ENC_LITTLE_ENDIAN);
                        ioffset = ioffset + 2;
                        break;
                    case 0x00000080:                /* Partition Root ID */
                        value1 = tvb_get_letohl(tvb, ioffset);
                        proto_tree_add_uint_format(ntree, hf_nds_partition_root_id, tvb, ioffset,
                                                   4, value1, "Partition Root ID %08x", value1);
                        ioffset = ioffset + 4;
                        break;
                    case 0x00000100:                /* Parent ID */
                        proto_tree_add_item(ntree, hf_nds_parent, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                        ioffset = ioffset + 4;
                        break;
                    case 0x00000200:                /* Revision Count */
                        proto_tree_add_item(ntree, hf_nds_revision, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
                        ioffset = ioffset + 4;
                        break;
                    case 0x00000400:                /* Replica Type & State */
                        value1 = tvb_get_letohl(tvb, ioffset);
                        value2 = value1 & 0x00ff;
                        proto_tree_add_uint(ntree, hf_replica_type, tvb, ioffset, 4, value2);
                        value3 = value1 & 0xff00;
                        proto_tree_add_uint(ntree, hf_replica_state, tvb, ioffset, 4, value3);
                        ioffset = ioffset + 4;
                        break;
                    case 0x00000800:                /* Base Class */
                        value1 = tvb_get_letohl(tvb, ioffset);
                        ioffset = ioffset + 4;
                        temp_values.vstring = get_string(tvb, ioffset, value1);
                        proto_tree_add_string(ntree, hf_nds_base, tvb, ioffset,
                                              value1, temp_values.vstring);
                        ioffset = ioffset + value1;
                        break;
                    case 0x00001000:                /* Relative Distinguished Name */
                        value1 = tvb_get_letohl(tvb, ioffset);
                        ioffset = ioffset + 4;
                        temp_values.vstring = get_string(tvb, ioffset, value1);
                        proto_tree_add_string(ntree, hf_nds_relative_dn, tvb, ioffset,
                                              value1, temp_values.vstring);
                        ioffset = ioffset + value1;
                        break;
                    case 0x00002000:                /* Distinguished Name */
                        value1 = tvb_get_letohl(tvb, ioffset);
                        ioffset = ioffset + 4;
                        temp_values.vstring = get_string(tvb, ioffset, value1);
                        proto_tree_add_string(ntree, hf_nds_name, tvb, ioffset,
                                              value1, temp_values.vstring);
                        ioffset = ioffset + value1;
                        break;
                    case 0x00004000:                /* Root Distinguished Name */
                        value1 = tvb_get_letohl(tvb, ioffset);
                        ioffset = ioffset + 4;
                        temp_values.vstring = get_string(tvb, ioffset, value1);
                        proto_tree_add_string(ntree, hf_nds_name, tvb, ioffset,
                                              value1, temp_values.vstring);
                        ioffset = ioffset + value1;
                        break;
                    case 0x00008000:                /* Parent Distinguished Name */
                        value1 = tvb_get_letohl(tvb, ioffset);
                        ioffset = ioffset + 4;
                        temp_values.vstring = get_string(tvb, ioffset, value1);
                        proto_tree_add_string(ntree, hf_nds_name, tvb, ioffset,
                                              value1, temp_values.vstring);
                        ioffset = ioffset + value1;
                        break;
                    case 0x00010000:                /* Purge Time */
                        ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                        ns.nsecs = 0;
                        proto_tree_add_time_format(ntree, hf_es_seconds, tvb, ioffset,
                                                   4, &ns, "Purge Time: %s",
                                                   abs_time_secs_to_str(wmem_packet_scope(), ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                        ioffset = ioffset + 4;
                        break;
                    case 0x00020000:                /* Dereference Base Class */
                        value1 = tvb_get_letohl(tvb, ioffset);
                        ioffset = ioffset + 4;
                        temp_values.vstring = get_string(tvb, ioffset, value1);
                        proto_tree_add_string(ntree, hf_deref_base, tvb, ioffset,
                                              value1, temp_values.vstring);
                        ioffset = ioffset + value1;
                        break;
                    default:
                        break;

                    }
                    ioffset += align_4(tvb, ioffset);
                }
                bvalue = bvalue*2;
                /* We could loop forever so check to see if bvalue has wrapped to 0.
                 * if so then just abort loop.
                 */
                if (bvalue==0) {
                    break;
                }
                if(tvb_captured_length_remaining(tvb, ioffset) < 4 )
                {
                    break;
                }
            }
            if(tvb_captured_length_remaining(tvb, ioffset) < 4 )
            {
                break;
            }
        }
        break;

    case MVTYPE_CLASS_NAMES:      /* Class Names */
        number_of_referrals = values->vvalue;
        for (i = 0; i < number_of_referrals; i++)
        {
            ioffset += align_4(tvb, ioffset);
            value1 = tvb_get_letohl(tvb, ioffset);
            ioffset = ioffset + 4;
            temp_values.vstring = get_string(tvb, ioffset, value1);
            sub1item = proto_tree_add_string(ntree, hf_nds_base_class, tvb, ioffset,
                                             value1, temp_values.vstring);
            sub1tree = proto_item_add_subtree(sub1item, ett_nds);
            ioffset = ioffset + value1;
            ioffset += align_4(tvb, ioffset);
            if(values->vflags != 0)
            {
                proto_tree_add_bitmask(sub1tree, tvb, ioffset, hf_cflags, ett_ncp, ncp_cflags, ENC_LITTLE_ENDIAN);
                ioffset = ioffset+4;
                if(values->vflags != 5)
                {
                    value1 = tvb_get_letohl(tvb, ioffset); /* length of field */
                    length_remaining = tvb_captured_length_remaining(tvb, ioffset);
                    if(length_remaining == -1 || value1 > (guint32) length_remaining)
                    {
                        break;
                    }
                    ioffset += 4;
                    proto_tree_add_item(sub1tree, hf_nds_asn1, tvb, ioffset, value1, ENC_NA);
                    ioffset += value1;
                    ioffset += (value1%2);
                }
                if(values->vflags == 1 || values->vflags == 2 || values->vflags == 4)
                {
                    value1 = tvb_get_letohl(tvb, ioffset);  /* Super Classes */
                    sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_number_of_items, tvb, ioffset,
                                                          4, value1, "Super Classes %u", value1);
                    sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                    ioffset = ioffset + 4;
                    for (r = 0; r < value1; r++)
                    {
                        value2 = tvb_get_letohl(tvb, ioffset);
                        ioffset = ioffset + 4;
                        temp_values.vstring = get_string(tvb, ioffset, value2);
                        proto_tree_add_string(sub2tree, hf_nds_super, tvb, ioffset,
                                              value2, temp_values.vstring);
                        ioffset = ioffset + value2;
                        ioffset += align_4(tvb, ioffset);
                    }
                    value1 = tvb_get_letohl(tvb, ioffset);  /* Containment Classes */
                    sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_number_of_items, tvb, ioffset,
                                                          4, value1, "Containment Classes %u", value1);
                    sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                    ioffset = ioffset + 4;
                    for (r = 0; r < value1; r++)
                    {
                        value2 = tvb_get_letohl(tvb, ioffset);
                        ioffset = ioffset + 4;
                        temp_values.vstring = get_string(tvb, ioffset, value2);
                        proto_tree_add_string(sub2tree, hf_nds_base_class, tvb, ioffset,
                                              value2, temp_values.vstring);
                        ioffset = ioffset + value2;
                        ioffset += align_4(tvb, ioffset);
                    }
                    value1 = tvb_get_letohl(tvb, ioffset);  /* Naming Attributes */
                    sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_number_of_items, tvb, ioffset,
                                                          4, value1, "Naming Attributes %u", value1);
                    sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                    ioffset = ioffset + 4;
                    for (r = 0; r < value1; r++)
                    {
                        value2 = tvb_get_letohl(tvb, ioffset);
                        ioffset = ioffset + 4;
                        temp_values.vstring = get_string(tvb, ioffset, value2);
                        proto_tree_add_string(sub2tree, hf_mv_string, tvb, ioffset,
                                              value2, temp_values.vstring);
                        ioffset = ioffset + value2;
                        ioffset += align_4(tvb, ioffset);
                    }
                    value1 = tvb_get_letohl(tvb, ioffset);  /* Mandatory Attributes */
                    sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_number_of_items, tvb, ioffset,
                                                          4, value1, "Mandatory Attributes %u", value1);
                    sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                    ioffset = ioffset + 4;
                    for (r = 0; r < value1; r++)
                    {
                        value2 = tvb_get_letohl(tvb, ioffset);
                        ioffset = ioffset + 4;
                        temp_values.vstring = get_string(tvb, ioffset, value2);
                        proto_tree_add_string(sub2tree, hf_mv_string, tvb, ioffset,
                                              value2, temp_values.vstring);
                        ioffset = ioffset + value2;
                        ioffset += align_4(tvb, ioffset);
                    }
                    value1 = tvb_get_letohl(tvb, ioffset);  /* Optional Attributes */
                    sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_number_of_items, tvb, ioffset,
                                                          4, value1, "Optional Attributes %u", value1);
                    sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                    ioffset = ioffset + 4;
                    for (r = 0; r < value1; r++)
                    {
                        ioffset += align_4(tvb, ioffset);
                        value2 = tvb_get_letohl(tvb, ioffset);
                        ioffset = ioffset + 4;
                        temp_values.vstring = get_string(tvb, ioffset, value2);
                        proto_tree_add_string(sub2tree, hf_mv_string, tvb, ioffset,
                                              value2, temp_values.vstring);
                        ioffset = ioffset + value2;
                        if(tvb_captured_length_remaining(tvb, ioffset) < 4 )
                        {
                            break;
                        }
                    }
                }
#if 0
                if(values->vflags == 2 || values->vflags == 4)   /* Class Definitions of Super Classes */
#endif
                if(values->vflags == 4)   /* Class Definitions of Super Classes */
                {
                    value1 = tvb_get_letohl(tvb, ioffset);  /* Containment Classes */
                    sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_number_of_items, tvb, ioffset,
                                                          4, value1, "Containment Classes %u", value1);
                    sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                    ioffset = ioffset + 4;
                    for (r = 0; r < value1; r++)
                    {
                        value2 = tvb_get_letohl(tvb, ioffset);
                        ioffset = ioffset + 4;
                        temp_values.vstring = get_string(tvb, ioffset, value2);
                        proto_tree_add_string(sub2tree, hf_nds_base_class, tvb, ioffset,
                                              value2, temp_values.vstring);
                        ioffset = ioffset + value2;
                        ioffset += align_4(tvb, ioffset);
                    }
                    value1 = tvb_get_letohl(tvb, ioffset);  /* Naming Attributes */
                    sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_number_of_items, tvb, ioffset,
                                                          4, value1, "Naming Attributes %u", value1);
                    sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                    ioffset = ioffset + 4;
                    for (r = 0; r < value1; r++)
                    {
                        value2 = tvb_get_letohl(tvb, ioffset);
                        ioffset = ioffset + 4;
                        temp_values.vstring = get_string(tvb, ioffset, value2);
                        proto_tree_add_string(sub2tree, hf_mv_string, tvb, ioffset,
                                              value2, temp_values.vstring);
                        ioffset = ioffset + value2;
                        ioffset += align_4(tvb, ioffset);
                    }
                    value1 = tvb_get_letohl(tvb, ioffset);  /* Mandatory Attributes */
                    sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_number_of_items, tvb, ioffset,
                                                          4, value1, "Mandatory Attributes %u", value1);
                    sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                    ioffset = ioffset + 4;
                    for (r = 0; r < value1; r++)
                    {
                        value2 = tvb_get_letohl(tvb, ioffset);
                        ioffset = ioffset + 4;
                        temp_values.vstring = get_string(tvb, ioffset, value2);
                        proto_tree_add_string(sub2tree, hf_mv_string, tvb, ioffset,
                                              value2, temp_values.vstring);
                        ioffset = ioffset + value2;
                        ioffset += align_4(tvb, ioffset);
                    }
                    value1 = tvb_get_letohl(tvb, ioffset);  /* Optional Attributes */
                    sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_number_of_items, tvb, ioffset,
                                                          4, value1, "Optional Attributes %u", value1);
                    sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                    ioffset = ioffset + 4;
                    for (r = 0; r < value1; r++)
                    {
                        value2 = tvb_get_letohl(tvb, ioffset);
                        ioffset = ioffset + 4;
                        temp_values.vstring = get_string(tvb, ioffset, value2);
                        proto_tree_add_string(sub2tree, hf_mv_string, tvb, ioffset,
                                              value2, temp_values.vstring);
                        ioffset = ioffset + value2;
                        ioffset += align_4(tvb, ioffset);
                    }
                    value1 = tvb_get_letohl(tvb, ioffset);    /* Default ACL */
                    proto_tree_add_uint_format(sub1tree, hf_nds_eid, tvb, ioffset,
                                               4, value1, "Default ACL %08x", value1);
                    ioffset = ioffset + 4;
                    if(tvb_captured_length_remaining(tvb, ioffset) < 4 )
                    {
                        break;
                    }
                }
                if(values->vflags == 5)   /* Base Class Definitions */
                {
                    ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                    ns.nsecs = 0;
                    proto_tree_add_time_format(sub1tree, hf_es_seconds, tvb, ioffset,
                                               4, &ns, "Creation Timestamp: %s",
                                               abs_time_secs_to_str(wmem_packet_scope(), ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                    ioffset = ioffset + 4;
                    proto_tree_add_item(sub1tree, hf_nds_replica_num, tvb, ioffset,
                                        2, ENC_LITTLE_ENDIAN);
                    ioffset = ioffset + 2;
                    proto_tree_add_item(sub1tree, hf_nds_event_num, tvb, ioffset,
                                        2, ENC_LITTLE_ENDIAN);
                    ioffset = ioffset + 2;
                    ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                    ns.nsecs = 0;
                    proto_tree_add_time_format(sub1tree, hf_es_seconds, tvb, ioffset,
                                               4, &ns, "Modification Timestamp: %s",
                                               abs_time_secs_to_str(wmem_packet_scope(), ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                    ioffset = ioffset + 4;
                    proto_tree_add_item(sub1tree, hf_nds_replica_num, tvb, ioffset,
                                        2, ENC_LITTLE_ENDIAN);
                    ioffset = ioffset + 2;
                    proto_tree_add_item(sub1tree, hf_nds_event_num, tvb, ioffset,
                                        2, ENC_LITTLE_ENDIAN);
                    ioffset = ioffset + 2;
                    /* Class Definition */
                    value1 = tvb_get_letohl(tvb, ioffset);  /* Super Classes */
                    sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_number_of_items, tvb, ioffset,
                                                          4, value1, "Super Classes %u", value1);
                    sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                    ioffset = ioffset + 4;
                    for (r = 0; r < value1; r++)
                    {
                        value2 = tvb_get_letohl(tvb, ioffset);
                        ioffset = ioffset + 4;
                        temp_values.vstring = get_string(tvb, ioffset, value2);
                        proto_tree_add_string(sub2tree, hf_nds_super, tvb, ioffset,
                                              value2, temp_values.vstring);
                        ioffset = ioffset + value2;
                        ioffset += align_4(tvb, ioffset);
                    }
                    value1 = tvb_get_letohl(tvb, ioffset);  /* Containment Classes */
                    sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_number_of_items, tvb, ioffset,
                                                          4, value1, "Containment Classes %u", value1);
                    sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                    ioffset = ioffset + 4;
                    for (r = 0; r < value1; r++)
                    {
                        value2 = tvb_get_letohl(tvb, ioffset);
                        ioffset = ioffset + 4;
                        temp_values.vstring = get_string(tvb, ioffset, value2);
                        proto_tree_add_string(sub2tree, hf_nds_base_class, tvb, ioffset,
                                              value2, temp_values.vstring);
                        ioffset = ioffset + value2;
                        ioffset += align_4(tvb, ioffset);
                    }
                    value1 = tvb_get_letohl(tvb, ioffset);  /* Naming Attributes */
                    sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_number_of_items, tvb, ioffset,
                                                          4, value1, "Naming Attributes %u", value1);
                    sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                    ioffset = ioffset + 4;
                    for (r = 0; r < value1; r++)
                    {
                        value2 = tvb_get_letohl(tvb, ioffset);
                        ioffset = ioffset + 4;
                        temp_values.vstring = get_string(tvb, ioffset, value2);
                        proto_tree_add_string(sub2tree, hf_mv_string, tvb, ioffset,
                                              value2, temp_values.vstring);
                        ioffset = ioffset + value2;
                        ioffset += align_4(tvb, ioffset);
                    }
                    value1 = tvb_get_letohl(tvb, ioffset);  /* Mandatory Attributes */
                    sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_number_of_items, tvb, ioffset,
                                                          4, value1, "Mandatory Attributes %u", value1);
                    sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                    ioffset = ioffset + 4;
                    for (r = 0; r < value1; r++)
                    {
                        value2 = tvb_get_letohl(tvb, ioffset);
                        ioffset = ioffset + 4;
                        temp_values.vstring = get_string(tvb, ioffset, value2);
                        proto_tree_add_string(sub2tree, hf_mv_string, tvb, ioffset,
                                              value2, temp_values.vstring);
                        ioffset = ioffset + value2;
                        ioffset += align_4(tvb, ioffset);
                    }
                    value1 = tvb_get_letohl(tvb, ioffset);  /* Optional Attributes */
                    sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_number_of_items, tvb, ioffset,
                                                          4, value1, "Optional Attributes %u", value1);
                    sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                    ioffset = ioffset + 4;
                    for (r = 0; r < value1; r++)
                    {
                        value2 = tvb_get_letohl(tvb, ioffset);
                        ioffset = ioffset + 4;
                        temp_values.vstring = get_string(tvb, ioffset, value2);
                        proto_tree_add_string(sub2tree, hf_mv_string, tvb, ioffset,
                                              value2, temp_values.vstring);
                        ioffset = ioffset + value2;
                        ioffset += align_4(tvb, ioffset);
                    }
                    value1 = tvb_get_letohl(tvb, ioffset);    /* Default ACL */
                    proto_tree_add_uint_format(sub1tree, hf_nds_eid, tvb, ioffset,
                                               4, value1, "Default ACL %08x", value1);
                    ioffset = ioffset + 4;
                    if(tvb_captured_length_remaining(tvb, ioffset) < 4 )
                    {
                        break;
                    }
                }
            }
        }
        break;

    case MVTYPE_MODIFY_CLASS:     /* Modify Class */
        for (i = 1 ; i <= values->vvalue; i++ )   /* Attribute Names to add*/
        {
            ioffset += align_4(tvb, ioffset);
            value1 = tvb_get_letohl(tvb, ioffset);
            ioffset = ioffset + 4;
            values->vstring = get_string(tvb, ioffset, value1);
            proto_tree_add_string(ntree, hf_mv_string, tvb, ioffset,
                                  value1, values->vstring);
            ioffset = ioffset + value1;
        }
        if(tvb_captured_length_remaining(tvb, ioffset) < 4 )
        {
            break;
        }
        ioffset += align_4(tvb, ioffset);
        proto_tree_add_item_ret_uint(ntree, hf_nds_att_del, tvb, ioffset, 4, ENC_LITTLE_ENDIAN, &value1);
        ioffset = ioffset + 4;
        for (i = 1 ; i <= value1; i++ )   /* Attribute Names to delete*/
        {
            ioffset += align_4(tvb, ioffset);
            value2 = tvb_get_letohl(tvb, ioffset);
            ioffset = ioffset + 4;
            values->vstring = get_string(tvb, ioffset, value2);
            proto_tree_add_string(ntree, hf_mv_string, tvb, ioffset,
                                  value2, values->vstring);
            ioffset = ioffset + value2;
        }
        if(tvb_captured_length_remaining(tvb, ioffset) < 4 )
        {
            break;
        }
        ioffset += align_4(tvb, ioffset);
        proto_tree_add_item_ret_uint(ntree, hf_nds_acl_add, tvb, ioffset, 4, ENC_LITTLE_ENDIAN, &value1);
        ioffset = ioffset + 4;
        for (i = 1 ; i <= value1; i++ )   /* ACL templates to add*/
        {
            ioffset += align_4(tvb, ioffset);
            value2 = tvb_get_letohl(tvb, ioffset);  /* Attribute Name */
            ioffset = ioffset + 4;
            values->vstring = get_string(tvb, ioffset, value2);
            proto_tree_add_string(ntree, hf_nds_attribute_dn, tvb, ioffset,
                                  value2, values->vstring);
            ioffset = ioffset + value2;
            ioffset += align_4(tvb, ioffset);
            value2 = tvb_get_letohl(tvb, ioffset);  /* DN of Trustee */
            ioffset = ioffset + 4;
            values->vstring = get_string(tvb, ioffset, value2);
            proto_tree_add_string(ntree, hf_nds_trustee_dn, tvb, ioffset,
                                  value2, values->vstring);
            ioffset = ioffset + value2;
            ioffset += align_4(tvb, ioffset);
            proto_tree_add_item(ntree, hf_nds_privileges, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
            ioffset = ioffset + 4;
        }
        if(tvb_captured_length_remaining(tvb, ioffset) < 4 )
        {
            break;
        }
        ioffset += align_4(tvb, ioffset);
        proto_tree_add_item_ret_uint(ntree, hf_nds_acl_del, tvb, ioffset,
                                   4, ENC_LITTLE_ENDIAN, &value1);
        ioffset = ioffset + 4;
        for (i = 1 ; i <= value1; i++ )   /* ACL templates to delete*/
        {
            ioffset += align_4(tvb, ioffset);
            value2 = tvb_get_letohl(tvb, ioffset);  /* Attribute Name */
            ioffset = ioffset + 4;
            values->vstring = get_string(tvb, ioffset, value2);
            proto_tree_add_string(ntree, hf_nds_attribute_dn, tvb, ioffset,
                                  value2, values->vstring);
            ioffset = ioffset + value2;
            ioffset += align_4(tvb, ioffset);
            value2 = tvb_get_letohl(tvb, ioffset);  /* DN of Trustee */
            ioffset = ioffset + 4;
            values->vstring = get_string(tvb, ioffset, value2);
            proto_tree_add_string(ntree, hf_nds_trustee_dn, tvb, ioffset,
                                  value2, values->vstring);
            ioffset = ioffset + value2;
            ioffset += align_4(tvb, ioffset);
            value1 = tvb_get_letohl(tvb, ioffset);  /* Privileges */
            proto_tree_add_item(ntree, hf_nds_privileges, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
            ioffset = ioffset + 4;
        }
        break;

    case MVTYPE_PROCESS_TAGS: /* Process tags and paths depending on name type returned. */
        switch (values->vflags) {

        case 8:  /* Tuned Name */
            proto_tree_add_item(ntree, hf_nds_tune_mark, tvb, ioffset, 2, ENC_BIG_ENDIAN);
            ioffset += 2;
            value1 = tvb_get_letohs(tvb, ioffset);
            valuestr = val_to_str_const(value1, nds_tuned_tags, "(Undefined Tuned Name Tag)");
            proto_tree_add_string_format(ntree, hf_value_string, tvb, ioffset,
                                         2, valuestr, "Tuned Name Tag -> %s", valuestr);
            ioffset += 2;
            ioffset += align_4(tvb, ioffset);
            if (value1 == 0) { /* RDN Hint - really just returns the dist name + timestamp info */
                value2 = tvb_get_letohl(tvb, ioffset);  /* Distinguished Name Len, String[len]*/
                ioffset = ioffset + 4;
                values->vstring = get_string(tvb, ioffset, value2);
                proto_tree_add_string(ntree, hf_mv_string, tvb, ioffset,
                                      value2, values->vstring);
                ioffset += value2;
                ioffset += align_4(tvb, ioffset);
                ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                ns.nsecs = 0;
                proto_tree_add_time_format(ntree, hf_es_seconds, tvb, ioffset,
                                           4, &ns, "Creation Timestamp: %s",
                                           abs_time_secs_to_str(wmem_packet_scope(), ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                ioffset += 4;
                proto_tree_add_item(ntree, hf_nds_replica_num, tvb, ioffset,
                                    2, ENC_LITTLE_ENDIAN);
                ioffset = ioffset + 2;
                proto_tree_add_item(ntree, hf_nds_event_num, tvb, ioffset,
                                    2, ENC_LITTLE_ENDIAN);
                ioffset = ioffset + 2;
            }
            else /* Process the full RDN history including ancestors */
            {
                value1 = tvb_get_letohl(tvb, ioffset);
                sub1item = proto_tree_add_uint_format(ntree, hf_nds_acl_del, tvb, ioffset,
                                                      4, value1, "Number of RDN Items %u", value1);
                sub1tree = proto_item_add_subtree(sub1item, ett_nds);
                ioffset = ioffset + 4;
                for (i=1; i <= value1; i++) {
                    sub2tree = proto_tree_add_subtree_format(sub1tree, tvb, ioffset, 0, ett_nds, NULL, "Item %u", i);
                    ioffset += align_4(tvb, ioffset);

                    value5 = tvb_get_letohl(tvb, ioffset);
                    valuestr = val_to_str_const(value5, nds_tuned_item_tags, "(Undefined Tuned Name Tag)");
                    if (value5 == 0) { /* Items are timestamp + Distinguished name (0 value == one entry)*/
                        proto_tree_add_string_format(sub2tree, hf_value_string, tvb, ioffset,
                                                     4, valuestr, "Item Tag -> %s", valuestr);
                        ioffset += 4;
                        ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                        ns.nsecs = 0;
                        proto_tree_add_time_format(sub2tree, hf_es_seconds, tvb, ioffset,
                                                   4, &ns, "Timestamp: %s",
                                                   abs_time_secs_to_str(wmem_packet_scope(), ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                        ioffset += 4;
                        proto_tree_add_item(sub2tree, hf_nds_replica_num, tvb, ioffset,
                                            2, ENC_LITTLE_ENDIAN);
                        ioffset = ioffset + 2;
                        proto_tree_add_item(sub2tree, hf_nds_event_num, tvb, ioffset,
                                            2, ENC_LITTLE_ENDIAN);
                        ioffset = ioffset + 2;
                        value2 = tvb_get_letohl(tvb, ioffset);  /* Distinguished Name Len, String[len]*/
                        ioffset = ioffset + 4;
                        values->vstring = get_string(tvb, ioffset, value2);
                        proto_tree_add_string(sub2tree, hf_mv_string, tvb, ioffset,
                                              value2, values->vstring);
                        ioffset += value2;
                    }
                    /* XXX: What if "multiple items" ?                 */
                    /*      What if "Undefined ... " ?                 */
                    /*      For now: we'll just keep on walking...     */
                    /*      Presumably we'll get a ReportedBoundsError */
                    /*       pretty quickly.                           */
                    else   /* Undefined or "multiple items" ... */
                    {
                        ioffset += 4;
                    }
                } /* for */
            } /* else */
            values->voffset=ioffset;
            break;
        default: /* All other name types are just a string */
            values->vstring = get_string(tvb, ioffset, values->vlength);
            proto_tree_add_string(ntree, hf_mv_string, tvb, ioffset,
                                  values->vlength, values->vstring);
            values->voffset=ioffset + values->vlength;
            /*ioffset = values->voffset;
            ioffset += align_4(tvb, ioffset);*/
            break;
        } /* switch (values->vflags) */
        break;

    case MVTYPE_PROCESS_ITERATOR: /* Process Iterator subverbs. */
        proto_tree_add_item(ntree, hf_nds_info_type, tvb, ioffset, 4, ENC_LITTLE_ENDIAN);
        ioffset += 4;
        value5 = tvb_get_letohl(tvb, ioffset);
        proto_tree_add_bitmask(ncp_tree, tvb, ioffset, hf_infoflagsl, ett_ncp, ncp_infoflagsl, ENC_LITTLE_ENDIAN);
        ioffset += 2;
        proto_tree_add_bitmask(ncp_tree, tvb, ioffset, hf_infoflagsh, ett_ncp, ncp_infoflagsh, ENC_LITTLE_ENDIAN);
        ioffset += 2;
        proto_tree_add_item(ntree, hf_nds_time_filter, tvb, ioffset, 4, ENC_BIG_ENDIAN);
        ioffset += 4;
        proto_tree_add_item(ntree, hf_nds_all_attr, tvb, ioffset, 4, ENC_BIG_ENDIAN);
        ioffset += 4;
        value2 = tvb_get_letohl(tvb, ioffset);
        sub1item = proto_tree_add_uint_format(ntree, hf_nds_number_of_items, tvb, ioffset,
                                              4, value2, "Number of Attributes %u", value2);
        sub1tree = proto_item_add_subtree(sub1item, ett_nds);
        ioffset += 4;
        for (i=1; i<=value2; i++) {
            sub2tree = proto_tree_add_subtree_format(sub1tree, tvb, ioffset, 0, ett_nds, NULL, "Attribute %u", i);
            ioffset += align_4(tvb, ioffset);
            value3 = tvb_get_letohl(tvb, ioffset);  /* Attribute Name */
            ioffset = ioffset + 4;
            values->vstring = get_string(tvb, ioffset, value3);
            proto_tree_add_string(sub2tree, hf_nds_attribute_dn, tvb, ioffset,
                                  value3, values->vstring);
            ioffset = ioffset + value3;

            if(tvb_captured_length_remaining(tvb, ioffset) < 4 )
            {
                break;
            }
        }
        ioffset += align_4(tvb, ioffset);
        value4 = tvb_get_letohl(tvb, ioffset);
        values->vstring = val_to_str_const(value4, iterator_subverbs, "(No Iteration Verb Found)");
        ioffset += 4;
        dissect_nds_iterator(ntree, tvb, pinfo, value4, value5, ioffset, TRUE);

        values->vstring = wmem_strdup_printf(wmem_packet_scope(), "(%s)", values->vstring);
        break;

    default:
        break;
    }
}

static void
dissect_ncp_89_6_request(tvbuff_t *tvb, proto_tree *volatile ncp_tree, guint32 offset)
{
    guint32 string_len, datatype, count, i;

    datatype = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(ncp_tree, hf_ncp_data_type_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(ncp_tree, hf_ncp_reserved5, tvb, offset, 5, ENC_NA);
    offset += 5;
    count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(ncp_tree, hf_ncp_path_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    for (i=0; i < count; i++) {
        if (datatype == 0) {
            string_len = (tvb_get_guint8(tvb, offset))+1;
            proto_tree_add_item(ncp_tree, hf_ncp_directory_path, tvb, offset+1, string_len-1, ENC_ASCII|ENC_NA);
        }
        else
        {
            string_len = (tvb_get_letohs(tvb, offset))+2;
            proto_tree_add_item(ncp_tree, hf_ncp_directory_path, tvb, offset+2, string_len-2, ENC_ASCII|ENC_NA);
        }
        offset += string_len;
        if(tvb_captured_length_remaining(tvb, offset) < 4 )
        {
            break;
        }
    }
}


static void
dissect_ncp_123_11_reply(tvbuff_t *tvb, proto_tree *volatile ncp_tree, ncp_req_hash_value *request_value)
{
    int string_len, loffset;

    loffset = 76;
    if (request_value->length == 7) {
        /* Undocumented, if request value length is 7 then the reply is offset by 8 bytes.
         * Unknown what these 8 bytes represent */
        loffset += 8;
    }
    string_len = tvb_get_guint8(tvb, loffset);
    proto_tree_add_item(ncp_tree, hf_ncp_file_name_12, tvb, loffset+1, string_len, ENC_ASCII|ENC_NA);
    loffset += string_len+1;
    string_len = tvb_get_guint8(tvb, loffset);
    proto_tree_add_item(ncp_tree, hf_ncp_name12, tvb, loffset+1, string_len, ENC_ASCII|ENC_NA);
    loffset += string_len+1;
    string_len = tvb_get_guint8(tvb, loffset);
    proto_tree_add_item(ncp_tree, hf_ncp_copyright, tvb, loffset+1, string_len, ENC_ASCII|ENC_NA);
}

static void
dissect_ncp_123_17_reply(tvbuff_t *tvb, packet_info* pinfo, proto_tree *volatile ncp_tree)
{
    proto_tree              *atree;
    proto_item              *aitem;
    guint32 loffset, number_of_items, addr_type;
    guint16 x;

    number_of_items = tvb_get_letohl(tvb, 36);
    proto_tree_add_item(ncp_tree, hf_ncp_items_in_packet, tvb, 36, 4, ENC_LITTLE_ENDIAN);
    loffset = 40;
    for (x = 1; x <= number_of_items; x++)
    {
        atree = proto_tree_add_subtree_format(ncp_tree, tvb, loffset, -1, ett_ncp, &aitem, "Network Address - %u", x);

        addr_type = tvb_get_guint8(tvb, loffset);
        proto_tree_add_item(atree, hf_ncp_transport_type, tvb, loffset, 1, ENC_LITTLE_ENDIAN);
        /* The address type is one byte of a 4 byte value. The next 4 bytes are
         * the length of the address. Since we already know the length based upon
         * the type of address, we can skip this value. So set the offset accourdingly */
        loffset += 8;

        switch (addr_type)
        {
        case 1:
            proto_tree_add_item(atree, hf_nds_net, tvb, loffset, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(atree, hf_nds_node, tvb, loffset+4, 6, ENC_NA);
            proto_tree_add_item(atree, hf_nds_socket, tvb, loffset+10, 2, ENC_BIG_ENDIAN);
            loffset += 12;
            break;
        case 5:
            proto_tree_add_item(atree, hf_nds_port, tvb, loffset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(atree, hf_add_ref_udp, tvb, loffset+2, 4, ENC_BIG_ENDIAN);
            loffset += 6;
            break;
        case 6:
            proto_tree_add_item(atree, hf_nds_port, tvb, loffset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(atree, hf_add_ref_tcp, tvb, loffset+2, 4, ENC_BIG_ENDIAN);
            loffset += 6;
            break;
        default:
            expert_add_info(pinfo, aitem, &ei_ncp_address_type);
            /* unknown type so read the length field and then
             * just skip the record and move on to the next */
            loffset += tvb_get_letohl(tvb, loffset - 4);
            break;
        }
        proto_item_set_end(aitem, tvb, loffset);
        if(tvb_captured_length_remaining(tvb, loffset) < 4 )
        {
            break;
        }
    }
}

static void
dissect_ncp_87_72_reply(tvbuff_t *tvb, proto_tree *volatile ncp_tree)
{
    proto_tree_add_item(ncp_tree, hf_ncp_bytes_actually_trans_64, tvb, tvb_captured_length_remaining(tvb, 0)-4, 4, ENC_BIG_ENDIAN);
}

static void
dissect_ncp_23_26_reply(tvbuff_t *tvb, proto_tree *volatile ncp_tree)
{
    /* For an IP-only server, the 4-byte IP address is placed into the 4-byte NetworkAddress
     * field of the NetworkAddressStruct, while the NetworkNodeAddress and NetworkSocket
     * fields are left blank. */
    if (tvb_get_letohl(tvb, 12)==0) {
        /* IP Address */
        proto_tree_add_item(ncp_tree, hf_ncp_ip_address, tvb, 8, 4, ENC_BIG_ENDIAN);
    }
    else
    {
        /* IPX Address */
        proto_tree_add_item(ncp_tree, hf_nds_net, tvb, 8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ncp_tree, hf_nds_node, tvb, 12, 6, ENC_NA);
        proto_tree_add_item(ncp_tree, hf_nds_socket, tvb, 18, 2, ENC_BIG_ENDIAN);
    }
    proto_tree_add_item(ncp_tree, hf_ncp_connection_type, tvb, 20, 1, ENC_NA);
}

/*
 * XXX - this actually handles both 89 3 and 89 20.
 * It should also probably handle 87 3 and 87 20.
 */
static void
dissect_ncp_8x20req(tvbuff_t *tvb, proto_tree *volatile ncp_tree, guint32 offset, guint func)
{
    guint32 string_len, str_length, buffer_offset;
    gint i;
    guint8 c_char;
    wmem_strbuf_t *string_buf;
    gint length_remaining = 0;

    length_remaining = tvb_captured_length_remaining(tvb, offset);
    /*
     * XXX - the Novell documentation for function code 89 (0x59) says
     * that the length is 1 byte if the data format byte is 0 for ASCII
     * and 2 bytes if the data format byte is 1 for UTF-8.
     *
     * The documentation for function code 87 (0x57) says it's always
     * 1 byte - and that there's no data format byte.
     */
    if (func == 0x57)
    {
        string_len = tvb_get_guint8(tvb, offset);
        str_length = tvb_get_guint8(tvb, offset);
    }
    else
    {
        string_len = tvb_get_letohs(tvb, offset);
        str_length = tvb_get_letohs(tvb, offset);
    }

    if((gint)str_length > length_remaining)
    {
        THROW(ReportedBoundsError);
    }

    string_buf = wmem_strbuf_new(wmem_packet_scope(), NULL);
    offset++;
    buffer_offset = offset;

    /*
     * XXX - should this treat ASCII and UTF-8 differently?
     */
    for ( i = 0; i <= (gint)str_length; i++ )
    {
        c_char = tvb_get_guint8(tvb, buffer_offset );
        if (c_char<0x20 || c_char>0x7e)
        {
            /* Not printable ASCII */
            if (c_char == 0xff)
            {
                /*
                 * 0xff is not a valid ASCII character and is not
                 * part of a valid UTF-8 octet sequence.
                 *
                 * What is the significance of 0xbf, 0xaa, and 0xae
                 * here?
                 *
                 * Will these show up in UTF-8 strings?
                 */
                buffer_offset++;
                length_remaining--;
                c_char = tvb_get_guint8(tvb, buffer_offset);
                if (c_char == '?')
                {
                    wmem_strbuf_append_c(string_buf, '?');
                    proto_tree_add_uint_format_value(ncp_tree, hf_search_modifier, tvb, buffer_offset-1, 2, c_char, "Wildcard Question");
                }
                else if (c_char == '*')
                {
                    wmem_strbuf_append_c(string_buf, '*');
                    proto_tree_add_uint_format_value(ncp_tree, hf_search_modifier, tvb, buffer_offset-1, 2, c_char, "Wildcard Asterisk");
                }
                else if (c_char == 0xbf)
                {
                    /*
                     * For what it's worth, in ISO 8859-1, 0xbf is a
                     * Spanish-style upside-down question mark.
                     */
                    wmem_strbuf_append_c(string_buf, '?');
                    proto_tree_add_uint_format_value(ncp_tree, hf_search_modifier, tvb, buffer_offset-1, 2, c_char, "DOS Wildcard Question");
                }
                else if (c_char == 0xaa)
                {
                    /*
                     * But, in 8859-1, this is a feminine ordinal indicator
                     * (underlined subscripted "a").
                     */
                    c_char = '*';
                    wmem_strbuf_append_c(string_buf, c_char);
                    proto_tree_add_uint_format_value(ncp_tree, hf_search_modifier, tvb, buffer_offset-1, 2, c_char, "DOS Wildcard Asterisk");
                }
                else if (c_char == 0xae)
                {
                    /*
                     * And this is a registered trademark symbol.
                     */
                    wmem_strbuf_append_c(string_buf, '.');
                    proto_tree_add_uint_format_value(ncp_tree, hf_search_modifier, tvb, buffer_offset-1, 2, c_char, "DOS Wildcard Period");
                }
                else
                {
                    wmem_strbuf_append_c(string_buf, '.');
                }
            }
            else if (c_char == 0xef)
            {
                /*
                 * XXX - if these 3-character sequences are considered
                 * as UTF-8 sequences, they map to characters in the
                 * private use range from f87b to f87f.
                 *
                 * Is that what's happening here?
                 *
                 * If so, will these show up in ASCII strings?
                 */
                buffer_offset++;
                length_remaining--;
                c_char = tvb_get_guint8(tvb, buffer_offset);
                if (c_char == 0xa3)
                {
                    buffer_offset++;
                    length_remaining--;
                    c_char = tvb_get_guint8(tvb, buffer_offset);
                    if (c_char == 0xbb)
                    {
                        wmem_strbuf_append_c(string_buf, '?');
                        proto_tree_add_uint_format_value(ncp_tree, hf_search_modifier, tvb, buffer_offset-1, 2, c_char, "Wildcard Question");
                    }
                    else if (c_char == 0xbc)
                    {
                        wmem_strbuf_append_c(string_buf, '*');
                        proto_tree_add_uint_format_value(ncp_tree, hf_search_modifier, tvb, buffer_offset-1, 2, c_char, "Wildcard Asterisk");
                    }
                    else if (c_char == 0xbd)
                    {
                        c_char = '?';
                        wmem_strbuf_append_c(string_buf, c_char);
                        proto_tree_add_uint_format_value(ncp_tree, hf_search_modifier, tvb, buffer_offset-1, 2, c_char, "DOS Wildcard Question");
                    }
                    else if (c_char == 0xbe)
                    {
                        wmem_strbuf_append_c(string_buf, '*');
                        proto_tree_add_uint_format_value(ncp_tree, hf_search_modifier, tvb, buffer_offset-1, 2, c_char, "DOS Wildcard Asterisk");
                    }
                    else if (c_char == 0xbf)
                    {
                        wmem_strbuf_append_c(string_buf, '.');
                        proto_tree_add_uint_format_value(ncp_tree, hf_search_modifier, tvb, buffer_offset-1, 2, c_char, "DOS Wildcard Period");
                    }
                }
            }
            else
            {
                if (c_char != 0x00)
                {
                    wmem_strbuf_append_c(string_buf, '.');
                }
                else
                {
                    i--;
                    str_length--;
                    offset++;
                }
            }
        }
        else
        {
            /* printable ASCII */
            wmem_strbuf_append_c(string_buf, c_char);
        }
        buffer_offset++;
        length_remaining--;

        if(length_remaining==1)
        {
            break;
        }
        if (i >= 1023) { /* Don't process beyond the size of our variable */
            break;       /* If string is too long just return the first 1K. */
        }
    }

    proto_tree_add_string(ncp_tree, hf_search_pattern, tvb, offset, string_len, wmem_strbuf_get_str(string_buf));
}

static void
dissect_ncp_8x20reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *volatile ncp_tree,
                      const ncp_record *ncp_rec, ncp_req_hash_value *request_value)
{
    guint16             x;
    guint32             loffset, number_of_items, str_length;
    ptvcursor_t         *ptvc = NULL;
    proto_tree          *atree, *btree;
    proto_item          *aitem, *bitem;

    if ((request_value->req_mask ==0) & (request_value->req_mask_ext == 0))
    {
        return;
    }
    atree = proto_tree_add_subtree(ncp_tree, tvb, 8, 9, ett_ncp, &aitem, "Search Sequence");

    proto_tree_add_item(atree, hf_ncp_volume_number, tvb, 8, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(atree, hf_ncp_directory_entry_number, tvb, 9, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(atree, hf_ncp_sequence_number, tvb, 13, 4, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(ncp_tree, hf_ncp_more_flag, tvb, 17, 1, ENC_LITTLE_ENDIAN);
    number_of_items = tvb_get_letohs(tvb, 18);
    proto_tree_add_item(ncp_tree, hf_ncp_info_count, tvb, 18, 2, ENC_LITTLE_ENDIAN);
    loffset = 20;
    for (x = 1; x <= number_of_items; x++ )
    {
        atree = proto_tree_add_subtree_format(ncp_tree, tvb, loffset, -1, ett_ncp, &aitem, "Information Item %u", x);

        /* Data Stream Space Allocated */
        if (request_value->req_mask & 0x0002) {
            proto_tree_add_item(atree, hf_ncp_data_stream_space_alloc, tvb, loffset, 4, ENC_LITTLE_ENDIAN);
            loffset += 4;
        }
        else
        {
            if ((request_value->req_mask_ext & 0x8000)==FALSE) {
                loffset += 4;
            }
        }
        /* Attributes */
        if (request_value->req_mask & 0x0004) {
            btree = proto_tree_add_subtree(atree, tvb, loffset, -1, ett_ncp, &bitem, "Attributes");

            ptvc = ptvcursor_new(btree, tvb, loffset);
            process_ptvc_record(ptvc, pinfo, ptvc_struct_attributes_struct,
                    NULL, TRUE, ncp_rec, FALSE);
            ptvcursor_free(ptvc);
            loffset += 6;
            proto_item_set_end(bitem, tvb, loffset);
        }
        else
        {
            if ((request_value->req_mask_ext & 0x8000)==FALSE) {
                loffset += 6;
            }
        }
        /* Data Stream Size */
        if (request_value->req_mask & 0x0008) {
            btree = proto_tree_add_subtree(atree, tvb, loffset, -1, ett_ncp, &bitem, "Data Stream Size");

            proto_tree_add_item(btree, hf_ncp_data_stream_size, tvb, loffset, 4, ENC_LITTLE_ENDIAN);
            loffset += 4;
            proto_item_set_end(bitem, tvb, loffset);
        }
        else
        {
            if ((request_value->req_mask_ext & 0x8000)==FALSE) {
                loffset += 4;
            }
        }
        /* Total Stream Size */
        if (request_value->req_mask & 0x0010) {
            btree = proto_tree_add_subtree(atree, tvb, loffset, -1, ett_ncp, &bitem, "Total Stream Size");

            proto_tree_add_item(btree, hf_ncp_ttl_ds_disk_space_alloc, tvb, loffset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(btree, hf_ncp_number_of_data_streams, tvb, loffset+4, 2, ENC_LITTLE_ENDIAN);
            loffset += 6;
            proto_item_set_end(bitem, tvb, loffset);
        }
        else
        {
            if ((request_value->req_mask_ext & 0x8000)==FALSE) {
                loffset += 6;
            }
        }
        /* Extended Attributes oldstyle location*/
        if (request_value->req_mask & 0x0020 && !ncp_newstyle) {
            btree = proto_tree_add_subtree(atree, tvb, loffset, -1, ett_ncp, &bitem, "Extended Attributes");
            ptvc = ptvcursor_new(btree, tvb, loffset);
            process_ptvc_record(ptvc, pinfo, ptvc_struct_ea_info_struct,
                    NULL, TRUE, ncp_rec, FALSE);
            ptvcursor_free(ptvc);
            loffset += 12;
            proto_item_set_end(bitem, tvb, loffset);
        }
        else
        {
            if ((request_value->req_mask_ext & 0x8000)==FALSE && !ncp_newstyle) {
                loffset += 12;
            }
        }
        /* Extended Attributes new style location*/
        if (request_value->req_mask & 0x0020 && ncp_newstyle) {
            btree = proto_tree_add_subtree(atree, tvb, loffset, -1, ett_ncp, &bitem, "Extended Attributes");

            ptvc = ptvcursor_new(btree, tvb, loffset);
            process_ptvc_record(ptvc, pinfo, ptvc_struct_ea_info_struct,
                    NULL, TRUE, ncp_rec, FALSE);
            ptvcursor_free(ptvc);
            loffset += 12;
            proto_item_set_end(bitem, tvb, loffset);
        }
        else
        {
            if ((request_value->req_mask_ext & 0x8000)==FALSE && ncp_newstyle) {
                loffset += 12;
            }
        }
        /* Archive Information */
        if (request_value->req_mask & 0x0040) {
            btree = proto_tree_add_subtree(atree, tvb, loffset, -1, ett_ncp, &bitem, "Archive");
            ptvc = ptvcursor_new(btree, tvb, loffset);
            process_ptvc_record(ptvc, pinfo, ptvc_struct_archive_info_struct,
                    NULL, TRUE, ncp_rec, FALSE);
            ptvcursor_free(ptvc);
            loffset += 8;
            proto_item_set_end(bitem, tvb, loffset);
        }
        else
        {
            if ((request_value->req_mask_ext & 0x8000)==FALSE) {
                loffset += 8;
            }
        }
        /* Modification Information */
        if (request_value->req_mask & 0x0080) {
            btree = proto_tree_add_subtree(atree, tvb, loffset, -1, ett_ncp, &bitem, "Modification");

            ptvc = ptvcursor_new(btree, tvb, loffset);
            process_ptvc_record(ptvc, pinfo, ptvc_struct_modify_info_struct,
                    NULL, TRUE, ncp_rec, FALSE);
            ptvcursor_free(ptvc);
            loffset += 10;
            proto_item_set_end(bitem, tvb, loffset);
        }
        else
        {
            if ((request_value->req_mask_ext & 0x8000)==FALSE) {
                loffset += 10;
            }
        }
        /* Creation Information old style location */
        if (request_value->req_mask & 0x0100 && !ncp_newstyle) {
            btree = proto_tree_add_subtree(atree, tvb, loffset, -1, ett_ncp, &bitem, "Creation");
            ptvc = ptvcursor_new(btree, tvb, loffset);
            process_ptvc_record(ptvc, pinfo, ptvc_struct_creation_info_struct,
                    NULL, TRUE, ncp_rec, FALSE);
            ptvcursor_free(ptvc);
            loffset += 8;
            proto_item_set_end(bitem, tvb, loffset);
        }
        else
        {
            if ((request_value->req_mask_ext & 0x8000)==FALSE && !ncp_newstyle) {
                loffset += 8;
            }
        }
        /* Creation Information new style location */
        if (request_value->req_mask & 0x0100 && ncp_newstyle) {
            btree = proto_tree_add_subtree(atree, tvb, loffset, -1, ett_ncp, &bitem, "Creation");
            ptvc = ptvcursor_new(btree, tvb, loffset);
            process_ptvc_record(ptvc, pinfo, ptvc_struct_creation_info_struct,
                    NULL, TRUE, ncp_rec, FALSE);
            ptvcursor_free(ptvc);
            loffset += 8;
            proto_item_set_end(bitem, tvb, loffset);
        }
        else
        {
            if ((request_value->req_mask_ext & 0x8000)==FALSE && ncp_newstyle) {
                loffset += 8;
            }
        }
        /* Name Space Information */
        if (request_value->req_mask & 0x0200) {
            proto_tree_add_item(atree, hf_ncp_creator_name_space_number, tvb, loffset, 1, ENC_LITTLE_ENDIAN);
            loffset += 4;
        }
        else
        {
            if ((request_value->req_mask_ext & 0x8000)==FALSE) {
                loffset += 4;
            }
        }
        /* Directory Entry */
        if (request_value->req_mask & 0x0400) {
            btree = proto_tree_add_subtree(atree, tvb, loffset, -1, ett_ncp, &bitem, "Directory Entry");
            ptvc = ptvcursor_new(btree, tvb, loffset);
            process_ptvc_record(ptvc, pinfo, ptvc_struct_dir_entry_struct,
                    NULL, TRUE, ncp_rec, FALSE);
            ptvcursor_free(ptvc);
            loffset += 12;
            proto_item_set_end(bitem, tvb, loffset);
        }
        else
        {
            if ((request_value->req_mask_ext & 0x8000)==FALSE) {
                loffset += 12;
            }
        }
        /* Rights Information */
        if (request_value->req_mask & 0x0800) {
            ptvc = ptvcursor_new(atree, tvb, loffset);
            process_ptvc_record(ptvc, pinfo, ptvc_struct_rights_info_struct,
                    NULL, TRUE, ncp_rec, FALSE);
            ptvcursor_free(ptvc);
            loffset += 2;
        }
        else
        {
            if ((request_value->req_mask_ext & 0x8000)==FALSE) {
                loffset += 2;
            }
        }
        /* Return ID Information */
        if (request_value->req_mask & 0x1000) {
            proto_tree_add_item(atree, hf_ncp_curr_ref_id, tvb, loffset, 2, ENC_LITTLE_ENDIAN);
            loffset += 2;
        }
        /* Return Name Space Attributes Information */
        if (request_value->req_mask & 0x2000) {
            proto_tree_add_item(atree, hf_ncp_attr_def_32, tvb, loffset, 1, ENC_LITTLE_ENDIAN);
            loffset += 4;
        }
        /* Return Actual Information */
        if (request_value->req_mask & 0x4000) {
            btree = proto_tree_add_subtree(atree, tvb, loffset, -1, ett_ncp, &bitem, "Actual");

            proto_tree_add_item(btree, hf_ncp_data_stream_num_long, tvb, loffset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(btree, hf_ncp_data_stream_fat_blks, tvb, loffset+4, 4, ENC_LITTLE_ENDIAN);
            loffset += 8;
            proto_item_set_end(bitem, tvb, loffset);
        }
        /* Return Logical Information */
        if (request_value->req_mask & 0x8000) {
            btree = proto_tree_add_subtree(atree, tvb, loffset, -1, ett_ncp, &bitem, "Logical");
            proto_tree_add_item(btree, hf_ncp_number_of_data_streams_long, tvb, loffset, 4, ENC_LITTLE_ENDIAN);
            number_of_items = tvb_get_letohs(tvb, loffset);
            loffset += 4;
            for (x = 1; x <= number_of_items; x++ )
            {
                proto_tree_add_item(btree, hf_ncp_data_stream_num_long, tvb, loffset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(btree, hf_ncp_data_stream_size, tvb, loffset+4, 4, ENC_LITTLE_ENDIAN);
                loffset += 8;
            }
            proto_item_set_end(bitem, tvb, loffset);
        }
        /* Last Update */
        if (request_value->req_mask_ext & 0x0001 && ncp_newstyle) {
            proto_tree_add_item(atree, hf_ncp_sec_rel_to_y2k, tvb, loffset, 4, ENC_LITTLE_ENDIAN);
            loffset += 4;
        }
        /* Dos Name */
        if (request_value->req_mask_ext & 0x0002 && ncp_newstyle) {
            btree = proto_tree_add_subtree(atree, tvb, loffset, -1, ett_ncp, &bitem, "DOS Name");

            if (ncp_rec->func == 0x57) {
                str_length = tvb_get_guint8(tvb, loffset);
                loffset += 1;
            }
            else
            {
                str_length = tvb_get_letohs(tvb, loffset);
                loffset += 2;
            }
            proto_tree_add_item(btree, hf_ncp_file_name_12, tvb, loffset, str_length, ENC_ASCII|ENC_NA);
            loffset += str_length;
            proto_item_set_end(bitem, tvb, loffset);
        }
        /* Flush Time */
        if (request_value->req_mask_ext & 0x0004 && ncp_newstyle) {
            ptvc = ptvcursor_new(atree, tvb, loffset);
            process_ptvc_record(ptvc, pinfo, ptvc_struct_flush_time_struct,
                    NULL, TRUE, ncp_rec, FALSE);
            ptvcursor_free(ptvc);
            loffset += 4;
        }
        /* Parental */
        if (request_value->req_mask_ext & 0x0008 && ncp_newstyle) {
            proto_tree_add_item(atree, hf_ncp_parent_base_id, tvb, loffset, 4, ENC_LITTLE_ENDIAN);
            loffset += 4;
        }
        /* MAC finder */
        if (request_value->req_mask_ext & 0x0010 && ncp_newstyle) {
            proto_tree_add_item(atree, hf_ncp_mac_finder_info, tvb, loffset, 32, ENC_NA);
            loffset += 32;
        }
        /* Sibling */
        if (request_value->req_mask_ext & 0x0020 && ncp_newstyle) {
            proto_tree_add_item(atree, hf_ncp_sibling_count, tvb, loffset, 4, ENC_LITTLE_ENDIAN);
            loffset += 4;
        }
        /* Effective */
        if (request_value->req_mask_ext & 0x0040 && ncp_newstyle) {
            proto_tree_add_item(atree, hf_ncp_effective_rights, tvb, loffset, 1, ENC_LITTLE_ENDIAN);
            loffset += 4;
        }
        /* MAC Date */
        if (request_value->req_mask_ext & 0x0080 && ncp_newstyle) {
            btree = proto_tree_add_subtree(atree, tvb, loffset, -1, ett_ncp, &bitem, "Mac Date");

            ptvc = ptvcursor_new(btree, tvb, loffset);
            process_ptvc_record(ptvc, pinfo, ptvc_struct_mac_time_struct,
                    NULL, TRUE, ncp_rec, FALSE);
            ptvcursor_free(ptvc);
            loffset += 8;
            proto_item_set_end(bitem, tvb, loffset);
        }
        /* Last Access */
        if (request_value->req_mask_ext & 0x0100 && ncp_newstyle) {
            ptvc = ptvcursor_new(atree, tvb, loffset);
            process_ptvc_record(ptvc, pinfo, ptvc_struct_last_access_time_struct,
                    NULL, TRUE, ncp_rec, FALSE);
            ptvcursor_free(ptvc);
            loffset += 2;
        }
        /* 64 bit file sizes */
        if (request_value->req_mask_ext & 0x0400 && ncp_newstyle) {
            proto_tree_add_item(atree, hf_ncp_f_size_64bit, tvb, loffset, 8, ENC_LITTLE_ENDIAN);
            loffset += 8;
        }
        /* We always return the file name */
        if (ncp_rec->func == 0x57) {
            str_length = tvb_get_guint8(tvb, loffset);
            loffset += 1;
        }
        else
        {
            str_length = tvb_get_letohs(tvb, loffset);
            loffset += 2;
        }
        proto_tree_add_item(atree, hf_ncp_file_name_12, tvb, loffset, str_length, ENC_UTF_8);
        loffset += str_length;

        proto_item_set_end(aitem, tvb, loffset);

        if(tvb_captured_length_remaining(tvb, loffset) < 4 )
        {
                break;
        }
    }
}

static void
dissect_ncp_123_62_reply(tvbuff_t *tvb, proto_tree *volatile ncp_tree)
{
    guint8 cmd_type;
    guint8* param_string;
    gint ret_len;

    cmd_type = tvb_get_guint8(tvb, 8+16);
    param_string = tvb_get_stringz_enc(wmem_packet_scope(), tvb, 8+24, &ret_len, ENC_ASCII);

    switch (cmd_type) {
    case 0:   /* { 0x00, "Numeric Value" }, */
    case 2:   /* { 0x02, "Ticks Value" },   */
    case 4:   /* { 0x04, "Time Value" },    */
    case 6:   /* { 0x06, "Trigger Value" }, */
    case 7:   /* { 0x07, "Numeric Value" }, */
        proto_tree_add_item(ncp_tree, hf_srvr_param_number, tvb, 37+(gint)strlen(param_string), 4, ENC_LITTLE_ENDIAN);
        break;
    case 1:   /* { 0x01, "Boolean Value" }, */
        proto_tree_add_item(ncp_tree, hf_srvr_param_boolean, tvb, 37+(gint)strlen(param_string), 1, ENC_LITTLE_ENDIAN);
        break;
    case 5:   /* { 0x05, "String Value" },  */
        proto_tree_add_item(ncp_tree, hf_srvr_param_string, tvb, 37+(gint)strlen(param_string), -1, ENC_ASCII|ENC_NA);
        break;
    default:
        break;
    }
}

/*
 * Defrag logic
 *
 * NDS fragment not being set to 0xffffffff indicates we are inside or at the
 * beginning of a fragment. But when the end of the fragment
 * is encounterd the flag is set to 0xffffffff. So we must mark what the
 * frame number is of the end fragment so that we will be
 * able to redissect if the user clicks on the packet
 * or resorts/filters the trace.
 *
 * Once we are certain that we are in a fragment sequence
 * then we can just process each fragment in this conversation
 * until we reach the fragment == 0xffffffff packet.
 *
 * We will be able to easily determine if a conversation is a fragment
 * with the exception of the last packet in the fragment. So remember
 * the last fragment packet number.
 *
 * Also the NDS dissection requires the values of NDS Verb, Version, and Flags.
 * Without these values being remembered from the first request packet then
 * we will be unable to dissect the reply packet. For this reason we remember
 * these values on the first fragment and then populate the values in the final
 * fragment. We only do this on the first dissection.
 */
void
nds_defrag(tvbuff_t *tvb, packet_info *pinfo, guint32 nw_connection, guint8 sequence, guint16 type, proto_tree *tree, struct novell_tap *ncp_tap)
{
    int                 i, frag_count=0;
    guint               len=0;
    guint32             tid = 1;
    tvbuff_t            *frag_tvb = NULL;
    fragment_head       *fd_head;
    ncp_req_hash_value  *request_value = NULL;
    conversation_t      *conversation;
    guint32             nds_frag;

    for (i = 0; i < 99; i++) {
        if (!frags[i].nds_fragmented)
        {
            frags[i].nds_frag = 0xfffffff0;
        }
    }
    /* Check to see if defragmentation is enabeled in the dissector */
    if (!nds_defragment) {
        dissect_ncp_reply(tvb, pinfo, nw_connection, sequence, type, tree, ncp_tap);
        return;
    }
    /* Has this already been dissected? */
    if (!pinfo->fd->flags.visited) {
        /* Find the conversation whence the request would have come. */
        conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
                                         PT_NCP, nw_connection, nw_connection, 0);
        if (conversation != NULL) {
            /* find the record telling us the request made that caused
               this reply */
            request_value = ncp_hash_lookup(conversation, sequence, pinfo->num);
            if (!request_value) {
                dissect_ncp_reply(tvb, pinfo, nw_connection, sequence, type, tree, ncp_tap);
                return;
            }
            p_add_proto_data(wmem_file_scope(), pinfo, proto_ncp, 0, (void*) request_value);
        }
        /* else... we haven't seen an NCP Request for that conversation and sequence. */
        else
            {
                dissect_ncp_reply(tvb, pinfo, nw_connection, sequence, type, tree, ncp_tap);
                return;
            }
    }
    else {
        request_value = (ncp_req_hash_value *)p_get_proto_data(wmem_file_scope(), pinfo, proto_ncp, 0);
        if (!request_value) {
                dissect_ncp_reply(tvb, pinfo, nw_connection, sequence, type, tree, ncp_tap);
                return;
        }
    }
    /* Validate that this is an NDS packet */
    /* If this isn't an NDS packet then just return */
    if (!request_value->ncp_rec ||
        request_value->ncp_rec->func!=104 || request_value->ncp_rec->subfunc!=2) {
        dissect_ncp_reply(tvb, pinfo, nw_connection, sequence, type, tree, ncp_tap);
        return;
    }
    /* Check to see if there is at least enough packet info to get the fragment flag */
    if (tvb_reported_length_remaining(tvb, 12) < 4) {
        dissect_ncp_reply(tvb, pinfo, nw_connection, sequence, type, tree, ncp_tap);
        return;
    }
    /* Get the fragment flag */
    nds_frag = tvb_get_letohl(tvb, 12);

    /* Now we need to find if this is a new fragment or already one defined. */
    /* We currently limit the maximum number of simultaneous fragments to 100. */
    for (i=0; i<100; i++)
    {
        if (frags[i].nds_frag == nds_frag || frags[i].nds_frag == 0xfffffff0)
        {
            if (frags[i].nds_frag == 0xfffffff0)
                {
                    frags[i].nds_length = 0;
                    frags[i].nds_frag = nds_frag;
                    frags[i].nds_fragmented = TRUE;
                    frags[i].sequence = 0;
                }
            break;
        }
    }
    if (i > 99)
        return;

    frag_count = i;

    /* is this the end of an existing fragment or just another reply */
    if (nds_frag == 0xffffffff && request_value->nds_frag_num == 0xffffffff)
    {
        dissect_ncp_reply(tvb, pinfo, nw_connection, sequence, type, tree, ncp_tap);
        return;
    }

    /* Now we process the fragments */
    if (request_value->nds_frag || (request_value->nds_end_frag == pinfo->num))
    {
        /* Check to see of this is a fragment. If so then mark as a fragment. */
        if (frags[frag_count].nds_frag==0xffffffff) {
            request_value->nds_frag = FALSE;
            /* nds_length of 0 means start of fragment */
            frags[frag_count].nds_length = 0;
        }
        else
        {
            if (frags[frag_count].nds_length == 0)
            {
                frags[frag_count].nds_length = tvb_get_letohl(tvb, 0);
            }
        }
        /*
         * Fragment
         *
         */
        tid = (pinfo->srcport+pinfo->destport);
        len = tvb_reported_length(tvb);
        if (len > 0 && tvb_bytes_exist(tvb, 0, len))
        {
            if (frags[frag_count].nds_length > len)
            {
                /* This is the first fragment so remember the verb, version, and flags. */
                frags[frag_count].nds_frag_verb = request_value->nds_request_verb;
                frags[frag_count].nds_frag_version = request_value->nds_version;
                frags[frag_count].nds_frag_flags = request_value->req_nds_flags;
                frags[frag_count].nds_frag_prot_flags = request_value->req_nds_prot_flags;
                fd_head = fragment_add_seq_next(&nds_reassembly_table, tvb, 0, pinfo, tid, NULL, len, request_value->nds_frag);
                frags[frag_count].sequence = sequence;
                frags[frag_count].nds_length = 1;
            }
            else
            {
                /* Subsequent fragments should be offset by 16 since we do not need */
                /* the additional fragment handle and size fields in our composite data */
                /* Also do not add retransmitted packets, just mark and return */
                if (!pinfo->fd->flags.visited)
                {
                    if (sequence != frags[frag_count].sequence) {
                        fd_head = fragment_add_seq_next(&nds_reassembly_table, tvb, 16, pinfo, tid, NULL, len-16, request_value->nds_frag);
                        frags[frag_count].sequence = sequence;
                    }
                    else
                    {
                        col_add_fstr(pinfo->cinfo, COL_INFO, "[Retransmitted NDS Fragment 0x%08x]", frags[frag_count].nds_frag);
                        return;
                    }
                }
                else
                {
                    fd_head = fragment_add_seq_next(&nds_reassembly_table, tvb, 16, pinfo, tid, NULL, len-16, request_value->nds_frag);
                    frags[frag_count].sequence = sequence;
                }
            }
            if (fd_head != NULL)
            {
                /* Is this the last fragment? nds_frag will indicate */
                if (fd_head->next != NULL && !request_value->nds_frag)
                {
                    frag_tvb = tvb_new_chain(tvb, fd_head->tvb_data);
                    add_new_data_source(pinfo,
                                        frag_tvb,
                                        "Reassembled NDS");
                    /* Show all fragments. */
                    if (tree)
                    {
                        proto_item *frag_tree_item;
                        show_fragment_seq_tree(fd_head,
                                               &nds_frag_items,
                                               tree, pinfo,
                                               frag_tvb, &frag_tree_item);
                        tid++;
                    }

                    if (!pinfo->fd->flags.visited)
                    {
                        /* Now we need to find the original fragment number. */
                        /* Get the fragment flag */
                        nds_frag = tvb_get_letohl(frag_tvb, 12);
                        for (i=0; i<100; i++)
                        {
                            if (frags[i].nds_frag == nds_frag)
                            {
                                break;
                            }
                        }
                        if (i > 99)
                            return;
                        if (frags[i].nds_frag == 0xffffffff)
                        {
                            /* Error can't find fragment */
                            /*DISSECTOR_ASSERT(0);*/
                        }
                        frag_count = i;
                        /* Remember this fragment information so we can dissect.
                         * Only do this on the first dissection. After the first
                         * dissection we will just read the memory values.
                         */
                        request_value->nds_end_frag = pinfo->num;
                        request_value->nds_request_verb = frags[frag_count].nds_frag_verb;
                        request_value->nds_version = frags[frag_count].nds_frag_version;
                        request_value->req_nds_flags = frags[frag_count].nds_frag_flags;
                        request_value->req_nds_prot_flags = frags[frag_count].nds_frag_prot_flags;
                    }

                }
                else
                {
                    /* This is either a beggining or middle fragment on second dissection */
                    frag_tvb = tvb_new_subset(tvb, 0, -1, -1);
                    if (request_value->nds_frag)
                    {
                      col_add_fstr(pinfo->cinfo, COL_INFO, "[NDS Fragment 0x%08x]", frags[frag_count].nds_frag);
                    }
                }
            }
            else
            {
                /* Fragment from first pass of dissection */
                if (request_value->nds_frag)
                {
                   col_add_fstr(pinfo->cinfo, COL_INFO, "[NDS Fragment 0x%08x]", frags[frag_count].nds_frag);
                }

                frag_tvb = NULL;
            }
        }
        else
        {
            /*
             * There are no bytes so Dissect this
             */
            frag_tvb = tvb_new_subset(tvb, 0, -1, -1);
        }
        if (frag_tvb == NULL)
        {
            /* This is a fragment packet */
            frag_tvb = tvb_new_subset (tvb, 0, -1, -1);
            nds_data_handle = find_dissector("data");
            call_dissector(nds_data_handle, frag_tvb, pinfo, tree);
        }
        else
        {
            /* This is the end fragment so dissect */
            if (!request_value->nds_frag) {
                frags[frag_count].nds_length = 0;
                dissect_ncp_reply(frag_tvb, pinfo, nw_connection, sequence, type, tree, ncp_tap);
            }
        }
    }
    else
    {
        /* This is not any fragment packet */
        request_value->nds_frag = FALSE;
        /* Trap for retransmitted end fragment */
        if (request_value->nds_end_frag < pinfo->num) {
            col_add_fstr(pinfo->cinfo, COL_INFO, "[Retransmitted end of NDS Fragment 0x%08x, see packet #%d for details.]", request_value->nds_frag_num, request_value->nds_end_frag);
        }
        else
        {
            dissect_ncp_reply(tvb, pinfo, nw_connection, sequence, type, tree, ncp_tap);
        }
    }
}

static gboolean ncp2222_dfilters_compiled = FALSE;

static void
ncp2222_compile_dfilters(void)
{
    int i;
    gchar *err_msg;

    for (i = 0; i < NUM_REQ_CONDS; i++) {
        if (!dfilter_compile((const gchar*)req_conds[i].dfilter_text,
                             &req_conds[i].dfilter, &err_msg)) {
            g_error("NCP dissector failed to compile dfilter \"%s\": %s\n",
                      req_conds[i].dfilter_text, err_msg);
            g_free(err_msg);
            g_assert_not_reached();
        }
    }
}

void
dissect_ncp_request(tvbuff_t *tvb, packet_info *pinfo,
                guint32 nw_connection, guint8 sequence,
                guint16 type, proto_tree *volatile ncp_tree)
{
    volatile guint8         func=0;
    volatile guint8         subfunc = 0;
    gboolean                requires_subfunc = FALSE;
    gboolean                has_length = FALSE;
    ncp_req_hash_value      *volatile request_value = NULL;
    const ncp_record        *volatile ncp_rec = NULL;
    conversation_t          *conversation;
    ptvcursor_t             *volatile ptvc = NULL;
    proto_tree              *temp_tree = NULL;
    volatile gboolean       run_req_cond = FALSE;
    guint32                 length_remaining;
    guint32                 testvar;
    volatile unsigned long  exception_code;
    const char              *volatile message;
    proto_item              *ti;


    /* We're dissecting an ncp2222 request; Compile the dfilters (if not yet done). */
    /* XXX: We do this here rather than at "post-registration" (as previouly done)  */
    /*      so compiling over 100 dfilters is done only if needed (thus avoiding    */
    /*      compiling the dfilters each time Wireshark is started.                  */
    if (! ncp2222_dfilters_compiled) {
        ncp2222_compile_dfilters();
        ncp2222_dfilters_compiled = TRUE;
    }

    /* Determine which ncp_record to use. */
    switch (type) {
    case NCP_ALLOCATE_SLOT:
        length_remaining = tvb_captured_length_remaining(tvb, 4);
        if (length_remaining > 4)
        {
            testvar = tvb_get_ntohl(tvb, 4);
            if( testvar == 0x4c495020)
            {
                ncp_rec = &ncplip_echo;
            }
            else
            {
                ncp_rec = &ncp1111_request;
                if (ncp_echo_conn) {
                    expert_add_info(pinfo, NULL, &ei_ncp_connection_request);
                }
            }
        }
        else
        {
            ncp_rec = &ncp1111_request;
            if (ncp_echo_conn) {
                expert_add_info(pinfo, NULL, &ei_ncp_connection_request);
            }
        }
        break;
    case NCP_SERVICE_REQUEST:
        func = tvb_get_guint8(tvb, 6);
        requires_subfunc = ncp_requires_subfunc(func);
        has_length = ncp_has_length_parameter(func);
        if (requires_subfunc) {
            if (has_length) {
                subfunc = tvb_get_guint8(tvb, 9);
            }
            else {
                subfunc = tvb_get_guint8(tvb, 7);
            }
        }
        ncp_rec = ncp_record_find(func, subfunc);
        break;
    case NCP_DEALLOCATE_SLOT:
        ncp_rec = &ncp5555_request;
        if (ncp_echo_conn) {
            expert_add_info_format(pinfo, NULL, &ei_ncp_destroy_connection, "Destroy Connection %u Request", nw_connection);
        }
        break;
    case NCP_BROADCAST_SLOT:
        ncp_rec = &ncpbbbb_request;
        break;
    case NCP_LIP_ECHO:
        ncp_rec = &ncplip_echo;
        break;
    default:
        ncp_rec = NULL;
        break;
    }

    /* Fill in the INFO column. */
    if (ncp_rec) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "C %s", ncp_rec->name);
    }
    else {
        if (requires_subfunc) {
            col_add_fstr(pinfo->cinfo, COL_INFO,
                            "C Unknown Function %u %u (0x%02X/0x%02x)",
                            func, subfunc, func, subfunc);
            return;
        }
        else {
            col_add_fstr(pinfo->cinfo, COL_INFO,
                            "C Unknown Function %u (0x%02x)",
                            func, func);
            return;
        }
    }

    if (!pinfo->fd->flags.visited) {
        /* This is the first time we've looked at this packet.
           Keep track of the address and connection whence the request
           came, and the address and connection to which the request
           is being sent, so that we can match up calls with replies.
           (We don't include the sequence number, as we may want
           to have all packets over the same connection treated
           as being part of a single conversation so that we can
           let the user select that conversation to be displayed.) */
        conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
                                         PT_NCP, nw_connection, nw_connection, 0);

        if (conversation == NULL) {
            /* It's not part of any conversation - create a new one. */
            conversation = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst,
                                            PT_NCP, nw_connection, nw_connection, 0);
        }
        request_value = ncp_hash_insert(conversation, sequence, ncp_rec, pinfo->num);
        request_value->req_frame_num = pinfo->num;
        request_value->req_frame_time = pinfo->abs_ts;

        /* If this is the first time we're examining the packet,
         * check to see if this NCP type uses a "request condition".
         * If so, we have to build a proto_tree because request conditions
         * use display filters to work, and without a proto_tree,
         * display filters can't possibly work. */
        if (ncp_rec) {
            if (ncp_rec->req_cond_indexes) {
                run_req_cond = TRUE;
            }
        }
    }

    /* If we have to handle a request condition, or have to
       add to the Info column, we need to construct a protocol
       tree.  If we already have a proto_tree, then wonderful.
       If we don't, we need to build one. */
    if (run_req_cond && !ncp_tree) {
        temp_tree = proto_tree_create_root(pinfo);
        proto_tree_set_visible(temp_tree, FALSE);
        ti = proto_tree_add_item(temp_tree, proto_ncp, tvb, 0, -1, ENC_NA);
        ncp_tree = proto_item_add_subtree(ti, ett_ncp);
    }

    if (ncp_tree) {
        /* If the dissection throws an exception, be sure to free
         * the temporary proto_tree that was created. Because of the
         * way the CLEANUP_PUSH macro works, we can't put it in an 'if'
         * block; it has to be in the same scope as the terminating
         * CLEANUP_POP or CLEANUP_POP_AND_ALLOC. So, we always
         * call CLEANUP_POP and friends, but the value of temp_tree is
         * NULL if no cleanup is needed, and non-null if cleanup is needed. */
        CLEANUP_PUSH_PFX(xx,free_proto_tree, temp_tree);

#ifdef FAKE_TREE_IS_VISIBLE
        PTREE_DATA(ncp_tree)->visible=1;
#endif

        /* Before the dissection, if we're saving data for a request
         * condition, we have to prime the proto tree using the
         * dfilter information */
        if (run_req_cond) {
            const int *needed;
            dfilter_t *dfilter;

            needed = ncp_rec->req_cond_indexes;

            while (*needed != -1) {
                dfilter = req_conds[*needed].dfilter;
                /* Prime the proto_tree with "interesting fields". */
                dfilter_prime_proto_tree(dfilter, ncp_tree);
                needed++;
            }
        }

        switch (type) {
        case NCP_BROADCAST_SLOT:
            ; /* nothing */
            break;

        case NCP_SERVICE_REQUEST:
            proto_tree_add_uint_format_value(ncp_tree, hf_ncp_func, tvb, 6, 1,
                                       func, "%u (0x%02X), %s",
                                       func, func, ncp_rec ? ncp_rec->name : "Unknown");
            break;

        default:
            ; /* nothing */
            break;
        }
        if (request_value) {
            request_value->length = 0;
        }
        if (requires_subfunc) {
            if (has_length) {
                if (request_value && func==123) {
                    request_value->length = tvb_get_ntohs(tvb, 7);
                }
                proto_tree_add_item(ncp_tree, hf_ncp_length, tvb, 7,
                                    2, ENC_BIG_ENDIAN);
                proto_tree_add_uint(ncp_tree, hf_ncp_subfunc, tvb, 9, 1, subfunc);
                ptvc = ptvcursor_new(ncp_tree, tvb, 10);
            }
            else {
                proto_tree_add_uint(ncp_tree, hf_ncp_subfunc, tvb, 7, 1, subfunc);
                ptvc = ptvcursor_new(ncp_tree, tvb, 8);
            }
        }
        else {
            ptvc = ptvcursor_new(ncp_tree, tvb, 7);
        }

        /* The group is not part of the packet, but it's useful
         * information to display anyway. Put it in the tree for filtering and tap use*/
        if (ncp_rec) {
            ti = proto_tree_add_uint_format_value(ncp_tree, hf_ncp_group, tvb, 0, 0, ncp_rec->group, "%s", ncp_groups[ncp_rec->group]);
            PROTO_ITEM_SET_GENERATED(ti);
        }

        exception_code = 0;
        message = NULL;
        if (ncp_rec && ncp_rec->request_ptvc) {
            clear_repeat_vars();
            /*
             * We need to remember the results even if we
             * throw an exception dissecting this request,
             * so that we can properly dissect the reply.
             * We catch any exceptions thrown when
             * dissecting the request, and re-throw them
             * after saving the results of any conditional
             * tests.
             */
            TRY {
                process_ptvc_record(ptvc, pinfo, ncp_rec->request_ptvc, NULL, TRUE, ncp_rec, TRUE);
            } CATCH_ALL {
                exception_code = EXCEPT_CODE;
                message = GET_MESSAGE;
            }
            ENDTRY;
        }
        ptvcursor_free(ptvc);

        /* Now that the dissection is done, do we need to run
         * some display filters on the resulting tree in order
         * to save results for "request conditions" ? */
        if (run_req_cond) {
            const int   *needed;
            gboolean    *results;
            dfilter_t   *dfilter;

            results = (gboolean *)wmem_alloc0(wmem_file_scope(), sizeof(gboolean)*NUM_REQ_CONDS);
            needed = ncp_rec->req_cond_indexes;

            while (*needed != -1) {
                /* ncp_tree is not a root proto_tree, but
                 * dfilters will still work on it. */
                dfilter = req_conds[*needed].dfilter;
                results[*needed] = dfilter_apply(dfilter, ncp_tree);
                needed++;
            }

            /* Save the results so the reply packet dissection
             * get to them. */
            request_value->req_cond_results = results;
        }

        if (!request_value)
        {
             conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
                                                 PT_NCP, nw_connection, nw_connection, 0);
             if (conversation != NULL) {
                 /* find the record telling us the request made that caused
                    this reply */
                 request_value = ncp_hash_lookup(conversation, sequence, pinfo->num);
              }
        }
        /* SecretStore packets are dessected in packet-ncp-sss.c */
        if (func == 0x5c && ncp_tree) {
            dissect_sss_request(tvb, pinfo, ncp_tree, request_value);
        }
        /* NMAS packets are dessected in packet-ncp-nmas.c */
        if (func == 0x5e && ncp_tree) {
            dissect_nmas_request(tvb, pinfo, ncp_tree, request_value);
        }

        /* Store NCP request specific flags for manual dissection */
        if ((func == 0x57 || func == 0x59) && subfunc == 0x14 && ncp_tree && request_value) {
            request_value->req_mask = tvb_get_letohs(tvb, 8+4);
            request_value->req_mask_ext = tvb_get_letohs(tvb, 8+6);
        }
        /* NCP function 89/6 passes either ASCII or UTF8 data */
        /* Decode manually since it is not possible to SREC the request */
        /* packets from the python code */
        if (func == 0x59 && subfunc == 0x6) {
            dissect_ncp_89_6_request(tvb, ncp_tree, 22);
        }
        /*
         * Need to parse for Novell specific wildcard values in Search
         * Pattern, decode this ncp (89)/20 and (89)/03 req manually here.
         *
         * XXX - do 0x57/87 and 0x59/89 both have this?  87 doesn't
         * appear to have the ASCII/UTF-8 data type field.
         */
        if (ncp_rec->func == 0x59 && (ncp_rec->subfunc == 0x14 || ncp_rec->subfunc == 0x03)) {
            if (ncp_rec->subfunc == 0x03)
            {
                 dissect_ncp_8x20req(tvb, ncp_tree, 26, ncp_rec->func);
            }
/*if (ncp_rec->func == 0x57)
{
            dissect_ncp_8x20req(tvb, ncp_tree, 27, ncp_rec->func);
}*/
            else
            {
                dissect_ncp_8x20req(tvb, ncp_tree, 28, ncp_rec->func);
            }
        }
        /* Free the temporary proto_tree */
        CLEANUP_CALL_AND_POP_PFX(xx);

        /* Re-throw any exception. */
        if (exception_code != 0)
            THROW_MESSAGE(exception_code, message);
    }
}

static void
dissect_nds_ping_reply(tvbuff_t *tvb, packet_info *pinfo _U_,
                       proto_tree *ncp_tree, ncp_req_hash_value *request_value)
{
    guint8     ping_version;
    guint32    nds_string_len;
    guint32    nds_offset;
    guint32    bvalue;
    guint32    nds_flags;
    int        i;
    nstime_t   ns;

    ping_version = tvb_get_guint8(tvb, 8);
    proto_tree_add_item(ncp_tree, hf_ping_version, tvb, 8, 1, ENC_NA);
    if (ping_version == 9) {
        nds_string_len = tvb_get_ntohl(tvb, 9);
        nds_offset = nds_string_len+16;
        proto_tree_add_item(ncp_tree, hf_nds_tree_name, tvb, 16, nds_string_len, ENC_ASCII|ENC_NA);
        proto_tree_add_item(ncp_tree, hf_nds_reply_depth, tvb, nds_offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ncp_tree, hf_nds_reply_rev, tvb, (nds_offset+4), 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ncp_tree, hf_nds_reply_flags, tvb, (nds_offset+8), 4, ENC_LITTLE_ENDIAN);
    }
    else {
        nds_offset = 12;
        nds_flags = request_value->req_nds_flags;
        bvalue = 0x00000001;

        for (i = 0 ; i < 32; i++ ) {
            if (nds_flags & bvalue)
            {
                switch(bvalue)
                {
                case 0x00000001:   /* Supported Fields */
                    proto_tree_add_bitmask(ncp_tree, tvb, nds_offset, hf_pingflags1, ett_ncp, ncp_pingflags1, ENC_LITTLE_ENDIAN);
                    nds_offset += 2;
                    proto_tree_add_bitmask(ncp_tree, tvb, nds_offset, hf_pingflags2, ett_ncp, ncp_pingflags2, ENC_LITTLE_ENDIAN);
                    nds_offset += 2;
                    break;
                case 0x00000002:
                    proto_tree_add_item(ncp_tree, hf_nds_reply_depth, tvb, nds_offset, 4, ENC_LITTLE_ENDIAN);
                    nds_offset += 4;
                    break;
                case 0x00000004:
                    proto_tree_add_item(ncp_tree, hf_nds_reply_rev, tvb, nds_offset, 4, ENC_LITTLE_ENDIAN);
                    nds_offset += 4;
                    break;
                case 0x00000008:
                    proto_tree_add_bitmask(ncp_tree, tvb, nds_offset, hf_pingpflags1, ett_ncp, ncp_pingpflags1, ENC_LITTLE_ENDIAN);
                    nds_offset += 4;
                    break;
                case 0x00000010:
                    proto_tree_add_bitmask(ncp_tree, tvb, nds_offset, hf_pingvflags1, ett_ncp, ncp_pingvflags1, ENC_LITTLE_ENDIAN);
                    nds_offset += 4;
                    break;
                case 0x00000020:
                    proto_tree_add_item(ncp_tree, hf_nds_letter_ver, tvb, nds_offset, 4, ENC_LITTLE_ENDIAN);
                    nds_offset += 4;
                    break;
                case 0x00000040:
                    proto_tree_add_item(ncp_tree, hf_nds_os_majver, tvb, nds_offset, 4, ENC_LITTLE_ENDIAN);
                    nds_offset += 4;
                    proto_tree_add_item(ncp_tree, hf_nds_os_minver, tvb, nds_offset, 4, ENC_LITTLE_ENDIAN);
                    nds_offset += 4;
                    proto_tree_add_item(ncp_tree, hf_ncp_os_revision, tvb, nds_offset, 4, ENC_LITTLE_ENDIAN);
                    nds_offset += 4;
                    break;
                case 0x00000100:
                    proto_tree_add_item(ncp_tree, hf_nds_lic_flags, tvb, nds_offset, 4, ENC_LITTLE_ENDIAN);
                    nds_offset += 4;
                    break;
                case 0x00000200:
                    ns.secs = tvb_get_letohl(tvb, nds_offset);
                    ns.nsecs = 0;
                    proto_tree_add_time(ncp_tree, hf_nds_ds_time, tvb, nds_offset, 4, &ns);
                    nds_offset += 4;
                    break;
                case 0x00000400:
                    ns.secs = tvb_get_letohl(tvb, nds_offset);
                    ns.nsecs = 0;
                    proto_tree_add_time(ncp_tree, hf_nds_svr_time, tvb, nds_offset, 4, &ns);
                    nds_offset += 4;
                    break;
                case 0x00000800:
                    ns.secs = tvb_get_letohl(tvb, nds_offset);
                    ns.nsecs = 0;
                    proto_tree_add_time(ncp_tree, hf_nds_crt_time, tvb, nds_offset, 4, &ns);
                    nds_offset += 4;
                    break;
                case 0x00010000:
                    if(tvb_get_guint8(tvb, nds_offset) == 0x00)
                    {
                        nds_offset += 2;
                    }
                    nds_string_len = tvb_get_letohl(tvb, nds_offset);
                    nds_offset += 4;
                    proto_tree_add_item(ncp_tree, hf_sap_name, tvb, nds_offset, nds_string_len, ENC_ASCII|ENC_NA);
                    nds_offset += nds_string_len;
                    nds_offset += align_4(tvb, nds_offset);
                    break;
                case 0x00020000:
                    if(tvb_get_guint8(tvb, nds_offset) == 0x00)
                    {
                        nds_offset += 2;
                    }
                    nds_string_len = tvb_get_letohl(tvb, nds_offset);
                    nds_offset += 4;
                    proto_tree_add_item(ncp_tree, hf_nds_tree_name, tvb, nds_offset, nds_string_len, ENC_ASCII|ENC_NA);
                    nds_offset += nds_string_len;
                    nds_offset += align_4(tvb, nds_offset);
                    break;
                case 0x00040000:
                    if(tvb_get_guint8(tvb, nds_offset) == 0x00)
                    {
                        nds_offset += 2;
                    }
                    nds_string_len = tvb_get_letohl(tvb, nds_offset);
                    nds_offset += 4;
                    proto_tree_add_item(ncp_tree, hf_os_name, tvb, nds_offset, nds_string_len, ENC_ASCII|ENC_NA);
                    nds_offset += nds_string_len;
                    nds_offset += align_4(tvb, nds_offset);
                    break;
                case 0x00080000:
                    if(tvb_get_guint8(tvb, nds_offset) == 0x00)
                    {
                        nds_offset += 2;
                    }
                    nds_string_len = tvb_get_letohl(tvb, nds_offset);
                    nds_offset += 4;
                    proto_tree_add_item(ncp_tree, hf_hardware_name, tvb, nds_offset, nds_string_len, ENC_ASCII|ENC_NA);
                    nds_offset += nds_string_len;
                    nds_offset += align_4(tvb, nds_offset);
                    break;
                case 0x00100000:
                    if(tvb_get_guint8(tvb, nds_offset) == 0x00)
                    {
                        nds_offset += 2;
                    }
                    nds_string_len = tvb_get_letohl(tvb, nds_offset);
                    nds_offset += 4;
                    proto_tree_add_item(ncp_tree, hf_vendor_name, tvb, nds_offset, nds_string_len, ENC_ASCII|ENC_NA);
                    nds_offset += nds_string_len;
                    nds_offset += align_4(tvb, nds_offset);
                    break;
                default:
                    break;
                }
            }
            bvalue = bvalue*2;
        }
    }
}

static void
dissect_nds_reply(tvbuff_t *tvb, packet_info *pinfo,
                  proto_tree *ncp_tree, guint32 nds_error_code,
                  const char *nds_error_string, ncp_req_hash_value *request_value,
                  conversation_t *conversation)
{
    guint32                         nds_offset;
    proto_item                      *expert_item;
    const char                      *verb_string;
    gboolean                        resolve_eid=FALSE;
    guint32                         global_eid=0;
    gboolean                        add_eid = FALSE;
    char                            *global_object_name = NULL;
    ncp_req_eid_hash_value          *request_eid_value = NULL;
    nds_val                         temp_value;

    nds_offset = 8;

    proto_tree_add_item(ncp_tree, hf_ncp_fragment_size, tvb, nds_offset,
                        4, ENC_LITTLE_ENDIAN);
    nds_offset += 4;
    proto_tree_add_item(ncp_tree, hf_ncp_fragment_handle, tvb, nds_offset,
                        4, ENC_LITTLE_ENDIAN);
    nds_offset += 4;
    /*
     * Is the possibly-reassembled reply large enough to have a completion
     * code?  (We can't check the fragment size as this might just be the
     * last fragment.)
     */
    if (tvb_reported_length_remaining(tvb, nds_offset) >= 4)
    {
        /* Yes - process the completion code. */
        expert_item = proto_tree_add_uint_format(ncp_tree, hf_nds_reply_error, tvb, nds_offset,
                                                 4, nds_error_code, "NDS Completion Code: 0x%08x, %s",
                                                 nds_error_code, nds_error_string);

        if (nds_error_code != 0 && ncp_echo_err) {
            expert_add_info_format(pinfo, expert_item, &ei_nds_reply_error, "NDS Error: 0x%08x %s", nds_error_code, nds_error_string);
        }
    }

    if ((request_value == NULL) || (nds_error_code != 0))
        return;

    nds_offset = 20;
    verb_string = val_to_str_const(request_value->nds_request_verb,
                                    ncp_nds_verb_vals, "Continuation Fragment");
    if(request_value->req_nds_prot_flags & 0x4000)
    {
        /* CRC is included in the NDS header so justify the offset */
        proto_tree_add_item(ncp_tree, hf_nds_crc, tvb, nds_offset, 4, ENC_LITTLE_ENDIAN);
        nds_offset += 4;
    }

    if(request_value->nds_request_verb != 0)
    {
        proto_tree_add_uint_format_value(ncp_tree,
                                    hf_ncp_nds_verb, tvb, 6, 0,
                                    request_value->nds_request_verb,
                                    "%d, %s",
                                    request_value->nds_request_verb, verb_string);
    }

    memset(&temp_value, 0, sizeof(temp_value));
    switch (request_value->nds_request_verb)
    {
    case 0x01:
        proto_tree_add_item_ret_uint(ncp_tree, hf_nds_tag_string, tvb, nds_offset, 4, ENC_LITTLE_ENDIAN, &temp_value.vvalue);
        nds_offset += 4;

        switch(temp_value.vvalue)
        {
        case NDS_TAG_NO_SUCH_ENTRY:
            break;
        case NDS_TAG_LOCAL_ENTRY:
            proto_tree_add_item_ret_uint(ncp_tree, hf_nds_eid, tvb, nds_offset, 4, ENC_LITTLE_ENDIAN, &global_eid);
            add_eid = TRUE;
            resolve_eid = TRUE;
            global_object_name = request_value->object_name;
            nds_offset += 4;

            temp_value.vvalue = tvb_get_letohl(tvb, nds_offset);
            temp_value.vtype = VTYPE_MULTIVALUE_UINT32;
            temp_value.vdesc = "Referral Records: %u";
            temp_value.vlength = 4;
            temp_value.voffset = nds_offset;
            temp_value.hfname = hf_nds_referrals;
            temp_value.mvtype = MVTYPE_LOC_ADDR_REFERRAL_REPLY;
            process_multivalues(ncp_tree, tvb, pinfo, &temp_value);
            break;
        case NDS_TAG_REMOTE_ENTRY:
            nds_offset += 4;   /* GUINT32 reserved field */
            proto_tree_add_item(ncp_tree, hf_nds_eid, tvb, nds_offset, 4, ENC_LITTLE_ENDIAN);
            nds_offset += 4;
            temp_value.vvalue = tvb_get_letohl(tvb, nds_offset);
            temp_value.vtype = VTYPE_MULTIVALUE_UINT32;
            temp_value.vdesc = "Referral Records: %u";
            temp_value.vlength = 4;
            temp_value.voffset = nds_offset;
            temp_value.hfname = hf_nds_referrals;
            temp_value.mvtype = MVTYPE_LOC_ADDR_REFERRAL_REPLY;
            process_multivalues(ncp_tree, tvb, pinfo, &temp_value);
            break;
        case NDS_TAG_ALIAS_ENTRY:
            temp_value.vvalue = tvb_get_letohl(tvb, nds_offset);
            if (temp_value.vvalue == 0x00)
                break;

            temp_value.vstring = tvb_get_string_enc(wmem_packet_scope(), tvb, nds_offset+4, temp_value.vvalue, ENC_UTF_16|ENC_LITTLE_ENDIAN);
            proto_tree_add_string_format(ncp_tree, hf_nds_name, tvb, nds_offset, 4+temp_value.vvalue, temp_value.vstring, "Alias Name: %s", temp_value.vstring);
            break;
        case NDS_TAG_REFERRAL_INFORMATION:
            temp_value.vvalue = tvb_get_letohl(tvb, nds_offset);
            proto_tree_add_uint_format(ncp_tree, hf_nds_eid, tvb, nds_offset, 4, temp_value.vvalue, "Distance Object is From Root: 0x%08x", temp_value.vvalue);
            nds_offset += 4;

            temp_value.vvalue = tvb_get_letohl(tvb, nds_offset);
            temp_value.vtype = VTYPE_MULTIVALUE_UINT32;
            temp_value.vdesc = "Referral Records: %u";
            temp_value.vlength = 4;
            temp_value.voffset = nds_offset;
            temp_value.hfname = hf_nds_referrals;
            temp_value.mvtype = MVTYPE_ADDR_REFERRAL_REPLY;
            process_multivalues(ncp_tree, tvb, pinfo, &temp_value);
            break;
        case NDS_TAG_ENTRY_AND_REFERRALS:
            proto_tree_add_item(ncp_tree, hf_nds_result_flags, tvb, nds_offset, 4, ENC_LITTLE_ENDIAN);
            nds_offset += 4;
            proto_tree_add_item_ret_uint(ncp_tree, hf_nds_eid, tvb, nds_offset, 4, ENC_LITTLE_ENDIAN, &global_eid);
            add_eid = TRUE;
            resolve_eid = TRUE;
            global_object_name = request_value->object_name;
            nds_offset += 4;

            temp_value.vvalue = tvb_get_letohl(tvb, nds_offset);
            temp_value.vtype = VTYPE_MULTIVALUE_UINT32;
            temp_value.vdesc = "Referral Records: %u";
            temp_value.vlength = 4;
            temp_value.voffset = nds_offset;
            temp_value.hfname = hf_nds_referrals;
            temp_value.mvtype = MVTYPE_ADDR_REFERRAL_REPLY;
            process_multivalues(ncp_tree, tvb, pinfo, &temp_value);
            break;
        default:
            break;
        }
        break;
    case 0x02:
        nds_offset -= 4;
        temp_value.vvalue = 1;
        temp_value.vtype = VTYPE_MULTIVALUE_UINT32;
        temp_value.vdesc = "Entry Information";
        temp_value.vlength = 0;
        temp_value.voffset = nds_offset;
        temp_value.hfname = hf_nds_name;
        temp_value.mvtype = MVTYPE_LIST_PARTITIONS;
        temp_value.vflags = request_value->req_nds_flags;
        process_multivalues(ncp_tree, tvb, pinfo, &temp_value);
        break;
    case 0x03:
        proto_tree_add_item(ncp_tree, hf_nds_iteration, tvb, nds_offset, 4, ENC_LITTLE_ENDIAN);
        nds_offset += 4;
        proto_tree_add_item(ncp_tree, hf_nds_info_type, tvb, nds_offset, 4, ENC_LITTLE_ENDIAN);
        nds_offset += 4;

        temp_value.vvalue = tvb_get_letohl(tvb, nds_offset);
        temp_value.vtype = VTYPE_MULTIVALUE_UINT32;
        temp_value.vdesc = "Number of Attributes: %u";
        temp_value.vlength = 4;
        temp_value.voffset = nds_offset;
        temp_value.hfname = hf_nds_attr;
        temp_value.mvtype = MVTYPE_ATTR_REPLY;
        temp_value.vflags = request_value->req_nds_flags;
        temp_value.nds_version = request_value->nds_version;
        temp_value.pflags = request_value->req_nds_prot_flags;
        process_multivalues(ncp_tree, tvb, pinfo, &temp_value);
        break;
    case 0x04:
        temp_value.vvalue = tvb_get_guint8(tvb, nds_offset);
        if (temp_value.vvalue == 0)
        {
            proto_tree_add_uint_format_value(ncp_tree, hf_nds_compare_results, tvb, nds_offset, 1, temp_value.vvalue, "Did Not Match");
        }
        else
        {
            proto_tree_add_uint_format_value(ncp_tree, hf_nds_compare_results, tvb, nds_offset, 1, temp_value.vvalue, "Matched");
        }
        break;
    case 0x05:
        proto_tree_add_item(ncp_tree, hf_nds_iteration, tvb, nds_offset, 4, ENC_LITTLE_ENDIAN);
        nds_offset += 4;

        temp_value.vvalue = tvb_get_letohl(tvb, nds_offset);
        temp_value.vtype = VTYPE_MULTIVALUE_UINT32;
        temp_value.vdesc = "Entry Information";
        temp_value.vlength = 0;
        temp_value.voffset = nds_offset;
        temp_value.hfname = hf_nds_name;
        temp_value.mvtype = MVTYPE_LIST_PARTITIONS;
        temp_value.vflags = request_value->req_nds_flags;
        process_multivalues(ncp_tree, tvb, pinfo, &temp_value);
        break;
    case 0x06:
    case 0x07:
    case 0x08:
    case 0x09:
    case 0x0a:
    case 0x0b:
    case 0x0c:
    case 0x0d:
    case 0x0e:
        break;
    case 0x0f:
        proto_tree_add_item(ncp_tree, hf_nds_iteration, tvb, nds_offset, 4, ENC_LITTLE_ENDIAN);
        nds_offset += 4;
        proto_tree_add_item(ncp_tree, hf_nds_class_def_type, tvb, nds_offset, 4, ENC_LITTLE_ENDIAN);
        nds_offset += 4;

        temp_value.vvalue = tvb_get_letohl(tvb, nds_offset);
        temp_value.vtype = VTYPE_MULTIVALUE_UINT32;
        temp_value.vdesc = "Class Definitions %u";
        temp_value.vlength = 0;
        temp_value.voffset = nds_offset;
        temp_value.hfname = hf_nds_classes;
        temp_value.mvtype = MVTYPE_CLASS_NAMES;
        temp_value.vflags = request_value->req_nds_flags;
        process_multivalues(ncp_tree, tvb, pinfo, &temp_value);
        break;
    case 0x10:
    case 0x11:
        break;
    case 0x12:
        proto_tree_add_item(ncp_tree, hf_nds_iteration, tvb, nds_offset, 4, ENC_LITTLE_ENDIAN);
        nds_offset += 4;

        temp_value.vvalue = tvb_get_letohl(tvb, nds_offset);
        temp_value.vtype = VTYPE_MULTIVALUE_UINT32;
        temp_value.vdesc = "Classes: %u";
        temp_value.vlength = 4;
        temp_value.voffset = nds_offset;
        temp_value.mvtype = MVTYPE_READ_CLASS_REQ;
        temp_value.hfname= hf_nds_classes;
        process_multivalues(ncp_tree, tvb, pinfo, &temp_value);
        break;
    case 0x13:
        proto_tree_add_item(ncp_tree, hf_nds_privileges, tvb, nds_offset, 4, ENC_LITTLE_ENDIAN);
        break;
    case 0x14:
    case 0x15:
        break;
    case 0x16:
        proto_tree_add_item(ncp_tree, hf_nds_iteration, tvb, nds_offset, 4, ENC_LITTLE_ENDIAN);
        nds_offset += 4;

        temp_value.vvalue = tvb_get_letohl(tvb, nds_offset);
        if (temp_value.vvalue == 0)
            break;

        temp_value.vstring = tvb_get_string_enc(wmem_packet_scope(), tvb, nds_offset+4, temp_value.vvalue, ENC_UTF_16|ENC_LITTLE_ENDIAN);
        proto_tree_add_string_format(ncp_tree, hf_nds_name, tvb, nds_offset, 4+temp_value.vvalue, temp_value.vstring, "Server Distinguished Name: %s", temp_value.vstring);
        nds_offset += 4+temp_value.vvalue;
        nds_offset += align_4(tvb, nds_offset);

        temp_value.vvalue = tvb_get_letohl(tvb, nds_offset);
        temp_value.vtype = VTYPE_MULTIVALUE_UINT32;
        temp_value.vdesc = "Replicas: %u";
        temp_value.vlength = 4;
        temp_value.voffset = nds_offset;
        temp_value.hfname = hf_nds_replicas;
        temp_value.mvtype = MVTYPE_READ_REPLICAS;
        temp_value.bit1 = "Output Flags";
        temp_value.bit2 = "Entry ID";
        temp_value.bit3 = "Replica State";
        temp_value.bit4 = "Modification Timestamp";
        temp_value.bit5 = "Purge Time";
        temp_value.bit6 = "Local Partition ID";
        temp_value.bit7 = "Distinguished Name";
        temp_value.bit8 = "Replica Type";
        temp_value.bit9 = "Partition Busy";
        temp_value.vflags = request_value->req_nds_flags;
        process_multivalues(ncp_tree, tvb, pinfo, &temp_value);
        break;
    case 0x17:
    case 0x18:
    case 0x19:
    case 0x1a:
        break;
    case 0x1b:
        proto_tree_add_item(ncp_tree, hf_nds_file_handle, tvb, nds_offset, 4, ENC_BIG_ENDIAN);
        nds_offset += 4;
        proto_tree_add_item(ncp_tree, hf_nds_file_size, tvb, nds_offset, 4, ENC_LITTLE_ENDIAN);
        break;
    case 0x1c:
    case 0x1d:
    case 0x1e:
    case 0x1f:
    case 0x20:
    case 0x21:
    case 0x22:
    case 0x23:
    case 0x24:
    case 0x25:
    case 0x26:
    case 0x27:
    case 0x28:
    case 0x29:
    case 0x2a:
    case 0x2b:
    case 0x2c:
    case 0x2d:
    case 0x2e:
    case 0x2f:
    case 0x30:
    case 0x31:
    case 0x32:
    case 0x33:
    case 0x34:
        break;
    case 0x35:
        temp_value.vtype = VTYPE_MULTIVALUE_UINT32;
        temp_value.vdesc = "Server Name";
        temp_value.mvtype = MVTYPE_PROCESS_TAGS;
        temp_value.vflags = request_value->req_nds_flags;
        temp_value.hfname = hf_nds_svr_dst_name;
        temp_value.vlength = tvb_get_letohl(tvb, nds_offset);
        if (temp_value.vlength == 0x00)
            break;

        temp_value.voffset = nds_offset;
        process_multivalues(ncp_tree, tvb, pinfo, &temp_value);
        nds_offset += temp_value.vlength + 4;
        nds_offset += align_4(tvb, nds_offset);

        temp_value.vvalue = tvb_get_letohl(tvb, nds_offset);
        temp_value.vtype = VTYPE_MULTIVALUE_UINT32;
        temp_value.vdesc = "Referral Records: %u";
        temp_value.vlength = 4;
        temp_value.voffset = nds_offset;
        temp_value.hfname = hf_nds_referrals;
        temp_value.mvtype = MVTYPE_LOC_ADDR_REFERRAL_REPLY;
        process_multivalues(ncp_tree, tvb, pinfo, &temp_value);
        break;
    case 0x36:
    case 0x37:
    case 0x38:
        break;
    case 0x39:
        proto_tree_add_item_ret_uint(ncp_tree, hf_nds_eid, tvb, nds_offset, 4, ENC_LITTLE_ENDIAN, &global_eid);
        add_eid = TRUE;
        resolve_eid = TRUE;
        global_object_name = request_value->object_name;
        break;
    case 0x3a:
    case 0x3b:
    case 0x3c:
    case 0x3d:
    case 0x3e:
    case 0x3f:
    case 0x40:
    case 0x41:
    case 0x42:
    case 0x43:
    case 0x44:
    case 0x45:
    case 0x46:
    case 0x47:
    case 0x48:
    case 0x49:
    case 0x4a:
    case 0x4b:
    case 0x4c:
    case 0x4d:
        break;
    case 0x6e:
        proto_tree_add_item(ncp_tree, hf_nds_iteration, tvb, nds_offset, 4, ENC_LITTLE_ENDIAN);
        nds_offset += 4;
        expert_item = proto_tree_add_item_ret_uint(ncp_tree, hf_iter_completion_code, tvb, nds_offset, 4, ENC_LITTLE_ENDIAN, &temp_value.vvalue);
        nds_offset += 4;

        if (temp_value.vvalue != 0 && ncp_echo_err) {
            expert_add_info_format(pinfo, expert_item, &ei_nds_iteration, "NDS Iteration Error: 0x%08x %s",
                                    temp_value.vvalue, val_to_str(temp_value.vvalue, nds_reply_errors, "Unknown: %d"));
        }
        temp_value.vvalue = tvb_get_letohl(tvb, nds_offset);
        temp_value.vtype = VTYPE_ITEM;
        temp_value.vlength = 4;
        temp_value.voffset = nds_offset;
        temp_value.mvtype = MVTYPE_PROCESS_ITERATOR;
        temp_value.hfname = hf_ncp_nds_iterverb;
        dissect_nds_iterator(ncp_tree, tvb, pinfo, temp_value.vvalue, 0, nds_offset, FALSE);
        break;
    default:
        break;
    }
    /* NDS Entry ID's (EID) is identified in the reply
        * packet of an NDS resolve name. We need to store
        * this EID and its associated name into our hash
        * so that we can resolve the name for other NDS
        * requests. */
    if (!pinfo->fd->flags.visited) {
        if(add_eid)
        {
            request_eid_value = ncp_eid_hash_lookup(conversation, global_eid);
            if (!request_eid_value) {
                request_eid_value = ncp_eid_hash_insert(global_eid);
                if (global_object_name != NULL)
                    g_strlcpy(request_eid_value->object_name, global_object_name, 256);
                else
                    request_eid_value->object_name[0] = '\0';
            }
        }
    }
    /* Echo EID data to expert Chat window */
    if (add_eid && nds_echo_eid) {
        expert_add_info_format(pinfo, NULL, &ei_ncp_eid,
                                "EID (%08x) = %s", global_eid, global_object_name);
    }
    /* For NDS requests with just an EID, resolve name
        * from hash table. */
    if(resolve_eid)
    {
        request_eid_value = ncp_eid_hash_lookup(conversation, global_eid);
        if (request_eid_value) {
            proto_tree_add_string_format(ncp_tree,
                                            hf_nds_name, tvb, 6, 0,
                                            request_eid_value->object_name,
                                            "NDS Name for EID - %s",
                                            request_eid_value->object_name);
        }
    }
}

void
dissect_ncp_reply(tvbuff_t *tvb, packet_info *pinfo,
                  guint32 nw_connection, guint8 sequence, guint16 type,
                  proto_tree *ncp_tree, struct novell_tap *ncp_tap)
{
    conversation_t      *conversation = NULL;
    ncp_req_hash_value  *request_value = NULL;
    const ncp_record    *ncp_rec = NULL;
    gboolean            *req_cond_results;
    guint8               completion_code=0;
    ptvcursor_t         *ptvc = NULL;
    const char          *error_string;
    guint32              nds_offset = 0;
    guint32              nds_error_code = 0;
    /*guint32              nds_reply_buffer = 0;*/
    const char          *nds_error_string = NULL;
    /*guint32              nds_frag=0;*/
    proto_item          *expert_item;
    guint8               conn_stat;


#ifdef FAKE_TREE_IS_VISIBLE
    if (ncp_tree) {
        PTREE_DATA(ncp_tree)->visible=1;
    }
#endif

    if (!pinfo->fd->flags.visited) {
        /* Find the conversation whence the request would have come. */
        conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
                                         PT_NCP, nw_connection, nw_connection, 0);
        if (conversation != NULL) {
            /* find the record telling us the request made that caused
               this reply */
            request_value = ncp_hash_lookup(conversation, sequence, pinfo->num);
            if (request_value) {
                ncp_rec = request_value->ncp_rec;
            }
            p_add_proto_data(wmem_file_scope(), pinfo, proto_ncp, 0, (void*) request_value);
        }
        /* else... we haven't seen an NCP Request for that conversation
           and sequence.
           Create Service request packets do not contain nw_connection.
           The initial value is set to 65535 or 0. The reply packet has the
           valid connection. So, we can't find the request packet in
           our conversation list. To trap for this we can just perform
           the search again with 65535 to see if we can locate the
           proper request packet. */
        else {
            conversation = find_conversation(pinfo->num,
                                             &pinfo->src, &pinfo->dst, PT_NCP, 65535, 65535, 0);
            if (conversation != NULL) {
                /* find the record telling us the request made
                   that caused this reply */
                request_value = ncp_hash_lookup(conversation,
                                                sequence, pinfo->num);
                if (request_value) {
                    ncp_rec = request_value->ncp_rec;
                }
                p_add_proto_data(wmem_file_scope(), pinfo, proto_ncp, 0,
                                 (void*) request_value);
            }
            else {
                conversation = find_conversation(pinfo->num,
                                                 &pinfo->src, &pinfo->dst, PT_NCP, 0, 0, 0);
                if (conversation != NULL) {
                    /* find the record telling us the request made
                       that caused this reply */
                    request_value = ncp_hash_lookup(conversation,
                                                    sequence, pinfo->num);
                    if (request_value) {
                        ncp_rec = request_value->ncp_rec;
                    }
                    p_add_proto_data(wmem_file_scope(), pinfo, proto_ncp, 0,
                                     (void*) request_value);
                }
                /* else... we haven't seen an NCP Request for that
                   conversation and sequence. */
            }
        }
    }
    else {
        /*request_value = p_get_proto_data(wmem_file_scope(), pinfo, proto_ncp);*/
        conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
                                         PT_NCP, nw_connection, nw_connection, 0);
        if (conversation != NULL) {

             request_value = ncp_hash_lookup(conversation,
                               sequence, pinfo->num);
        }
        if (request_value) {
            ncp_rec = request_value->ncp_rec;
        }
    }

    /*
     * Tap the packet before the dissectors are called so we
     * still get the tap listener called even if there is an
     * exception.
     */
    tap_queue_packet(ncp_tap->stat, pinfo, request_value);

    if (ncp_rec && ncp_rec->func==0x68 &&
        (ncp_rec->subfunc==0x02 || ncp_rec->subfunc==0x01)) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "NDS");
    }

    /* A completion code of 0 always means OK. Non-zero means failure,
     * but each non-zero value has a different meaning. And the same value
     * can have different meanings, depending on the ncp.func (and ncp.subfunc)
     * value. */
    completion_code = tvb_get_guint8(tvb, 6);
    if (completion_code == 0) {
        if(type == NCP_POSITIVE_ACK)
        {
            error_string = "Server Busy, Request Being Processed";
        }
        else
        {
            error_string = "OK";
        }
    } else {
        if (ncp_rec && ncp_rec->errors) {
            error_string = ncp_error_string(ncp_rec->errors, completion_code);
        }
        else {
            error_string = "Original Request Packet not Found";
        }
    }
    if (type == NCP_SERVICE_REPLY && ncp_rec && ncp_rec->func==0x68 &&
        ncp_rec->subfunc==0x02 && (tvb_reported_length_remaining(tvb, 8) >= 8))
    {
        nds_offset = 8;
        /*nds_reply_buffer = tvb_get_letohl(tvb, nds_offset);*/
        nds_offset += 4;
        /*nds_frag = tvb_get_letohl(tvb, nds_offset);*/
        nds_offset += 4;
        /*
         * Is the possibly-reassembled reply large enough to have
         * a completion code?  (We can't check the fragment size
         * as this might just be the last fragment.)
         */
        if (tvb_reported_length_remaining(tvb, nds_offset) >= 4)
        {
            /* Yes - process the completion code. */
            nds_error_code = tvb_get_letohl(tvb, nds_offset);
            nds_error_string = val_to_str_const(nds_error_code, nds_reply_errors, "NDS Error - No Definition Found");
        }
    }
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
                    type == NCP_SERVICE_REPLY ? "R" : "ACK",
                    nds_error_string ? nds_error_string : error_string);

    if (ncp_tree) {

        if (request_value) {
            nstime_t ns;

            proto_tree_add_uint(ncp_tree, hf_ncp_req_frame_num, tvb, 0, 0,
                                request_value->req_frame_num);
            nstime_delta(&ns, &pinfo->abs_ts, &request_value->req_frame_time);
            proto_tree_add_time(ncp_tree, hf_ncp_req_frame_time, tvb, 0, 0, &ns);
        }

        /* Put the func (and maybe subfunc) from the request packet
         * in the proto tree, but hidden. That way filters on ncp.func
         * or ncp.subfunc will find both the requests and the replies.
         */
        if (ncp_rec) {
            proto_tree_add_uint_format_value(ncp_tree, hf_ncp_func, tvb, 6, 0,
                                       ncp_rec->func, "%u (0x%02X), %s",
                                       ncp_rec->func, ncp_rec->func, ncp_rec->name);
            if (ncp_requires_subfunc(ncp_rec->func)) {
                proto_tree_add_uint(ncp_tree, hf_ncp_subfunc, tvb, 6, 0, ncp_rec->subfunc);
            }
        }
    }

    expert_item = proto_tree_add_uint_format_value(ncp_tree, hf_ncp_completion_code, tvb, 6, 1,
                                             completion_code, "%d (0x89%02x), %s",
                                             completion_code, completion_code, error_string);
    if ((completion_code != 0 || type == NCP_POSITIVE_ACK) && ncp_echo_err) {
        expert_add_info_format(pinfo, expert_item, &ei_ncp_completion_code,
                               "Error: %d (0x89%02x) %s", completion_code,
                               completion_code, error_string);
    }

    conn_stat = tvb_get_guint8(tvb, 7);
    expert_item = proto_tree_add_item(ncp_tree, hf_ncp_connection_status, tvb,
                                      7, 1, ENC_NA);
    if (conn_stat != 0 && conn_stat != 0x40 ) {
        col_set_str(pinfo->cinfo, COL_INFO,
                    "Error: Bad Connection Status");
        if (ncp_echo_err) {
            expert_add_info(pinfo, expert_item, &ei_ncp_connection_status);
        }
        return;
    }
    /*
     * Unless this is a successful reply, that's all there
     * is to parse.
     */
    if (type != NCP_SERVICE_REPLY || completion_code != 0)
        return;

    if (ncp_rec) {
        /* Dissect SSS Reply packets */
        if (ncp_rec->func == 0x5c && request_value)
        {
            dissect_sss_reply(tvb, pinfo, ncp_tree, ncp_rec->subfunc, request_value);
        }
        /* Dissect NMAS Reply packets */
        if (ncp_rec->func == 0x5e && request_value)
        {
            dissect_nmas_reply(tvb, pinfo, ncp_tree, ncp_rec->func, ncp_rec->subfunc, request_value);
        }
        /* Dissect NDS Ping packets */
        if (ncp_rec->func == 0x68 && ncp_rec->subfunc == 0x01)
        {
            dissect_nds_ping_reply(tvb, pinfo, ncp_tree,
                                   request_value);
        }
        /* Dissect NDS Reply packets */
        if (ncp_rec->func == 0x68 && ncp_rec->subfunc == 0x02)
        {
            dissect_nds_reply(tvb, pinfo, ncp_tree, nds_error_code,
                              nds_error_string, request_value, conversation);
        }
        /* Due to lack of group repeat fields in reply structure, decode this ncp 87/20 reply manually here. */
        if ((ncp_rec->func == 0x57 || ncp_rec->func == 0x59) && ncp_rec->subfunc == 0x14) {
            dissect_ncp_8x20reply(tvb, pinfo, ncp_tree, ncp_rec, request_value);
        }
        if (ncp_rec->func == 5 && ncp_echo_conn) {
            expert_add_info(pinfo, NULL, &ei_ncp_connection_destroyed);
        }
        if (ncp_rec->reply_ptvc) {
            /* If we're not building a protocol tree, quit;
             * "process_ptvc_record()" assumes we're building
             * a protocol tree, and we don't support putting
             * stuff in the Info column in replies, and no
             * state information is currently updated for
             * replies by "process_ptvc_record()", so we
             * can't, and don't have a reason to, dissect
             * any further if we're not building a protocol
             * tree. */
            if (!ncp_tree)
                return;

            /* If a non-zero completion code was found, it is
             * legal to not have any fields, even if the packet
             * type is defined as having fields.
             *
             * XXX - we already know that the completion code
             * is 0, as we checked it above.  Is there any
             * reason why we'd want to do a full dissection
             * if the completion code isn't 0? */
            if (completion_code != 0 && tvb_captured_length(tvb) == 8) {
                return;
            }

            /* Any request condition results? */
            if (request_value) {
                req_cond_results = request_value->req_cond_results;
            }
            else {
                req_cond_results = NULL;
            }
            clear_repeat_vars();
            ptvc = ptvcursor_new(ncp_tree, tvb, 8);
            process_ptvc_record(ptvc, pinfo, ncp_rec->reply_ptvc,
                                req_cond_results, TRUE, ncp_rec, FALSE);
            ptvcursor_free(ptvc);

            /* Process ncp 123/17 address records manually to format correctly. */
            if (ncp_rec->func == 0x7b && ncp_rec->subfunc == 0x11) {
                dissect_ncp_123_17_reply(tvb, pinfo, ncp_tree);
            }
            /* Process ncp 123/11 NLM names manually to format correctly. */
            if (ncp_rec->func == 0x7b && ncp_rec->subfunc == 0x0b && request_value) {
                dissect_ncp_123_11_reply(tvb, ncp_tree, request_value);
            }
            /* Process ncp 123/62 server set parameter values manually to format correctly. */
            if (ncp_rec->func == 0x7b && ncp_rec->subfunc == 0x3e) {
                dissect_ncp_123_62_reply(tvb, ncp_tree);
            }
            /* Process ncp 23/26 address records manually to format correctly. */
            if (ncp_rec->func == 0x17 && ncp_rec->subfunc == 0x1a) {
                dissect_ncp_23_26_reply(tvb, ncp_tree);
            }
            /* Process ncp 87/72 bytes transferred value. */
            if (ncp_rec->func == 0x57 && ncp_rec->subfunc == 0x48) {
                dissect_ncp_87_72_reply(tvb, ncp_tree);
            }

        }
    } else {
        if (tvb_reported_length(tvb) > 8) {
            expert_item = proto_tree_add_item(ncp_tree, hf_no_request_record_found, tvb, 8, -1, ENC_NA);
            if (ncp_echo_err) {
                expert_add_info(pinfo, expert_item, &ei_ncp_no_request_record_found);
            }
        }
    }
}

void
dissect_nds_request(tvbuff_t *tvb, packet_info *pinfo,
                    guint32 nw_connection, guint8 sequence,
                    guint16 type, proto_tree *ncp_tree)
{
    guint8                   func, subfunc;
    ncp_req_hash_value      *request_value = NULL;
    ncp_req_eid_hash_value  *request_eid_value = NULL;
    const ncp_record        *ncp_rec = NULL;
    conversation_t          *conversation;
    ptvcursor_t             *ptvc = NULL;
    proto_tree              *temp_tree = NULL;
    gboolean                 run_req_cond = FALSE;
    guint8                   nds_verb = 0;
    const char              *verb_string = "";
    guint32                  nds_frag = 0;
    guint8                   nds_version = 0;
    guint32                  foffset = 0;
    const char*              global_object_name = NULL;
    guint32                  global_eid=0;
    gboolean                 resolve_eid=FALSE;
    guint32                  global_flags=0, nds_prot_flags=0;
    guint32                  version, value1;
    nds_val                  temp_value;

    func = tvb_get_guint8(tvb, 6);
    subfunc = tvb_get_guint8(tvb, 7);

    ncp_rec = ncp_record_find(func, subfunc);
    if (ncp_rec) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "NDS");
    } else {
        col_add_fstr(pinfo->cinfo, COL_INFO,
                        "C Unknown Function %d (0x%02x)",
                        func, func);
    }

    /* Check to see if this is a fragment packet */
    nds_frag = tvb_get_letohl(tvb, 8);

    /* Keep track of the address and connection whence the request
       came, and the address and connection to which the request
       is being sent, so that we can match up calls with replies.
       (We don't include the sequence number, as we may want
       to have all packets over the same connection treated
       as being part of a single conversation so that we can
       let the user select that conversation to be displayed.) */

    conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
                                     PT_NCP, nw_connection, nw_connection, 0);
    if (conversation == NULL) {
        /* It's not part of any conversation - create a new one. */
        conversation = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst,
                                        PT_NCP, nw_connection, nw_connection, 0);
    }

    if (!pinfo->fd->flags.visited) {
        request_value = ncp_hash_insert(conversation, sequence, ncp_rec, pinfo->num);
        request_value->req_frame_num = pinfo->num;
        request_value->req_frame_time=pinfo->abs_ts;

        /* If this is the first time we're examining the packet,
         * check to see if this NCP type uses a "request condition".
         * If so, we have to build a proto_tree because request conditions
         * use display filters to work, and without a proto_tree,
         * display filters can't possibly work. If we already have
         * a proto_tree, then wonderful. If we don't, we need to build
         * one. */
        if (ncp_rec && !ncp_tree) {
            run_req_cond = TRUE;
        }
        /* Keep track of the Fragment number in the request for defrag logic */
        request_value->nds_frag_num = nds_frag;
    }

    /* If we have to handle a request condition, or have to
       add to the Info column, we need to construct a protocol
       tree.  If we already have a proto_tree, then wonderful.
       If we don't, we need to build one. */
    if (run_req_cond && !ncp_tree) {
        proto_item *ti;

        temp_tree = proto_tree_create_root(pinfo);
        proto_tree_set_visible(temp_tree, FALSE);
        ti = proto_tree_add_item(temp_tree, proto_ncp, tvb, 0, -1, ENC_NA);
        ncp_tree = proto_item_add_subtree(ti, ett_ncp);
    }

    /* Get NDS Verb */
    if (nds_frag == 0xffffffff) {
        /* First fragment or only fragment. */
        nds_verb = tvb_get_guint8(tvb, 24);
        if (nds_verb == 0xfe)
        {
            nds_version = nds_verb;
            nds_verb = tvb_get_guint8(tvb, 32);
            foffset = 36;
        }
        else
        {
            nds_version = 0;
            foffset = 28;
        }
        if (type == NCP_SERVICE_REQUEST) {
            proto_tree_add_item(ncp_tree, hf_nds_buffer_size, tvb, foffset,
                                4, ENC_LITTLE_ENDIAN);
        }
        foffset = foffset+4;
        verb_string = val_to_str_const(nds_verb, ncp_nds_verb_vals,
                                       "Continuation Fragment");

        if (ncp_rec)
            col_add_fstr(pinfo->cinfo, COL_INFO, "C NDS %s", verb_string);
    } else {
        if (ncp_rec)
            col_add_fstr(pinfo->cinfo, COL_INFO, "C Continue NDS Fragment 0x%08x", nds_frag);
    }

    if (ncp_tree) {
        /* If the dissection throws an exception, be sure to free
         * the temporary proto_tree that was created. Because of the
         * way the CLEANUP_PUSH macro works, we can't put it in an 'if'
         * block; it has to be in the same scope as the terminating
         * CLEANUP_POP or CLEANUP_POP_AND_ALLOC. So, we always
         * call CLEANUP_POP and friends, but the value of temp_tree is
         * NULL if no cleanup is needed, and non-null if cleanup is needed.
         */
        CLEANUP_PUSH(free_proto_tree, temp_tree);

#ifdef FAKE_TREE_IS_VISIBLE
        PTREE_DATA(ncp_tree)->visible=1;
#endif

    if (type == NCP_SERVICE_REQUEST) {
        memset(&temp_value, 0, sizeof(temp_value));
        request_value = ncp_hash_lookup(conversation, sequence, pinfo->num);

        if (ncp_rec && ncp_rec->request_ptvc)
        {
            ptvc = ptvcursor_new(ncp_tree, tvb, 7);
            clear_repeat_vars();
            process_ptvc_record(ptvc, pinfo, ncp_rec->request_ptvc, NULL, TRUE, ncp_rec, TRUE);
            ptvcursor_free(ptvc);
        }
        if (ncp_tree) {
            proto_tree_add_uint_format_value(ncp_tree, hf_ncp_func, tvb, 6, 1,
                                       func, "%d (0x%02X), %s",
                                       func, func, ncp_rec ? ncp_rec->name : "Unknown");

            proto_tree_add_uint(ncp_tree, hf_ncp_subfunc, tvb, 7, 1, subfunc);

            proto_tree_add_uint(ncp_tree, hf_ncp_fragment_handle, tvb, 8, 4,
                                nds_frag);
        }

        if (nds_frag == 0xffffffff) {

            if (ncp_tree) {
                proto_tree_add_item(ncp_tree, hf_ncp_fragment_size, tvb, 12, 4, ENC_LITTLE_ENDIAN);

                proto_tree_add_item(ncp_tree, hf_ncp_message_size, tvb, 16, 4, ENC_LITTLE_ENDIAN);

                proto_tree_add_bitmask(ncp_tree, tvb, 22, hf_ncp_nds_flag, ett_ncp, ndsprotflags, ENC_LITTLE_ENDIAN);

                if (nds_version == 0) {
                    proto_tree_add_uint_format_value(ncp_tree, hf_ncp_nds_verb, tvb, 24, 4,
                                            nds_verb, "%d, (0x%02x), %s",
                                            nds_verb, nds_verb, verb_string);
                }
                else {
                    proto_tree_add_uint_format_value(ncp_tree, hf_ncp_nds_verb, tvb, 32, 4,
                                            nds_verb, "%d, (0x%02x), %s",
                                            nds_verb, nds_verb, verb_string);
                }
            }

            switch(nds_verb) {

            case 0x01:
                proto_tree_add_item_ret_uint(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &version);
                foffset += 4;
                proto_tree_add_bitmask(ncp_tree, tvb, foffset, hf_nds_nflags, ett_ncp, ncp_nflags, ENC_LITTLE_ENDIAN);
                foffset += 4;

                if (version == 0 || version == 1)
                {
                    proto_tree_add_item(ncp_tree, hf_nds_scope, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                    foffset += 4;
                    value1 = tvb_get_letohl(tvb, foffset);
                    if (value1 == 0)
                        break;

                    global_object_name = tvb_get_string_enc(wmem_packet_scope(), tvb, foffset+4, value1, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                    proto_tree_add_string(ncp_tree, hf_nds_name, tvb, foffset, 4+value1, global_object_name);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", global_object_name);
                    foffset += 4+value1;
                    foffset += align_4(tvb, foffset);

                    temp_value.vvalue = tvb_get_letohl(tvb, foffset);
                    temp_value.vtype = VTYPE_MULTIVALUE_UINT32;
                    temp_value.vdesc = "Communications Transports: %u";
                    temp_value.vlength = 4;
                    temp_value.hfname= hf_nds_comm_trans;
                    temp_value.voffset = foffset;
                    temp_value.mvtype = MVTYPE_ADDR_REFERRAL_REQUEST;
                    process_multivalues(ncp_tree, tvb, pinfo, &temp_value);
                    foffset = foffset + (temp_value.vvalue * 4) + 4;

                    temp_value.vvalue = tvb_get_letohl(tvb, foffset);
                    temp_value.vdesc = "Tree Walker Transport Type: %u";
                    temp_value.hfname= hf_nds_tree_trans;
                    temp_value.voffset = foffset;
                    process_multivalues(ncp_tree, tvb, pinfo, &temp_value);
                }
                else
                {
                    proto_tree_add_item(ncp_tree, hf_min_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                    foffset += 4;

                    temp_value.vvalue = tvb_get_letohl(tvb, foffset);
                    temp_value.vtype = VTYPE_MULTIVALUE_UINT32;
                    temp_value.vdesc = "Number of Versions to Include: %u";
                    temp_value.vlength = 4;
                    temp_value.mvtype = MVTYPE_ATTR_REQUEST2;
                    temp_value.voffset = foffset;
                    temp_value.hfname= hf_nds_ver_include;
                    process_multivalues(ncp_tree, tvb, pinfo, &temp_value);
                    foffset += (temp_value.vvalue * 4) + 4;

                    temp_value.vvalue = tvb_get_letohl(tvb, foffset);
                    temp_value.vdesc = "Number of Versions to Exclude: %u";
                    temp_value.hfname= hf_nds_ver_exclude;
                    temp_value.voffset = foffset;
                    process_multivalues(ncp_tree, tvb, pinfo, &temp_value);
                    foffset += (temp_value.vvalue * 4) + 4;

                    proto_tree_add_item(ncp_tree, hf_nds_dn_output_type, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                    foffset += 4;
                    proto_tree_add_item(ncp_tree, hf_nds_nested_output_type, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                    foffset += 4;

                    value1 = tvb_get_letohl(tvb, foffset);
                    global_object_name = tvb_get_string_enc(wmem_packet_scope(), tvb, foffset+4, value1, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                    proto_tree_add_string(ncp_tree, hf_nds_output_delimiter, tvb, foffset, 4+value1, global_object_name);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", global_object_name);
                    foffset += 4+value1;
                    foffset += align_4(tvb, foffset);

                    temp_value.vvalue = tvb_get_letohl(tvb, foffset);
                    temp_value.vdesc = "Size of Entry Specifier: %u";
                    temp_value.mvtype = MVTYPE_PROC_ENTRY_SPECIFIERS;
                    temp_value.hfname= hf_nds_output_entry_specifier;
                    temp_value.voffset = foffset;
                    process_multivalues(ncp_tree, tvb, pinfo, &temp_value);
                }
                break;
            case 0x02:
                proto_tree_add_item_ret_uint(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &version);
                foffset += 4;
                switch(version)
                {
                case 0:
                    proto_tree_add_item(ncp_tree, hf_nds_eid, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                    break;
                case 1:
                    proto_tree_add_bitmask(ncp_tree, tvb, foffset, hf_nds_rflags, ett_ncp, ncp_rflags, ENC_LITTLE_ENDIAN);
                    value1 = tvb_get_letohl(tvb, foffset);

                    if ((value1 & 0xf000) == 0xc000)
                    {
                        proto_tree_add_string(ncp_tree, hf_nds_name_type, tvb, 0, 0, "Partial");
                    }
                    else
                    {
                        proto_tree_add_string(ncp_tree, hf_nds_name_type, tvb, 0, 0, "Full");
                    }
                    foffset += 4;

                    proto_tree_add_item_ret_uint(ncp_tree, hf_nds_eid, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &global_eid);
                    resolve_eid = TRUE;
                    break;
                case 2:
                    proto_tree_add_bitmask(ncp_tree, tvb, foffset, hf_nds_rflags, ett_ncp, ncp_rflags, ENC_LITTLE_ENDIAN);
                    value1 = tvb_get_letohl(tvb, foffset);
                    if ((value1 & 0xf000) == 0xc000)
                    {
                        proto_tree_add_string(ncp_tree, hf_nds_name_type, tvb, 0, 0, "Return Partion Name");
                    }
                    else
                    {
                        proto_tree_add_string(ncp_tree, hf_nds_name_type, tvb, 0, 0, "Return Full Name");
                    }
                    foffset += 4;
                    proto_tree_add_bitmask(ncp_tree, tvb, foffset, hf_retinfoflagsl, ett_ncp, ncp_infoflagsl, ENC_LITTLE_ENDIAN);
                    global_flags = tvb_get_letohl(tvb, foffset);
                    foffset += 2;
                    proto_tree_add_bitmask(ncp_tree, tvb, foffset, hf_retinfoflagsh, ett_ncp, ncp_infoflagsh, ENC_LITTLE_ENDIAN);
                    foffset += 2;

                    proto_tree_add_item_ret_uint(ncp_tree, hf_nds_eid, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &global_eid);
                    resolve_eid = TRUE;
                    break;
                default:
                    break;
                }
                break;

            case 0x03:
                proto_tree_add_item_ret_uint(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &version);
                foffset += 4;

                if (version == 0)
                {
                    proto_tree_add_item(ncp_tree, hf_nds_iteration, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                    foffset += 4;
                    proto_tree_add_item_ret_uint(ncp_tree, hf_nds_eid, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &global_eid);
                    resolve_eid = TRUE;
                    foffset += 4;
                    proto_tree_add_item_ret_uint(ncp_tree, hf_nds_info_type, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &global_flags);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", rval_to_str_const(global_flags, nds_info_type, "No Info Type Set"));

                    foffset += 4;
                    proto_tree_add_item(ncp_tree, hf_nds_all_attr, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                    foffset += 4;

                    temp_value.vvalue = tvb_get_letohl(tvb, foffset);
                    temp_value.vtype = VTYPE_MULTIVALUE_UINT32;
                    temp_value.vdesc = "Attributes: %u";
                    temp_value.vlength = 4;
                    temp_value.voffset = foffset;
                    temp_value.mvtype = MVTYPE_ATTR_REQUEST;
                    temp_value.hfname= hf_nds_attr;
                    process_multivalues(ncp_tree, tvb, pinfo, &temp_value);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", temp_value.vstring);
                }
                else
                {
                    proto_tree_add_item(ncp_tree, hf_nds_req_flags, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                    foffset += 4;
                    proto_tree_add_item(ncp_tree, hf_nds_iteration, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                    foffset += 4;
                    proto_tree_add_item_ret_uint(ncp_tree, hf_nds_eid, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &global_eid);
                    resolve_eid = TRUE;
                    foffset += 4;
                    proto_tree_add_item_ret_uint(ncp_tree, hf_nds_info_type, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &global_flags);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", rval_to_str_const(global_flags, nds_info_type, "No Info Type Set"));
                    foffset += 4;
                    proto_tree_add_item(ncp_tree, hf_nds_all_attr, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                    foffset += 4;

                    temp_value.vvalue = tvb_get_letohl(tvb, foffset);
                    temp_value.vtype = VTYPE_MULTIVALUE_UINT32;
                    temp_value.vdesc = "Attributes: %u";
                    temp_value.vlength = 4;
                    temp_value.voffset = foffset;
                    temp_value.mvtype = MVTYPE_ATTR_REQUEST;
                    temp_value.hfname= hf_nds_attr;
                    process_multivalues(ncp_tree, tvb, pinfo, &temp_value);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", temp_value.vstring);
               }
               break;
            case 0x04:
                proto_tree_add_item_ret_uint(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &version);
                foffset += 4;

                if (version == 1)
                {
                    /* Version 1 specifies for this offset value to always be a value of 1*/
                    /* No need to display to user */
                    foffset += 4;
                }

                proto_tree_add_item_ret_uint(ncp_tree, hf_nds_eid, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &global_eid);
                resolve_eid = TRUE;
                foffset += 4;

                foffset += 4;       /* Attribute Count = 1 */

                value1 = tvb_get_letohl(tvb, foffset);
                if (value1 == 0)
                    break;

                global_object_name = tvb_get_string_enc(wmem_packet_scope(), tvb, foffset+4, value1, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                proto_tree_add_string_format(ncp_tree, hf_nds_name, tvb, foffset, 4+value1, global_object_name, "Attribute Name Being Compared: %s", global_object_name);
                col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", global_object_name);
                foffset += 4+value1;
                foffset += align_4(tvb, foffset);

                foffset += 4;       /* Attribute Count = 1 */

                value1 = tvb_get_letohl(tvb, foffset);
                temp_value.vstring = tvb_get_string_enc(wmem_packet_scope(), tvb, foffset+4, value1, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                proto_tree_add_string_format(ncp_tree, hf_value_string, tvb, foffset, 4+value1, temp_value.vstring, "Attribute Value: %s", temp_value.vstring);
                col_append_fstr(pinfo->cinfo, COL_INFO, " %s", temp_value.vstring);
                break;
            case 0x05:
                proto_tree_add_item_ret_uint(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &version);
                foffset += 4;
                proto_tree_add_bitmask(ncp_tree, tvb, foffset, hf_nds_rflags, ett_ncp, ncp_lflags, ENC_LITTLE_ENDIAN);
                foffset += 2;
                proto_tree_add_item(ncp_tree, hf_nds_iteration, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                proto_tree_add_item(ncp_tree, hf_nds_parent, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                proto_tree_add_bitmask(ncp_tree, tvb, foffset, hf_retinfoflagsl, ett_ncp, ncp_infoflagsl, ENC_LITTLE_ENDIAN);
                foffset += 2;
                proto_tree_add_bitmask(ncp_tree, tvb, foffset, hf_retinfoflagsh, ett_ncp, ncp_infoflagsh, ENC_LITTLE_ENDIAN);
                foffset += 2;

                value1 = tvb_get_letohl(tvb, foffset);
                temp_value.vstring = tvb_get_string_enc(wmem_packet_scope(), tvb, foffset+4, value1, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                proto_tree_add_string(ncp_tree, hf_nds_name_filter, tvb, foffset, 4+value1, temp_value.vstring);
                col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", temp_value.vstring);
                foffset += 4+value1;
                if (version == 0)
                    break;

                foffset += align_4(tvb, foffset);

                value1 = tvb_get_letohl(tvb, foffset);
                temp_value.vstring = tvb_get_string_enc(wmem_packet_scope(), tvb, foffset+4, value1, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                proto_tree_add_string(ncp_tree, hf_nds_class_filter, tvb, foffset, 4+value1, temp_value.vstring);
                col_append_fstr(pinfo->cinfo, COL_INFO, " %s", temp_value.vstring);
                foffset += 4+value1;
                if (version == 1)
                    break;

                foffset += align_4(tvb, foffset);

                temp_value.vvalue = tvb_get_letohl(tvb, foffset);
                temp_value.vtype = VTYPE_MULTIVALUE_UINT32;
                temp_value.vdesc = "Seconds: %u";
                temp_value.vlength = 4;
                temp_value.mvtype = MVTYPE_PRINT_TIMESTAMP;
                temp_value.hfname= hf_nds_time_filter;
                temp_value.voffset = foffset;
                process_multivalues(ncp_tree, tvb, pinfo, &temp_value);
                break;
            case 0x06:
                proto_tree_add_item_ret_uint(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &version);
                foffset += 4;
                proto_tree_add_item(ncp_tree, hf_nds_req_flags, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                proto_tree_add_item(ncp_tree, hf_nds_iteration, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                proto_tree_add_item_ret_uint(ncp_tree, hf_nds_eid, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &global_eid);
                resolve_eid = FALSE;
                foffset += 4;
                proto_tree_add_item(ncp_tree, hf_nds_search_scope, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                proto_tree_add_item(ncp_tree, hf_nds_num_objects, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                proto_tree_add_bitmask(ncp_tree, tvb, foffset, hf_siflags, ett_ncp, ncp_siflags, ENC_LITTLE_ENDIAN);
                foffset += 4;

                if (version != 2)
                {
                    proto_tree_add_bitmask(ncp_tree, tvb, foffset, hf_retinfoflagsl, ett_ncp, ncp_infoflagsl, ENC_LITTLE_ENDIAN);
                    foffset += 2;
                    proto_tree_add_bitmask(ncp_tree, tvb, foffset, hf_retinfoflagsh, ett_ncp, ncp_infoflagsh, ENC_LITTLE_ENDIAN);
                }
                break;
            case 0x07:
                proto_tree_add_item_ret_uint(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &version);
                foffset += 4;
                proto_tree_add_item(ncp_tree, hf_nds_req_flags, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                if (version != 0)
                {
                    proto_tree_add_item(ncp_tree, hf_nds_iteration, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                    foffset += 4;
                }

                global_eid = tvb_get_letohl(tvb, foffset);
                proto_tree_add_uint_format(ncp_tree, hf_nds_eid, tvb, foffset, 4, global_eid, "Parent Entry ID: 0x%08x", global_eid);
                resolve_eid = FALSE;
                foffset += 4;

                value1 = tvb_get_letohl(tvb, foffset);
                if (value1 == 0)
                    break;
                global_object_name = tvb_get_string_enc(wmem_packet_scope(), tvb, foffset+4, value1, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                proto_tree_add_string(ncp_tree, hf_nds_relative_dn, tvb, foffset, 4+value1, global_object_name);
                col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", global_object_name);
                foffset += 4+value1;
                foffset += align_4(tvb, foffset);

                temp_value.vvalue = tvb_get_letohl(tvb, foffset);
                temp_value.vtype = VTYPE_MULTIVALUE_UINT32;
                temp_value.vstring = "";
                temp_value.vdesc = "Attributes: %u";
                temp_value.vlength = 4;
                temp_value.voffset = foffset;
                temp_value.mvtype = MVTYPE_ADD_ATTR_REQUEST;
                temp_value.hfname= hf_nds_attr;
                process_multivalues(ncp_tree, tvb, pinfo, &temp_value);
                break;
            case 0x08:
                proto_tree_add_item(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                proto_tree_add_item_ret_uint(ncp_tree, hf_nds_eid, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &global_eid);
                resolve_eid = TRUE;
                break;

            case 0x09:
                proto_tree_add_item_ret_uint(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &version);
                foffset += 4;

                if (version != 0)
                {
                    proto_tree_add_item(ncp_tree, hf_nds_req_flags, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                    foffset += 4;
                }

                proto_tree_add_item(ncp_tree, hf_nds_iteration, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                proto_tree_add_item_ret_uint(ncp_tree, hf_nds_eid, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &global_eid);
                resolve_eid = TRUE;
                foffset += 4;

                temp_value.vvalue = tvb_get_letohl(tvb, foffset);
                temp_value.vtype = VTYPE_MULTIVALUE_UINT32;
                temp_value.vstring = "";
                temp_value.vdesc = "Number of Attributes to Change %u";
                temp_value.vlength = 4;
                temp_value.mvtype = MVTYPE_MODIFY_ATTR_REQUEST;
                temp_value.hfname= hf_nds_number_of_changes;
                temp_value.voffset = foffset;
                process_multivalues(ncp_tree, tvb, pinfo, &temp_value);
                break;
            case 0x0a:
                proto_tree_add_item(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;

                proto_tree_add_item_ret_uint(ncp_tree, hf_nds_eid, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &global_eid);
                resolve_eid = TRUE;
                foffset += 4;

                proto_tree_add_item(ncp_tree, hf_nds_keep, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                foffset += align_4(tvb, foffset);

                value1 = tvb_get_letohl(tvb, foffset);
                temp_value.vstring = tvb_get_string_enc(wmem_packet_scope(), tvb, foffset+4, value1, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                proto_tree_add_string(ncp_tree, hf_nds_new_rdn, tvb, foffset, 4+value1, temp_value.vstring);
                break;

            case 0x0b:
                proto_tree_add_item(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                proto_tree_add_bitmask(ncp_tree, tvb, foffset, hf_nds_acflags, ett_ncp, ncp_acflags, ENC_LITTLE_ENDIAN);
                foffset += 4;

                value1 = tvb_get_letohl(tvb, foffset);
                if (value1 == 0)
                    break;
                global_object_name = tvb_get_string_enc(wmem_packet_scope(), tvb, foffset+4, value1, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                proto_tree_add_string_format(ncp_tree, hf_nds_relative_dn, tvb, foffset, 4+value1, global_object_name, "Attribute Name: %s", global_object_name);
                col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", global_object_name);
                foffset += 4+value1;
                foffset += align_4(tvb, foffset);

                proto_tree_add_item(ncp_tree, hf_nds_syntax, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                proto_tree_add_item(ncp_tree, hf_nds_lower, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                proto_tree_add_item(ncp_tree, hf_nds_upper, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                value1 = tvb_get_letohl(tvb, foffset);
                foffset += 4;
                proto_tree_add_item(ncp_tree, hf_nds_asn1, tvb, foffset, value1, ENC_NA);
                break;
            case 0x0c: /* Not Defined */
                break;
            case 0x0d:
                proto_tree_add_item(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;

                value1 = tvb_get_letohl(tvb, foffset);
                if (value1 == 0)
                    break;

                global_object_name = tvb_get_string_enc(wmem_packet_scope(), tvb, foffset+4, value1, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                proto_tree_add_string(ncp_tree, hf_nds_attribute_dn, tvb, foffset, 4+value1, global_object_name);
                col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", global_object_name);
                break;
            case 0x0e: /* Not Defined */
                break;
            case 0x0f:
                proto_tree_add_item(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                proto_tree_add_item(ncp_tree, hf_nds_iteration, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                proto_tree_add_item(ncp_tree, hf_nds_class_def_type, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                value1 = tvb_get_letohl(tvb, foffset);
                if (value1 == 0)
                {
                    proto_tree_add_uint_format_value(ncp_tree, hf_nds_return_all_classes, tvb, foffset, 4, value1, "Do Not Return All Classes");
                }
                else
                {
                    proto_tree_add_uint_format_value(ncp_tree, hf_nds_return_all_classes, tvb, foffset, 4, value1, "Return All Classes");
                }
                foffset += 4;
                foffset += align_4(tvb, foffset);

                temp_value.vvalue = tvb_get_letohl(tvb, foffset);
                temp_value.vtype = VTYPE_MULTIVALUE_UINT32;
                temp_value.vdesc = "Classes: %u";
                temp_value.vlength = 4;
                temp_value.mvtype = MVTYPE_READ_CLASS_REQ;
                temp_value.hfname= hf_nds_classes;
                temp_value.voffset = foffset;
                process_multivalues(ncp_tree, tvb, pinfo, &temp_value);
                break;
            case 0x10:
                proto_tree_add_item_ret_uint(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &version);
                foffset += 4;

                value1 = tvb_get_letohl(tvb, foffset);
                if (value1 == 0)
                    break;

                global_object_name = tvb_get_string_enc(wmem_packet_scope(), tvb, foffset+4, value1, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                proto_tree_add_string_format(ncp_tree, hf_nds_base_class, tvb, foffset, 4+value1, global_object_name, "Class Name: %s", global_object_name);
                col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", global_object_name);
                foffset += 4+value1;
                foffset += align_4(tvb, foffset);

                temp_value.vvalue = tvb_get_letohl(tvb, foffset);
                temp_value.vtype = VTYPE_MULTIVALUE_UINT32;
                temp_value.vdesc = "Number of Attributes to Add: %u";
                temp_value.vlength = 4;
                temp_value.voffset = foffset;
                temp_value.mvtype = MVTYPE_MODIFY_CLASS;
                temp_value.hfname= hf_nds_att_add;
                break;
            case 0x11:
                proto_tree_add_item(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;

                value1 = tvb_get_letohl(tvb, foffset);
                if (value1 == 0)
                    break;

                global_object_name = tvb_get_string_enc(wmem_packet_scope(), tvb, foffset+4, value1, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                proto_tree_add_string_format(ncp_tree, hf_nds_base, tvb, foffset, 4+value1, global_object_name, "Class Name: %s", global_object_name);
                col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", global_object_name);
                break;
            case 0x12:
                proto_tree_add_item(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                proto_tree_add_item(ncp_tree, hf_nds_iteration, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                proto_tree_add_item_ret_uint(ncp_tree, hf_nds_eid, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &global_eid);
                resolve_eid = TRUE;
                break;
            case 0x13:
                proto_tree_add_item_ret_uint(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &version);
                foffset += 4;
                proto_tree_add_item_ret_uint(ncp_tree, hf_nds_eid, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &global_eid);
                resolve_eid = TRUE;
                foffset += 4;

                value1 = tvb_get_letohl(tvb, foffset);
                if (value1 == 0)
                    break;

                temp_value.vstring = tvb_get_string_enc(wmem_packet_scope(), tvb, foffset+4, value1, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                proto_tree_add_string_format(ncp_tree, hf_nds_name, tvb, foffset, 4+value1, temp_value.vstring, "Trustee Name: %s", temp_value.vstring);
                col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", temp_value.vstring);
                foffset += 4+value1;
                foffset += align_4(tvb, foffset);

                value1 = tvb_get_letohl(tvb, foffset);
                if (value1 == 0)
                    break;

                temp_value.vstring = tvb_get_string_enc(wmem_packet_scope(), tvb, foffset+4, value1, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                proto_tree_add_string_format(ncp_tree, hf_nds_name, tvb, foffset, 4+value1, temp_value.vstring, "Attribute to be Checked: %s", temp_value.vstring);
                foffset += 4+value1;
                foffset += align_4(tvb, foffset);

                if(version != 0)
                {
                    value1 = tvb_get_letohl(tvb, foffset);
                    if (value1 == 0)
                        break;

                    temp_value.vstring = tvb_get_string_enc(wmem_packet_scope(), tvb, foffset+4, value1, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                    proto_tree_add_string_format(ncp_tree, hf_nds_name, tvb, foffset, 4+value1, temp_value.vstring, "Security Equivalence: %s", temp_value.vstring);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", temp_value.vstring);
                }
                break;
            case 0x14: /* Not Defined */
            case 0x15:
                break;
            case 0x16:
                proto_tree_add_item_ret_uint(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &version);
                foffset += 4;
                proto_tree_add_bitmask(ncp_tree, tvb, foffset, hf_nds_rflags, ett_ncp, nds_bitflags, ENC_LITTLE_ENDIAN);
                foffset += 2;
                proto_tree_add_item(ncp_tree, hf_nds_iteration, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;

                if(version == 0)
                {
                    global_flags = 0x000000c0;
                    break;
                }

                proto_tree_add_bitmask(ncp_tree, tvb, foffset, hf_l1flagsl, ett_ncp, ncp_l1flagsl, ENC_LITTLE_ENDIAN);
                global_flags = tvb_get_letohs(tvb, foffset);
                foffset += 2;
                proto_tree_add_bitmask(ncp_tree, tvb, foffset, hf_l1flagsh, ett_ncp, ncp_l1flagsh, ENC_LITTLE_ENDIAN);
                foffset += 2;

                if(version == 1)
                    break;

                proto_tree_add_item(ncp_tree, hf_nds_partition_root_id, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                break;
            case 0x17:
                proto_tree_add_item(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                value1 = tvb_get_letohl(tvb, foffset);
                proto_tree_add_uint_format(ncp_tree, hf_nds_req_flags, tvb, foffset, 4, value1, "Flags: 0x%08x", value1);
                foffset += 4;
                proto_tree_add_item(ncp_tree, hf_nds_new_part_id, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                break;
            case 0x18:
                proto_tree_add_item(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                value1 = tvb_get_letohl(tvb, foffset);
                proto_tree_add_uint_format(ncp_tree, hf_nds_req_flags, tvb, foffset, 4, value1, "Flags: 0x%08x", value1);
                foffset += 4;
                proto_tree_add_item(ncp_tree, hf_nds_child_part_id, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                break;
            case 0x19:
                proto_tree_add_item(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                value1 = tvb_get_letohl(tvb, foffset);
                proto_tree_add_uint_format(ncp_tree, hf_nds_req_flags, tvb, foffset, 4, value1, "Flags: 0x%08x", value1);
                foffset += 4;
                proto_tree_add_item(ncp_tree, hf_nds_master_part_id, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                proto_tree_add_item(ncp_tree, hf_replica_type, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;

                value1 = tvb_get_letohl(tvb, foffset);
                if (value1 == 0)
                    break;

                temp_value.vstring = tvb_get_string_enc(wmem_packet_scope(), tvb, foffset+4, value1, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                proto_tree_add_string(ncp_tree, hf_nds_target_name, tvb, foffset, 4+value1, temp_value.vstring);
                break;
            case 0x1a: /* Not Defined */
                break;
            case 0x1b:
                proto_tree_add_item(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                proto_tree_add_item(ncp_tree, hf_nds_stream_flags, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                proto_tree_add_item_ret_uint(ncp_tree, hf_nds_eid, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &global_eid);
                resolve_eid = TRUE;
                foffset += 4;

                value1 = tvb_get_letohl(tvb, foffset);
                if (value1 == 0)
                    break;

                temp_value.vstring = tvb_get_string_enc(wmem_packet_scope(), tvb, foffset+4, value1, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                proto_tree_add_string(ncp_tree, hf_nds_stream_name, tvb, foffset, 4+value1, temp_value.vstring);
                col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", temp_value.vstring);
                break;
            case 0x1c: /* Not Defined */
            case 0x1d:
            case 0x1e:
            case 0x1f:
            case 0x20:
            case 0x21:
            case 0x22:
            case 0x23:
            case 0x24:
            case 0x25:
                break;
            case 0x26:
                proto_tree_add_item_ret_uint(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &version);
                foffset += 4;
                value1 = tvb_get_letohl(tvb, foffset);
                proto_tree_add_uint_format(ncp_tree, hf_nds_req_flags, tvb, foffset, 4, value1, "Flags: 0x%08x", value1);
                foffset += 4;
                proto_tree_add_item(ncp_tree, hf_nds_time_delay, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;

                if(version == 0)
                {
                    value1 = tvb_get_letohl(tvb, foffset);
                    if (value1 == 0)
                        break;

                    temp_value.vstring = tvb_get_string_enc(wmem_packet_scope(), tvb, foffset+4, value1, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                    proto_tree_add_string(ncp_tree, hf_nds_root_name, tvb, foffset, 4+value1, temp_value.vstring);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", temp_value.vstring);
                }
                else
                {
                    global_eid = tvb_get_letohl(tvb, foffset);
                    proto_tree_add_item_ret_uint(ncp_tree, hf_nds_eid, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &global_eid);
                    resolve_eid = TRUE;
                }
                break;
            case 0x27: /* Not Defined */
            case 0x28:
            case 0x29:
                break;
            case 0x2a:
                proto_tree_add_item(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                value1 = tvb_get_letohl(tvb, foffset);
                proto_tree_add_uint_format(ncp_tree, hf_nds_req_flags, tvb, foffset, 4, value1, "Flags: 0x%08x", value1);
                foffset += 4;
                global_eid = tvb_get_letohl(tvb, foffset);
                proto_tree_add_uint_format(ncp_tree, hf_nds_ver, tvb, foffset, 4, global_eid, "Destination Parent Entry ID: 0x%08x", global_eid);
                resolve_eid = TRUE;
                foffset += 4;

                value1 = tvb_get_letohl(tvb, foffset);
                temp_value.vstring = tvb_get_string_enc(wmem_packet_scope(), tvb, foffset+4, value1, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                proto_tree_add_string(ncp_tree, hf_nds_new_rdn, tvb, foffset, 4+value1, temp_value.vstring);
                foffset += (4+value1);
                foffset += align_4(tvb, foffset);

                value1 = tvb_get_letohl(tvb, foffset);
                if (value1 == 0)
                    break;
                temp_value.vstring = tvb_get_string_enc(wmem_packet_scope(), tvb, foffset+4, value1, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                proto_tree_add_string(ncp_tree, hf_nds_target_name, tvb, foffset, 4+value1, temp_value.vstring);
                break;
            case 0x2b:
                proto_tree_add_item(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                proto_tree_add_item(ncp_tree, hf_nds_verb2b_req_flags, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                global_eid = tvb_get_letohl(tvb, foffset);
                proto_tree_add_uint_format(ncp_tree, hf_nds_ver, tvb, foffset, 4, global_eid, "Source Entry ID: 0x%08x", global_eid);
                resolve_eid = TRUE;
                foffset += 4;
                value1 = tvb_get_letohl(tvb, foffset);
                proto_tree_add_uint_format(ncp_tree, hf_nds_ver, tvb, foffset, 4, value1, "Destination Parent Entry ID: 0x%08x", value1);
                foffset += 4;
                value1 = tvb_get_letohl(tvb, foffset);
                temp_value.vstring = tvb_get_string_enc(wmem_packet_scope(), tvb, foffset+4, value1, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                proto_tree_add_string(ncp_tree, hf_nds_new_rdn, tvb, foffset, 4+value1, temp_value.vstring);
                foffset += (4+value1);
                foffset += align_4(tvb, foffset);
                value1 = tvb_get_letohl(tvb, foffset);
                if (value1 == 0)
                    break;
                temp_value.vstring = tvb_get_string_enc(wmem_packet_scope(), tvb, foffset+4, value1, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                proto_tree_add_string(ncp_tree, hf_nds_target_name, tvb, foffset, 4+value1, temp_value.vstring);
                break;
            case 0x2c: /* Not Defined */
            case 0x2d:
            case 0x2e:
            case 0x2f:
            case 0x30:
            case 0x31:
                break;
            case 0x32:
                proto_tree_add_item(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                proto_tree_add_item(ncp_tree, hf_nds_iteration, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                value1 = tvb_get_letohl(tvb, foffset);
                temp_value.vstring = val_to_str_const(value1, ncp_nds_verb_vals, "(No Verb Found)");
                proto_tree_add_string_format(ncp_tree, hf_mv_string, tvb, foffset, 4+value1, temp_value.vstring, "NDS Verb: %s", temp_value.vstring);
            break;
            case 0x33: /* Not Defined */
            case 0x34:
                break;
            case 0x35:
                if (nds_version != 0)
                {
                    proto_tree_add_item(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                    foffset += 4;
                    proto_tree_add_bitmask(ncp_tree, tvb, foffset, hf_nds_rflags, ett_ncp, ncp_rflags, ENC_LITTLE_ENDIAN);
                    global_flags = tvb_get_letohl(tvb, foffset);
                }
                break;
            case 0x36: /* Not Defined */
            case 0x37:
            case 0x38:
                break;
            case 0x39:
                proto_tree_add_item(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                proto_tree_add_item_ret_uint(ncp_tree, hf_nds_eid, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &global_eid);
                resolve_eid = TRUE;
                break;
            case 0x3a:
                proto_tree_add_item(ncp_tree, hf_nds_buffer_size, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                proto_tree_add_item(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                proto_tree_add_item_ret_uint(ncp_tree, hf_nds_eid, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &global_eid);
                resolve_eid = TRUE;
                break;
            case 0x3b:
                proto_tree_add_item(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                proto_tree_add_item_ret_uint(ncp_tree, hf_nds_eid, tvb, foffset, 4, ENC_LITTLE_ENDIAN, &global_eid);
                resolve_eid = TRUE;
                break;
            case 0x3c: /* Not Defined */
            case 0x3d:
            case 0x3e:
            case 0x3f:
            case 0x40:
            case 0x41:
            case 0x42:
            case 0x43:
            case 0x44:
            case 0x45:
            case 0x46:
            case 0x47:
            case 0x48:
            case 0x49:
            case 0x4a:
            case 0x4b:
            case 0x4c:
            case 0x4d:
                break;
            case 0x6e:
                proto_tree_add_item(ncp_tree, hf_nds_ver, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                proto_tree_add_bitmask(ncp_tree, tvb, foffset, hf_nds_rflags, ett_ncp, ncp_rflags, ENC_LITTLE_ENDIAN);
                global_flags = tvb_get_letohl(tvb, foffset);
                foffset += 4;
                proto_tree_add_item(ncp_tree, hf_nds_iteration, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;
                global_eid = tvb_get_letohl(tvb, foffset);
                proto_tree_add_uint_format(ncp_tree, hf_nds_eid, tvb, foffset, 4, global_eid, "Base Entry ID: 0x%08x", global_eid);
                resolve_eid = TRUE;
                foffset += 4;
                proto_tree_add_item(ncp_tree, hf_nds_scope, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                foffset += 4;

                temp_value.vvalue = tvb_get_letohl(tvb, foffset);
                temp_value.vtype = VTYPE_MULTIVALUE_UINT32;
                temp_value.vdesc = "Iterator: 0x%08x";
                temp_value.vlength = 4;
                temp_value.voffset = foffset;
                temp_value.hfname= hf_nds_iterator;
                temp_value.mvtype = MVTYPE_PROCESS_ITERATOR;
                process_multivalues(ncp_tree, tvb, pinfo, &temp_value);
                col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", temp_value.vstring);
                break;
            default: /* Not Defined */
                break;
            }
        }

        /* For NDS requests with just an EID, resolve name from hash table. */
        request_eid_value = ncp_eid_hash_lookup(conversation, global_eid);
        if(resolve_eid) {
            if (request_eid_value) {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Object Name - %s", request_eid_value->object_name);
            }
        }
        if (request_value)
        {
            request_value->nds_request_verb = nds_verb;
            request_value->nds_version = nds_version;
            if (global_object_name)
                g_strlcpy(request_value->object_name, global_object_name, 256);
            else
                request_value->object_name[0] = '\0';
            request_value->req_nds_flags = global_flags;
            request_value->req_nds_prot_flags = nds_prot_flags;
        }
    }

        /* Free the temporary proto_tree */
        CLEANUP_CALL_AND_POP;
    }
}

/*
 * XXX - this duplicates stuff in "dissect_ncp_request()"; could
 * "dissect_ncp_request()" not just call "dissect_ping_req()" if
 * the operation is an NCP ping, and "dissect_ping_req()" just dissect
 * ping portion?
 */
void
dissect_ping_req(tvbuff_t *tvb, packet_info *pinfo,
                 guint32 nw_connection, guint8 sequence,
                 guint16 type, proto_tree *ncp_tree)
{
    guint8               func, subfunc = 0;
    ncp_req_hash_value  *request_value = NULL;
    const ncp_record    *ncp_rec = NULL;
    conversation_t      *conversation;
    ptvcursor_t         *ptvc = NULL;
    proto_tree          *temp_tree = NULL;
    gint                 length_remaining = 0;
    guint32              nds_flags;
    guint32              ping_version;

#ifdef FAKE_TREE_IS_VISIBLE
    if (ncp_tree) {
        PTREE_DATA(ncp_tree)->visible=1;
    }
#endif

    func = tvb_get_guint8(tvb, 6);
    subfunc = tvb_get_guint8(tvb, 7);

    ncp_rec = ncp_record_find(func, subfunc);

    /* Fill in the INFO column. */
    if (ncp_rec)
    {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "NDS");

        col_set_str(pinfo->cinfo, COL_INFO, "C Ping for NDS");

    }
    if (!pinfo->fd->flags.visited)
    {

        /* This is the first time we've looked at this packet.
           Keep track of the address and connection whence the request
           came, and the address and connection to which the request
           is being sent, so that we can match up calls with replies.
           (We don't include the sequence number, as we may want
           to have all packets over the same connection treated
           as being part of a single conversation so that we can
           let the user select that conversation to be displayed.) */

        conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
                                         PT_NCP, nw_connection, nw_connection, 0);

        if (conversation == NULL)
        {
            /* It's not part of any conversation - create a new one. */
            conversation = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst,
                                            PT_NCP, nw_connection, nw_connection, 0);
        }

        request_value = ncp_hash_insert(conversation, sequence, ncp_rec, pinfo->num);
        request_value->req_frame_num = pinfo->num;
        request_value->req_frame_time=pinfo->abs_ts;

        /* If this is the first time we're examining the packet,
         * check to see if this NCP type uses a "request condition".
         * If so, we have to build a proto_tree because request conditions
         * use display filters to work, and without a proto_tree,
         * display filters can't possibly work. If we already have
         * a proto_tree, then wonderful. If we don't, we need to build
         * one. */
        if (ncp_rec && !ncp_tree) {
            proto_item *ti;

            temp_tree = proto_tree_create_root(pinfo);
            proto_tree_set_visible(temp_tree, FALSE);
            ti = proto_tree_add_item(temp_tree, proto_ncp, tvb, 0, -1, ENC_NA);
            ncp_tree = proto_item_add_subtree(ti, ett_ncp);
        }
    }

    if (ncp_tree) {
        /* If the dissection throws an exception, be sure to free
         * the temporary proto_tree that was created. Because of the
         * way the CLEANUP_PUSH macro works, we can't put it in an 'if'
         * block; it has to be in the same scope as the terminating
         * CLEANUP_POP or CLEANUP_POP_AND_ALLOC. So, we always
         * call CLEANUP_POP and friends, but the value of temp_tree is
         * NULL if no cleanup is needed, and non-null if cleanup is needed.
         */
        CLEANUP_PUSH(free_proto_tree, temp_tree);

        switch (type) {

        case NCP_BROADCAST_SLOT:
            ; /* nothing */
            break;

        case NCP_SERVICE_REQUEST:
            proto_tree_add_uint_format_value(ncp_tree, hf_ncp_func, tvb, 6, 1,
                                       func, "%u (0x%02X), %s",
                                       func, func, ncp_rec ? ncp_rec->name : "Unknown");

            proto_tree_add_uint(ncp_tree, hf_ncp_subfunc, tvb, 7, 1, subfunc);

            length_remaining = tvb_reported_length_remaining(tvb, 8);

            if (length_remaining >= 8) {
                proto_item *pi;

                ping_version = tvb_get_letohl(tvb, 8);
                proto_tree_add_uint(ncp_tree, hf_nds_ping_version, tvb, 8,
                                    4, ping_version);
                nds_flags = tvb_get_letohl(tvb, 12);
                if (request_value){
                    request_value->nds_request_verb = 0xf0;
                    request_value->req_nds_flags = nds_flags;
                }

                pi = proto_tree_add_uint(ncp_tree, hf_ncp_nds_verb, tvb, 0, 0, 240);
                PROTO_ITEM_SET_HIDDEN(pi);

                proto_tree_add_bitmask(ncp_tree, tvb, 12, hf_pingflags1, ett_ncp, ncp_pingflags1, ENC_LITTLE_ENDIAN);
                proto_tree_add_bitmask(ncp_tree, tvb, 14, hf_pingflags2, ett_ncp, ncp_pingflags2, ENC_LITTLE_ENDIAN);
            }
            break;

        default:
            ; /* nothing */
            break;
        }
        ptvc = ptvcursor_new(ncp_tree, tvb, 7);
        if (ncp_rec && ncp_rec->request_ptvc) {
            clear_repeat_vars();
            process_ptvc_record(ptvc, pinfo, ncp_rec->request_ptvc, NULL, TRUE, ncp_rec, TRUE);
        }
        ptvcursor_free(ptvc);

        /* Free the temporary proto_tree */
        CLEANUP_CALL_AND_POP;
    }
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab filetype=c:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
