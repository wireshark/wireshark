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
 * $Id$
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

#define PROTO_LENGTH_UNTIL_END -1

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
#define DSI_OUTPUT_FIELDS               0x00000001L
#define DSI_ENTRY_ID                    0x00000002L
#define DSI_ENTRY_FLAGS                 0x00000004L
#define DSI_SUBORDINATE_COUNT           0x00000008L
#define DSI_MODIFICATION_TIME           0x00000010L
#define DSI_MODIFICATION_TIMESTAMP      0x00000020L
#define DSI_CREATION_TIMESTAMP          0x00000040L
#define DSI_PARTITION_ROOT_ID           0x00000080L
#define DSI_PARENT_ID                   0x00000100L
#define DSI_REVISION_COUNT              0x00000200L
#define DSI_REPLICA_TYPE                0x00000400L
#define DSI_BASE_CLASS                  0x00000800L
#define DSI_ENTRY_RDN                   0x00001000L
#define DSI_ENTRY_DN                    0x00002000L
#define DSI_PARTITION_ROOT_DN           0x00004000L
#define DSI_PARENT_DN                   0x00008000L
#define DSI_PURGE_TIME                  0x00010000L
#define DSI_DEREFERENCED_BASE_CLASS     0x00020000L
#define DSI_REPLICA_NUMBER              0x00040000L
#define DSI_REPLICA_STATE               0x00080000L
#define DSI_FEDERATION_BOUNDARY         0x00100000L
#define DSI_SCHEMA_BOUNDARY             0x00200000L
#define DSI_FEDERATION_BOUNDARY_ID      0x00400000L
#define DSI_SCHEMA_BOUNDARY_ID          0x00800000L
#define DSI_CUR_SUBCOUNT                0x01000000L
#define DSI_LOCAL_ENTRY_FLAGS           0x02000000L

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

static const value_string nds_scope_vals[] = {
    { 0, "Search Scope: 0x0000 - Examine base object only" },
    { 1, "Search Scope: 0x0001 - Search the immediate subordinates of the base object" },
    { 2, "Search Scope: 0x0002 - Search the base object and all of its subordinates" },
    { 3, "Search Scope: 0x0003 - Search the base objects and all objects in its partition (NDS version 8 or higher)" },
    {0, NULL }
};

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

static const value_string nds_info_type[] = {
    { 0x00000000, "Attribute Names Only / " },
    { 0x00000001, "Attribute Name & Value / " },
    { 0x00000002, "Effective Privileges / " },
    { 0x00000003, "Value Information / " },
    { 0x00000004, "Abbreviated Value / " },
    { 0, NULL }
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
    { 0xffffff09, "(-247) No Property Create Rigths" },
    { 0xffffff08, "(-248) No Property Write Rights" },
    { 0xffffff07, "(-249) No Propery Read Rights" },
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

static const value_string nds_search_scope[] = {
    { 0x0000, "Examine the base object only" },
    { 0x0001, "Search the immediate subordinates of the base object" },
    { 0x0002, "Search the base object and all its subordinates" },
    { 0x0003, "Search the base objects and all objects in its partition (Implemented in NDS 8)" },
    { 0, NULL }
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

static void
process_ptvc_record(ptvcursor_t *ptvc, const ptvc_record *rec,
                    gboolean *req_cond_results, gboolean really_decode,
                    const ncp_record *ncp_rec);

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
    fragment_table_init(&nds_fragment_table);
    reassembled_table_init(&nds_reassembled_table);

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
    request_key = se_alloc(sizeof(ncp_req_hash_key));
    request_key->conversation = conversation;
	/* Make sequence number unique */
    request_key->nw_sequence_long = (0x10000 + ((pkt_num/255)<<16)) | nw_sequence;

    request_value = se_alloc(sizeof(ncp_req_hash_value));
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
    request_eid_key = se_alloc(sizeof(ncp_req_eid_hash_key));
    request_eid_key->nw_eid = nw_eid;

    request_eid_value = se_alloc(sizeof(ncp_req_eid_hash_value));
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
    request_key.nw_sequence_long = (0x10000+((pkt_num/255)<<16)) | nw_sequence;

	/* Since masking of sequence number utilizes the packet number as
	 * part of it's algorythm it is possible for a packet to sit right
	 * on the boundary and fail. (depending on number of packets in trace)
	 * Loop through all the previous sequence numbers in the hash to see
	 * if the original request packet can be found.
	 */
	temp_value = g_hash_table_lookup(ncp_req_hash, &request_key);
	while(!temp_value)
	{
       request_key.nw_sequence_long = request_key.nw_sequence_long-0x10000;
	   if((request_key.nw_sequence_long & 0xffff0000) == 0){
	        break;
	   }  
       temp_value = g_hash_table_lookup(ncp_req_hash, &request_key);
	}
	
    return temp_value;
}

/* Returns the value_rec* for needed EID, or NULL if not found. */
static ncp_req_eid_hash_value*
ncp_eid_hash_lookup(conversation_t *conversation _U_, guint32 nw_eid)
{
    ncp_req_eid_hash_key  request_eid_key;

    request_eid_key.nw_eid = nw_eid;

    return g_hash_table_lookup(ncp_req_eid_hash, &request_eid_key);
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


/* Given a proto_item*, assume it contains an integer value
 * and return a guint from it. */
static guint
get_finfo_value_integer(field_info *finfo)
{
    /* XXX the fvalue functions are no longer safe to call directly
       since we sometimes fake the entries to speed things up.
       this dissector should not call fvalue_ functions directly.
    */
    if(!finfo->value.ftype->get_value_uinteger){
        return 0;
    }
    return fvalue_get_uinteger(&finfo->value);
}
static guint
get_item_value(proto_item *item)
{
    return get_finfo_value_integer(PITEM_FINFO(item));
}


static guint
get_finfo_length(field_info *finfo)
{
    return fvalue_length(&finfo->value);
}


static char *
get_finfo_value_string(field_info *finfo)
{
    return fvalue_get(&finfo->value);
}
#if 0
static char *
get_item_string(proto_item *item)
{
    return get_finfo_value_string(PITEM_FINFO(item));
}
#endif

static const char *
get_item_name(proto_item *item)
{
    return PITEM_FINFO(item)->hfinfo->name;
}


typedef proto_item* (*padd_func_t)(ptvcursor_t*, const ptvc_record*);

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
typedef struct {
    guint       year;
    guint       month;
    guint       day;
} nw_date_t;

typedef struct {
    guint       hour;
    guint       minute;
    guint       second;
} nw_time_t;

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


/* Given an integer, fill in a nw_date_t struct. */
static void
uint_to_nwdate(guint data, nw_date_t *nwdate)
{
    nwdate->day   =  data & 0x001f;
    nwdate->month = (data & 0x01e0) >> 5;
    nwdate->year  = ((data & 0xfe00) >> 9) + 1980;
}

/* Given an integer, fill in a nw_time_t struct. */
static void
uint_to_nwtime(guint data, nw_time_t *nwtime)
{
    /* 2-second resolution */
    nwtime->second = (data & 0x001f) * 2;
    nwtime->minute = ((data & 0x07e0) >> 5);
    nwtime->hour   = ((data & 0xf800) >> 11);
}

static proto_item*
padd_normal(ptvcursor_t *ptvc, const ptvc_record *rec)
{
    return
        ptvcursor_add(ptvc, *rec->hf_ptr,
                      rec->length, rec->endianness);
}

static proto_item*
padd_date(ptvcursor_t *ptvc, const ptvc_record *rec)
{
    proto_item  *item;
    nw_date_t   nw_date;

    item = ptvcursor_add(ptvc, *rec->hf_ptr,
                         rec->length, rec->endianness);

    if (item) {
        uint_to_nwdate(get_item_value(item), &nw_date);

        proto_item_set_text(item, "%s", get_item_name(item));
        proto_item_append_text(item, ": %04u/%02u/%02u",
                               nw_date.year, nw_date.month, nw_date.day);
    }
    return item;
}

static proto_item*
padd_time(ptvcursor_t *ptvc, const ptvc_record *rec)
{
    proto_item  *item;
    nw_time_t   nw_time;

    item = ptvcursor_add(ptvc, *rec->hf_ptr,
                         rec->length, rec->endianness);

    if (item) {
        uint_to_nwtime(get_item_value(item), &nw_time);

        proto_item_set_text(item, "%s", get_item_name(item));
        proto_item_append_text(item, ": %02u:%02u:%02u",
                               nw_time.hour, nw_time.minute, nw_time.second);
    }
    return item;
}


/* Convert a string from little-endian unicode to ascii.  At the moment we
   fake it by taking every odd byte.  )-:  The caller must free the
   result returned. */
/* XXX This prints the proto_item name, but not its value. */
static proto_item*
padd_uni(ptvcursor_t *ptvc, const ptvc_record *rec)
{
    proto_item      *item;
    /* nw_uni_t        nw_uni; */

    /* nw_uni.buffer[0] = '\0'; */

    item = ptvcursor_add(ptvc, *rec->hf_ptr,
                         rec->length, rec->endianness);

    if (item) {
        proto_item_set_text(item, "%s", get_item_name(item));
        /* proto_item_append_text(item, " %s",
           nw_uni.buffer); */
    }

    return item;
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
                                     sub_rec->length, sub_rec->endianness);
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
process_struct_sub_ptvc_record(ptvcursor_t *ptvc, const ptvc_record *rec,
                               gboolean *req_cond_results, gboolean really_decode,
                               const ncp_record *ncp_rec)
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
        item = proto_tree_add_text(old_tree, ptvcursor_tvbuff(ptvc),
                                   offset, PROTO_LENGTH_UNTIL_END, "%s",
                                   rec->sub_ptvc_rec->descr);
        new_tree = proto_item_add_subtree(item, ett);
        ptvcursor_set_tree(ptvc, new_tree);
    }

    /* Get the ptvc_record for the struct and call our caller
     * to process it. */
    sub_rec = rec->sub_ptvc_rec->ptvc_rec;
    process_ptvc_record(ptvc, sub_rec, req_cond_results, really_decode, ncp_rec);

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
_process_ptvc_record(ptvcursor_t *ptvc, const ptvc_record *rec,
                     gboolean *req_cond_results, gboolean really_decode,
                     const ncp_record *ncp_rec)
{
    proto_item  *item;
    guint       i, repeat_count;
    padd_func_t func = NULL;

    if (rec->sub_ptvc_rec) {
        /* Repeat this? */
        if (rec->repeat_index >= NO_REPEAT) {
            if (rec->hf_ptr == PTVC_STRUCT) {
                process_struct_sub_ptvc_record(ptvc, rec,
                                               req_cond_results, really_decode,
                                               ncp_rec);
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
                    process_struct_sub_ptvc_record(ptvc, rec,
                                                   req_cond_results, really_decode,
                                                   ncp_rec);
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
                /* Handle any special formatting. */
                switch(rec->special_fmt) {
                case NCP_FMT_NONE:
                    func = padd_normal;
                    break;
                case NCP_FMT_NW_DATE:
                    func = padd_date;
                    break;
                case NCP_FMT_NW_TIME:
                    func = padd_time;
                    break;
                case NCP_FMT_UNICODE:
                    func = padd_uni;
                    break;
                default:
                    DISSECTOR_ASSERT_NOT_REACHED();
                }
                item = func(ptvc, rec);

                /* Set the value as a 'var' ? */
                if (rec->var_index != NO_VAR) {
                    repeat_vars[rec->var_index] = get_item_value(item);
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
                /* Handle any special formatting. */
                switch(rec->special_fmt) {
                case NCP_FMT_NONE:
                    func = padd_normal;
                    break;
                case NCP_FMT_NW_DATE:
                    func = padd_date;
                    break;
                case NCP_FMT_NW_TIME:
                    func = padd_time;
                    break;
                case NCP_FMT_UNICODE:
                    func = padd_uni;
                    break;
                default:
                    DISSECTOR_ASSERT_NOT_REACHED();
                }
                for (i = 0; i < repeat_count; i++ ) {
                    func(ptvc, rec);
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
process_ptvc_record(ptvcursor_t *ptvc, const ptvc_record *rec,
                    gboolean *req_cond_results, gboolean really_decode,
                    const ncp_record *ncp_rec)
{
    gboolean decode;

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
            _process_ptvc_record(ptvc, rec, req_cond_results, decode, ncp_rec);
        }
        rec++;
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
    if(tvb_length_remaining(tvb, aoffset) > 4 )
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

    length_remaining = tvb_length_remaining(tvb, offset);
    if((gint)str_length > length_remaining)
    {
        THROW(ReportedBoundsError);
    }

    if(str_length == 0)
    {
        return "";
    }

    dest_buf = ep_alloc(max_length + 1);
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

static void
uni_to_string(char * data, guint32 str_length, char *dest_buf)
{
    gint i;
    guint16 c_char;
    gint length_remaining = 0;

    length_remaining = str_length;
    dest_buf[0] = '\0';
    if(str_length == 0)
    {
        return;
    }
    for ( i = 0; i < (gint) str_length; i++ )
    {
        c_char = data[i];
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
        length_remaining--;

        if(length_remaining==0)
        {
            dest_buf[i+1] = '\0';
            return;
        }
    }
    if (i < 0) {
        i = 0;
    }
    dest_buf[i] = '\0';
    return;
}

/*************************************
 * Return based on % format in request
 * %d = integer in decimal format = 0
 * %x = integer in hex format = 1
 * %s = string = 2
 **************************************/
static int
get_info_type(const gchar* check_string)
{
    guint length;
    guint i;

    length =  (guint) strlen(check_string);

    for (i = 0 ; i < length-1 ; i++ ) {
        if (check_string[i] == 0x25 && check_string[i+1] == 0x64) {   /* %d Digits*/
            return 0;
        }
        if ( check_string[i] == 0x78 && check_string[i+1] == 0x25 && check_string[i+2] == 0x73) {  /* x%s Bytes*/
            return 1;
        }
    }
    return 2; /* Normal String */
}

static void
process_bitfield(proto_tree *ncp_tree, tvbuff_t *tvb, nds_val *values)
{
    gchar        flags_str[512];
    const gchar *sep;
    proto_item  *tinew;
    proto_tree  *flags_tree;
    guint32      i;
    guint32      bvalue = 0;

    bvalue = 0x00000001;
    flags_str[0]='\0';
    sep="";
    for (i = 0 ; i < (values->vlength*8); i++ ) {
        if (values->vvalue & bvalue)
        {
            g_strlcat(flags_str, sep, 512);
            switch(bvalue){
            case 0x00000001:
                g_strlcat(flags_str, values->bit1, 512);
                break;
            case 0x00000002:
                g_strlcat(flags_str, values->bit2, 512);
                break;
            case 0x00000004:
                g_strlcat(flags_str, values->bit3, 512);
                break;
            case 0x00000008:
                g_strlcat(flags_str, values->bit4, 512);
                break;
            case 0x00000010:
                g_strlcat(flags_str, values->bit5, 512);
                break;
            case 0x00000020:
                g_strlcat(flags_str, values->bit6, 512);
                break;
            case 0x00000040:
                g_strlcat(flags_str, values->bit7, 512);
                break;
            case 0x00000080:
                g_strlcat(flags_str, values->bit8, 512);
                break;
            case 0x00000100:
                g_strlcat(flags_str, values->bit9, 512);
                break;
            case 0x00000200:
                g_strlcat(flags_str, values->bit10, 512);
                break;
            case 0x00000400:
                g_strlcat(flags_str, values->bit11, 512);
                break;
            case 0x00000800:
                g_strlcat(flags_str, values->bit12, 512);
                break;
            case 0x00001000:
                g_strlcat(flags_str, values->bit13, 512);
                break;
            case 0x00002000:
                g_strlcat(flags_str, values->bit14, 512);
                break;
            case 0x00004000:
                g_strlcat(flags_str, values->bit15, 512);
                break;
            case 0x00008000:
                g_strlcat(flags_str, values->bit16, 512);
                break;
            default:
                break;
            }
            sep = ", ";
        }
        bvalue = bvalue*2;
    }
    if(values->vlength==4)
    {
        tinew = proto_tree_add_uint_format(ncp_tree, values->hfname,
                                           tvb, values->voffset, values->vlength, values->vvalue, "%s 0x%08x",
                                           values->vdesc, values->vvalue);
    }
    else
    {
        tinew = proto_tree_add_uint_format(ncp_tree, values->hfname,
                                           tvb, values->voffset, values->vlength, values->vvalue, "%s 0x%04x",
                                           values->vdesc, values->vvalue);
    }
    if (flags_str[0] != '\0')
        proto_item_append_text(tinew, " - (%s)", flags_str);

    flags_tree = proto_item_add_subtree(tinew, ett_nds);

    bvalue = 0x00000001;

    for (i = 0 ; i < (values->vlength*8); i++ ) {
        if (values->vvalue & bvalue)
        {
            switch(bvalue)
            {
            case 0x00000001:
                proto_tree_add_item(flags_tree, values->bit1hfname, tvb, values->voffset, values->vlength, TRUE);
                break;
            case 0x00000002:
                proto_tree_add_item(flags_tree, values->bit2hfname, tvb, values->voffset, values->vlength, TRUE);
                break;
            case 0x00000004:
                proto_tree_add_item(flags_tree, values->bit3hfname, tvb, values->voffset, values->vlength, TRUE);
                break;
            case 0x00000008:
                proto_tree_add_item(flags_tree, values->bit4hfname, tvb, values->voffset, values->vlength, TRUE);
                break;
            case 0x00000010:
                proto_tree_add_item(flags_tree, values->bit5hfname, tvb, values->voffset, values->vlength, TRUE);
                break;
            case 0x00000020:
                proto_tree_add_item(flags_tree, values->bit6hfname, tvb, values->voffset, values->vlength, TRUE);
                break;
            case 0x00000040:
                proto_tree_add_item(flags_tree, values->bit7hfname, tvb, values->voffset, values->vlength, TRUE);
                break;
            case 0x00000080:
                proto_tree_add_item(flags_tree, values->bit8hfname, tvb, values->voffset, values->vlength, TRUE);
                break;
            case 0x00000100:
                proto_tree_add_item(flags_tree, values->bit9hfname, tvb, values->voffset, values->vlength, TRUE);
                break;
            case 0x00000200:
                proto_tree_add_item(flags_tree, values->bit10hfname, tvb, values->voffset, values->vlength, TRUE);
                break;
            case 0x00000400:
                proto_tree_add_item(flags_tree, values->bit11hfname, tvb, values->voffset, values->vlength, TRUE);
                break;
            case 0x00000800:
                proto_tree_add_item(flags_tree, values->bit12hfname, tvb, values->voffset, values->vlength, TRUE);
                break;
            case 0x00001000:
                proto_tree_add_item(flags_tree, values->bit13hfname, tvb, values->voffset, values->vlength, TRUE);
                break;
            case 0x00002000:
                proto_tree_add_item(flags_tree, values->bit14hfname, tvb, values->voffset, values->vlength, TRUE);
                break;
            case 0x00004000:
                proto_tree_add_item(flags_tree, values->bit15hfname, tvb, values->voffset, values->vlength, TRUE);
                break;
            case 0x00008000:
                proto_tree_add_item(flags_tree, values->bit16hfname, tvb, values->voffset, values->vlength, TRUE);
                break;
            default:
                break;
            }
        }
        bvalue = bvalue*2;
    }
}

/* NCP data from python code can't be accessed directly. Parse the ncp tree and find the items
 * and their associated values. Store results in passed buffer.
 */
static void
build_expert_data(proto_tree *ncp_tree, const char *hf_name, char *buffer,
                  size_t buffer_size, int repeat_lookup,
                  gboolean search_structs)
{
    proto_tree     *tree_pointer;
    proto_tree     *tree_loc;
    proto_tree     *struct_tree_pointer = NULL;
    char            temp_buffer[256]="\0";
    gboolean        in_struct=FALSE;

    tree_loc = ncp_tree->first_child;
    for (tree_pointer=tree_loc; tree_pointer!=NULL; tree_pointer=tree_pointer->next)
    {
        /* We currently only go one structure deep in our search for values */
        if (tree_pointer->first_child && !in_struct && search_structs) {
            struct_tree_pointer = tree_pointer;
            tree_pointer = tree_pointer->first_child;
            in_struct=TRUE;
        }
        if (strcmp(PTREE_FINFO(tree_pointer)->hfinfo->abbrev, hf_name)==0)
        {
            switch (PTREE_FINFO(tree_pointer)->hfinfo->type)
            {
            case 3:                /* uint8 */
            case 4:                /* uint16 */
                g_snprintf(buffer, (gulong) buffer_size, "%u", get_finfo_value_integer(PTREE_FINFO(tree_pointer)));
                break;

            case 6:             /* uint32 */
                g_snprintf(buffer, (gulong) buffer_size, "%08x", get_finfo_value_integer(PTREE_FINFO(tree_pointer)));
                break;
            case 17:
            case 18:
            case 19:
            case 20:            /* string */
                /* XXX: Should we verify: buffer_size is as large as value returned by get_finfo_length(...)  ???      */
                uni_to_string(get_finfo_value_string(PTREE_FINFO(tree_pointer)), get_finfo_length(PTREE_FINFO(tree_pointer)), buffer);
                if (repeat_lookup > 0) {
                    if (strlen(temp_buffer) + strlen(buffer) < 250) {
                        g_strlcat(temp_buffer, buffer, 256);
                        repeat_lookup--;
                        if (repeat_lookup == 0) {
                            g_strlcpy(buffer, temp_buffer, buffer_size);
                            break;
                        }
                        else
                        {
                            g_strlcat(temp_buffer, "/", 256);
                            break;
                        }
                    }
                    else
                    {
                        return;
                    }
                }
                else
                {
                    break;
                }
            case 21:
            case 22:             /* Bytes */
                g_snprintf(buffer, (gulong) buffer_size, "%s", bytes_to_str(get_finfo_value_string(PTREE_FINFO(tree_pointer)), get_finfo_length(PTREE_FINFO(tree_pointer))));
                break;
            default:             /* Dont currently handle. Only need string, integers, and bytes */
                g_snprintf(buffer, (gulong) buffer_size, "Unsupported Expert Type");
                return;
            }
            if (repeat_lookup ==0) {
                break;
            }
        }
        if (tree_pointer->next==NULL && in_struct && search_structs) {
                tree_pointer = struct_tree_pointer;
                in_struct=FALSE;
        }
    }
    if (strlen(buffer)==0) {
        g_snprintf(buffer, (gulong) buffer_size, "No Value");
    }
    return;
}

/* Some NCP data may be desirable to echo to the expert table.
 * But to extract we must have visability to the tree
 * This means that to extract the data we can only perform
 * this code path on the first dissection or a redissect.
 *
 * Should the dissector store this info in memory so that
 * the data can be reported wihout a complete redissection?
 */
static void
trap_for_expert_event(proto_tree *ncp_tree, packet_info *pinfo, const ncp_record *ncp_rec, int request_reply)
{
    if (ncp_rec == NULL)
        return;
    /* Request == 0, Reply == 1 */
    if (request_reply==0) {
        if (ncp_echo_file) {
            /* The following allows for Update file handle rights echoed to expert tap. */
            if (ncp_rec->func == 66) {
                char p_filehandle[15]="\0";

                build_expert_data(ncp_tree, "ncp.file_handle", p_filehandle,
                                  sizeof p_filehandle, 0, FALSE);

                expert_add_info_format(pinfo, NULL, PI_REQUEST_CODE, PI_CHAT, "Close file handle %s", p_filehandle);
            }
            /* The following allows for oplock level 1 file opens echoed to expert tap. */
            if ((ncp_rec->func == 89 || ncp_rec->func == 87) && (ncp_rec->subfunc == 1 || ncp_rec->subfunc == 30 || ncp_rec->subfunc == 32 || ncp_rec->subfunc == 33)) {
                char oaction[3]="\0";
                char p_filename[256]="\0";
                char p_rights[3]="\0";
                char p_path_count[3]="\0";

                build_expert_data(ncp_tree, "ncp.open_create_mode", oaction,
                                  sizeof oaction, 0, FALSE);
                build_expert_data(ncp_tree, "ncp.desired_access_rights",
                                  p_rights, sizeof p_rights, 0, FALSE);
                build_expert_data(ncp_tree, "ncp.path_count", p_path_count,
                                  sizeof p_path_count, 0, FALSE);

                if (ncp_rec->func == 87) {
                    build_expert_data(ncp_tree, "ncp.path", p_filename,
                                      sizeof p_filename,  atoi(p_path_count),
                                      FALSE);
                }
                else
                {
                    build_expert_data(ncp_tree, "ncp.path16", p_filename,
                                      sizeof p_filename,  atoi(p_path_count),
                                      FALSE);
                }

                expert_add_info_format(pinfo, NULL, PI_REQUEST_CODE, PI_CHAT, "%s: %s, Rights:(%s)",
                                       val_to_str((strtoul(oaction, NULL, 16) & 0xeb), open_create_mode_vals, "Unknown: %d"),
                                       p_filename,
                                       val_to_str((atoi(p_rights) & 0x5f), ncp_rights_vals, "Unknown: %d"));
            }
            /* The following allows for oplock ack's and level 2 request echoed to expert tap. */
            if (ncp_rec->func == 87 && ncp_rec->subfunc == 34) {
                char cc_function[3]="\0";
                char p_filehandle[15]="\0";

                build_expert_data(ncp_tree, "ncp.cc_file_handle",
                                  p_filehandle, sizeof p_filehandle, 0, FALSE);
                build_expert_data(ncp_tree, "ncp.cc_function",
                                  cc_function, sizeof cc_function, 0, FALSE);

                expert_add_info_format(pinfo, NULL, PI_REQUEST_CODE, PI_CHAT, "Op-lock on handle %s - %s", p_filehandle,
                                       val_to_str(atoi(cc_function), ncp_cc_function_vals, "Unknown: %d"));
            }
            /* The following allows for Update file handle rights echoed to expert tap. */
            if (ncp_rec->func == 87 && ncp_rec->subfunc == 44) {
                char p_rights[20]="\0";
                char n_rights[20]="\0";
                char p_filehandle[15]="\0";

                build_expert_data(ncp_tree, "ncp.file_handle",
                                  p_filehandle, sizeof p_filehandle, 0, FALSE);
                build_expert_data(ncp_tree, "ncp.access_rights_mask_word",
                                  p_rights, sizeof p_rights, 0, FALSE);
                build_expert_data(ncp_tree, "ncp.new_access_rights_mask",
                                  n_rights, sizeof n_rights, 0, FALSE);
                expert_add_info_format(pinfo, NULL, PI_REQUEST_CODE, PI_CHAT, "Change handle %s rights from:(%s) to:(%s)",
                                       p_filehandle,
                                       val_to_str((atoi(p_rights) & 0x1ff), access_rights_vals, "Unknown: %d"),
                                       val_to_str((atoi(n_rights) & 0x1ff), access_rights_vals, "Unknown: %d"));
            }
        }
    }
    else
    {

        if (ncp_echo_file) { /* Echo File System Data */
            /* The following allows for oplock level 1 file opens echoed to expert tap. */
            if ((ncp_rec->func == 89 || ncp_rec->func == 87) && (ncp_rec->subfunc == 32 || ncp_rec->subfunc == 1)) {
                char oaction[3]="\0";
                char oplockflg[3]="\0";
                char p_filehandle[15]="\0";

                build_expert_data(ncp_tree, "ncp.open_create_action",
                                  oaction, sizeof oaction, 0, FALSE);
                build_expert_data(ncp_tree, "ncp.file_handle",
                                  p_filehandle, sizeof p_filehandle, 0, FALSE);

                if (ncp_rec->subfunc == 1) {
                    expert_add_info_format(pinfo, NULL, PI_RESPONSE_CODE, PI_CHAT, "%s - File handle %s",
                                           val_to_str((atoi(oaction) & 0x8f), open_create_action_vals, "Unknown: %d"),
                                           p_filehandle);
                }
                else
                {
                    build_expert_data(ncp_tree, "ncp.o_c_ret_flags",
                                      oplockflg, sizeof oplockflg, 0, FALSE);
                    expert_add_info_format(pinfo, NULL, PI_RESPONSE_CODE, PI_CHAT, "%s - File handle %s, %s",
                                           val_to_str((atoi(oaction) & 0x8f), open_create_action_vals, "Unknown: %d"),
                                           p_filehandle,
                                           val_to_str(atoi(oplockflg), ncp_o_c_ret_flags_vals, "Unknown: %d"));
                }
            }
            /* The following allows for Update file handle rights echoed to expert tap. */
            if (ncp_rec->func == 87 && ncp_rec->subfunc == 44) {
                char p_rights[20]="\0";
                char p_filehandle[15]="\0";

                build_expert_data(ncp_tree, "ncp.file_handle",
                                  p_filehandle, sizeof p_filehandle, 0, FALSE);
                build_expert_data(ncp_tree, "ncp.effective_rights",
                                  p_rights, sizeof p_rights, 0, FALSE);
                expert_add_info_format(pinfo, NULL, PI_RESPONSE_CODE, PI_CHAT, "Handle %s effective rights:(%s)", p_filehandle,
                                       val_to_str((atoi(p_rights) & 0x1ff), access_rights_vals, "Unknown: %d"));
            }
        }
        /* The following allows for specific NCP server info to be echoed to the expert tap. */
        if (ncp_rec->func == 23 && ncp_rec->subfunc == 17 && ncp_echo_server) {
            char fsname[50]="\0";
            char p_maj_ver[3]="\0";
            char p_min_ver[3]="\0";
            char p_rev[3]="\0";
            char p_lang[3]="\0";
			char p_serv_type[3]="\0";
			char p_kernel[3]="\0";

            /* Get Server name and version info */
            build_expert_data(ncp_tree, "ncp.server_name",
                              fsname, sizeof fsname, 0, FALSE);
            build_expert_data(ncp_tree, "ncp.product_major_version",
                              p_maj_ver, sizeof p_maj_ver, 0, FALSE);
            build_expert_data(ncp_tree, "ncp.product_minor_version",
                              p_min_ver, sizeof p_min_ver, 0, FALSE);
            build_expert_data(ncp_tree, "ncp.product_revision_version",
                              p_rev, sizeof p_rev, 0, FALSE);
            build_expert_data(ncp_tree, "ncp.os_language_id",
                              p_lang, sizeof p_lang, 0, FALSE);
            build_expert_data(ncp_tree, "ncp.oes_server",
                              p_serv_type, sizeof p_serv_type, 0, FALSE);
            build_expert_data(ncp_tree, "ncp.oeslinux_or_netware",
                              p_kernel, sizeof p_kernel, 0, FALSE);

            expert_add_info_format(pinfo, NULL, PI_RESPONSE_CODE, PI_CHAT, "Server %s, version %s.%s, support pack %s, language %s, server type %s, kernel %s", fsname,
                                   p_maj_ver, p_min_ver, p_rev, p_lang, val_to_str((atoi(p_serv_type) & 0x01), serv_type_vals, "Unknown: %d"), val_to_str((atoi(p_kernel) & 0x01), kernel_type_vals, "Unknown: %d") );
        }
    }
}


static void
print_nds_values(proto_tree *vtree, tvbuff_t *tvb, guint32 syntax_type, nds_val *vvalues)
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
    guint16         rtype = 0;
    guint16         rstate = 0;
    guint16         rnum = 0;
    guint16         revent = 0;
    gint            length_remaining;
    nstime_t        ns;
    gboolean        entry_rights = FALSE;
    nds_val         temp_values;

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
            proto_tree_add_text(nvtree, tvb, 0, 0, "[ Invalid offset: %u ]", voffset);
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
            tvb_ensure_bytes_exist(tvb, voffset, 1);
            proto_tree_add_string(nvtree, hf_value_string, tvb, voffset,
                                  1, vvalues->vstring);
            voffset=voffset+1;
            voffset += align_4(tvb, voffset);
            break;
        case 0x00000009:        /* Binary String */
            value1 = tvb_get_letohl(tvb, voffset); /* length of field */
            length_remaining = tvb_length_remaining(tvb, voffset);
            if(length_remaining == -1 || value1 > (guint32) length_remaining)
            {
                break;
            }
            voffset += 4;
            tvb_ensure_bytes_exist(tvb, voffset, value1);
            proto_tree_add_bytes(nvtree, hf_value_bytes, tvb, voffset, value1, tvb_get_ptr(tvb, voffset, value1));
            voffset += value1;
            voffset += (value1%2);
            break;
        case 0x0000000d:        /* Binary String List */
            value1 = tvb_get_letohl(tvb, voffset); /* Overall length of field list */
            length_remaining = tvb_length_remaining(tvb, voffset);
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
                length_remaining = tvb_length_remaining(tvb, voffset);
                if(length_remaining == -1 || value1 > (guint32) length_remaining)
                {
                    break;
                }
                voffset += 4;
                tvb_ensure_bytes_exist(tvb, voffset, value1);
                proto_tree_add_bytes(nvtree, hf_value_bytes, tvb, voffset, value1, tvb_get_ptr(tvb, voffset, value1));
                voffset += value1;
                voffset += (value1%2);
            }
            break;
        case 0x00000015:        /* Stream */
            value1 = tvb_get_letohl(tvb, voffset); /* length of field */
            length_remaining = tvb_length_remaining(tvb, voffset);
            if(length_remaining == -1 || value1 > (guint32) length_remaining)
            {
                break;
            }
            proto_tree_add_text(nvtree, tvb, voffset, 4, "No value, Open stream file for data.");
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
            tvb_ensure_bytes_exist(tvb, voffset, value1);
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
            tvb_ensure_bytes_exist(tvb, voffset, value1);
            proto_tree_add_uint_format(nvtree, hf_nds_uint32value, tvb, voffset,
                                       value1, value2, valuestr, value2);
            voffset = voffset+4;
            value3 = tvb_get_letohl(tvb, voffset); /* length of address */
            voffset = voffset+4;
            switch (value2)
            {
            case NDS_PTYPE_IPX:
                proto_tree_add_item(nvtree, hf_nds_net, tvb, voffset, 4, FALSE);
                proto_tree_add_item(nvtree, hf_nds_node, tvb, voffset+4, 6, FALSE);
                proto_tree_add_item(nvtree, hf_nds_socket, tvb, voffset+10, 2, FALSE);
                break;
            case NDS_PTYPE_IP:
                if (value3 > 4) {
                    proto_tree_add_item(nvtree, hf_nds_port, tvb, voffset, 2, FALSE);
                    voffset += 2;
                }
                proto_tree_add_item(nvtree, hf_add_ref_ip, tvb, voffset, 4, FALSE);
                break;
            case NDS_PTYPE_UDP:
                if (value3 > 4) {
                    proto_tree_add_item(nvtree, hf_nds_port, tvb, voffset, 2, FALSE);
                    voffset += 2;
                }
                proto_tree_add_item(nvtree, hf_add_ref_udp, tvb, voffset, 4, FALSE);
                break;
            case NDS_PTYPE_TCP:
                proto_tree_add_item(nvtree, hf_nds_port, tvb, voffset, 2, FALSE);
                proto_tree_add_item(nvtree, hf_add_ref_tcp, tvb, voffset+2, 4, FALSE);
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
            value1 = tvb_get_letohl(tvb, voffset); /* length of field */
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
            value1 = tvb_get_letohl(tvb, voffset); /* length of field */
            voffset = voffset + 4;
            value2 = tvb_get_letohl(tvb, voffset); /* Length of Server name */
            voffset = voffset+4;
            vvalues->vstring = get_string(tvb, voffset, value2);
            proto_tree_add_string(nvtree, hf_value_string, tvb, voffset,
                                  value2, vvalues->vstring);
            voffset = voffset+value2;
            voffset += align_4(tvb, voffset);
            rtype = tvb_get_letohs(tvb, voffset); /* replica type */
            valuestr = val_to_str_const(rtype, nds_replica_type, "(Unknown Replica Type)");
            proto_tree_add_string(nvtree, hf_replica_type, tvb, voffset,
                                  2, valuestr);
            voffset = voffset+2;
            rstate = tvb_get_letohs(tvb, voffset); /* replica state */
            valuestr = val_to_str_const(rstate, nds_replica_state, "(Unknown Replica State)");
            proto_tree_add_string(nvtree, hf_replica_state, tvb, voffset,
                                  2, valuestr);
            voffset = voffset+2;
            value3 = tvb_get_letohl(tvb, voffset); /* Replica number */
            proto_tree_add_uint_format(nvtree, hf_replica_number, tvb, voffset,
                                       4, value3, "Replica Number %d", value3);
            voffset = voffset+4;
            if((vvalues->pflags & 0x8000) | (vvalues->pflags & 0x4000))
            {
                /* If this request flag is set then this is a server. Server structures
                 * include the RootID as part of the replica data. */
                proto_tree_add_item(nvtree, hf_nds_partition_root_id, tvb, voffset, 4, FALSE);
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
                if(tvb_length_remaining(tvb, voffset)<12)
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
                    proto_tree_add_item(adtree, hf_nds_net, tvb, voffset, 4, FALSE);
                    proto_tree_add_item(adtree, hf_nds_node, tvb, voffset+4, 6, FALSE);
                    proto_tree_add_item(adtree, hf_nds_socket, tvb, voffset+10, 2, FALSE);
                    break;
                case NDS_PTYPE_IP:
                    proto_tree_add_item(adtree, hf_nds_port, tvb, voffset, 2, FALSE);
                    proto_tree_add_item(adtree, hf_add_ref_ip, tvb, voffset+2, 4, FALSE);
                    break;
                case NDS_PTYPE_UDP:
                    proto_tree_add_item(adtree, hf_nds_port, tvb, voffset, 2, FALSE);
                    proto_tree_add_item(adtree, hf_add_ref_udp, tvb, voffset+2, 4, FALSE);
                    break;
                case NDS_PTYPE_TCP:
                    proto_tree_add_item(adtree, hf_nds_port, tvb, voffset, 2, FALSE);
                    proto_tree_add_item(adtree, hf_add_ref_tcp, tvb, voffset+2, 4, FALSE);
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
            value1 = tvb_get_letohl(tvb, voffset); /* Length of Field */
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
            temp_values.vvalue = tvb_get_letohl(tvb, voffset); /* Entry or Attribute Privileges */
            temp_values.vlength = 2;
            temp_values.hfname = hf_nds_vflags;
            temp_values.voffset = voffset;
            temp_values.vdesc = "Privileges";
            if (entry_rights) {
                /* if Entries then use these bits */
                temp_values.bit1 = "Compare Attributes";
                temp_values.bit1hfname = hf_nds_compare_attributes;
                temp_values.bit2 = "Read Attribute";
                temp_values.bit2hfname = hf_nds_read_attribute;
                temp_values.bit3 = "Write, Add, Delete Attribute";
                temp_values.bit3hfname = hf_nds_write_add_delete_attribute;
                temp_values.bit4 = "Add/Delete Self";
                temp_values.bit4hfname = hf_nds_add_delete_self;
                temp_values.bit5 = "Attribute Privilege Not Defined";
                temp_values.bit5hfname = hf_nds_privilege_not_defined;
                temp_values.bit6 = "Supervisor";
                temp_values.bit6hfname = hf_nds_supervisor;
                temp_values.bit7 = "Inheritance Control";
                temp_values.bit7hfname = hf_nds_inheritance_control;
                temp_values.bit8 = "Not Defined";
                temp_values.bit8hfname = hf_bit8vflags;
                temp_values.bit9 = "Not Defined";
                temp_values.bit9hfname = hf_bit9vflags;
                temp_values.bit10 = "Not Defined";
                temp_values.bit10hfname = hf_bit10vflags;
                temp_values.bit11 = "Not Defined";
                temp_values.bit11hfname = hf_bit11vflags;
                temp_values.bit12 = "Not Defined";
                temp_values.bit12hfname = hf_bit12vflags;
                temp_values.bit13 = "Not Defined";
                temp_values.bit13hfname = hf_bit13vflags;
                temp_values.bit14 = "Not Defined";
                temp_values.bit14hfname = hf_bit14vflags;
                temp_values.bit15 = "Not Defined";
                temp_values.bit15hfname = hf_bit15vflags;
                temp_values.bit16 = "Not Defined";
                temp_values.bit16hfname = hf_bit16vflags;
            }
            else
            {
                /* if attribute rights then do these bits */
                temp_values.bit1 = "Browse";
                temp_values.bit1hfname = hf_nds_browse_entry;
                temp_values.bit2 = "Add";
                temp_values.bit2hfname = hf_nds_add_entry;
                temp_values.bit3 = "Delete";
                temp_values.bit3hfname = hf_nds_delete_entry;
                temp_values.bit4 = "Rename";
                temp_values.bit4hfname = hf_nds_rename_entry;
                temp_values.bit5 = "Supervisor";
                temp_values.bit5hfname = hf_nds_supervisor_entry;
                temp_values.bit6 = "Entry Privilege Not Defined";
                temp_values.bit6hfname = hf_nds_entry_privilege_not_defined;
                temp_values.bit7 = "Inheritance Control";
                temp_values.bit7hfname = hf_nds_inheritance_control;
                temp_values.bit8 = "Not Defined";
                temp_values.bit8hfname = hf_bit8vflags;
                temp_values.bit9 = "Not Defined";
                temp_values.bit9hfname = hf_bit9vflags;
                temp_values.bit10 = "Not Defined";
                temp_values.bit10hfname = hf_bit10vflags;
                temp_values.bit11 = "Not Defined";
                temp_values.bit11hfname = hf_bit11vflags;
                temp_values.bit12 = "Not Defined";
                temp_values.bit12hfname = hf_bit12vflags;
                temp_values.bit13 = "Not Defined";
                temp_values.bit13hfname = hf_bit13vflags;
                temp_values.bit14 = "Not Defined";
                temp_values.bit14hfname = hf_bit14vflags;
                temp_values.bit15 = "Not Defined";
                temp_values.bit15hfname = hf_bit15vflags;
                temp_values.bit16 = "Not Defined";
                temp_values.bit16hfname = hf_bit16vflags;
            }
            process_bitfield(nvtree, tvb, &temp_values);
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
            proto_tree_add_time_format(nvtree, hf_nds_ds_time, tvb, voffset, 4, &ns, "Timestamp: %s", abs_time_secs_to_str(ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
            voffset = voffset + 4;
            rnum = tvb_get_letohs(tvb, voffset); /* replica number */
            proto_tree_add_uint_format(nvtree, hf_nds_rnum, tvb, voffset,
                                       2, rnum, "Replica Number: %d", rnum);
            voffset = voffset+2;
            revent = tvb_get_letohs(tvb, voffset); /* Event */
            proto_tree_add_uint_format(nvtree, hf_nds_revent, tvb, voffset,
                                       2, revent, "Event: %d", revent);
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
            proto_tree_add_time_format(nvtree, hf_nds_ds_time, tvb, voffset, 4, &ns, "Time: %s", abs_time_secs_to_str(ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
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
    guint16         replica_num;
    guint16         event_num;
    proto_tree      *nestree;
    proto_item      *nesitem;
    proto_tree      *sub1tree;
    proto_item      *sub1item;
    proto_tree      *sub2tree;
    proto_item      *sub2item;
    const char      *vstring="";
    nstime_t        ns;

    switch (vtype)
    {
    case 0: /* No Specifier Type */
        value1 = tvb_get_letohl(tvb, ioffset);   /* ES Type */
        proto_tree_add_item(estree, hf_es_value, tvb, ioffset,
                            4, value1);
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
            value2 = tvb_get_letohl(tvb, ioffset);   /* ES Type */
            proto_tree_add_item(nestree, hf_es_value, tvb, ioffset,
                                4, value2);
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
                                4, value2);
            ioffset = ioffset + 4;
            for (r = 1 ; r <= value2; r++ )
            {
                ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                ns.nsecs = 0;
                proto_tree_add_time_format(nestree, hf_es_seconds, tvb, ioffset,
                                           4, &ns, "Timestamp: %s", abs_time_secs_to_str(ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                ioffset = ioffset + 4;
                replica_num = tvb_get_letohs(tvb, ioffset);   /* Replica */
                proto_tree_add_item(nestree, hf_nds_replica_num, tvb, ioffset,
                                    2, replica_num);
                ioffset = ioffset + 2;
                event_num = tvb_get_letohs(tvb, ioffset);   /* Event */
                proto_tree_add_item(nestree, hf_nds_event_num, tvb, ioffset,
                                    2, event_num);
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
            value1 = tvb_get_letohl(tvb, ioffset);   /* ES Type */
            /* XXX: nestree rather than estree ?? */
            proto_tree_add_item(estree, hf_es_value, tvb, ioffset,
                                4, value1);
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
            value2 = tvb_get_letohl(tvb, ioffset);   /* ES Type */
            proto_tree_add_item(nestree, hf_es_value, tvb, ioffset,
                                4, value2);
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
                                4, value2);
            ioffset = ioffset + 4;
            for (r = 1 ; r <= value2; r++ )
            {
                ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                ns.nsecs = 0;
                proto_tree_add_time_format(nestree, hf_es_seconds, tvb, ioffset,
                                           4, &ns, "Timestamp: %s", abs_time_secs_to_str(ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                ioffset = ioffset + 4;
                replica_num = tvb_get_letohs(tvb, ioffset);   /* Replica */
                proto_tree_add_item(nestree, hf_nds_replica_num, tvb, ioffset,
                                    2, replica_num);
                ioffset = ioffset + 2;
                event_num = tvb_get_letohs(tvb, ioffset);   /* Event */
                proto_tree_add_item(nestree, hf_nds_event_num, tvb, ioffset,
                                    2, event_num);
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
            value1 = tvb_get_letohl(tvb, ioffset);   /* ES Type */
            /* XXX: nestree rather than estree ?? */
            proto_tree_add_item(estree, hf_es_value, tvb, ioffset,
                                4, value1);
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

            value1 = tvb_get_letohl(tvb, ioffset);

            proto_tree_add_uint_format(sub1tree, hf_referral_addcount, tvb, ioffset, 4,
                                       value1, "Number of Addresses in Referral - %u", value1);

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
                    proto_tree_add_item(sub1tree, hf_nds_net, tvb, ioffset, 4, FALSE);
                    proto_tree_add_item(sub1tree, hf_nds_node, tvb, ioffset+4, 6, FALSE);
                    proto_tree_add_item(sub1tree, hf_nds_socket, tvb, ioffset+10, 2, FALSE);
                    break;
                case NDS_PTYPE_IP:
                    proto_tree_add_item(sub1tree, hf_nds_port, tvb, ioffset, 2, FALSE);
                    proto_tree_add_item(sub1tree, hf_add_ref_ip, tvb, ioffset+2, 4, FALSE);
                    break;
                case NDS_PTYPE_UDP:
                    proto_tree_add_item(sub1tree, hf_nds_port, tvb, ioffset, 2, FALSE);
                    proto_tree_add_item(sub1tree, hf_add_ref_udp, tvb, ioffset+2, 4, FALSE);
                    break;
                case NDS_PTYPE_TCP:
                    proto_tree_add_item(sub1tree, hf_nds_port, tvb, ioffset, 2, FALSE);
                    proto_tree_add_item(sub1tree, hf_add_ref_tcp, tvb, ioffset+2, 4, FALSE);
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
            value2 = tvb_get_letohl(tvb, ioffset);   /* ES Type */
            proto_tree_add_item(nestree, hf_es_value, tvb, ioffset,
                                4, value2);
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
                                4, value2);
            ioffset = ioffset + 4;
            for (r = 1 ; r <= value2; r++ )
            {
                ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                ns.nsecs = 0;
                proto_tree_add_time_format(nestree, hf_es_seconds, tvb, ioffset,
                                           4, &ns, "Timestamp: %s", abs_time_secs_to_str(ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                ioffset = ioffset + 4;
                replica_num = tvb_get_letohs(tvb, ioffset);   /* Replica */
                proto_tree_add_item(nestree, hf_nds_replica_num, tvb, ioffset,
                                    2, replica_num);
                ioffset = ioffset + 2;
                event_num = tvb_get_letohs(tvb, ioffset);   /* Event */
                proto_tree_add_item(nestree, hf_nds_event_num, tvb, ioffset,
                                    2, event_num);
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
            value1 = tvb_get_letohl(tvb, ioffset);   /* ES Type */
            /* XXX: nestree rather than estree ?? */
            proto_tree_add_item(estree, hf_es_value, tvb, ioffset,
                                4, value1);
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
            sub2item = proto_tree_add_text(sub1tree, tvb, ioffset, 0, "Item %u", r);
            sub2tree = proto_item_add_subtree(sub2item, ett_nds);

            ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
            ns.nsecs = 0;
            proto_tree_add_time_format(sub2tree, hf_es_seconds, tvb, ioffset,
                                       4, &ns, "Timestamp: %s", abs_time_secs_to_str(ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
            ioffset = ioffset + 4;
            replica_num = tvb_get_letohs(tvb, ioffset);   /* Replica */
            proto_tree_add_item(sub2tree, hf_nds_replica_num, tvb, ioffset,
                                2, replica_num);
            ioffset = ioffset + 2;
            event_num = tvb_get_letohs(tvb, ioffset);   /* Event */
            proto_tree_add_item(sub2tree, hf_nds_event_num, tvb, ioffset,
                                2, event_num);
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
        value1 = tvb_get_letohl(tvb, ioffset);   /* ES Type */
        proto_tree_add_item(estree, hf_es_value, tvb, ioffset,
                            4, value1);
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
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        values->vstring = val_to_str_const(values->vvalue, nds_syntax, "No Syntax Found");
        proto_tree_add_string(it_tree, hf_nds_syntax, tvb, ioffset,
                                  4, values->vstring);
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
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        values->vstring = val_to_str_const(values->vvalue, nds_syntax, "No Syntax Found");
        proto_tree_add_string(it_tree, hf_nds_syntax, tvb, ioffset,
                              4, values->vstring);
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
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        values->vstring = val_to_str_const(values->vvalue, nds_syntax, "No Syntax Found");
        proto_tree_add_string(it_tree, hf_nds_syntax, tvb, ioffset,
                              4, values->vstring);
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
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        values->vstring = val_to_str_const(values->vvalue, nds_syntax, "No Syntax Found");
        proto_tree_add_string(it_tree, hf_nds_syntax, tvb, ioffset,
                              4, values->vstring);
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
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        values->vstring = val_to_str_const(values->vvalue, nds_syntax, "No Syntax Found");
        proto_tree_add_string(it_tree, hf_nds_syntax, tvb, ioffset,
                              4, values->vstring);
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
        if (tvb_length_remaining(tvb, ioffset) < 4) {
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
    proto_item  *it_subitem, *it_subitem1;
    guint32     i, ioffset, number_of_items;

    ioffset = values->voffset;
    if (values->vvalue != NDS_SEARCH_NOT) {
        number_of_items = tvb_get_letohl(tvb, ioffset);
        it_subitem = proto_tree_add_item(it_tree, hf_this_count, tvb, ioffset, 4, TRUE);
        it_subtree = proto_item_add_subtree(it_subitem, ett_nds);
        ioffset += 4;
        for (i = 0; i < number_of_items; i++)
        {
            it_subitem1 = proto_tree_add_text(it_subtree, tvb, ioffset, -1, "Item #: %u", i+1);
            it_subtree1 = proto_item_add_subtree(it_subitem1, ett_nds);

            values->voffset = ioffset;
            process_set_filter(it_subtree1, tvb, pinfo, values);
            ioffset = values->voffset;

            if (tvb_length_remaining(tvb, ioffset) < 4) {
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
    proto_tree_add_item(it_tree, hf_nds_oid, tvb, ioffset, values->vvalue, TRUE);
    ioffset += values->vvalue;

    ioffset += align_4(tvb, ioffset);

    proto_tree_add_item(it_tree, hf_iter_ans, tvb, ioffset, 4, TRUE);
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
    values->vvalue = tvb_get_letohl(tvb, ioffset);
    values->vstring = val_to_str_const(values->vvalue, nds_syntax, "No Syntax Found");
    proto_tree_add_string(it_tree, hf_nds_syntax, tvb, ioffset,
    4, values->vstring);
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
        if (tvb_length_remaining(tvb, ioffset) < 4) {
            THROW(ReportedBoundsError);
        }
        break;
    }
    ioffset = values->voffset;
    return;
}

static void
process_entry_info(proto_tree *it_tree, tvbuff_t *tvb, nds_val *values)
{
    guint32     iter_flags, ioffset = values->voffset;
    guint16     replica_num, event_num;
    nstime_t    ns;

    values->vstring = NULL;
    ioffset += align_4(tvb, ioffset);
    iter_flags = tvb_get_letohl(tvb, ioffset);


    if (iter_flags & DSI_OUTPUT_FIELDS) { /* Output Flags */
        values->vvalue = tvb_get_letohs(tvb, ioffset);
        values->vdesc = "Return Information Flags (low) Byte:";
        values->vlength = 2;
        values->hfname = hf_nds_rflags;
        values->voffset = ioffset;
        values->bit1 = "Output Flags";
        values->bit1hfname = hf_bit1infoflagsl;
        values->bit2 = "Entry ID";
        values->bit2hfname = hf_bit2infoflagsl;
        values->bit3 = "Entry Flags";
        values->bit3hfname = hf_bit3infoflagsl;
        values->bit4 = "Subordinate Count";
        values->bit4hfname = hf_bit4infoflagsl;
        values->bit5 = "Modification Time";
        values->bit5hfname = hf_bit5infoflagsl;
        values->bit6 = "Modification Timestamp";
        values->bit6hfname = hf_bit6infoflagsl;
        values->bit7 = "Creation Timestamp";
        values->bit7hfname = hf_bit7infoflagsl;
        values->bit8 = "Partition Root ID";
        values->bit8hfname = hf_bit8infoflagsl;
        values->bit9 = "Parent ID";
        values->bit9hfname = hf_bit9infoflagsl;
        values->bit10 = "Revision Count";
        values->bit10hfname = hf_bit10infoflagsl;
        values->bit11 = "Replica Type";
        values->bit11hfname = hf_bit11infoflagsl;
        values->bit12 = "Base Class";
        values->bit12hfname = hf_bit12infoflagsl;
        values->bit13 = "Relative Distinguished Name";
        values->bit13hfname = hf_bit13infoflagsl;
        values->bit14 = "Distinguished Name";
        values->bit14hfname = hf_bit14infoflagsl;
        values->bit15 = "Root Distinguished Name";
        values->bit15hfname = hf_bit15infoflagsl;
        values->bit16 = "Parent Distinguished Name";
        values->bit16hfname = hf_bit16infoflagsl;
        process_bitfield(it_tree, tvb, values);
        ioffset = ioffset+2;

        values->vvalue = tvb_get_letohs(tvb, ioffset);
        values->vtype = VTYPE_BITFIELD;
        values->vdesc = "Return Information Flags (high) Byte:";
        values->vlength = 2;
        values->hfname= hf_nds_rflags;
        values->voffset = ioffset;
        values->bit1 = "Purge Time";
        values->bit1hfname = hf_bit1infoflagsh;
        values->bit2 = "Dereference Base Class";
        values->bit2hfname = hf_bit2infoflagsh;
        values->bit3 = "Replica Number";
        values->bit3hfname = hf_bit3infoflagsh;
        values->bit4 = "Replica State";
        values->bit4hfname = hf_bit4infoflagsh;
        values->bit5 = "Federation Boundary";
        values->bit5hfname = hf_bit5infoflagsh;
        values->bit6 = "Schema Boundary";
        values->bit6hfname = hf_bit6infoflagsh;
        values->bit7 = "Federation Boundary ID";
        values->bit7hfname = hf_bit7infoflagsh;
        values->bit8 = "Schema Boundary ID";
        values->bit8hfname = hf_bit8infoflagsh;
        values->bit9 = "Current Subcount";
        values->bit9hfname = hf_bit9infoflagsh;
        values->bit10 = "Local Entry Flags";
        values->bit10hfname = hf_bit10infoflagsh;
        values->bit11 = "Not Defined";
        values->bit11hfname = hf_bit11infoflagsh;
        values->bit12 = "Not Defined";
        values->bit12hfname = hf_bit12infoflagsh;
        values->bit13 = "Not Defined";
        values->bit13hfname = hf_bit13infoflagsh;
        values->bit14 = "Not Defined";
        values->bit14hfname = hf_bit14infoflagsh;
        values->bit15 = "Not Defined";
        values->bit15hfname = hf_bit15infoflagsh;
        values->bit16 = "Not Defined";
        values->bit16hfname = hf_bit16infoflagsh;
        process_bitfield(it_tree, tvb, values);
        ioffset = ioffset+2;
    }
    if (iter_flags & DSI_ENTRY_ID) { /* Entry ID */
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        proto_tree_add_uint_format(it_tree, hf_nds_eid, tvb, ioffset,
                4, values->vvalue, "Entry ID 0x%08x", values->vvalue);
        ioffset = ioffset + 4;
    }
    if (iter_flags & DSI_ENTRY_FLAGS) { /* Entry Flags */
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        values->vtype = VTYPE_BITFIELD;
        values->vdesc = "Entry Flags:";
        values->vlength = 2;
        values->hfname= hf_nds_eflags;
        values->voffset = ioffset;
        values->bit1 = "Alias Entry";
        values->bit1hfname = hf_bit1eflags;
        values->bit2 = "Partition Root";
        values->bit2hfname = hf_bit2eflags;
        values->bit3 = "Container Entry";
        values->bit3hfname = hf_bit3eflags;
        values->bit4 = "Container Alias";
        values->bit4hfname = hf_bit4eflags;
        values->bit5 = "Matches List Filter";
        values->bit5hfname = hf_bit5eflags;
        values->bit6 = "Reference Entry";
        values->bit6hfname = hf_bit6eflags;
        values->bit7 = "40x Reference Entry";
        values->bit7hfname = hf_bit7eflags;
        values->bit8 = "Back Linked";
        values->bit8hfname = hf_bit8eflags;
        values->bit9 = "New Entry";
        values->bit9hfname = hf_bit9eflags;
        values->bit10 = "Temporary Reference";
        values->bit10hfname = hf_bit10eflags;
        values->bit11 = "Audited";
        values->bit11hfname = hf_bit11eflags;
        values->bit12 = "Entry Not Present";
        values->bit12hfname = hf_bit12eflags;
        values->bit13 = "Entry Verify CTS";
        values->bit13hfname = hf_bit13eflags;
        values->bit14 = "Entry Damaged";
        values->bit14hfname = hf_bit14eflags;
        values->bit15 = "Not Defined";
        values->bit15hfname = hf_bit15eflags;
        values->bit16 = "Not Defined";
        values->bit16hfname = hf_bit16eflags;
        process_bitfield(it_tree, tvb, values);
        ioffset = ioffset+4;
    }
    if (iter_flags & DSI_SUBORDINATE_COUNT) { /* Subordinate Count */
        proto_tree_add_item(it_tree, hf_sub_count, tvb, ioffset, 4, TRUE);
        ioffset += 4;
    }
    if (iter_flags & DSI_MODIFICATION_TIME) { /* Modification Time */
        ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
        ns.nsecs = 0;
        proto_tree_add_time_format(it_tree, hf_es_seconds, tvb, ioffset,
                4, &ns, "Modification Time: %s", abs_time_secs_to_str(ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
        ioffset = ioffset + 4;
    }
    if (iter_flags & DSI_MODIFICATION_TIMESTAMP) { /* Modification Timestamp */
        ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
        ns.nsecs = 0;
        proto_tree_add_time_format(it_tree, hf_es_seconds, tvb, ioffset,
                4, &ns, "Modification Timestamp: %s", abs_time_secs_to_str(ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
        ioffset = ioffset + 4;
        replica_num = tvb_get_letohs(tvb, ioffset);   /* Replica */
        proto_tree_add_item(it_tree, hf_nds_replica_num, tvb, ioffset,
                2, replica_num);
        ioffset = ioffset + 2;
        event_num = tvb_get_letohs(tvb, ioffset);   /* Event */
        proto_tree_add_item(it_tree, hf_nds_event_num, tvb, ioffset,
                2, event_num);
        ioffset = ioffset + 2;
    }
    if (iter_flags & DSI_CREATION_TIMESTAMP) { /* Creation Timestamp */
        ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
        ns.nsecs = 0;
        proto_tree_add_time_format(it_tree, hf_es_seconds, tvb, ioffset,
                4, &ns, "Creation Timestamp: %s", abs_time_secs_to_str(ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
        ioffset = ioffset + 4;
        replica_num = tvb_get_letohs(tvb, ioffset);   /* Replica */
        proto_tree_add_item(it_tree, hf_nds_replica_num, tvb, ioffset,
                2, replica_num);
        ioffset = ioffset + 2;
        event_num = tvb_get_letohs(tvb, ioffset);   /* Event */
        proto_tree_add_item(it_tree, hf_nds_event_num, tvb, ioffset,
                2, event_num);
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
        values->vstring = val_to_str_const(values->vvalue, nds_replica_type, "No Replica Type Found");
        proto_tree_add_string(it_tree, hf_replica_type, tvb, ioffset,
        4, values->vstring);
        values->vvalue = tvb_get_letohl(tvb, ioffset) & 0xff00;
        values->vstring = val_to_str_const(values->vvalue, nds_replica_state, "No Replica State Found");
        proto_tree_add_string(it_tree, hf_replica_state, tvb, ioffset,
        4, values->vstring);
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
    if (iter_flags & DSI_ENTRY_RDN) { /* Relative Distiguished Name */
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
        proto_tree_add_time_format(it_tree, hf_nds_purge, tvb, ioffset,
                4, &ns, "Purge Time: %s", abs_time_secs_to_str(ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
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
        values->vvalue = tvb_get_letohl(tvb, ioffset); /* Replica number */
        proto_tree_add_uint_format(it_tree, hf_replica_number, tvb, ioffset,
                 4, values->vvalue, "Replica Number %d", values->vvalue);
        ioffset = ioffset+4;
    }
    if (iter_flags & DSI_REPLICA_STATE) { /* Replica State */
        values->vvalue = tvb_get_letohl(tvb, ioffset) & 0xff00;
        values->vstring = val_to_str_const(values->vvalue, nds_replica_state, "No Replica State Found");
        proto_tree_add_string(it_tree, hf_replica_state, tvb, ioffset,
        4, values->vstring);
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
        values->vvalue = tvb_get_letohl(tvb, ioffset);
        values->vtype = VTYPE_BITFIELD;
        values->vdesc = "Local Entry Flags:";
        values->vlength = 2;
        values->hfname= hf_nds_eflags;
        values->voffset = ioffset;
        values->bit1 = "Alias Entry";
        values->bit1hfname = hf_bit1eflags;
        values->bit2 = "Partition Root";
        values->bit2hfname = hf_bit2eflags;
        values->bit3 = "Container Entry";
        values->bit3hfname = hf_bit3eflags;
        values->bit4 = "Container Alias";
        values->bit4hfname = hf_bit4eflags;
        values->bit5 = "Matches List Filter";
        values->bit5hfname = hf_bit5eflags;
        values->bit6 = "Reference Entry";
        values->bit6hfname = hf_bit6eflags;
        values->bit7 = "40x Reference Entry";
        values->bit7hfname = hf_bit7eflags;
        values->bit8 = "Back Linked";
        values->bit8hfname = hf_bit8eflags;
        values->bit9 = "New Entry";
        values->bit9hfname = hf_bit9eflags;
        values->bit10 = "Temporary Reference";
        values->bit10hfname = hf_bit10eflags;
        values->bit11 = "Audited";
        values->bit11hfname = hf_bit11eflags;
        values->bit12 = "Entry Not Present";
        values->bit12hfname = hf_bit12eflags;
        values->bit13 = "Entry Verify CTS";
        values->bit13hfname = hf_bit13eflags;
        values->bit14 = "Entry Damaged";
        values->bit14hfname = hf_bit14eflags;
        values->bit15 = "Not Defined";
        values->bit15hfname = hf_bit15eflags;
        values->bit16 = "Not Defined";
        values->bit16hfname = hf_bit16eflags;
        process_bitfield(it_tree, tvb, values);
        ioffset = ioffset+4;
    }
    values->voffset = ioffset;
    return;
}

static void
dissect_nds_iterator(proto_tree *it_tree, tvbuff_t *tvb, packet_info *pinfo, guint32 it_verb, guint32 request_flags, guint32 ioffset, gboolean request_reply)
{
    guint32     rcode, i, number_of_items, number_to_get;
    const char  *error_string, *verb_string;
    nds_val     values;
    proto_tree  *it_subtree, *it_subtree1;
    proto_item  *it_subitem, *it_subitem1;
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
        verb_string = val_to_str_const(it_verb, iterator_subverbs, "(No Iteration Verb Found)");
        it_subitem = proto_tree_add_uint_format(it_tree, hf_ncp_nds_iterverb, tvb, ioffset-4, 4,
            it_verb, "Iterator Verb: %d, (0x%04x), %s",
            it_verb, it_verb, verb_string);

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
                proto_tree_add_item(it_subtree, hf_timelimit, tvb, ioffset, 4, TRUE);
                ioffset += 4;
                proto_tree_add_item(it_subtree, hf_max_entries, tvb, ioffset, 4, TRUE);
                ioffset += 4;
                proto_tree_add_item(it_subtree, hf_move_position, tvb, ioffset, 4, TRUE);
                ioffset += 4;
                break;
            case IT_CREATE:
            case IT_CURRENT:
            case IT_DESTROY:
            case IT_DONE:
                break;
            case IT_FIRST:
                proto_tree_add_item(it_subtree, hf_timelimit, tvb, ioffset, 4, TRUE);
                ioffset += 4;
                break;
            case IT_GETPOSITION:
            case IT_ISPOSITIONABLE:
                break;
            case IT_LAST:
                proto_tree_add_item(it_subtree, hf_timelimit, tvb, ioffset, 4, TRUE);
                ioffset += 4;
                break;
            case IT_NEXT:
            case IT_PREV:
                proto_tree_add_item(it_subtree, hf_timelimit, tvb, ioffset, 4, TRUE);
                ioffset += 4;
                proto_tree_add_item(it_subtree, hf_num_to_get, tvb, ioffset, 4, TRUE);
                ioffset += 4;
                break;
            case IT_POSITION:
                proto_tree_add_item(it_subtree, hf_iter_position, tvb, ioffset, 4, TRUE);
                ioffset += 4;
                proto_tree_add_item(it_subtree, hf_timelimit, tvb, ioffset, 4, TRUE);
                ioffset += 4;
                break;
            case IT_POSITION_IT:
                proto_tree_add_item(it_subtree, hf_iter_other, tvb, ioffset, 4, TRUE);
                ioffset += 4;
                break;
            case IT_SETINDEX:
                proto_tree_add_item(it_subtree, hf_nds_number_of_items, tvb, ioffset, 4, TRUE);
                number_of_items = tvb_get_letohl(tvb, ioffset);
                ioffset += 4;
                for (i=0; i < number_of_items; i++) {
                    /* Process the attribute tag */
#if 0
                    values.vvalue = tvb_get_letohl(tvb, ioffset);
                    values.vstring = val_to_str_const(values.vvalue, nds_tags, "No Tags Set");
                    proto_tree_add_string(it_subtree, hf_nds_tag_string, tvb, ioffset, 4, values.vstring);
#endif
                    proto_tree_add_item(it_subtree, hf_iter_index, tvb, ioffset, 4, TRUE);
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
                    if (tvb_length_remaining(tvb, ioffset) < 4) {
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
                proto_tree_add_item(it_subtree, hf_timelimit, tvb, ioffset, 4, TRUE);
                ioffset += 4;
                proto_tree_add_item(it_subtree, hf_num_to_skip, tvb, ioffset, 4, TRUE);
                ioffset += 4;
                break;
            case IT_TYPEDOWN:
                proto_tree_add_item(it_subtree, hf_num_to_get, tvb, ioffset, 4, TRUE);
                number_to_get = tvb_get_letohl(tvb, ioffset);
                ioffset += 4;
                if (number_to_get == 0) {
                    values.vvalue = tvb_get_letohl(tvb, ioffset);
                    values.vstring = val_to_str_const(values.vvalue, nds_tags, "No Tags Set");
                    proto_tree_add_string(it_tree, hf_nds_tag_string, tvb, ioffset, 4, values.vstring);
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
                if (tvb_length_remaining(tvb, ioffset) < 4) {
                    THROW(ReportedBoundsError);
                }
                return;
            }
        }
        else    /* Reply Packets */
        {                                           /* All replies include a completion code first */
            rcode = tvb_get_letohl(tvb, ioffset);
            error_string = val_to_str_const(rcode, nds_reply_errors, "Unknown Interation Verb Completion Code");
            expert_item = proto_tree_add_uint_format(it_subtree, hf_iter_verb_completion_code, tvb, ioffset,
                    4, rcode, "Completion Code: 0x%08x, %s",
                    rcode, error_string );

            if (rcode != 0 && ncp_echo_err) {
                expert_add_info_format(pinfo, expert_item, PI_RESPONSE_CODE, PI_ERROR, "Iteration Verb Error: 0x%08x %s", rcode, error_string);
            }
            ioffset += 4;

            switch (it_verb) {
            case IT_ATFIRST:
            case IT_ATEOF:
            case IT_ATLAST:
            case IT_ATBOF:
                proto_tree_add_item(it_subtree, hf_iter_ans, tvb, ioffset, 4, TRUE);
                ioffset += 4;
                break;
            case IT_CLEAR:
                break;
            case IT_COPY:
                proto_tree_add_item(it_subtree, hf_iter_copy, tvb, ioffset, 4, TRUE);
                ioffset += 4;
                break;
            case IT_COUNT:
                proto_tree_add_item(it_subtree, hf_this_count, tvb, ioffset, 4, TRUE);
                ioffset += 4;
                break;
            case IT_CREATE:
                proto_tree_add_item(it_subtree, hf_nds_iterator, tvb, ioffset, 4, TRUE);
                ioffset += 4;
                break;
            case IT_CURRENT:
            case IT_NEXT:
            case IT_PREV:
            case IT_FIRST:
            case IT_LAST:
                values.vvalue = tvb_get_letohl(tvb, ioffset);
                values.vstring = val_to_str_const(values.vvalue, nds_info_type, "No Info Type Set");
                proto_tree_add_string(it_subtree, hf_nds_info_type, tvb, ioffset, 4, values.vstring);
                ioffset = ioffset + 4;
                proto_tree_add_item(it_subtree, hf_data_size, tvb, ioffset, 4, TRUE);
                ioffset += 4;
                number_of_items = tvb_get_letohl(tvb, ioffset);
                proto_tree_add_item(it_subtree, hf_this_count, tvb, ioffset, 4, TRUE);
                ioffset += 4;
                for (i = 0; i < number_of_items; i++)
                {
                    it_subitem1 = proto_tree_add_text(it_subtree, tvb, ioffset, -1, "Item #: %u", i+1);
                    it_subtree1 = proto_item_add_subtree(it_subitem1, ett_nds);

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

                    if (tvb_length_remaining(tvb, ioffset) < 4) {
                        break;
                    }
                }
                break;
            case IT_DESTROY:
            case IT_DONE:
                break;
            case IT_GETPOSITION:
                proto_tree_add_item(it_subtree, hf_iter_position, tvb, ioffset, 4, TRUE);
                ioffset += 4;
                break;
            case IT_ISPOSITIONABLE:
                proto_tree_add_item(it_subtree, hf_positionable, tvb, ioffset, 4, TRUE);
                ioffset += 4;
                break;
            case IT_POSITION:
            case IT_POSITION_IT:
            case IT_SETFILTER:
            case IT_TYPEDOWN:
                break;
            case IT_SETINDEX:
                proto_tree_add_item(it_subtree, hf_iter_index, tvb, ioffset, 4, TRUE);
                ioffset += 4;
                break;
            case IT_SKIP:
                proto_tree_add_item(it_subtree, hf_num_skipped, tvb, ioffset, 4, TRUE);
                ioffset += 4;
                break;
            default:
                if (tvb_length_remaining(tvb, ioffset) < 4) {
                    THROW(ReportedBoundsError);
                }
                return;
            }
        }
        it_verb = tvb_get_letohl(tvb, ioffset);
        ioffset += 4;
        if (it_verb == IT_DONE || tvb_length_remaining(tvb, ioffset) < 4) {
            verb_string = val_to_str_const(it_verb, iterator_subverbs, "Internal error processing NDS iteration verbs");
            proto_tree_add_uint_format(it_tree, hf_ncp_nds_iterverb, tvb, ioffset-4, 4,
                it_verb, "Iterator Verb: %d, (0x%04x), %s",
                it_verb, it_verb, verb_string);
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
    guint16         replica_num = 0;
    guint16         event_num = 0;
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
                value1 = tvb_get_letohl(tvb, ioffset);
                values->vstring = val_to_str_const(value1, nds_syntax, "No Syntax Found");
                proto_tree_add_string(ntree, hf_nds_syntax, tvb, ioffset,
                                      4, values->vstring);
                ioffset = ioffset + 4;
                value2 = tvb_get_letohl(tvb, ioffset);
                ioffset = ioffset + 4;
                values->vstring = get_string(tvb, ioffset, value2);
                proto_tree_add_string(ntree, hf_mv_string, tvb, ioffset,
                                      value2, values->vstring);
                ioffset += value2;
                ioffset += align_4(tvb, ioffset);
                values->voffset = ioffset;

                print_nds_values(ntree, tvb, value1, values);
                ioffset = values->voffset;
            }
            break;
        case 2:
            for (i = 1 ; i <= values->vvalue; i++ )
            {
                value1 = tvb_get_letohl(tvb, ioffset);
                values->vstring = val_to_str_const(value1, nds_syntax, "No Syntax Found");
                proto_tree_add_string(ntree, hf_nds_syntax, tvb, ioffset,
                                      4, values->vstring);
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
                    value4 = tvb_get_letohl(tvb, ioffset);
                    tvb_ensure_bytes_exist(tvb, ioffset, values->vlength);
                    proto_tree_add_uint(ntree, hf_nds_privileges, tvb, ioffset,
                                        values->vlength, value4);

                    ioffset = ioffset+4;
                }
            }
            break;
        case 3:
            for (i = 1 ; i <= values->vvalue; i++ )
            {
                value1 = tvb_get_letohl(tvb, ioffset);
                values->vstring = val_to_str_const(value1, nds_syntax, "No Syntax Found");
                proto_tree_add_string(ntree, hf_nds_syntax, tvb, ioffset,
                                      4, values->vstring);
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
                    temp_values.vvalue = tvb_get_letohl(tvb, ioffset);
                    temp_values.vlength = 2;
                    temp_values.hfname = hf_nds_vflags;
                    temp_values.voffset = ioffset;
                    temp_values.vdesc = "Value Flags";
                    temp_values.bit1 = "Naming";
                    temp_values.bit1hfname = hf_bit1vflags;
                    temp_values.bit2 = "Base Class";
                    temp_values.bit2hfname = hf_bit2vflags;
                    temp_values.bit3 = "Present";
                    temp_values.bit3hfname = hf_bit3vflags;
                    temp_values.bit4 = "Value Damaged";
                    temp_values.bit4hfname = hf_bit4vflags;
                    temp_values.bit5 = "Not Defined";
                    temp_values.bit5hfname = hf_bit5vflags;
                    temp_values.bit6 = "Not Defined";
                    temp_values.bit6hfname = hf_bit6vflags;
                    temp_values.bit7 = "Not Defined";
                    temp_values.bit7hfname = hf_bit7vflags;
                    temp_values.bit8 = "Not Defined";
                    temp_values.bit8hfname = hf_bit8vflags;
                    temp_values.bit9 = "Not Defined";
                    temp_values.bit9hfname = hf_bit9vflags;
                    temp_values.bit10 = "Not Defined";
                    temp_values.bit10hfname = hf_bit10vflags;
                    temp_values.bit11 = "Not Defined";
                    temp_values.bit11hfname = hf_bit11vflags;
                    temp_values.bit12 = "Not Defined";
                    temp_values.bit12hfname = hf_bit12vflags;
                    temp_values.bit13 = "Not Defined";
                    temp_values.bit13hfname = hf_bit13vflags;
                    temp_values.bit14 = "Not Defined";
                    temp_values.bit14hfname = hf_bit14vflags;
                    temp_values.bit15 = "Not Defined";
                    temp_values.bit15hfname = hf_bit15vflags;
                    temp_values.bit16 = "Not Defined";
                    temp_values.bit16hfname = hf_bit16vflags;
                    process_bitfield(atree, tvb, &temp_values);
                    ioffset = ioffset + 4;
                    ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                    ns.nsecs = 0;
                    proto_tree_add_time_format(atree, hf_es_seconds, tvb, ioffset,
                                               4, &ns, "Timestamp: %s", abs_time_secs_to_str(ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                    ioffset = ioffset + 4;
                    replica_num = tvb_get_letohs(tvb, ioffset);   /* Replica */
                    proto_tree_add_item(atree, hf_nds_replica_num, tvb, ioffset,
                                        2, replica_num);
                    ioffset = ioffset + 2;
                    event_num = tvb_get_letohs(tvb, ioffset);   /* Event */
                    proto_tree_add_item(atree, hf_nds_event_num, tvb, ioffset,
                                        2, event_num);
                    ioffset = ioffset + 2;
                    value5 = tvb_get_letohl(tvb, ioffset); /* length of field */
                    if(value5 > tvb_length_remaining(tvb, ioffset))
                    {
                        break;
                    }
                    ioffset += 4;
                    tvb_ensure_bytes_exist(tvb, ioffset, value5);
                    proto_tree_add_bytes(atree, hf_value_bytes, tvb, ioffset, value5, tvb_get_ptr(tvb, ioffset, value5));
                    ioffset += value5;
                    ioffset += (value5%2);
                }
            }
            break;
        case 4:
            for (i = 1 ; i <= values->vvalue; i++ )
            {
                value1 = tvb_get_letohl(tvb, ioffset);
                values->vstring = val_to_str_const(value1, nds_syntax, "No Syntax Found");
                proto_tree_add_string(ntree, hf_nds_syntax, tvb, ioffset,
                                      4, values->vstring);
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
                    temp_values.vvalue = tvb_get_letohl(tvb, ioffset);
                    temp_values.vlength = 2;
                    temp_values.hfname = hf_nds_vflags;
                    temp_values.voffset = ioffset;
                    temp_values.vdesc = "Value Flags";
                    temp_values.bit1 = "Naming";
                    temp_values.bit1hfname = hf_bit1vflags;
                    temp_values.bit2 = "Base Class";
                    temp_values.bit2hfname = hf_bit2vflags;
                    temp_values.bit3 = "Present";
                    temp_values.bit3hfname = hf_bit3vflags;
                    temp_values.bit4 = "Value Damaged";
                    temp_values.bit4hfname = hf_bit4vflags;
                    temp_values.bit5 = "Not Defined";
                    temp_values.bit5hfname = hf_bit5vflags;
                    temp_values.bit6 = "Not Defined";
                    temp_values.bit6hfname = hf_bit6vflags;
                    temp_values.bit7 = "Not Defined";
                    temp_values.bit7hfname = hf_bit7vflags;
                    temp_values.bit8 = "Not Defined";
                    temp_values.bit8hfname = hf_bit8vflags;
                    temp_values.bit9 = "Not Defined";
                    temp_values.bit9hfname = hf_bit9vflags;
                    temp_values.bit10 = "Not Defined";
                    temp_values.bit10hfname = hf_bit10vflags;
                    temp_values.bit11 = "Not Defined";
                    temp_values.bit11hfname = hf_bit11vflags;
                    temp_values.bit12 = "Not Defined";
                    temp_values.bit12hfname = hf_bit12vflags;
                    temp_values.bit13 = "Not Defined";
                    temp_values.bit13hfname = hf_bit13vflags;
                    temp_values.bit14 = "Not Defined";
                    temp_values.bit14hfname = hf_bit14vflags;
                    temp_values.bit15 = "Not Defined";
                    temp_values.bit15hfname = hf_bit15vflags;
                    temp_values.bit16 = "Not Defined";
                    temp_values.bit16hfname = hf_bit16vflags;
                    process_bitfield(ntree, tvb, &temp_values);
                    ioffset = ioffset + 4;
                    ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                    ns.nsecs = 0;
                    proto_tree_add_time_format(ntree, hf_es_seconds, tvb, ioffset,
                                               4, &ns, "Creation Time: %s", abs_time_secs_to_str(ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                    ioffset = ioffset + 4;
                    replica_num = tvb_get_letohs(tvb, ioffset);   /* Replica */
                    proto_tree_add_item(ntree, hf_nds_replica_num, tvb, ioffset,
                                        2, replica_num);
                    ioffset = ioffset + 2;
                    event_num = tvb_get_letohs(tvb, ioffset);   /* Event */
                    proto_tree_add_item(ntree, hf_nds_event_num, tvb, ioffset,
                                        2, event_num);
                    ioffset = ioffset + 2;
                    value1 = tvb_get_letohl(tvb, ioffset);
                    proto_tree_add_uint(ntree, hf_nds_value_len, tvb, ioffset,
                                        4, value1);
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
                proto_tree_add_text(ntree, tvb, 0, 0, "[ Invalid offset: %u ]", ioffset);
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
            print_nds_values(ntree, tvb, 9, values);
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
                        temp_values.vvalue = tvb_get_letohl(tvb, ioffset);
                        temp_values.vlength = 2;
                        temp_values.hfname = hf_nds_rflags;
                        temp_values.voffset = ioffset;
                        temp_values.vdesc = "Output Flags";
                        temp_values.bit1 = values->bit1;
                        temp_values.bit1hfname = hf_bit1outflags;
                        temp_values.bit2 = values->bit2;
                        temp_values.bit2hfname = hf_bit2outflags;
                        temp_values.bit3 = values->bit3;
                        temp_values.bit3hfname = hf_bit3outflags;
                        temp_values.bit4 = values->bit4;
                        temp_values.bit4hfname = hf_bit4outflags;
                        temp_values.bit5 = values->bit5;
                        temp_values.bit5hfname = hf_bit5outflags;
                        temp_values.bit6 = values->bit6;
                        temp_values.bit6hfname = hf_bit6outflags;
                        temp_values.bit7 = values->bit7;
                        temp_values.bit7hfname = hf_bit7outflags;
                        temp_values.bit8 = values->bit8;
                        temp_values.bit8hfname = hf_bit8outflags;
                        temp_values.bit9 = values->bit9;
                        temp_values.bit9hfname = hf_bit9outflags;
                        temp_values.bit10 = "Not Defined";
                        temp_values.bit10hfname = hf_bit10outflags;
                        temp_values.bit11 = "Not Defined";
                        temp_values.bit11hfname = hf_bit11outflags;
                        temp_values.bit12 = "Not Defined";
                        temp_values.bit12hfname = hf_bit12outflags;
                        temp_values.bit13 = "Not Defined";
                        temp_values.bit13hfname = hf_bit13outflags;
                        temp_values.bit14 = "Not Defined";
                        temp_values.bit14hfname = hf_bit14outflags;
                        temp_values.bit15 = "Not Defined";
                        temp_values.bit15hfname = hf_bit15outflags;
                        temp_values.bit16 = "Not Defined";
                        temp_values.bit16hfname = hf_bit16outflags;
                        process_bitfield(ntree, tvb, &temp_values);
                        ioffset = ioffset + 4;
                        break;
                    case 0x00000002:                /*p3values.bit2 = "Entry ID"*/
                        value1 = tvb_get_letohl(tvb, ioffset);
                        proto_tree_add_uint_format(ntree, hf_nds_eid, tvb, ioffset,
                                                   4, value1, "Entry ID %08x", value1);
                        ioffset = ioffset + 4;
                        break;
                    case 0x00000004:                /*p3values.bit3 = "Replica State"*/
                        value1 = tvb_get_letohl(tvb, ioffset);
                        temp_values.vstring = val_to_str_const(value1, nds_replica_state, "No Replica State Found");
                        proto_tree_add_string(ntree, hf_replica_state, tvb, ioffset,
                                              4, temp_values.vstring);
                        ioffset = ioffset + 4;
                        break;
                    case 0x0000008:                 /*p3values.bit4 = "Modification Timestamp"*/
                        ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                        ns.nsecs = 0;
                        proto_tree_add_time_format(ntree, hf_es_seconds, tvb, ioffset,
                                                   4, &ns, "Modification Timestamp: %s", abs_time_secs_to_str(ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                        ioffset = ioffset + 4;
                        replica_num = tvb_get_letohs(tvb, ioffset);   /* Replica */
                        proto_tree_add_item(ntree, hf_nds_replica_num, tvb, ioffset,
                                            2, replica_num);
                        ioffset = ioffset + 2;
                        event_num = tvb_get_letohs(tvb, ioffset);   /* Event */
                        proto_tree_add_item(ntree, hf_nds_event_num, tvb, ioffset,
                                            2, event_num);
                        ioffset = ioffset + 2;
                        break;
                    case 0x00000010:                /*p3values.bit5 = "Purge Time"*/
                        ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                        ns.nsecs = 0;
                        proto_tree_add_time_format(ntree, hf_nds_purge, tvb, ioffset,
                                                   4, &ns, "Purge Time: %s", abs_time_secs_to_str(ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                        ioffset = ioffset + 4;
                        break;
                    case 0x00000020:                /*p3values.bit6 = "Local Partition ID"*/
                        value1 = tvb_get_letohl(tvb, ioffset);
                        proto_tree_add_uint_format(ntree, hf_nds_local_partition, tvb, ioffset,
                                                   4, value1, "Local Partition ID %08x", value1);
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
                        temp_values.vstring = val_to_str_const(value2, nds_replica_type, "No Replica Type Found");
                        proto_tree_add_string(ntree, hf_replica_type, tvb, ioffset,
                                              4, temp_values.vstring);
                        value3 = value1 & 0xff00;
                        temp_values.vstring = val_to_str_const(value3, nds_replica_state, "No Replica State Found");
                        proto_tree_add_string(ntree, hf_replica_state, tvb, ioffset,
                                              4, temp_values.vstring);
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
                if(tvb_length_remaining(tvb, ioffset) < 4 )
                {
                    break;
                }
            }
            if(tvb_length_remaining(tvb, ioffset) < 4 )
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
            tvb_ensure_bytes_exist(tvb, ioffset, values->vlength);
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
                print_nds_values(ntree, tvb, 9, values);
                ioffset = values->voffset;
            }
        }
        break;

    case MVTYPE_ADDR_REFERRAL_REQUEST: /* Address Referral Request */
        for (i = 0 ; i < values->vvalue; i++ )
        {
            value1 = tvb_get_letohl(tvb, ioffset);
            valuestr = val_to_str_const(value1, nds_protocol_type, "(Undefined Protocol)");
            tvb_ensure_bytes_exist(tvb, ioffset, values->vlength);
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

            value1 = tvb_get_letohl(tvb, ioffset);

            proto_tree_add_uint_format(atree, hf_referral_addcount, tvb, ioffset, 4,
                                       value1, "Number of Addresses in Referral - %u", value1);

            ioffset = ioffset + 4;
            for (i = 1 ; i <= value1; i++ )
            {
                value2 = tvb_get_letohl(tvb, ioffset);
                valuestr = val_to_str_const(value2, nds_protocol_type, "(Undefined Protocol)");
                tvb_ensure_bytes_exist(tvb, ioffset, values->vlength);
                proto_tree_add_uint_format(atree, hf_nds_uint32value, tvb, ioffset,
                                           values->vlength, value2, valuestr, value2);
                ioffset = ioffset+4;
                value3 = tvb_get_letohl(tvb, ioffset);
                ioffset = ioffset+4;
                switch (value2)
                {
                case NDS_PTYPE_IPX:
                    proto_tree_add_item(atree, hf_nds_net, tvb, ioffset, 4, FALSE);
                    proto_tree_add_item(atree, hf_nds_node, tvb, ioffset+4, 6, FALSE);
                    proto_tree_add_item(atree, hf_nds_socket, tvb, ioffset+10, 2, FALSE);
                    break;
                case NDS_PTYPE_IP:
                    proto_tree_add_item(atree, hf_nds_port, tvb, ioffset, 2, FALSE);
                    proto_tree_add_item(atree, hf_add_ref_ip, tvb, ioffset+2, 4, FALSE);
                    break;
                case NDS_PTYPE_UDP:
                    proto_tree_add_item(atree, hf_nds_port, tvb, ioffset, 2, FALSE);
                    proto_tree_add_item(atree, hf_add_ref_udp, tvb, ioffset+2, 4, FALSE);
                    break;
                case NDS_PTYPE_TCP:
                    proto_tree_add_item(atree, hf_nds_port, tvb, ioffset, 2, FALSE);
                    proto_tree_add_item(atree, hf_add_ref_tcp, tvb, ioffset+2, 4, FALSE);
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
            tvb_ensure_bytes_exist(tvb, ioffset, values->vlength);
            proto_tree_add_uint_format(atree, hf_nds_uint32value, tvb, ioffset,
                                       values->vlength, value2, valuestr, value2);
            ioffset = ioffset+4;
            value3 = tvb_get_letohl(tvb, ioffset);
            ioffset = ioffset+4;

            switch (value2)
            {
            case NDS_PTYPE_IPX:
                proto_tree_add_item(atree, hf_nds_net, tvb, ioffset, 4, FALSE);
                proto_tree_add_item(atree, hf_nds_node, tvb, ioffset+4, 6, FALSE);
                proto_tree_add_item(atree, hf_nds_socket, tvb, ioffset+10, 2, FALSE);
                break;
            case NDS_PTYPE_IP:
                proto_tree_add_item(atree, hf_nds_port, tvb, ioffset, 2, FALSE);
                proto_tree_add_item(atree, hf_add_ref_ip, tvb, ioffset+2, 4, FALSE);
                break;
            case NDS_PTYPE_UDP:
                proto_tree_add_item(atree, hf_nds_port, tvb, ioffset, 2, FALSE);
                proto_tree_add_item(atree, hf_add_ref_udp, tvb, ioffset+2, 4, FALSE);
                break;
            case NDS_PTYPE_TCP:
                proto_tree_add_item(atree, hf_nds_port, tvb, ioffset, 2, FALSE);
                proto_tree_add_item(atree, hf_add_ref_tcp, tvb, ioffset+2, 4, FALSE);
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
        replica_num = tvb_get_letohs(tvb, ioffset);   /* Replica */
        proto_tree_add_item(ncp_tree, hf_nds_replica_num, tvb, ioffset,
                            2, replica_num);
        ioffset = ioffset + 2;
        event_num = tvb_get_letohs(tvb, ioffset);   /* Event */
        proto_tree_add_item(ncp_tree, hf_nds_event_num, tvb, ioffset,
                            2, event_num);
        ioffset = ioffset + 2;
        /* fall through */

    case MVTYPE_LIST_PARTITIONS:  /* List Partitions */
        number_of_referrals = values->vvalue;
        /* A bad packet could put us in a tight loop so trap for anything
         * over 256 referrals.
         */
        if (number_of_referrals > 256) {
            proto_tree_add_text(ntree, tvb, 0, 0, "[ Bad referal at offset: %u ]", ioffset);
            THROW(ReportedBoundsError);
            break;
        }
        for (i = 0; i < number_of_referrals; i++)
        {
            bvalue = 0x00000001;

            for (r = 0 ; r < 32; r++ )
            {
                oldioffset = ioffset;
                if (values->vflags & bvalue)
                {
                    switch(bvalue)
                    {
                    case 0x00000001:                /* Information Flags */
                        temp_values.vvalue = tvb_get_letohs(tvb, ioffset);
                        temp_values.vtype = VTYPE_BITFIELD;
                        temp_values.vdesc = "Information Flags (low) Byte:";
                        temp_values.vlength = 2;
                        temp_values.hfname= hf_nds_rflags;
                        temp_values.voffset = ioffset;
                        temp_values.bit1 = "Output Flags";
                        temp_values.bit1hfname = hf_bit1infoflagsl;
                        temp_values.bit2 = "Entry ID";
                        temp_values.bit2hfname = hf_bit2infoflagsl;
                        temp_values.bit3 = "Entry Flags";
                        temp_values.bit3hfname = hf_bit3infoflagsl;
                        temp_values.bit4 = "Subordinate Count";
                        temp_values.bit4hfname = hf_bit4infoflagsl;
                        temp_values.bit5 = "Modification Time";
                        temp_values.bit5hfname = hf_bit5infoflagsl;
                        temp_values.bit6 = "Modification Timestamp";
                        temp_values.bit6hfname = hf_bit6infoflagsl;
                        temp_values.bit7 = "Creation Timestamp";
                        temp_values.bit7hfname = hf_bit7infoflagsl;
                        temp_values.bit8 = "Partition Root ID";
                        temp_values.bit8hfname = hf_bit8infoflagsl;
                        temp_values.bit9 = "Parent ID";
                        temp_values.bit9hfname = hf_bit9infoflagsl;
                        temp_values.bit10 = "Revision Count";
                        temp_values.bit10hfname = hf_bit10infoflagsl;
                        temp_values.bit11 = "Replica Type";
                        temp_values.bit11hfname = hf_bit11infoflagsl;
                        temp_values.bit12 = "Base Class";
                        temp_values.bit12hfname = hf_bit12infoflagsl;
                        temp_values.bit13 = "Relative Distinguished Name";
                        temp_values.bit13hfname = hf_bit13infoflagsl;
                        temp_values.bit14 = "Distinguished Name";
                        temp_values.bit14hfname = hf_bit14infoflagsl;
                        temp_values.bit15 = "Root Distinguished Name";
                        temp_values.bit15hfname = hf_bit15infoflagsl;
                        temp_values.bit16 = "Parent Distinguished Name";
                        temp_values.bit16hfname = hf_bit16infoflagsl;
                        process_bitfield(ntree, tvb, &temp_values);
                        ioffset = ioffset+2;
                        temp_values.vvalue = tvb_get_letohs(tvb, ioffset);
                        temp_values.vtype = VTYPE_BITFIELD;
                        temp_values.vdesc = "Information Flags (high) Byte:";
                        temp_values.vlength = 2;
                        temp_values.hfname= hf_nds_rflags;
                        temp_values.voffset = ioffset;
                        temp_values.bit1 = "Purge Time";
                        temp_values.bit1hfname = hf_bit1infoflagsh;
                        temp_values.bit2 = "Dereference Base Class";
                        temp_values.bit2hfname = hf_bit2infoflagsh;
                        temp_values.bit3 = "Not Defined";
                        temp_values.bit3hfname = hf_bit3infoflagsh;
                        temp_values.bit4 = "Not Defined";
                        temp_values.bit4hfname = hf_bit4infoflagsh;
                        temp_values.bit5 = "Not Defined";
                        temp_values.bit5hfname = hf_bit5infoflagsh;
                        temp_values.bit6 = "Not Defined";
                        temp_values.bit6hfname = hf_bit6infoflagsh;
                        temp_values.bit7 = "Not Defined";
                        temp_values.bit7hfname = hf_bit7infoflagsh;
                        temp_values.bit8 = "Not Defined";
                        temp_values.bit8hfname = hf_bit8infoflagsh;
                        temp_values.bit9 = "Not Defined";
                        temp_values.bit9hfname = hf_bit9infoflagsh;
                        temp_values.bit10 = "Not Defined";
                        temp_values.bit10hfname = hf_bit10infoflagsh;
                        temp_values.bit11 = "Not Defined";
                        temp_values.bit11hfname = hf_bit11infoflagsh;
                        temp_values.bit12 = "Not Defined";
                        temp_values.bit12hfname = hf_bit12infoflagsh;
                        temp_values.bit13 = "Not Defined";
                        temp_values.bit13hfname = hf_bit13infoflagsh;
                        temp_values.bit14 = "Not Defined";
                        temp_values.bit14hfname = hf_bit14infoflagsh;
                        temp_values.bit15 = "Not Defined";
                        temp_values.bit15hfname = hf_bit15infoflagsh;
                        temp_values.bit16 = "Not Defined";
                        temp_values.bit16hfname = hf_bit16infoflagsh;
                        process_bitfield(ntree, tvb, &temp_values);
                        ioffset = ioffset+2;
                        break;
                    case 0x00000002:                /* Entry ID */
                        value1 = tvb_get_letohl(tvb, ioffset);
                        proto_tree_add_uint_format(ntree, hf_nds_eid, tvb, ioffset,
                                                   4, value1, "Entry ID %08x", value1);
                        ioffset = ioffset + 4;
                        break;
                    case 0x00000004:                /* Entry Flags */
                        temp_values.vvalue = tvb_get_letohl(tvb, ioffset);
                        temp_values.vtype = VTYPE_BITFIELD;
                        temp_values.vdesc = "Entry Flags:";
                        temp_values.vlength = 2;
                        temp_values.hfname= hf_nds_eflags;
                        temp_values.voffset = ioffset;
                        temp_values.bit1 = "Alias Entry";
                        temp_values.bit1hfname = hf_bit1eflags;
                        temp_values.bit2 = "Partition Root";
                        temp_values.bit2hfname = hf_bit2eflags;
                        temp_values.bit3 = "Container Entry";
                        temp_values.bit3hfname = hf_bit3eflags;
                        temp_values.bit4 = "Container Alias";
                        temp_values.bit4hfname = hf_bit4eflags;
                        temp_values.bit5 = "Matches List Filter";
                        temp_values.bit5hfname = hf_bit5eflags;
                        temp_values.bit6 = "Reference Entry";
                        temp_values.bit6hfname = hf_bit6eflags;
                        temp_values.bit7 = "40x Reference Entry";
                        temp_values.bit7hfname = hf_bit7eflags;
                        temp_values.bit8 = "Back Linked";
                        temp_values.bit8hfname = hf_bit8eflags;
                        temp_values.bit9 = "New Entry";
                        temp_values.bit9hfname = hf_bit9eflags;
                        temp_values.bit10 = "Temporary Reference";
                        temp_values.bit10hfname = hf_bit10eflags;
                        temp_values.bit11 = "Audited";
                        temp_values.bit11hfname = hf_bit11eflags;
                        temp_values.bit12 = "Entry Not Present";
                        temp_values.bit12hfname = hf_bit12eflags;
                        temp_values.bit13 = "Entry Verify CTS";
                        temp_values.bit13hfname = hf_bit13eflags;
                        temp_values.bit14 = "Entry Damaged";
                        temp_values.bit14hfname = hf_bit14eflags;
                        temp_values.bit15 = "Not Defined";
                        temp_values.bit15hfname = hf_bit15eflags;
                        temp_values.bit16 = "Not Defined";
                        temp_values.bit16hfname = hf_bit16eflags;
                        process_bitfield(ntree, tvb, &temp_values);
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
                                                   4, &ns, "Modification Time: %s", abs_time_secs_to_str(ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                        ioffset = ioffset + 4;
                        break;
                    case 0x0000020:                 /* Modification Timestamp */
                        ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                        ns.nsecs = 0;
                        proto_tree_add_time_format(ntree, hf_es_seconds, tvb, ioffset,
                                                   4, &ns, "Modification Timestamp: %s", abs_time_secs_to_str(ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                        ioffset = ioffset + 4;
                        replica_num = tvb_get_letohs(tvb, ioffset);   /* Replica */
                        proto_tree_add_item(ntree, hf_nds_replica_num, tvb, ioffset,
                                            2, replica_num);
                        ioffset = ioffset + 2;
                        event_num = tvb_get_letohs(tvb, ioffset);   /* Event */
                        proto_tree_add_item(ntree, hf_nds_event_num, tvb, ioffset,
                                            2, event_num);
                        ioffset = ioffset + 2;
                        break;
                    case 0x0000040:                 /* Creation Timestamp */
                        ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                        ns.nsecs = 0;
                        proto_tree_add_time_format(ntree, hf_es_seconds, tvb, ioffset,
                                                   4, &ns, "Creation Timestamp: %s", abs_time_secs_to_str(ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                        ioffset = ioffset + 4;
                        replica_num = tvb_get_letohs(tvb, ioffset);   /* Replica */
                        proto_tree_add_item(ntree, hf_nds_replica_num, tvb, ioffset,
                                            2, replica_num);
                        ioffset = ioffset + 2;
                        event_num = tvb_get_letohs(tvb, ioffset);   /* Event */
                        proto_tree_add_item(ntree, hf_nds_event_num, tvb, ioffset,
                                            2, event_num);
                        ioffset = ioffset + 2;
                        break;
                    case 0x00000080:                /* Partition Root ID */
                        value1 = tvb_get_letohl(tvb, ioffset);
                        proto_tree_add_uint_format(ntree, hf_nds_partition_root_id, tvb, ioffset,
                                                   4, value1, "Partition Root ID %08x", value1);
                        ioffset = ioffset + 4;
                        break;
                    case 0x00000100:                /* Parent ID */
                        value1 = tvb_get_letohl(tvb, ioffset);
                        proto_tree_add_uint_format(ntree, hf_nds_parent, tvb, ioffset,
                                                   4, value1, "Parent ID %08x", value1);
                        ioffset = ioffset + 4;
                        break;
                    case 0x00000200:                /* Revision Count */
                        value1 = tvb_get_letohl(tvb, ioffset);
                        proto_tree_add_uint_format(ntree, hf_nds_revision, tvb, ioffset,
                                                   4, value1, "Revision Count %u", value1);
                        ioffset = ioffset + 4;
                        break;
                    case 0x00000400:                /* Replica Type & State */
                        value1 = tvb_get_letohl(tvb, ioffset);
                        value2 = value1 & 0x00ff;
                        temp_values.vstring = val_to_str_const(value2, nds_replica_type, "No Replica Type Found");
                        proto_tree_add_string(ntree, hf_replica_type, tvb, ioffset,
                                              4, temp_values.vstring);
                        value3 = value1 & 0xff00;
                        temp_values.vstring = val_to_str_const(value3, nds_replica_state, "No Replica State Found");
                        proto_tree_add_string(ntree, hf_replica_state, tvb, ioffset,
                                              4, temp_values.vstring);
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
                                                   4, &ns, "Purge Time: %s", abs_time_secs_to_str(ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
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
                if(tvb_length_remaining(tvb, ioffset) < 4 )
                {
                    break;
                }
            }
            if(tvb_length_remaining(tvb, ioffset) < 4 )
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
                temp_values.vvalue = tvb_get_letohl(tvb, ioffset);
                temp_values.vtype = VTYPE_BITFIELD;
                temp_values.vdesc = "Class Flags:";
                temp_values.vlength = 2;
                temp_values.hfname= hf_nds_cflags;
                temp_values.voffset = ioffset;
                temp_values.bit1 = "Container";
                temp_values.bit1hfname = hf_bit1cflags;
                temp_values.bit2 = "Effective";
                temp_values.bit2hfname = hf_bit2cflags;
                temp_values.bit3 = "Class Definition Cannot be Removed";
                temp_values.bit3hfname = hf_bit3cflags;
                temp_values.bit4 = "Ambiguous Naming";
                temp_values.bit4hfname = hf_bit4cflags;
                temp_values.bit5 = "Ambiguous Containment";
                temp_values.bit5hfname = hf_bit5cflags;
                temp_values.bit6 = "Auxiliary";
                temp_values.bit6hfname = hf_bit6cflags;
                temp_values.bit7 = "Operational";
                temp_values.bit7hfname = hf_bit7cflags;
                temp_values.bit8 = "Sparse Required";
                temp_values.bit8hfname = hf_bit8cflags;
                temp_values.bit9 = "Sparse Operational";
                temp_values.bit9hfname = hf_bit9cflags;
                temp_values.bit10 = "Not Defined";
                temp_values.bit10hfname = hf_bit10cflags;
                temp_values.bit11 = "Not Defined";
                temp_values.bit11hfname = hf_bit11cflags;
                temp_values.bit12 = "Not Defined";
                temp_values.bit12hfname = hf_bit12cflags;
                temp_values.bit13 = "Not Defined";
                temp_values.bit13hfname = hf_bit13cflags;
                temp_values.bit14 = "Not Defined";
                temp_values.bit14hfname = hf_bit14cflags;
                temp_values.bit15 = "Not Defined";
                temp_values.bit15hfname = hf_bit15cflags;
                temp_values.bit16 = "Not Defined";
                temp_values.bit16hfname = hf_bit16cflags;
                process_bitfield(sub1tree, tvb, &temp_values);
                ioffset = ioffset+4;
                if(values->vflags != 5)
                {
                    value1 = tvb_get_letohl(tvb, ioffset); /* length of field */
                    length_remaining = tvb_length_remaining(tvb, ioffset);
                    if(length_remaining == -1 || value1 > (guint32) length_remaining)
                    {
                        break;
                    }
                    ioffset += 4;
                    tvb_ensure_bytes_exist(tvb, ioffset, value1);
                    proto_tree_add_bytes(sub1tree, hf_nds_asn1, tvb, ioffset, value1, tvb_get_ptr(tvb, ioffset, value1));
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
                        if(tvb_length_remaining(tvb, ioffset) < 4 )
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
                    if(tvb_length_remaining(tvb, ioffset) < 4 )
                    {
                        break;
                    }
                }
                if(values->vflags == 5)   /* Base Class Definitions */
                {
                    ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                    ns.nsecs = 0;
                    proto_tree_add_time_format(sub1tree, hf_es_seconds, tvb, ioffset,
                                               4, &ns, "Creation Timestamp: %s", abs_time_secs_to_str(ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                    ioffset = ioffset + 4;
                    replica_num = tvb_get_letohs(tvb, ioffset);   /* Replica */
                    proto_tree_add_item(sub1tree, hf_nds_replica_num, tvb, ioffset,
                                        2, replica_num);
                    ioffset = ioffset + 2;
                    event_num = tvb_get_letohs(tvb, ioffset);   /* Event */
                    proto_tree_add_item(sub1tree, hf_nds_event_num, tvb, ioffset,
                                        2, event_num);
                    ioffset = ioffset + 2;
                    ns.secs = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                    ns.nsecs = 0;
                    proto_tree_add_time_format(sub1tree, hf_es_seconds, tvb, ioffset,
                                               4, &ns, "Modification Timestamp: %s", abs_time_secs_to_str(ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                    ioffset = ioffset + 4;
                    replica_num = tvb_get_letohs(tvb, ioffset);   /* Replica */
                    proto_tree_add_item(sub1tree, hf_nds_replica_num, tvb, ioffset,
                                        2, replica_num);
                    ioffset = ioffset + 2;
                    event_num = tvb_get_letohs(tvb, ioffset);   /* Event */
                    proto_tree_add_item(sub1tree, hf_nds_event_num, tvb, ioffset,
                                        2, event_num);
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
                    if(tvb_length_remaining(tvb, ioffset) < 4 )
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
        if(tvb_length_remaining(tvb, ioffset) < 4 )
        {
            break;
        }
        ioffset += align_4(tvb, ioffset);
        value1 = tvb_get_letohl(tvb, ioffset);
        proto_tree_add_uint_format(ntree, hf_nds_att_del, tvb, ioffset,
                                   4, value1, "Attribute Names to Delete %u", value1);
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
        if(tvb_length_remaining(tvb, ioffset) < 4 )
        {
            break;
        }
        ioffset += align_4(tvb, ioffset);
        value1 = tvb_get_letohl(tvb, ioffset);
        proto_tree_add_uint_format(ntree, hf_nds_acl_add, tvb, ioffset,
                                   4, value1, "ACL Templates to Add %u", value1);
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
            value1 = tvb_get_letohl(tvb, ioffset);
            proto_tree_add_uint_format(ntree, hf_nds_privileges, tvb, ioffset,
                                       4, value1, "Privileges 0x%08x", value1);
            ioffset = ioffset + 4;
        }
        if(tvb_length_remaining(tvb, ioffset) < 4 )
        {
            break;
        }
        ioffset += align_4(tvb, ioffset);
        value1 = tvb_get_letohl(tvb, ioffset);
        proto_tree_add_uint_format(ntree, hf_nds_acl_del, tvb, ioffset,
                                   4, value1, "ACL Templates to Delete %u", value1);
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
            proto_tree_add_uint_format(ntree, hf_nds_privileges, tvb, ioffset,
                                       4, value1, "Privileges 0x%08x", value1);
            ioffset = ioffset + 4;
        }
        break;

    case MVTYPE_PROCESS_TAGS: /* Process tags and paths depending on name type returned. */
        switch (values->vflags) {

        case 8:  /* Tuned Name */
            proto_tree_add_item(ntree, hf_nds_tune_mark, tvb, ioffset, 2, FALSE);
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
                                           4, &ns, "Creation Timestamp: %s", abs_time_secs_to_str(ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                ioffset += 4;
                replica_num = tvb_get_letohs(tvb, ioffset);   /* Replica */
                proto_tree_add_item(ntree, hf_nds_replica_num, tvb, ioffset,
                                    2, replica_num);
                ioffset = ioffset + 2;
                event_num = tvb_get_letohs(tvb, ioffset);   /* Event */
                proto_tree_add_item(ntree, hf_nds_event_num, tvb, ioffset,
                                    2, event_num);
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
                    sub2item = proto_tree_add_text(sub1tree, tvb, ioffset, 0, "Item %u", i);
                    sub2tree = proto_item_add_subtree(sub2item, ett_nds);
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
                                                   4, &ns, "Timestamp: %s", abs_time_secs_to_str(ns.secs, ABSOLUTE_TIME_LOCAL, TRUE));
                        ioffset += 4;
                        replica_num = tvb_get_letohs(tvb, ioffset);   /* Replica */
                        proto_tree_add_item(sub2tree, hf_nds_replica_num, tvb, ioffset,
                                            2, replica_num);
                        ioffset = ioffset + 2;
                        event_num = tvb_get_letohs(tvb, ioffset);   /* Event */
                        proto_tree_add_item(sub2tree, hf_nds_event_num, tvb, ioffset,
                                            2, event_num);
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
            ioffset = values->voffset;
            ioffset += align_4(tvb, ioffset);
            break;
        } /* switch (values->vflags) */
        break;

    case MVTYPE_PROCESS_ITERATOR: /* Process Iterator subverbs. */
        temp_values.vvalue = tvb_get_letohl(tvb, ioffset);

        temp_values.vstring = val_to_str_const(temp_values.vvalue, nds_info_type, "No Info Type Set");
        /*g_strdup(value)*/
        proto_tree_add_string(ntree, hf_nds_info_type, tvb, ioffset, 4, temp_values.vstring);
        ioffset = ioffset + 4;
        temp_values.vvalue = tvb_get_letohs(tvb, ioffset);
        value5 = tvb_get_letohl(tvb, ioffset);
        temp_values.vdesc = "Information Flags (low) Byte:";
        temp_values.vlength = 2;
        temp_values.hfname = hf_nds_rflags;
        temp_values.voffset = ioffset;
        temp_values.bit1 = "Output Flags";
        temp_values.bit1hfname = hf_bit1infoflagsl;
        temp_values.bit2 = "Entry ID";
        temp_values.bit2hfname = hf_bit2infoflagsl;
        temp_values.bit3 = "Entry Flags";
        temp_values.bit3hfname = hf_bit3infoflagsl;
        temp_values.bit4 = "Subordinate Count";
        temp_values.bit4hfname = hf_bit4infoflagsl;
        temp_values.bit5 = "Modification Time";
        temp_values.bit5hfname = hf_bit5infoflagsl;
        temp_values.bit6 = "Modification Timestamp";
        temp_values.bit6hfname = hf_bit6infoflagsl;
        temp_values.bit7 = "Creation Timestamp";
        temp_values.bit7hfname = hf_bit7infoflagsl;
        temp_values.bit8 = "Partition Root ID";
        temp_values.bit8hfname = hf_bit8infoflagsl;
        temp_values.bit9 = "Parent ID";
        temp_values.bit9hfname = hf_bit9infoflagsl;
        temp_values.bit10 = "Revision Count";
        temp_values.bit10hfname = hf_bit10infoflagsl;
        temp_values.bit11 = "Replica Type";
        temp_values.bit11hfname = hf_bit11infoflagsl;
        temp_values.bit12 = "Base Class";
        temp_values.bit12hfname = hf_bit12infoflagsl;
        temp_values.bit13 = "Relative Distinguished Name";
        temp_values.bit13hfname = hf_bit13infoflagsl;
        temp_values.bit14 = "Distinguished Name";
        temp_values.bit14hfname = hf_bit14infoflagsl;
        temp_values.bit15 = "Root Distinguished Name";
        temp_values.bit15hfname = hf_bit15infoflagsl;
        temp_values.bit16 = "Parent Distinguished Name";
        temp_values.bit16hfname = hf_bit16infoflagsl;
        process_bitfield(ntree, tvb, &temp_values);
        ioffset = ioffset+2;
        temp_values.vvalue = tvb_get_letohs(tvb, ioffset);
        temp_values.vtype = VTYPE_BITFIELD;
        temp_values.vdesc = "Information Flags (high) Byte:";
        temp_values.vlength = 2;
        temp_values.hfname= hf_nds_rflags;
        temp_values.voffset = ioffset;
        temp_values.bit1 = "Purge Time";
        temp_values.bit1hfname = hf_bit1infoflagsh;
        temp_values.bit2 = "Dereference Base Class";
        temp_values.bit2hfname = hf_bit2infoflagsh;
        temp_values.bit3 = "Replica Number";
        temp_values.bit3hfname = hf_bit3infoflagsh;
        temp_values.bit4 = "Replica State";
        temp_values.bit4hfname = hf_bit4infoflagsh;
        temp_values.bit5 = "Federation Boundary";
        temp_values.bit5hfname = hf_bit5infoflagsh;
        temp_values.bit6 = "Schema Boundary";
        temp_values.bit6hfname = hf_bit6infoflagsh;
        temp_values.bit7 = "Federation Boundary ID";
        temp_values.bit7hfname = hf_bit7infoflagsh;
        temp_values.bit8 = "Schema Boundary ID";
        temp_values.bit8hfname = hf_bit8infoflagsh;
        temp_values.bit9 = "Current Subcount";
        temp_values.bit9hfname = hf_bit9infoflagsh;
        temp_values.bit10 = "Local Entry Flags";
        temp_values.bit10hfname = hf_bit10infoflagsh;
        temp_values.bit11 = "Not Defined";
        temp_values.bit11hfname = hf_bit11infoflagsh;
        temp_values.bit12 = "Not Defined";
        temp_values.bit12hfname = hf_bit12infoflagsh;
        temp_values.bit13 = "Not Defined";
        temp_values.bit13hfname = hf_bit13infoflagsh;
        temp_values.bit14 = "Not Defined";
        temp_values.bit14hfname = hf_bit14infoflagsh;
        temp_values.bit15 = "Not Defined";
        temp_values.bit15hfname = hf_bit15infoflagsh;
        temp_values.bit16 = "Not Defined";
        temp_values.bit16hfname = hf_bit16infoflagsh;
        ioffset = ioffset+2;
        process_bitfield(ntree, tvb, &temp_values);
        ioffset += 4;
        proto_tree_add_item(ntree, hf_nds_time_filter, tvb, ioffset, 4, FALSE);
        ioffset += 4;
        proto_tree_add_item(ntree, hf_nds_all_attr, tvb, ioffset, 4, FALSE);
        ioffset += 4;
        value2 = tvb_get_letohl(tvb, ioffset);
        sub1item = proto_tree_add_uint_format(ntree, hf_nds_number_of_items, tvb, ioffset,
                                              4, value2, "Number of Attributes %u", value2);
        sub1tree = proto_item_add_subtree(sub1item, ett_nds);
        ioffset += 4;
        for (i=1; i<=value2; i++) {
            sub2item = proto_tree_add_text(sub1tree, tvb, ioffset, 0, "Attribute %u", i);
            sub2tree = proto_item_add_subtree(sub2item, ett_nds);
            ioffset += align_4(tvb, ioffset);
            value3 = tvb_get_letohl(tvb, ioffset);  /* Attribute Name */
            ioffset = ioffset + 4;
            values->vstring = get_string(tvb, ioffset, value3);
            proto_tree_add_string(sub2tree, hf_nds_attribute_dn, tvb, ioffset,
                                  value3, values->vstring);
            ioffset = ioffset + value3;

            if(tvb_length_remaining(tvb, ioffset) < 4 )
            {
                break;
            }
        }
        ioffset += align_4(tvb, ioffset);
        value4 = tvb_get_letohl(tvb, ioffset);
        values->vstring = val_to_str_const(value4, iterator_subverbs, "(No Iteration Verb Found)");
        ioffset += 4;
        dissect_nds_iterator(ntree, tvb, pinfo, value4, value5, ioffset, TRUE);

        values->vstring = ep_strdup_printf("(%s)", values->vstring);
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
    proto_tree_add_item(ncp_tree, hf_ncp_data_type_flag, tvb, offset, 1, TRUE);
    offset += 1;
    proto_tree_add_item(ncp_tree, hf_ncp_reserved5, tvb, offset, 5, TRUE);
    offset += 5;
    count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(ncp_tree, hf_ncp_path_count, tvb, offset, 1, TRUE);
    offset += 1;
    for (i=0; i < count; i++) {
        if (datatype == 0) {
            string_len = (tvb_get_guint8(tvb, offset))+1;
            proto_tree_add_item(ncp_tree, hf_ncp_directory_path, tvb, offset+1, string_len-1, TRUE);
        }
        else
        {
            string_len = (tvb_get_letohs(tvb, offset))+2;
            proto_tree_add_item(ncp_tree, hf_ncp_directory_path, tvb, offset+2, string_len-2, TRUE);
        }
        offset += string_len;
        if(tvb_length_remaining(tvb, offset) < 4 )
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
    proto_tree_add_item(ncp_tree, hf_ncp_file_name_12, tvb, loffset+1, string_len, TRUE);
    loffset += string_len+1;
    string_len = tvb_get_guint8(tvb, loffset);
    proto_tree_add_item(ncp_tree, hf_ncp_name12, tvb, loffset+1, string_len, TRUE);
    loffset += string_len+1;
    string_len = tvb_get_guint8(tvb, loffset);
    proto_tree_add_item(ncp_tree, hf_ncp_copyright, tvb, loffset+1, string_len, TRUE);
}

static void
dissect_ncp_123_17_reply(tvbuff_t *tvb, proto_tree *volatile ncp_tree)
{
    proto_tree              *atree;
    proto_item              *aitem;
    guint32 loffset, number_of_items, addr_type;
    guint16 x;

    number_of_items = tvb_get_letohl(tvb, 36);
    proto_tree_add_item(ncp_tree, hf_ncp_items_in_packet, tvb, 36, 4, TRUE);
    loffset = 40;
    for (x = 1; x <= number_of_items; x++)
    {
        aitem = proto_tree_add_text(ncp_tree, tvb, loffset, -1, "Network Address - %u", x);
        atree = proto_item_add_subtree(aitem, ett_ncp);

        addr_type = tvb_get_guint8(tvb, loffset);
        proto_tree_add_item(atree, hf_ncp_transport_type, tvb, loffset, 1, TRUE);
        /* The address type is one byte of a 4 byte value. The next 4 bytes are
         * the length of the address. Since we already know the length based upon
         * the type of address, we can skip this value. So set the offset accourdingly */
        loffset += 8;

        switch (addr_type)
        {
        case 1:
            proto_tree_add_item(atree, hf_nds_net, tvb, loffset, 4, FALSE);
            proto_tree_add_item(atree, hf_nds_node, tvb, loffset+4, 6, FALSE);
            proto_tree_add_item(atree, hf_nds_socket, tvb, loffset+10, 2, FALSE);
            loffset += 12;
            break;
        case 5:
            proto_tree_add_item(atree, hf_nds_port, tvb, loffset, 2, FALSE);
            proto_tree_add_item(atree, hf_add_ref_udp, tvb, loffset+2, 4, FALSE);
            loffset += 6;
            break;
        case 6:
            proto_tree_add_item(atree, hf_nds_port, tvb, loffset, 2, FALSE);
            proto_tree_add_item(atree, hf_add_ref_tcp, tvb, loffset+2, 4, FALSE);
            loffset += 6;
            break;
        default:
            proto_tree_add_text(atree, tvb, loffset, -1, "Unknown Address Type");
            /* unknown type so read the length field and then
             * just skip the record and move on to the next */
            loffset += tvb_get_letohl(tvb, loffset - 4);
            break;
        }
        proto_item_set_end(aitem, tvb, loffset);
        if(tvb_length_remaining(tvb, loffset) < 4 )
        {
            break;
        }
    }
}

static void
dissect_ncp_23_26_reply(tvbuff_t *tvb, proto_tree *volatile ncp_tree)
{
    /* For an IP-only server, the 4-byte IP address is placed into the 4-byte NetworkAddress
     * field of the NetworkAddressStruct, while the NetworkNodeAddress and NetworkSocket
     * fields are left blank. */
    if (tvb_get_letohl(tvb, 12)==0) {
        /* IP Address */
        proto_tree_add_item(ncp_tree, hf_ncp_ip_address, tvb, 8, 4, FALSE);
    }
    else
    {
        /* IPX Address */
        proto_tree_add_item(ncp_tree, hf_nds_net, tvb, 8, 4, FALSE);
        proto_tree_add_item(ncp_tree, hf_nds_node, tvb, 12, 6, FALSE);
        proto_tree_add_item(ncp_tree, hf_nds_socket, tvb, 18, 2, FALSE);
    }
    proto_tree_add_item(ncp_tree, hf_ncp_connection_type, tvb, 20, 1, TRUE);
}

static void
dissect_ncp_8x20reply(tvbuff_t *tvb, proto_tree *volatile ncp_tree,
                      const ncp_record *ncp_rec, ncp_req_hash_value *request_value)
{
    guint16             x;
    guint32             loffset, number_of_items, str_length;
    ptvcursor_t         *ptvc = NULL;
    proto_tree          *atree, *btree;
    proto_item          *aitem, *bitem;

    aitem = proto_tree_add_text(ncp_tree, tvb, 8, 9, "Search Sequence:");
    atree = proto_item_add_subtree(aitem, ett_ncp);

    proto_tree_add_item(atree, hf_ncp_volume_number, tvb, 8, 1, TRUE);
    proto_tree_add_item(atree, hf_ncp_directory_entry_number, tvb, 9, 4, TRUE);
    proto_tree_add_item(atree, hf_ncp_sequence_number, tvb, 13, 4, TRUE);

    proto_tree_add_item(ncp_tree, hf_ncp_more_flag, tvb, 17, 1, TRUE);
    number_of_items = tvb_get_letohs(tvb, 18);
    proto_tree_add_item(ncp_tree, hf_ncp_info_count, tvb, 18, 2, TRUE);
    loffset = 20;
    for (x = 1; x <= number_of_items; x++ )
    {
        aitem = proto_tree_add_text(ncp_tree, tvb, loffset, -1, "Information Item %u", x);
        atree = proto_item_add_subtree(aitem, ett_ncp);
        /* Data Stream Space Allocated */
        if (request_value->req_mask & 0x0002) {
            proto_tree_add_item(atree, hf_ncp_data_stream_space_alloc, tvb, loffset, 4, TRUE);
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
            bitem = proto_tree_add_text(atree, tvb, loffset, -1, "Attributes");
            btree = proto_item_add_subtree(bitem, ett_ncp);
            ptvc = ptvcursor_new(btree, tvb, loffset);
            process_ptvc_record(ptvc, ptvc_struct_attributes_struct,
                    NULL, TRUE, ncp_rec);
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
            bitem = proto_tree_add_text(atree, tvb, loffset, -1, "Data Stream Size");
            btree = proto_item_add_subtree(bitem, ett_ncp);
            proto_tree_add_item(btree, hf_ncp_data_stream_size, tvb, loffset, 4, TRUE);
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
            bitem = proto_tree_add_text(atree, tvb, loffset, -1, "Total Stream Size");
            btree = proto_item_add_subtree(bitem, ett_ncp);
            proto_tree_add_item(btree, hf_ncp_ttl_ds_disk_space_alloc, tvb, loffset, 4, TRUE);
            proto_tree_add_item(btree, hf_ncp_number_of_data_streams, tvb, loffset+4, 2, TRUE);
            loffset += 6;
            proto_item_set_end(bitem, tvb, loffset);
        }
        else
        {
            if ((request_value->req_mask_ext & 0x8000)==FALSE) {
                loffset += 6;
            }
        }
        /* Extended Attributes new style location*/
        if (request_value->req_mask & 0x0020 && ncp_newstyle) {
            bitem = proto_tree_add_text(atree, tvb, loffset, -1, "Extended Attributes");
            btree = proto_item_add_subtree(bitem, ett_ncp);
            ptvc = ptvcursor_new(btree, tvb, loffset);
            process_ptvc_record(ptvc, ptvc_struct_ea_info_struct,
                    NULL, TRUE, ncp_rec);
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
        /* Creation Information old style location */
        if (request_value->req_mask & 0x0100 && !ncp_newstyle) {
            bitem = proto_tree_add_text(atree, tvb, loffset, -1, "Creation");
            btree = proto_item_add_subtree(bitem, ett_ncp);
            ptvc = ptvcursor_new(btree, tvb, loffset);
            process_ptvc_record(ptvc, ptvc_struct_creation_info_struct,
                    NULL, TRUE, ncp_rec);
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
        /* Modification Information */
        if (request_value->req_mask & 0x0080) {
            bitem = proto_tree_add_text(atree, tvb, loffset, -1, "Modification");
            btree = proto_item_add_subtree(bitem, ett_ncp);
            ptvc = ptvcursor_new(btree, tvb, loffset);
            process_ptvc_record(ptvc, ptvc_struct_modify_info_struct,
                    NULL, TRUE, ncp_rec);
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
        /* Creation Information new style location */
        if (request_value->req_mask & 0x0100 && ncp_newstyle) {
            bitem = proto_tree_add_text(atree, tvb, loffset, -1, "Creation");
            btree = proto_item_add_subtree(bitem, ett_ncp);
            ptvc = ptvcursor_new(btree, tvb, loffset);
            process_ptvc_record(ptvc, ptvc_struct_creation_info_struct,
                    NULL, TRUE, ncp_rec);
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
        /* Archive Information */
        if (request_value->req_mask & 0x0040) {
            bitem = proto_tree_add_text(atree, tvb, loffset, -1, "Archive");
            btree = proto_item_add_subtree(bitem, ett_ncp);
            ptvc = ptvcursor_new(btree, tvb, loffset);
            process_ptvc_record(ptvc, ptvc_struct_archive_info_struct,
                    NULL, TRUE, ncp_rec);
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
        /* Rights Information */
        if (request_value->req_mask & 0x0800) {
            ptvc = ptvcursor_new(atree, tvb, loffset);
            process_ptvc_record(ptvc, ptvc_struct_rights_info_struct,
                    NULL, TRUE, ncp_rec);
            ptvcursor_free(ptvc);
            loffset += 2;
        }
        else
        {
            if ((request_value->req_mask_ext & 0x8000)==FALSE) {
                loffset += 2;
            }
        }
        /* Directory Entry */
        if (request_value->req_mask & 0x0400) {
            bitem = proto_tree_add_text(atree, tvb, loffset, -1, "Directory Entry");
            btree = proto_item_add_subtree(bitem, ett_ncp);
            ptvc = ptvcursor_new(btree, tvb, loffset);
            process_ptvc_record(ptvc, ptvc_struct_dir_entry_struct,
                    NULL, TRUE, ncp_rec);
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
        /* Extended Attributes oldstyle location*/
        if (request_value->req_mask & 0x0020 && !ncp_newstyle) {
            bitem = proto_tree_add_text(atree, tvb, loffset, -1, "Extended Attributes");
            btree = proto_item_add_subtree(bitem, ett_ncp);
            ptvc = ptvcursor_new(btree, tvb, loffset);
            process_ptvc_record(ptvc, ptvc_struct_ea_info_struct,
                    NULL, TRUE, ncp_rec);
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
        /* Name Space Information */
        if (request_value->req_mask & 0x0200) {
            proto_tree_add_item(atree, hf_ncp_creator_name_space_number, tvb, loffset, 1, TRUE);
            loffset += 4;
        }
        else
        {
            if ((request_value->req_mask_ext & 0x8000)==FALSE) {
                loffset += 4;
            }
        }
        if (request_value->req_mask & 0x1000) {
            proto_tree_add_item(atree, hf_ncp_curr_ref_id, tvb, loffset, 2, TRUE);
            loffset += 2;
        }
        if (request_value->req_mask & 0x2000) {
            proto_tree_add_item(atree, hf_ncp_attr_def_32, tvb, loffset, 1, TRUE);
            loffset += 4;
        }
        if (request_value->req_mask & 0x4000) {
            bitem = proto_tree_add_text(atree, tvb, loffset, -1, "Actual");
            btree = proto_item_add_subtree(bitem, ett_ncp);
            proto_tree_add_item(btree, hf_ncp_data_stream_num_long, tvb, loffset, 4, TRUE);
            proto_tree_add_item(btree, hf_ncp_data_stream_fat_blks, tvb, loffset+4, 4, TRUE);
            loffset += 8;
            proto_item_set_end(bitem, tvb, loffset);
        }
        if (request_value->req_mask & 0x8000) {
            bitem = proto_tree_add_text(atree, tvb, loffset, -1, "Logical");
            btree = proto_item_add_subtree(bitem, ett_ncp);
            proto_tree_add_item(btree, hf_ncp_data_stream_num_long, tvb, loffset, 4, TRUE);
            proto_tree_add_item(btree, hf_ncp_data_stream_size, tvb, loffset+4, 4, TRUE);
            loffset += 8;
            proto_item_set_end(bitem, tvb, loffset);
        }
        if (request_value->req_mask_ext & 0x0001 && ncp_newstyle) {
            proto_tree_add_item(atree, hf_ncp_sec_rel_to_y2k, tvb, loffset, 4, TRUE);
            loffset += 4;
        }
        if (request_value->req_mask_ext & 0x0002 && ncp_newstyle) {
            bitem = proto_tree_add_text(atree, tvb, loffset, -1, "DOS Name");
            btree = proto_item_add_subtree(bitem, ett_ncp);
            if (ncp_rec->func == 0x57) {
                str_length = tvb_get_guint8(tvb, loffset);
                loffset += 1;
            }
            else
            {
                str_length = tvb_get_letohs(tvb, loffset);
                loffset += 2;
            }
            proto_tree_add_item(btree, hf_ncp_file_name_12, tvb, loffset, str_length, FALSE);
            loffset += str_length;
            proto_item_set_end(bitem, tvb, loffset);
        }
        if (request_value->req_mask_ext & 0x0004 && ncp_newstyle) {
            ptvc = ptvcursor_new(atree, tvb, loffset);
            process_ptvc_record(ptvc, ptvc_struct_flush_time_struct,
                    NULL, TRUE, ncp_rec);
            ptvcursor_free(ptvc);
            loffset += 4;
        }
        if (request_value->req_mask_ext & 0x0008 && ncp_newstyle) {
            proto_tree_add_item(atree, hf_ncp_parent_base_id, tvb, loffset, 4, TRUE);
            loffset += 4;
        }
        if (request_value->req_mask_ext & 0x0010 && ncp_newstyle) {
            proto_tree_add_item(atree, hf_ncp_mac_finder_info, tvb, loffset, 32, TRUE);
            loffset += 32;
        }
        if (request_value->req_mask_ext & 0x0020 && ncp_newstyle) {
            proto_tree_add_item(atree, hf_ncp_sibling_count, tvb, loffset, 4, TRUE);
            loffset += 4;
        }
        if (request_value->req_mask_ext & 0x0040 && ncp_newstyle) {
            proto_tree_add_item(atree, hf_ncp_effective_rights, tvb, loffset, 1, TRUE);
            loffset += 4;
        }
        if (request_value->req_mask_ext & 0x0080 && ncp_newstyle) {
            bitem = proto_tree_add_text(atree, tvb, loffset, -1, "Mac Date");
            btree = proto_item_add_subtree(bitem, ett_ncp);
            ptvc = ptvcursor_new(btree, tvb, loffset);
            process_ptvc_record(ptvc, ptvc_struct_mac_time_struct,
                    NULL, TRUE, ncp_rec);
            ptvcursor_free(ptvc);
            loffset += 8;
            proto_item_set_end(bitem, tvb, loffset);
        }
        if (request_value->req_mask_ext & 0x0100 && ncp_newstyle) {
            ptvc = ptvcursor_new(atree, tvb, loffset);
            process_ptvc_record(ptvc, ptvc_struct_last_access_time_struct,
                    NULL, TRUE, ncp_rec);
            ptvcursor_free(ptvc);
            loffset += 2;
        }
        if (request_value->req_mask_ext & 0x0400 && ncp_newstyle) {
            proto_tree_add_item(atree, hf_ncp_f_size_64bit, tvb, loffset, 8, TRUE);
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
        proto_tree_add_item(atree, hf_ncp_file_name_12, tvb, loffset, str_length, FALSE);
        loffset += str_length;

        proto_item_set_end(aitem, tvb, loffset);

        if(tvb_length_remaining(tvb, loffset) < 4 )
        {
                break;
        }
    }
}

static void
dissect_ncp_123_62_reply(tvbuff_t *tvb, proto_tree *volatile ncp_tree)
{
    char value_format[2]="\0";
    char param_string[256]="\0";

    build_expert_data(ncp_tree, "ncp.set_cmd_type",
                      value_format, sizeof value_format, 0, FALSE);
    build_expert_data(ncp_tree, "ncp.set_cmd_name",
                      param_string, sizeof param_string, 0, FALSE);
    switch (atoi(value_format)) {
    case 0:   /* { 0x00, "Numeric Value" }, */
    case 2:   /* { 0x02, "Ticks Value" },   */
    case 4:   /* { 0x04, "Time Value" },    */
    case 6:   /* { 0x06, "Trigger Value" }, */
    case 7:   /* { 0x07, "Numeric Value" }, */
        proto_tree_add_item(ncp_tree, hf_srvr_param_number, tvb, 37+(gint)strlen(param_string), 4, TRUE);
        break;
    case 1:   /* { 0x01, "Boolean Value" }, */
        proto_tree_add_item(ncp_tree, hf_srvr_param_boolean, tvb, 37+(gint)strlen(param_string), 1, TRUE);
        break;
    case 5:   /* { 0x05, "String Value" },  */
        proto_tree_add_item(ncp_tree, hf_srvr_param_string, tvb, 37+(gint)strlen(param_string), -1, TRUE);
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
    fragment_data       *fd_head;
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
        conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                         PT_NCP, nw_connection, nw_connection, 0);
        if (conversation != NULL) {
            /* find the record telling us the request made that caused
               this reply */
            request_value = ncp_hash_lookup(conversation, sequence, pinfo->fd->num);
            if (!request_value) {
                dissect_ncp_reply(tvb, pinfo, nw_connection, sequence, type, tree, ncp_tap);
                return;
            }
            p_add_proto_data(pinfo->fd, proto_ncp, (void*) request_value);
        }
        /* else... we haven't seen an NCP Request for that conversation and sequence. */
        else
            {
                dissect_ncp_reply(tvb, pinfo, nw_connection, sequence, type, tree, ncp_tap);
                return;
            }
    }
    else {
        request_value = p_get_proto_data(pinfo->fd, proto_ncp);
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
    if (request_value->nds_frag || (request_value->nds_end_frag == pinfo->fd->num))
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
                fd_head = fragment_add_seq_next(tvb, 0, pinfo, tid, nds_fragment_table, nds_reassembled_table, len, request_value->nds_frag);
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
                        fd_head = fragment_add_seq_next(tvb, 16, pinfo, tid, nds_fragment_table, nds_reassembled_table, len-16, request_value->nds_frag);
                        frags[frag_count].sequence = sequence;
                    }
                    else
                    {
                        if (check_col(pinfo->cinfo, COL_INFO)) {
                            col_add_fstr(pinfo->cinfo, COL_INFO, "[Retransmitted NDS Fragment 0x%08x]", frags[frag_count].nds_frag);
                        }
                        return;
                    }
                }
                else
                {
                    fd_head = fragment_add_seq_next(tvb, 16, pinfo, tid, nds_fragment_table, nds_reassembled_table, len-16, request_value->nds_frag);
                    frags[frag_count].sequence = sequence;
                }
            }
            if (fd_head != NULL)
            {
                /* Is this the last fragment? nds_frag will indicate */
                if (fd_head->next != NULL && !request_value->nds_frag)
                {
                    frag_tvb = tvb_new_child_real_data(tvb, fd_head->data,
                                                 fd_head->len, fd_head->len);
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
                        request_value->nds_end_frag = pinfo->fd->num;
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
                    if (check_col(pinfo->cinfo, COL_INFO))
                    {
                      if (request_value->nds_frag)
                      {
                        col_add_fstr(pinfo->cinfo, COL_INFO, "[NDS Fragment 0x%08x]", frags[frag_count].nds_frag);
                      }
                    }
                }
            }
            else
            {
                /* Fragment from first pass of dissection */
                if (check_col(pinfo->cinfo, COL_INFO))
                {
                  if (request_value->nds_frag)
                  {
                     col_add_fstr(pinfo->cinfo, COL_INFO, "[NDS Fragment 0x%08x]", frags[frag_count].nds_frag);
                  }
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
        if (request_value->nds_end_frag < pinfo->fd->num) {
            if (check_col(pinfo->cinfo, COL_INFO)) {
                col_add_fstr(pinfo->cinfo, COL_INFO, "[Retransmitted end of NDS Fragment 0x%08x, see packet #%d for details.]", request_value->nds_frag_num, request_value->nds_end_frag);
            }
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

    for (i = 0; i < NUM_REQ_CONDS; i++) {
        if (!dfilter_compile((const gchar*)req_conds[i].dfilter_text,
                             &req_conds[i].dfilter)) {
            g_message("NCP dissector failed to compile dfilter: %s\n",
                      req_conds[i].dfilter_text);
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
    volatile gboolean       run_info_str = FALSE;
    guint32                 length_remaining;
    guint32                 testvar;
    volatile unsigned long  exception_code;
    const char              *volatile message;


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
        length_remaining = tvb_length_remaining(tvb, 4);
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
                    expert_add_info_format(pinfo, NULL, PI_RESPONSE_CODE, PI_CHAT, "Connection Request");
                }
            }
        }
        else
        {
            ncp_rec = &ncp1111_request;
            if (ncp_echo_conn) {
                expert_add_info_format(pinfo, NULL, PI_RESPONSE_CODE, PI_CHAT, "Connection Request");
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
            expert_add_info_format(pinfo, NULL, PI_RESPONSE_CODE, PI_CHAT, "Destroy Connection %u Request", nw_connection);
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
    if (check_col(pinfo->cinfo, COL_INFO)) {
        if (ncp_rec) {
            col_add_fstr(pinfo->cinfo, COL_INFO, "C %s", ncp_rec->name);
            if (ncp_rec->req_info_str) {
                /* We want to add more stuff to the Info
                   column. */
                run_info_str = TRUE;
            }
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
        conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                         PT_NCP, nw_connection, nw_connection, 0);

        if (conversation == NULL) {
            /* It's not part of any conversation - create a new one. */
            conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                            PT_NCP, nw_connection, nw_connection, 0);
        }
        request_value = ncp_hash_insert(conversation, sequence, ncp_rec, pinfo->fd->num);
        request_value->req_frame_num = pinfo->fd->num;
        request_value->req_frame_time = pinfo->fd->abs_ts;

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
    if ((run_info_str || run_req_cond) && !ncp_tree) {
        proto_item *ti;

        temp_tree = proto_tree_create_root(pinfo);
        proto_tree_set_visible(temp_tree, FALSE);
        ti = proto_tree_add_item(temp_tree, proto_ncp, tvb, 0, -1, FALSE);
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

        /* Before the dissection, if we need a field for the info_str,
         * prime the tree. */
        if (run_info_str) {
            proto_tree_prime_hfid(ncp_tree, *ncp_rec->req_info_str->hf_ptr);
        }

        switch (type) {
        case NCP_BROADCAST_SLOT:
            ; /* nothing */
            break;

        case NCP_SERVICE_REQUEST:
            proto_tree_add_uint_format(ncp_tree, hf_ncp_func, tvb, 6, 1,
                                       func, "Function: %u (0x%02X), %s",
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
                                    2, FALSE);
                proto_tree_add_uint_format(ncp_tree, hf_ncp_subfunc, tvb, 9, 1,
                                           subfunc, "SubFunction: %u (0x%02x)",
                                           subfunc, subfunc);
                ptvc = ptvcursor_new(ncp_tree, tvb, 10);
            }
            else {
                proto_tree_add_uint_format(ncp_tree, hf_ncp_subfunc, tvb, 7, 1,
                                           subfunc, "SubFunction: %u (0x%02x)",
                                           subfunc, subfunc);
                ptvc = ptvcursor_new(ncp_tree, tvb, 8);
            }
        }
        else {
            ptvc = ptvcursor_new(ncp_tree, tvb, 7);
        }

        /* The group is not part of the packet, but it's useful
         * information to display anyway. Put it in the tree for filtering and tap use*/
        if (ncp_rec) {
            proto_tree_add_uint_format(ncp_tree, hf_ncp_group, tvb, 0, 0, ncp_rec->group, "Group: %s", ncp_groups[ncp_rec->group]);
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
                process_ptvc_record(ptvc, ncp_rec->request_ptvc, NULL, TRUE, ncp_rec);
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

            results = se_alloc0(sizeof(gboolean)*NUM_REQ_CONDS);
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
        /* Construct the info string if necessary */
        if (run_info_str) {
            GPtrArray *parray;
            char*   byte_string;
            char    non_uni_string[1024];
            int i, len;
            field_info *finfo;
            int info_type;

            if (!request_value)
            {
                conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                                 PT_NCP, nw_connection, nw_connection, 0);
                if (conversation != NULL) {
                    /* find the record telling us the request made that caused
                       this reply */
                    request_value = ncp_hash_lookup(conversation, sequence, pinfo->fd->num);
                }
                if (!conversation || !request_value)
                {
                    return;
                }
            }

            parray = proto_get_finfo_ptr_array(ncp_tree,
                                               *ncp_rec->req_info_str->hf_ptr);
            len = g_ptr_array_len(parray);

            if (len > 0) {

                col_set_str(pinfo->cinfo, COL_INFO, "C ");

                finfo = g_ptr_array_index(parray, 0);

                info_type = get_info_type((const gchar*) ncp_rec->req_info_str->first_string);

                if (info_type != 0) {    /* Is this  a string or not? */

                    if (info_type == 1) {   /* Is this bytes? */
                        byte_string = bytes_to_str(get_finfo_value_string(finfo), get_finfo_length(finfo));
                        col_append_fstr(pinfo->cinfo, COL_INFO,
                                        (const gchar*) ncp_rec->req_info_str->first_string,
                                        byte_string);
                    }
                    else
                    {
                        if (info_type == 2) {   /* Is this a String? */
                            uni_to_string(get_finfo_value_string(finfo), get_finfo_length(finfo), non_uni_string);
                            col_append_fstr(pinfo->cinfo, COL_INFO,
                                            (const gchar*) ncp_rec->req_info_str->first_string,
                                            non_uni_string);
                        }
                        else
                        {
                            col_append_fstr(pinfo->cinfo, COL_INFO,
                                            (const gchar*) ncp_rec->req_info_str->first_string,
                                            get_finfo_value_string(finfo));
                        }
                    }
                }
                else
                {
                    col_append_fstr(pinfo->cinfo, COL_INFO,
                                    (const gchar*) ncp_rec->req_info_str->first_string,
                                    get_finfo_value_integer(finfo));
                }
            }
            if (len > 1) {
                for (i = 1; i < len; i++) {
                    non_uni_string[0]='\0';
                    finfo = g_ptr_array_index(parray, i);
                    info_type = get_info_type((const gchar*) ncp_rec->req_info_str->repeat_string);

                    if (info_type != 0) {    /* Is this  a string or not? */
                        if (info_type == 1)
                        {   /* Is this bytes? */
                            byte_string = bytes_to_str(get_finfo_value_string(finfo), get_finfo_length(finfo));
                            col_append_fstr(pinfo->cinfo, COL_INFO,
                                            (const gchar*) ncp_rec->req_info_str->repeat_string,
                                            byte_string);
                        }
                        else
                        {
                            if (info_type == 2) {   /* Is this a String? */
                                uni_to_string(get_finfo_value_string(finfo), get_finfo_length(finfo), non_uni_string);
                                col_append_fstr(pinfo->cinfo, COL_INFO,
                                                (const gchar*) ncp_rec->req_info_str->repeat_string,
                                                non_uni_string);
                            }
                            else
                            {
                                col_append_fstr(pinfo->cinfo, COL_INFO,
                                                (const gchar*) ncp_rec->req_info_str->repeat_string,
                                                get_finfo_value_string(finfo));
                            }
                        }
                    }
                    else
                    {
                        col_append_fstr(pinfo->cinfo, COL_INFO,
                                        (const gchar*) ncp_rec->req_info_str->repeat_string,
                                        get_finfo_value_integer(finfo));
                    }
                }
            }
        }
        if (!request_value)
        {
             conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                                 PT_NCP, nw_connection, nw_connection, 0);
             if (conversation != NULL) {
                 /* find the record telling us the request made that caused
                    this reply */
                 request_value = ncp_hash_lookup(conversation, sequence, pinfo->fd->num);
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
            char ret_info_string[16];
            char ret_info_string_ext[16];

            build_expert_data(ncp_tree, "ncp.ret_info_mask",
                              ret_info_string, sizeof ret_info_string, 0, FALSE);
            request_value->req_mask = (guint32) atoi(ret_info_string);
            build_expert_data(ncp_tree, "ncp.ext_info",
                              ret_info_string_ext, sizeof ret_info_string_ext,
                              0, FALSE);
            request_value->req_mask_ext = (guint32) atoi(ret_info_string_ext);
        }
        /* NCP function 89/6 passes either ASCII or UTF8 data */
        /* Decode manually since it is not possible to SREC the request */
        /* packets from the python code */
        if (func == 0x59 && subfunc == 0x6) {
            dissect_ncp_89_6_request(tvb, ncp_tree, 22);
        }
        /* Check to see if we need to report to the expert table */
        trap_for_expert_event(ncp_tree, pinfo, ncp_rec, 0);
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
    const char *reply_buffer;
    guint8     ping_version;
    guint32    nds_string_len;
    guint32    nds_offset;
    guint32    bvalue;
    guint32    nds_flags;
    nds_val    pvalues[9];
    int        i;
    nstime_t   ns;

    ping_version = tvb_get_guint8(tvb, 8);
    proto_tree_add_item(ncp_tree, hf_ping_version, tvb, 8, 1, TRUE);
    if (ping_version == 9) {
        nds_string_len = tvb_get_ntohl(tvb, 9);
        nds_offset = nds_string_len+16;
        tvb_ensure_bytes_exist(tvb, 16, nds_string_len);
        proto_tree_add_item(ncp_tree, hf_nds_tree_name, tvb, 16, nds_string_len, FALSE);
        proto_tree_add_item(ncp_tree, hf_nds_reply_depth, tvb, nds_offset, 4, FALSE);
        proto_tree_add_item(ncp_tree, hf_nds_reply_rev, tvb, (nds_offset+4), 4, FALSE);
        proto_tree_add_item(ncp_tree, hf_nds_reply_flags, tvb, (nds_offset+8), 4, TRUE);
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
                    pvalues[0].vvalue = tvb_get_letohs(tvb, nds_offset);
                    pvalues[0].vtype = VTYPE_BITFIELD;
                    pvalues[0].vstring = "";
                    pvalues[0].vdesc = "Ping (low) Flags:";
                    pvalues[0].vlength = 2;
                    pvalues[0].hfname= hf_nds_rflags;
                    pvalues[0].voffset = nds_offset;
                    pvalues[0].bit1 = "Supported Fields";
                    pvalues[0].bit1hfname = hf_bit1pingflags1;
                    pvalues[0].bit2 = "Depth";
                    pvalues[0].bit2hfname = hf_bit2pingflags1;
                    pvalues[0].bit3 = "Build Number";
                    pvalues[0].bit3hfname = hf_bit3pingflags1;
                    pvalues[0].bit4 = "Flags";
                    pvalues[0].bit4hfname = hf_bit4pingflags1;
                    pvalues[0].bit5 = "Verification Flags";
                    pvalues[0].bit5hfname = hf_bit5pingflags1;
                    pvalues[0].bit6 = "Letter Version";
                    pvalues[0].bit6hfname = hf_bit6pingflags1;
                    pvalues[0].bit7 = "OS Version";
                    pvalues[0].bit7hfname = hf_bit7pingflags1;
                    pvalues[0].bit8 = "License Flags";
                    pvalues[0].bit8hfname = hf_bit8pingflags1;
                    pvalues[0].bit9 = "DS Time";
                    pvalues[0].bit9hfname = hf_bit9pingflags1;
                    pvalues[0].bit10 = "Server Time";
                    pvalues[0].bit10hfname = hf_bit10pingflags1;
                    pvalues[0].bit11 = "Create Time";
                    pvalues[0].bit11hfname = hf_bit11pingflags1;
                    pvalues[0].bit12 = "Not Defined";
                    pvalues[0].bit12hfname = hf_bit12pingflags1;
                    pvalues[0].bit13 = "Not Defined";
                    pvalues[0].bit13hfname = hf_bit13pingflags1;
                    pvalues[0].bit14 = "Not Defined";
                    pvalues[0].bit14hfname = hf_bit14pingflags1;
                    pvalues[0].bit15 = "Not Defined";
                    pvalues[0].bit15hfname = hf_bit15pingflags1;
                    pvalues[0].bit16 = "Not Defined";
                    pvalues[0].bit16hfname = hf_bit16pingflags1;

                    process_bitfield(ncp_tree, tvb, &pvalues[0]);
                    nds_offset += 2;

                    pvalues[0].vvalue = tvb_get_letohs(tvb, nds_offset);
                    pvalues[0].vtype = VTYPE_BITFIELD;
                    pvalues[0].vstring = "";
                    pvalues[0].vdesc = "Ping (high) Flags:";
                    pvalues[0].vlength = 2;
                    pvalues[0].hfname= hf_nds_rflags;
                    pvalues[0].voffset = nds_offset;
                    pvalues[0].bit1 = "Sap Name";
                    pvalues[0].bit1hfname = hf_bit1pingflags2;
                    pvalues[0].bit2 = "Tree Name";
                    pvalues[0].bit2hfname = hf_bit2pingflags2;
                    pvalues[0].bit3 = "OS Name";
                    pvalues[0].bit3hfname = hf_bit3pingflags2;
                    pvalues[0].bit4 = "Hardware Name";
                    pvalues[0].bit4hfname = hf_bit4pingflags2;
                    pvalues[0].bit5 = "Vendor Name";
                    pvalues[0].bit5hfname = hf_bit5pingflags2;
                    pvalues[0].bit6 = "Not Defined";
                    pvalues[0].bit6hfname = hf_bit6pingflags2;
                    pvalues[0].bit7 = "Not Defined";
                    pvalues[0].bit7hfname = hf_bit7pingflags2;
                    pvalues[0].bit8 = "Not Defined";
                    pvalues[0].bit8hfname = hf_bit8pingflags2;
                    pvalues[0].bit9 = "Not Defined";
                    pvalues[0].bit9hfname = hf_bit9pingflags2;
                    pvalues[0].bit10 = "Not Defined";
                    pvalues[0].bit10hfname = hf_bit10pingflags2;
                    pvalues[0].bit11 = "Not Defined";
                    pvalues[0].bit11hfname = hf_bit11pingflags2;
                    pvalues[0].bit12 = "Not Defined";
                    pvalues[0].bit12hfname = hf_bit12pingflags2;
                    pvalues[0].bit13 = "Not Defined";
                    pvalues[0].bit13hfname = hf_bit13pingflags2;
                    pvalues[0].bit14 = "Not Defined";
                    pvalues[0].bit14hfname = hf_bit14pingflags2;
                    pvalues[0].bit15 = "Not Defined";
                    pvalues[0].bit15hfname = hf_bit15pingflags2;
                    pvalues[0].bit16 = "Not Defined";
                    pvalues[0].bit16hfname = hf_bit16pingflags2;

                    process_bitfield(ncp_tree, tvb, &pvalues[0]);
                    nds_offset += 2;
                    break;
                case 0x00000002:
                    proto_tree_add_item(ncp_tree, hf_nds_reply_depth, tvb, nds_offset, 4, TRUE);
                    nds_offset += 4;
                    break;
                case 0x00000004:
                    proto_tree_add_item(ncp_tree, hf_nds_reply_rev, tvb, nds_offset, 4, TRUE);
                    nds_offset += 4;
                    break;
                case 0x00000008:
                    pvalues[0].vvalue = tvb_get_letohl(tvb, nds_offset);
                    pvalues[0].vtype = VTYPE_BITFIELD;
                    pvalues[0].vstring = "";
                    pvalues[0].vdesc = "Pong Data Flags:";
                    pvalues[0].vlength = 4;
                    pvalues[0].hfname= hf_nds_rflags;
                    pvalues[0].voffset = nds_offset;
                    pvalues[0].bit1 = "Root Most Master Replica";
                    pvalues[0].bit1hfname = hf_bit1pingpflags1;
                    pvalues[0].bit2 = "Time Synchronized?";
                    pvalues[0].bit2hfname = hf_bit2pingpflags1;
                    pvalues[0].bit3 = "Time Valid?";
                    pvalues[0].bit3hfname = hf_bit3pingpflags1;
                    pvalues[0].bit4 = "DS Time Synchronized?";
                    pvalues[0].bit4hfname = hf_bit4pingpflags1;
                    pvalues[0].bit5 = "Agent Has All Replicas?";
                    pvalues[0].bit5hfname = hf_bit5pingpflags1;
                    pvalues[0].bit6 = "Not Defined";
                    pvalues[0].bit6hfname = hf_bit6pingpflags1;
                    pvalues[0].bit7 = "Not Defined";
                    pvalues[0].bit7hfname = hf_bit7pingpflags1;
                    pvalues[0].bit8 = "Not Defined";
                    pvalues[0].bit8hfname = hf_bit8pingpflags1;
                    pvalues[0].bit9 = "Not Defined";
                    pvalues[0].bit9hfname = hf_bit9pingpflags1;
                    pvalues[0].bit10 = "Not Defined";
                    pvalues[0].bit10hfname = hf_bit10pingpflags1;
                    pvalues[0].bit11 = "Not Defined";
                    pvalues[0].bit11hfname = hf_bit11pingpflags1;
                    pvalues[0].bit12 = "Not Defined";
                    pvalues[0].bit12hfname = hf_bit12pingpflags1;
                    pvalues[0].bit13 = "Not Defined";
                    pvalues[0].bit13hfname = hf_bit13pingpflags1;
                    pvalues[0].bit14 = "Not Defined";
                    pvalues[0].bit14hfname = hf_bit14pingpflags1;
                    pvalues[0].bit15 = "Not Defined";
                    pvalues[0].bit15hfname = hf_bit15pingpflags1;
                    pvalues[0].bit16 = "Not Defined";
                    pvalues[0].bit16hfname = hf_bit16pingpflags1;

                    process_bitfield(ncp_tree, tvb, &pvalues[0]);
                    nds_offset += 4;
                    break;
                case 0x00000010:
                    pvalues[0].vvalue = tvb_get_letohl(tvb, nds_offset);
                    pvalues[0].vtype = VTYPE_BITFIELD;
                    pvalues[0].vstring = "";
                    pvalues[0].vdesc = "Verification Flags:";
                    pvalues[0].vlength = 4;
                    pvalues[0].hfname= hf_nds_rflags;
                    pvalues[0].voffset = nds_offset;
                    pvalues[0].bit1 = "Checksum Verification";
                    pvalues[0].bit1hfname = hf_bit1pingvflags1;
                    pvalues[0].bit2 = "CRC32 Verification";
                    pvalues[0].bit2hfname = hf_bit2pingvflags1;
                    pvalues[0].bit3 = "Server Verification Enforced";
                    pvalues[0].bit3hfname = hf_bit3pingvflags1;
                    pvalues[0].bit4 = "Not Defined";
                    pvalues[0].bit4hfname = hf_bit4pingvflags1;
                    pvalues[0].bit5 = "Not Defined";
                    pvalues[0].bit5hfname = hf_bit5pingvflags1;
                    pvalues[0].bit6 = "Not Defined";
                    pvalues[0].bit6hfname = hf_bit6pingvflags1;
                    pvalues[0].bit7 = "Not Defined";
                    pvalues[0].bit7hfname = hf_bit7pingvflags1;
                    pvalues[0].bit8 = "Not Defined";
                    pvalues[0].bit8hfname = hf_bit8pingvflags1;
                    pvalues[0].bit9 = "Not Defined";
                    pvalues[0].bit9hfname = hf_bit9pingvflags1;
                    pvalues[0].bit10 = "Not Defined";
                    pvalues[0].bit10hfname = hf_bit10pingvflags1;
                    pvalues[0].bit11 = "Not Defined";
                    pvalues[0].bit11hfname = hf_bit11pingvflags1;
                    pvalues[0].bit12 = "Not Defined";
                    pvalues[0].bit12hfname = hf_bit12pingvflags1;
                    pvalues[0].bit13 = "Not Defined";
                    pvalues[0].bit13hfname = hf_bit13pingvflags1;
                    pvalues[0].bit14 = "Not Defined";
                    pvalues[0].bit14hfname = hf_bit14pingvflags1;
                    pvalues[0].bit15 = "Not Defined";
                    pvalues[0].bit15hfname = hf_bit15pingvflags1;
                    pvalues[0].bit16 = "Not Defined";
                    pvalues[0].bit16hfname = hf_bit16pingvflags1;

                    process_bitfield(ncp_tree, tvb, &pvalues[0]);
                    nds_offset += 4;
                    break;
                case 0x00000020:
                    proto_tree_add_item(ncp_tree, hf_nds_letter_ver, tvb, nds_offset, 4, TRUE);
                    nds_offset += 4;
                    break;
                case 0x00000040:
                    proto_tree_add_item(ncp_tree, hf_nds_os_majver, tvb, nds_offset, 4, TRUE);
                    nds_offset += 4;
                    proto_tree_add_item(ncp_tree, hf_nds_os_minver, tvb, nds_offset, 4, TRUE);
                    nds_offset += 4;
                    proto_tree_add_item(ncp_tree, hf_ncp_os_revision, tvb, nds_offset, 4, TRUE);
                    nds_offset += 4;
                    break;
                case 0x00000100:
                    proto_tree_add_item(ncp_tree, hf_nds_lic_flags, tvb, nds_offset, 4, TRUE);
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
                    reply_buffer = get_string(tvb, nds_offset, nds_string_len);
                    tvb_ensure_bytes_exist(tvb, nds_offset, nds_string_len);
                    proto_tree_add_text(ncp_tree, tvb, nds_offset, nds_string_len, "SAP Name: %s", reply_buffer);
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
                    reply_buffer = get_string(tvb, nds_offset, nds_string_len);
                    tvb_ensure_bytes_exist(tvb, nds_offset, nds_string_len);
                    proto_tree_add_text(ncp_tree, tvb, nds_offset, nds_string_len, "NDS Tree Name: %s", reply_buffer);
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
                    reply_buffer = get_string(tvb, nds_offset, nds_string_len);
                    tvb_ensure_bytes_exist(tvb, nds_offset, nds_string_len);
                    proto_tree_add_text(ncp_tree, tvb, nds_offset, nds_string_len, "OS Name: %s", reply_buffer);
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
                    reply_buffer = get_string(tvb, nds_offset, nds_string_len);
                    tvb_ensure_bytes_exist(tvb, nds_offset, nds_string_len);
                    proto_tree_add_text(ncp_tree, tvb, nds_offset, nds_string_len, "Hardware Name: %s", reply_buffer);
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
                    reply_buffer = get_string(tvb, nds_offset, nds_string_len);
                    tvb_ensure_bytes_exist(tvb, nds_offset, nds_string_len);
                    proto_tree_add_text(ncp_tree, tvb, nds_offset, nds_string_len, "Vendor Name: %s", reply_buffer);
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
    guint32                         nds_reply_buffer;
    guint32                         nds_frag;
    proto_item                      *expert_item;
    const char                      *verb_string;
    nds_val                         pvalues[9];
    gboolean                        resolve_eid=FALSE;
    guint32                         global_eid=0;
    gboolean                        add_eid = FALSE;
    char                            global_object_name[256];
    ncp_req_eid_hash_value          *request_eid_value = NULL;
    int                             i;

    global_object_name[0] = '\0';

    nds_offset = 8;

    nds_reply_buffer = tvb_get_letohl(tvb, nds_offset);
    proto_tree_add_uint(ncp_tree, hf_ncp_fragment_size, tvb, nds_offset,
                        4, nds_reply_buffer);
    nds_offset += 4;
    nds_frag = tvb_get_letohl(tvb, nds_offset);
    proto_tree_add_uint(ncp_tree, hf_ncp_fragment_handle, tvb, nds_offset,
                        4, nds_frag);
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
            expert_add_info_format(pinfo, expert_item, PI_RESPONSE_CODE, PI_ERROR, "NDS Error: 0x%08x %s", nds_error_code, nds_error_string);
        }
    }
    if (request_value && nds_error_code == 0x00000000)
    {
        nds_offset = 20;
        for (i = 0; i < 9; i++) {
            pvalues[i].vtype = 0;
            pvalues[i].vvalue = 0;
            pvalues[i].vlength = 0;
            pvalues[i].voffset = 0;
            pvalues[i].hfname = 0;
            pvalues[i].vdesc = "";
            pvalues[i].vstring = NULL;
            pvalues[i].mvtype = 0;
        }
        verb_string = val_to_str_const(request_value->nds_request_verb,
                                       ncp_nds_verb_vals, "Continuation Fragment");
        if(request_value->req_nds_prot_flags & 0x4000)
        {
            /* CRC is included in the NDS header so justify the offset */
            proto_tree_add_item(ncp_tree, hf_nds_crc, tvb, nds_offset, 4, TRUE);
            nds_offset += 4;
        }
        switch (request_value->nds_request_verb)
        {
        case 0x01:
            pvalues[0].vvalue = tvb_get_letohl(tvb, nds_offset);
            pvalues[0].vstring = val_to_str_const(pvalues[0].vvalue, nds_tags, "No Tags Set");
            pvalues[0].vtype = VTYPE_STRING;
            pvalues[0].vdesc = "Tag: %s";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = nds_offset;
            pvalues[0].hfname = hf_nds_tag_string;
            nds_offset = nds_offset+pvalues[0].vlength;
            switch(pvalues[0].vvalue)
            {
            case NDS_TAG_NO_SUCH_ENTRY:
                break;
            case NDS_TAG_LOCAL_ENTRY:
                pvalues[1].vvalue = tvb_get_letohl(tvb, nds_offset);
                pvalues[1].vtype = VTYPE_UINT32;
                pvalues[1].vdesc = "Entry ID: 0x%08x";
                add_eid = TRUE;
                resolve_eid = TRUE;
                g_strlcpy(global_object_name, request_value->object_name, 256);
                global_eid = pvalues[1].vvalue;
                pvalues[1].vlength = 4;
                pvalues[1].voffset = nds_offset;
                pvalues[1].hfname = hf_nds_eid;
                nds_offset = nds_offset+pvalues[1].vlength;
                pvalues[2].vvalue = tvb_get_letohl(tvb, nds_offset);
                pvalues[2].vtype = VTYPE_MULTIVALUE_UINT32;
                pvalues[2].vdesc = "Referral Records: %u";
                pvalues[2].vlength = 4;
                pvalues[2].voffset = nds_offset;
                pvalues[2].hfname = hf_nds_referrals;
                pvalues[2].mvtype = MVTYPE_LOC_ADDR_REFERRAL_REPLY;
                break;
            case NDS_TAG_REMOTE_ENTRY:
                nds_offset += 4;   /* GUINT32 reserved field */
                pvalues[1].vvalue = tvb_get_letohl(tvb, nds_offset);
                pvalues[1].vtype = VTYPE_UINT32;
                pvalues[1].vdesc = "Entry ID: 0x%08x";
                pvalues[1].vlength = 4;
                pvalues[1].voffset = nds_offset;
                pvalues[1].hfname = hf_nds_eid;
                nds_offset = nds_offset+pvalues[1].vlength;
                pvalues[2].vvalue = tvb_get_letohl(tvb, nds_offset);
                pvalues[2].vtype = VTYPE_MULTIVALUE_UINT32;
                pvalues[2].vdesc = "Referral Records: %u";
                pvalues[2].vlength = 4;
                pvalues[2].voffset = nds_offset;
                pvalues[2].hfname = hf_nds_referrals;
                pvalues[2].mvtype = MVTYPE_LOC_ADDR_REFERRAL_REPLY;
                break;
            case NDS_TAG_ALIAS_ENTRY:
                pvalues[1].vtype = VTYPE_STRING;
                pvalues[1].vdesc = "Alias Name: %s";
                pvalues[1].mvtype = MVTYPE_ATTR_REQUEST;
                pvalues[1].vvalue = 0;
                pvalues[1].vlength = 256;
                pvalues[1].vlength = tvb_get_letohl(tvb, nds_offset);
                if (pvalues[1].vlength == 0x00)
                {
                    pvalues[1].vtype = VTYPE_NONE;
                    break;
                }
                pvalues[1].voffset = nds_offset+4;
                nds_offset += 4;
                pvalues[1].vstring = get_string(tvb, pvalues[1].voffset, pvalues[1].vlength);
                nds_offset += pvalues[1].vlength;
                nds_offset += align_4(tvb, nds_offset);
                pvalues[1].hfname= hf_nds_name;
                break;
            case NDS_TAG_REFERRAL_INFORMATION:
                pvalues[1].vvalue = tvb_get_letohl(tvb, nds_offset);
                pvalues[1].vtype = VTYPE_UINT32;
                pvalues[1].vdesc = "Distance Object is From Root: 0x%08x";
                pvalues[1].vlength = 4;
                pvalues[1].voffset = nds_offset;
                pvalues[1].hfname = hf_nds_eid;
                nds_offset = nds_offset+pvalues[1].vlength;
                pvalues[2].vvalue = tvb_get_letohl(tvb, nds_offset);
                pvalues[2].vtype = VTYPE_MULTIVALUE_UINT32;
                pvalues[2].vdesc = "Referral Records: %u";
                pvalues[2].vlength = 4;
                pvalues[2].voffset = nds_offset;
                pvalues[2].hfname = hf_nds_depth;
                pvalues[2].mvtype = MVTYPE_ADDR_REFERRAL_REPLY;
                break;
            case NDS_TAG_ENTRY_AND_REFERRALS:
                pvalues[1].vvalue = tvb_get_letohl(tvb, nds_offset);
                pvalues[1].vtype = VTYPE_UINT32;
                pvalues[1].vdesc = "Result Flags: 0x%08x";
                pvalues[1].vlength = 4;
                pvalues[1].voffset = nds_offset;
                pvalues[1].hfname = hf_nds_result_flags;
                nds_offset = nds_offset+pvalues[1].vlength;
                pvalues[2].vvalue = tvb_get_letohl(tvb, nds_offset);
                pvalues[2].vtype = VTYPE_UINT32;
                pvalues[2].vdesc = "Entry ID: 0x%08x";
                add_eid = TRUE;
                resolve_eid = TRUE;
                global_eid = pvalues[2].vvalue;
                g_strlcpy(global_object_name, request_value->object_name, 256);
                pvalues[2].vlength = 4;
                pvalues[2].voffset = nds_offset;
                pvalues[2].hfname = hf_nds_eid;
                nds_offset = nds_offset+pvalues[2].vlength;
                pvalues[3].vvalue = tvb_get_letohl(tvb, nds_offset);
                pvalues[3].vtype = VTYPE_MULTIVALUE_UINT32;
                pvalues[3].vdesc = "Referral Records: %u";
                pvalues[3].vlength = 4;
                pvalues[3].voffset = nds_offset;
                pvalues[3].mvtype = MVTYPE_ADDR_REFERRAL_REPLY;
                pvalues[3].hfname = hf_nds_referrals;
                break;
            default:
                break;
            }
            break;
        case 0x02:
            nds_offset -= 4;
            pvalues[0].vvalue = 1;
            pvalues[0].vtype = VTYPE_MULTIVALUE_UINT32;
            pvalues[0].vdesc = "Entry Information";
            pvalues[0].vlength = 0;
            pvalues[0].voffset = nds_offset;
            pvalues[0].hfname = hf_nds_name;
            pvalues[0].mvtype = MVTYPE_LIST_PARTITIONS;
            pvalues[0].vflags = request_value->req_nds_flags;
            break;
        case 0x03:
            pvalues[0].vvalue = tvb_get_letohl(tvb, nds_offset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Iteration Handle: 0x%08x";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = nds_offset;
            pvalues[0].hfname = hf_nds_iteration;
            nds_offset = nds_offset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, nds_offset);
            pvalues[1].vstring = val_to_str_const(pvalues[1].vvalue, nds_info_type, "No Info Type Set");
            pvalues[1].vtype = VTYPE_STRING;
            pvalues[1].vdesc = "Info Type: %s";
            pvalues[1].vlength = 4;
            pvalues[1].voffset = nds_offset;
            pvalues[1].hfname = hf_nds_info_type;
            nds_offset = nds_offset+pvalues[1].vlength;
            pvalues[2].vvalue = tvb_get_letohl(tvb, nds_offset);
            pvalues[2].vtype = VTYPE_MULTIVALUE_UINT32;
            pvalues[2].vdesc = "Number of Attributes: %u";
            pvalues[2].vlength = 4;
            pvalues[2].voffset = nds_offset;
            pvalues[2].hfname = hf_nds_attr;
            pvalues[2].mvtype = MVTYPE_ATTR_REPLY;
            pvalues[2].vflags = request_value->req_nds_flags;
            pvalues[2].nds_version = request_value->nds_version;
            pvalues[2].pflags = request_value->req_nds_prot_flags;
            break;
        case 0x04:
            pvalues[0].vvalue = tvb_get_guint8(tvb, nds_offset);
            if (pvalues[0].vvalue == 0)
            {
                pvalues[0].vstring = "Did Not Match";
            }
            else
            {
                pvalues[0].vstring = "Matched";
            }
            pvalues[0].vtype = VTYPE_STRING;
            pvalues[0].vdesc = "Compare Values Returned - %s";
            pvalues[0].vlength = 1;
            pvalues[0].voffset = nds_offset;
            pvalues[0].mvtype = 0;
            pvalues[0].hfname= hf_nds_compare_results;
            nds_offset += pvalues[0].vlength;
            break;
        case 0x05:
            pvalues[0].vvalue = tvb_get_letohl(tvb, nds_offset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Iteration Handle: 0x%08x";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = nds_offset;
            pvalues[0].hfname = hf_nds_iteration;
            nds_offset = nds_offset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, nds_offset);
            pvalues[1].vtype = VTYPE_MULTIVALUE_UINT32;
            pvalues[1].vdesc = "Entry Information";
            pvalues[1].vlength = 0;
            pvalues[1].voffset = nds_offset;
            pvalues[1].hfname = hf_nds_name;
            pvalues[1].mvtype = MVTYPE_LIST_PARTITIONS;
            pvalues[1].vflags = request_value->req_nds_flags;
            break;
        case 0x06:
            break;
        case 0x07:
            break;
        case 0x08:
            break;
        case 0x09:
            break;
        case 0x0a:
            break;
        case 0x0b:
            break;
        case 0x0c:
            break;
        case 0x0d:
            break;
        case 0x0e:
            break;
        case 0x0f:
            pvalues[0].vvalue = tvb_get_letohl(tvb, nds_offset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Iteration Handle: 0x%08x";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = nds_offset;
            pvalues[0].hfname = hf_nds_iteration;
            nds_offset = nds_offset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, nds_offset);
            pvalues[1].vstring = val_to_str_const(pvalues[1].vvalue, class_def_type,
                                                  "No Class Definition Type Set");
            pvalues[1].vtype = VTYPE_STRING;
            pvalues[1].vdesc = "Class Definition Type: %s";
            pvalues[1].vlength = 4;
            pvalues[1].voffset = nds_offset;
            pvalues[1].mvtype = 0;
            pvalues[1].hfname= hf_nds_class_def_type;
            nds_offset = nds_offset + pvalues[1].vlength;
            pvalues[2].vvalue = tvb_get_letohl(tvb, nds_offset);;
            pvalues[2].vtype = VTYPE_MULTIVALUE_UINT32;
            pvalues[2].vdesc = "Class Definitions %u";
            pvalues[2].vlength = 0;
            pvalues[2].voffset = nds_offset;
            pvalues[2].hfname = hf_nds_classes;
            pvalues[2].mvtype = MVTYPE_CLASS_NAMES;
            pvalues[2].vflags = request_value->req_nds_flags;
            break;
        case 0x10:
            break;
        case 0x11:
            break;
        case 0x12:
            pvalues[0].vvalue = tvb_get_letohl(tvb, nds_offset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Iteration Handle: 0x%08x";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = nds_offset;
            pvalues[0].hfname = hf_nds_iteration;
            nds_offset = nds_offset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, nds_offset);
            pvalues[1].vtype = VTYPE_MULTIVALUE_UINT32;
            pvalues[1].vdesc = "Classes: %u";
            pvalues[1].vlength = 4;
            pvalues[1].voffset = nds_offset;
            pvalues[1].mvtype = MVTYPE_READ_CLASS_REQ;
            pvalues[1].hfname= hf_nds_classes;
            break;
        case 0x13:
            pvalues[0].vvalue = tvb_get_letohl(tvb, nds_offset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Privileges: 0x%08x";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = nds_offset;
            pvalues[0].hfname = hf_nds_privileges;
            nds_offset = nds_offset+pvalues[0].vlength;
            break;
        case 0x14:
            break;
        case 0x15:
            break;
        case 0x16:
            pvalues[0].vvalue = tvb_get_letohl(tvb, nds_offset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Iteration Handle: 0x%08x";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = nds_offset;
            pvalues[0].hfname = hf_nds_iteration;
            nds_offset = nds_offset+pvalues[0].vlength;
            pvalues[1].vtype = VTYPE_STRING;
            pvalues[1].vdesc = "Server Distinguished Name: %s";
            pvalues[1].mvtype = MVTYPE_ATTR_REQUEST;
            pvalues[1].vvalue = 0;
            pvalues[1].vlength = 256;
            pvalues[1].vlength = tvb_get_letohl(tvb, nds_offset);
            if (pvalues[1].vlength == 0x00)
            {
                pvalues[1].vtype = VTYPE_NONE;
                break;
            }
            pvalues[1].voffset = nds_offset+4;
            nds_offset += 4;
            pvalues[1].vstring = get_string(tvb, pvalues[1].voffset, pvalues[1].vlength);
            nds_offset += pvalues[1].vlength;
            nds_offset += align_4(tvb, nds_offset);
            pvalues[1].hfname= hf_nds_name;
            nds_offset += align_4(tvb, nds_offset);
            pvalues[2].vvalue = tvb_get_letohl(tvb, nds_offset);
            pvalues[2].vtype = VTYPE_MULTIVALUE_UINT32;
            pvalues[2].vdesc = "Replicas: %u";
            pvalues[2].vlength = 4;
            pvalues[2].voffset = nds_offset;
            pvalues[2].hfname = hf_nds_replicas;
            pvalues[2].mvtype = MVTYPE_READ_REPLICAS;
            pvalues[2].bit1 = "Output Flags";
            pvalues[2].bit2 = "Entry ID";
            pvalues[2].bit3 = "Replica State";
            pvalues[2].bit4 = "Modification Timestamp";
            pvalues[2].bit5 = "Purge Time";
            pvalues[2].bit6 = "Local Partition ID";
            pvalues[2].bit7 = "Distinguished Name";
            pvalues[2].bit8 = "Replica Type";
            pvalues[2].bit9 = "Partition Busy";
            pvalues[2].vflags = request_value->req_nds_flags;
            break;
        case 0x17:
            break;
        case 0x18:
            break;
        case 0x19:
            break;
        case 0x1a:
            break;
        case 0x1b:
            pvalues[0].vvalue = tvb_get_ntohl(tvb, nds_offset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "File Handle: 0x%08x";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = nds_offset;
            pvalues[0].hfname = hf_nds_file_handle;
            nds_offset = nds_offset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, nds_offset);
            pvalues[1].vtype = VTYPE_UINT32;
            pvalues[1].vdesc = "File Size: %u";
            pvalues[1].vlength = 4;
            pvalues[1].voffset = nds_offset;
            pvalues[1].hfname = hf_nds_file_size;
            nds_offset = nds_offset+pvalues[1].vlength;
            break;
        case 0x1c:
            break;
        case 0x1d:
            break;
        case 0x1e:
            break;
        case 0x1f:
            break;
        case 0x20:
            break;
        case 0x21:
            break;
        case 0x22:
            break;
        case 0x23:
            break;
        case 0x24:
            break;
        case 0x25:
            break;
        case 0x26:
            break;
        case 0x27:
            break;
        case 0x28:
            break;
        case 0x29:
            break;
        case 0x2a:
            break;
        case 0x2b:
            break;
        case 0x2c:
            break;
        case 0x2d:
            break;
        case 0x2e:
            break;
        case 0x2f:
            break;
        case 0x30:
            break;
        case 0x31:
            break;
        case 0x32:
            break;
        case 0x33:
            break;
        case 0x34:
            break;
        case 0x35:
            pvalues[0].vtype = VTYPE_MULTIVALUE_UINT32;
            pvalues[0].vdesc = "Server Name";
            pvalues[0].mvtype = MVTYPE_PROCESS_TAGS;
            pvalues[0].vflags = request_value->req_nds_flags;
            pvalues[0].hfname = hf_nds_svr_dst_name;
            pvalues[0].vlength = tvb_get_letohl(tvb, nds_offset);
            if (pvalues[0].vlength == 0x00)
            {
                pvalues[0].vtype = VTYPE_NONE;
                break;
            }
            pvalues[0].voffset = nds_offset;
            nds_offset += pvalues[0].vlength + 4;
            nds_offset += align_4(tvb, nds_offset);
            pvalues[1].vvalue = tvb_get_letohl(tvb, nds_offset);
            pvalues[1].vtype = VTYPE_MULTIVALUE_UINT32;
            pvalues[1].vdesc = "Referral Records: %u";
            pvalues[1].vlength = 4;
            pvalues[1].voffset = nds_offset;
            pvalues[1].hfname = hf_nds_referrals;
            pvalues[1].mvtype = MVTYPE_LOC_ADDR_REFERRAL_REPLY;
            break;
        case 0x36:
            break;
        case 0x37:
            break;
        case 0x38:
            break;
        case 0x39:
            pvalues[1].vvalue = tvb_get_letohl(tvb, nds_offset);
            pvalues[1].vtype = VTYPE_UINT32;
            pvalues[1].vdesc = "Entry ID: 0x%08x";
            add_eid = TRUE;
            resolve_eid = TRUE;
            g_strlcpy(global_object_name, request_value->object_name, 256);
            global_eid = pvalues[1].vvalue;
            pvalues[1].vlength = 4;
            pvalues[1].voffset = nds_offset;
            pvalues[1].hfname = hf_nds_eid;
            nds_offset = nds_offset+pvalues[1].vlength;
            break;
        case 0x3a:
            break;
        case 0x3b:
            break;
        case 0x3c:
            break;
        case 0x3d:
            break;
        case 0x3e:
            break;
        case 0x3f:
            break;
        case 0x40:
            break;
        case 0x41:
            break;
        case 0x42:
            break;
        case 0x43:
            break;
        case 0x44:
            break;
        case 0x45:
            break;
        case 0x46:
            break;
        case 0x47:
            break;
        case 0x48:
            break;
        case 0x49:
            break;
        case 0x4a:
            break;
        case 0x4b:
            break;
        case 0x4c:
            break;
        case 0x4d:
            break;
        case 0x6e:
            pvalues[0].vvalue = tvb_get_letohl(tvb, nds_offset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Iteration Handle: 0x%08x";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = nds_offset;
            pvalues[0].hfname= hf_nds_iteration;
            nds_offset = nds_offset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, nds_offset);
            pvalues[1].vtype = VTYPE_NONE;
            pvalues[1].vdesc = "Iteration Completion Code: 0x%08x";
            pvalues[1].vlength = 4;
            pvalues[1].voffset = nds_offset;
            pvalues[1].hfname = hf_iter_completion_code;
            expert_item = proto_tree_add_uint_format(ncp_tree, pvalues[1].hfname, tvb, nds_offset,
                                                     4, pvalues[1].vvalue, "NDS Iteration Completion Code: 0x%08x, %s",
                                                     pvalues[1].vvalue, val_to_str(pvalues[1].vvalue, nds_reply_errors, "Unknown: %d"));

            if (pvalues[1].vvalue != 0 && ncp_echo_err) {
                expert_add_info_format(pinfo, expert_item, PI_RESPONSE_CODE, PI_ERROR, "NDS Iteration Error: 0x%08x %s",
                                       pvalues[1].vvalue, val_to_str(pvalues[1].vvalue, nds_reply_errors, "Unknown: %d"));
            }
            nds_offset = nds_offset+pvalues[1].vlength;
            pvalues[2].vvalue = tvb_get_letohl(tvb, nds_offset);
            pvalues[2].vtype = VTYPE_ITEM;
            pvalues[2].vlength = 4;
            pvalues[2].voffset = nds_offset;
            pvalues[2].mvtype = MVTYPE_PROCESS_ITERATOR;
            pvalues[2].hfname = hf_ncp_nds_iterverb;
            nds_offset = nds_offset + pvalues[2].vlength;
            break;
        default:
            break;
        }
        if(request_value->nds_request_verb != 0)
        {
            proto_tree_add_uint_format(ncp_tree,
                                       hf_ncp_nds_verb, tvb, 6, 0,
                                       request_value->nds_request_verb,
                                       "NDS Verb: %d, %s",
                                       request_value->nds_request_verb, verb_string);
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
                    g_strlcpy(request_eid_value->object_name, global_object_name, 256);
                }
            }
        }
        /* Echo EID data to expert Chat window */
        if (add_eid && nds_echo_eid) {
            expert_add_info_format(pinfo, NULL,
                                   PI_RESPONSE_CODE, PI_CHAT,
                                   "EID (%08x) = %s", global_eid, global_object_name);
        }
        /* For NDS requests with just an EID, resolve name
         * from hash table. */
        if(resolve_eid)
        {
            request_eid_value = ncp_eid_hash_lookup(conversation, global_eid);
            if (request_eid_value) {
                g_strlcpy(global_object_name, request_eid_value->object_name, 256);
                proto_tree_add_string_format(ncp_tree,
                                             hf_nds_name, tvb, 6, 0,
                                             global_object_name,
                                             "NDS Name for EID - %s",
                                             global_object_name);
            }
        }
        for (i = 0; i < 9; i++) {
            switch (pvalues[i].vtype) {

            case VTYPE_NONE: /* no value */
                break;

            case VTYPE_ITEM:
                if (pvalues[i].mvtype == MVTYPE_PROCESS_ITERATOR)
                {
                    dissect_nds_iterator(ncp_tree, tvb, pinfo, pvalues[i].vvalue, 0, nds_offset, FALSE);
                }
                else
                {
                    proto_tree_add_item(ncp_tree, pvalues[i].hfname, tvb, pvalues[i].voffset,
                                        pvalues[i].vlength, TRUE);
                }
                break;
            case VTYPE_UINT8:
                proto_tree_add_uint_format(ncp_tree, pvalues[i].hfname, tvb, pvalues[i].voffset,
                                           pvalues[i].vlength, pvalues[i].vtype, "NDS Parameter not defined %u",
                                           pvalues[i].vtype);
                break;

            case VTYPE_UINT16:
                proto_tree_add_uint_format(ncp_tree, pvalues[i].hfname, tvb, pvalues[i].voffset,
                                           pvalues[i].vlength, pvalues[i].vtype, "NDS Parameter not defined %u",
                                           pvalues[i].vtype);
                break;

            case VTYPE_UINT32:
                proto_tree_add_uint_format(ncp_tree, pvalues[i].hfname, tvb, pvalues[i].voffset,
                                           pvalues[i].vlength, pvalues[i].vvalue, pvalues[i].vdesc,
                                           pvalues[i].vvalue);
                break;

            case VTYPE_STRING:
                proto_tree_add_string_format(ncp_tree, pvalues[i].hfname, tvb, pvalues[i].voffset,
                                             pvalues[i].vlength, pvalues[i].vstring, pvalues[i].vdesc,
                                             pvalues[i].vstring);
                break;

            case VTYPE_BITFIELD:
                process_bitfield(ncp_tree, tvb, &pvalues[i]);
                break;

            case VTYPE_MULTIVALUE_UINT32:
                process_multivalues(ncp_tree, tvb, pinfo, &pvalues[i]);
                break;

            default:
                proto_tree_add_uint_format(ncp_tree, hf_nds_p1type, tvb, pvalues[i].voffset,
                                           pvalues[i].vlength, pvalues[i].vtype, "NDS Parameter not defined %u",
                                           pvalues[i].vtype);
                break;
            }
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
        conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                         PT_NCP, nw_connection, nw_connection, 0);
        if (conversation != NULL) {
            /* find the record telling us the request made that caused
               this reply */
            request_value = ncp_hash_lookup(conversation, sequence, pinfo->fd->num);
            if (request_value) {
                ncp_rec = request_value->ncp_rec;
            }
            p_add_proto_data(pinfo->fd, proto_ncp, (void*) request_value);
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
            conversation = find_conversation(pinfo->fd->num,
                                             &pinfo->src, &pinfo->dst, PT_NCP, 65535, 65535, 0);
            if (conversation != NULL) {
                /* find the record telling us the request made
                   that caused this reply */
                request_value = ncp_hash_lookup(conversation,
                                                sequence, pinfo->fd->num);
                if (request_value) {
                    ncp_rec = request_value->ncp_rec;
                }
                p_add_proto_data(pinfo->fd, proto_ncp,
                                 (void*) request_value);
            }
            else {
                conversation = find_conversation(pinfo->fd->num,
                                                 &pinfo->src, &pinfo->dst, PT_NCP, 0, 0, 0);
                if (conversation != NULL) {
                    /* find the record telling us the request made
                       that caused this reply */
                    request_value = ncp_hash_lookup(conversation,
                                                    sequence, pinfo->fd->num);
                    if (request_value) {
                        ncp_rec = request_value->ncp_rec;
                    }
                    p_add_proto_data(pinfo->fd, proto_ncp,
                                     (void*) request_value);
                }
                /* else... we haven't seen an NCP Request for that
                   conversation and sequence. */
            }
        }
    }
    else {
        /*request_value = p_get_proto_data(pinfo->fd, proto_ncp);*/
        conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                         PT_NCP, nw_connection, nw_connection, 0);
        if (conversation != NULL) {

             request_value = ncp_hash_lookup(conversation,
                               sequence, pinfo->fd->num);
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

    if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
        if (ncp_rec && ncp_rec->func==0x68 &&
            (ncp_rec->subfunc==0x02 || ncp_rec->subfunc==0x01)) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "NDS");
        }
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
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
                     type == NCP_SERVICE_REPLY ? "R" : "ACK",
                     nds_error_string ? nds_error_string : error_string);
    }

    if (ncp_tree) {

        if (request_value) {
            nstime_t ns;

            proto_tree_add_uint(ncp_tree, hf_ncp_req_frame_num, tvb, 0, 0,
                                request_value->req_frame_num);
            nstime_delta(&ns, &pinfo->fd->abs_ts, &request_value->req_frame_time);
            proto_tree_add_time(ncp_tree, hf_ncp_req_frame_time, tvb, 0, 0, &ns);
        }

        /* Put the func (and maybe subfunc) from the request packet
         * in the proto tree, but hidden. That way filters on ncp.func
         * or ncp.subfunc will find both the requests and the replies.
         */
        if (ncp_rec) {
            proto_tree_add_uint_format(ncp_tree, hf_ncp_func, tvb, 6, 0,
                                       ncp_rec->func, "Function: %u (0x%02X), %s",
                                       ncp_rec->func, ncp_rec->func, ncp_rec->name);
            if (ncp_requires_subfunc(ncp_rec->func)) {
                proto_tree_add_uint_format(ncp_tree, hf_ncp_subfunc, tvb, 6, 0,
                                           ncp_rec->subfunc, "SubFunction: %u (0x%02x)",
                                           ncp_rec->subfunc, ncp_rec->subfunc);
            }
        }
    }

    expert_item = proto_tree_add_uint_format(ncp_tree, hf_ncp_completion_code, tvb, 6, 1,
                                             completion_code, "Completion Code: %d (0x89%02x), %s",
                                             completion_code, completion_code, error_string);
    if ((completion_code != 0 || type == NCP_POSITIVE_ACK) && ncp_echo_err) {
        expert_add_info_format(pinfo, expert_item,
                               PI_RESPONSE_CODE, PI_ERROR,
                               "Error: %d (0x89%02x) %s", completion_code,
                               completion_code, error_string);
    }

    conn_stat = tvb_get_guint8(tvb, 7);
    expert_item = proto_tree_add_item(ncp_tree, hf_ncp_connection_status, tvb,
                                      7, 1, FALSE);
    if (conn_stat != 0 && conn_stat != 0x40 ) {
        col_set_str(pinfo->cinfo, COL_INFO,
                    "Error: Bad Connection Status");
        if (ncp_echo_err) {
            expert_add_info_format(pinfo, expert_item,
                                   PI_RESPONSE_CODE, PI_ERROR,
                                   "Error: Bad Connection Status");
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
            dissect_ncp_8x20reply(tvb, ncp_tree, ncp_rec, request_value);
        }
        /* Process ncp 23/26 address records manually to format correctly. */
        if (ncp_rec->func == 0x17 && ncp_rec->subfunc == 0x1a) {
            dissect_ncp_23_26_reply(tvb, ncp_tree);
        }
        if (ncp_rec->func == 5 && ncp_echo_conn) {
            expert_add_info_format(pinfo, NULL, PI_RESPONSE_CODE, PI_CHAT, "Connection Destroyed");
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
            if (completion_code != 0 && tvb_length(tvb) == 8) {
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
            process_ptvc_record(ptvc, ncp_rec->reply_ptvc,
                                req_cond_results, TRUE, ncp_rec);
            ptvcursor_free(ptvc);

            /* Echo the NDS EID and name for NCP 22,51 replies to expert tap */
            if (!pinfo->fd->flags.visited && ncp_rec->func == 0x16 && ncp_rec->subfunc == 0x33) {

                char    eid_string[10];
                char    global_object_name[256];

                build_expert_data(ncp_tree, "ncp.directory_services_object_id",
                                  eid_string, sizeof eid_string,
                                  0, TRUE);
                build_expert_data(ncp_tree, "ncp.volume_name_len",
                                  global_object_name, sizeof global_object_name,
                                  0, FALSE);

                /* Echo EID data to expert Chat window */
                if (nds_echo_eid) {
                    expert_add_info_format(pinfo, NULL,
                                           PI_RESPONSE_CODE, PI_CHAT,
                                           "EID (%s) = %s", eid_string, global_object_name);
                }
            }
            /* Process ncp 123/17 address records manually to format correctly. */
            if (ncp_rec->func == 0x7b && ncp_rec->subfunc == 0x11) {
                dissect_ncp_123_17_reply(tvb, ncp_tree);
            }
            /* Process ncp 123/11 NLM names manually to format correctly. */
            if (ncp_rec->func == 0x7b && ncp_rec->subfunc == 0x0b && request_value) {
                dissect_ncp_123_11_reply(tvb, ncp_tree, request_value);
            }
            /* Process ncp 123/62 server set parameter values manually to format correctly. */
            if (ncp_rec->func == 0x7b && ncp_rec->subfunc == 0x3e) {
                dissect_ncp_123_62_reply(tvb, ncp_tree);
            }
        }
        /* Check to see if we need to report to the expert table */
        trap_for_expert_event(ncp_tree, pinfo, ncp_rec, 1);
    } else {
        if (tvb_length(tvb) > 8) {
            expert_item = proto_tree_add_text(ncp_tree, tvb, 8, -1,
                                              "No request record found. Parsing is impossible.");
            if (ncp_echo_err) {
                expert_add_info_format(pinfo, expert_item, PI_SEQUENCE, PI_NOTE, "No request record found.");
            }
        }
    }
}

void
dissect_nds_request(tvbuff_t *tvb, packet_info *pinfo,
                    guint32 nw_connection, guint8 sequence,
                    guint16 type, proto_tree *ncp_tree)
{
    guint8                   func, subfunc = 0;
    ncp_req_hash_value      *request_value = NULL;
    ncp_req_eid_hash_value  *request_eid_value = NULL;
    const ncp_record        *ncp_rec = NULL;
    conversation_t          *conversation;
    ptvcursor_t             *ptvc = NULL;
    proto_tree              *temp_tree = NULL;
    gboolean                 run_req_cond = FALSE;
    gboolean                 run_info_str = FALSE;
    guint8                   nds_verb = 0;
    const char              *verb_string = "";
    guint32                  nds_frag = 0;
    gboolean                 added_arrow;
    nds_val                  pvalues[9], prot_flags[1];
    guint8                   nds_version = 0;
    guint32                  foffset = 0;
    char                     global_object_name[256];
    guint32                  global_eid=0;
    gboolean                 resolve_eid=FALSE;
    guint32                  global_flags=0, nds_prot_flags=0;
    int                      i;

    for (i = 0; i < 9; i++) {
        pvalues[i].vtype = 0;
        pvalues[i].vvalue = 0;
        pvalues[i].vlength = 0;
        pvalues[i].voffset = 0;
        pvalues[i].hfname = 0;
        pvalues[i].vdesc = "";
        pvalues[i].vstring = NULL;
        pvalues[i].mvtype = 0;
        pvalues[i].vflags = 0;
    }

    global_object_name[0] = '\0';

    func = tvb_get_guint8(tvb, 6);
    subfunc = tvb_get_guint8(tvb, 7);

    ncp_rec = ncp_record_find(func, subfunc);

    /* Check to see if this is a fragment packet */
    nds_frag = tvb_get_letohl(tvb, 8);

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
                                4, TRUE);
        }
        foffset = foffset+4;
        verb_string = val_to_str_const(nds_verb, ncp_nds_verb_vals,
                                       "Continuation Fragment");
        switch(nds_verb) {

        case 0x01:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].hfname = hf_nds_ver;
            pvalues[0].voffset = foffset;
            foffset = foffset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[1].vtype = VTYPE_BITFIELD;
            pvalues[1].vdesc = "Flags:";
            pvalues[1].vlength = 2;
            pvalues[1].hfname= hf_nds_nflags;
            pvalues[1].voffset = foffset;
            pvalues[1].bit1 = "Entry ID";
            pvalues[1].bit1hfname = hf_bit1nflags;
            pvalues[1].bit2 = "Readable";
            pvalues[1].bit2hfname = hf_bit2nflags;
            pvalues[1].bit3 = "Writeable";
            pvalues[1].bit3hfname = hf_bit3nflags;
            pvalues[1].bit4 = "Master";
            pvalues[1].bit4hfname = hf_bit4nflags;
            pvalues[1].bit5 = "Create ID";
            pvalues[1].bit5hfname = hf_bit5nflags;
            pvalues[1].bit6 = "Walk Tree";
            pvalues[1].bit6hfname = hf_bit6nflags;
            pvalues[1].bit7 = "Dereference Alias";
            pvalues[1].bit7hfname = hf_bit7nflags;
            pvalues[1].bit8 = "Not Defined";
            pvalues[1].bit8hfname = hf_bit8nflags;
            pvalues[1].bit9 = "Not Defined";
            pvalues[1].bit9hfname = hf_bit9nflags;
            pvalues[1].bit10 = "Not Defined";
            pvalues[1].bit10hfname = hf_bit10nflags;
            pvalues[1].bit11= "Not Defined";
            pvalues[1].bit11hfname = hf_bit11nflags;
            pvalues[1].bit12 = "Not Defined";
            pvalues[1].bit12hfname = hf_bit12nflags;
            pvalues[1].bit13 = "Not Defined";
            pvalues[1].bit13hfname = hf_bit13nflags;
            pvalues[1].bit14 = "Prefer Referrals";
            pvalues[1].bit14hfname = hf_bit14nflags;
            pvalues[1].bit15 = "Prefer Only Referrals";
            pvalues[1].bit15hfname = hf_bit15nflags;
            pvalues[1].bit16 = "Not Defined";
            pvalues[1].bit16hfname = hf_bit16nflags;
            foffset = foffset+4;
            if (pvalues[0].vvalue == 0 || pvalues[0].vvalue == 1)
            {
                pvalues[2].vtype = VTYPE_UINT32;
                pvalues[2].vdesc = "Scope: %u";
                pvalues[2].vlength = 4;
                pvalues[2].voffset = foffset;
                pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[2].hfname= hf_nds_scope;
                foffset = foffset+pvalues[2].vlength;
                pvalues[3].vtype = VTYPE_STRING;
                pvalues[3].vdesc = "Name: %s";
                pvalues[3].mvtype = MVTYPE_ATTR_REQUEST;
                pvalues[3].vvalue = 0;
                pvalues[3].vlength = 256;
                pvalues[3].vlength = tvb_get_letohl(tvb, foffset);
                if (pvalues[3].vlength == 0x00 || !tvb_bytes_exist(tvb, foffset, pvalues[3].vlength))
                {
                    pvalues[3].vtype = VTYPE_NONE;
                    break;
                }
                pvalues[3].voffset = foffset+4;
                foffset = foffset + 4;
                pvalues[3].vstring = get_string(tvb, pvalues[3].voffset, pvalues[3].vlength);
                g_strlcpy(global_object_name, pvalues[3].vstring, 256);
                pvalues[3].hfname= hf_nds_name;
                foffset = foffset+pvalues[3].vlength;
                foffset += align_4(tvb, foffset);
                pvalues[4].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[4].vtype = VTYPE_MULTIVALUE_UINT32;
                pvalues[4].vdesc = "Communications Transports: %u";
                pvalues[4].vlength = 4;
                pvalues[4].hfname= hf_nds_comm_trans;
                pvalues[4].voffset = foffset;
                pvalues[4].mvtype = MVTYPE_ADDR_REFERRAL_REQUEST;
                foffset = foffset + (pvalues[4].vvalue * 4) + 4;
                pvalues[5].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[5].vtype = VTYPE_MULTIVALUE_UINT32;
                pvalues[5].vdesc = "Tree Walker Transport Type: %u";
                pvalues[5].vlength = 4;
                pvalues[5].mvtype = MVTYPE_ADDR_REFERRAL_REQUEST;
                pvalues[5].hfname= hf_nds_tree_trans;
                pvalues[5].voffset = foffset;
            }
            else
            {
                pvalues[2].vtype = VTYPE_UINT32;
                pvalues[2].vdesc = "Minimum DS Version: %u";
                pvalues[2].vlength = 4;
                pvalues[2].voffset = foffset;
                pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[2].hfname= hf_min_nds_ver;
                foffset = foffset+pvalues[2].vlength;
                pvalues[3].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[3].vtype = VTYPE_MULTIVALUE_UINT32;
                pvalues[3].vdesc = "Number of Versions to Include: %u";
                pvalues[3].vlength = 4;
                pvalues[3].mvtype = MVTYPE_ATTR_REQUEST2;
                pvalues[3].voffset = foffset;
                pvalues[3].hfname= hf_nds_ver_include;
                foffset += (pvalues[3].vvalue * 4) + 4;
                pvalues[4].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[4].vtype = VTYPE_MULTIVALUE_UINT32;
                pvalues[4].vdesc = "Number of Versions to Exclude: %u";
                pvalues[4].vlength = 4;
                pvalues[4].mvtype = MVTYPE_ATTR_REQUEST2;
                pvalues[4].hfname= hf_nds_ver_exclude;
                pvalues[4].voffset = foffset;
                foffset += 4;
                pvalues[5].vtype = VTYPE_UINT32;
                pvalues[5].vdesc = "DN Output Type: %u";
                pvalues[5].vlength = 4;
                pvalues[5].voffset = foffset;
                pvalues[5].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[5].hfname= hf_nds_dn_output_type;
                foffset = foffset+pvalues[5].vlength;
                pvalues[6].vtype = VTYPE_UINT32;
                pvalues[6].vdesc = "Nested Output Type: %u";
                pvalues[6].vlength = 4;
                pvalues[6].voffset = foffset;
                pvalues[6].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[6].hfname= hf_nds_nested_output_type;
                foffset = foffset+pvalues[6].vlength;
                pvalues[7].vtype = VTYPE_STRING;
                pvalues[7].vdesc = "Output Delimiter: %s";
                pvalues[7].mvtype = MVTYPE_ATTR_REQUEST;
                pvalues[7].vvalue = 0;
                pvalues[7].vlength = 256;
                pvalues[7].vlength = tvb_get_letohl(tvb, foffset);
                pvalues[7].voffset = foffset+4;
                foffset = foffset + 4;
                pvalues[7].vstring = get_string(tvb, pvalues[7].voffset, pvalues[7].vlength);
                pvalues[7].hfname= hf_nds_output_delimiter;
                foffset = foffset+pvalues[7].vlength;
                foffset += align_4(tvb, foffset);
                pvalues[8].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[8].vtype = VTYPE_MULTIVALUE_UINT32;
                pvalues[8].vdesc = "Size of Entry Specifier: %u";
                pvalues[8].vlength = 4;
                pvalues[8].mvtype = MVTYPE_PROC_ENTRY_SPECIFIERS;
                pvalues[8].hfname= hf_nds_output_entry_specifier;
                pvalues[8].voffset = foffset;
            }
            break;
        case 0x02:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = foffset;
            pvalues[0].hfname= hf_nds_ver;
            foffset = foffset+pvalues[0].vlength;
            switch(pvalues[0].vvalue)
            {
            case 0:
                pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[1].vtype = VTYPE_UINT32;
                pvalues[1].vdesc = "Entry ID: 0x%08x";
                pvalues[1].vlength = 4;
                resolve_eid = TRUE;
                global_eid = pvalues[1].vvalue;
                pvalues[1].voffset = foffset;
                pvalues[1].hfname = hf_nds_eid;
                foffset = foffset+pvalues[1].vlength;
                break;
            case 1:
                pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[1].vtype = VTYPE_BITFIELD;
                pvalues[1].vdesc = "Request Flags:";
                pvalues[1].vlength = 2;
                pvalues[1].hfname= hf_nds_rflags;
                pvalues[1].voffset = foffset;
                pvalues[1].bit1 = "Typeless";
                pvalues[1].bit1hfname = hf_bit1rflags;
                pvalues[1].bit2 = "Slashed";
                pvalues[1].bit2hfname = hf_bit2rflags;
                pvalues[1].bit3 = "Dotted";
                pvalues[1].bit3hfname = hf_bit3rflags;
                pvalues[1].bit4 = "Tuned";
                pvalues[1].bit4hfname = hf_bit4rflags;
                pvalues[1].bit5 = "Not Defined";
                pvalues[1].bit5hfname = hf_bit5rflags;
                pvalues[1].bit6 = "Not Defined";
                pvalues[1].bit6hfname = hf_bit6rflags;
                pvalues[1].bit7 = "Not Defined";
                pvalues[1].bit7hfname = hf_bit7rflags;
                pvalues[1].bit8 = "Not Defined";
                pvalues[1].bit8hfname = hf_bit8rflags;
                pvalues[1].bit9 = "Not Defined";
                pvalues[1].bit9hfname = hf_bit9rflags;
                pvalues[1].bit10 = "Not Defined";
                pvalues[1].bit10hfname = hf_bit10rflags;
                pvalues[1].bit11 = "Not Defined";
                pvalues[1].bit11hfname = hf_bit11rflags;
                pvalues[1].bit12 = "Not Defined";
                pvalues[1].bit12hfname = hf_bit12rflags;
                pvalues[1].bit13 = "Not Defined";
                pvalues[1].bit13hfname = hf_bit13rflags;
                pvalues[1].bit14 = "Not Defined";
                pvalues[1].bit14hfname = hf_bit14rflags;
                pvalues[1].bit15 = "Not Defined";
                pvalues[1].bit15hfname = hf_bit15rflags;
                pvalues[1].bit16 = "Not Defined";
                pvalues[1].bit16hfname = hf_bit16rflags;
                if((pvalues[1].vvalue & 0xf000) == 0xc000)
                {
                    pvalues[2].vtype = VTYPE_STRING;
                    pvalues[2].vdesc = "Name Type: %s";
                    pvalues[2].vstring = "Partial";
                    pvalues[2].mvtype = 0;
                    pvalues[2].vvalue = 0;
                    pvalues[2].vlength = 0;
                    pvalues[2].voffset = 0;
                    pvalues[2].hfname= hf_nds_name_type;
                }
                else
                {
                    pvalues[2].vtype = VTYPE_STRING;
                    pvalues[2].vdesc = "Name Type: %s";
                    pvalues[2].vstring = "Full";
                    pvalues[2].vvalue = 0;
                    pvalues[2].mvtype = 0;
                    pvalues[2].vlength = 0;
                    pvalues[2].voffset = 0;
                    pvalues[2].hfname= hf_nds_name_type;
                }
                foffset = foffset+4;
                pvalues[3].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[3].vtype = VTYPE_UINT32;
                pvalues[3].vdesc = "Entry ID: 0x%08x";
                pvalues[3].vlength = 4;
                pvalues[3].voffset = foffset;
                resolve_eid = TRUE;
                global_eid = pvalues[3].vvalue;
                pvalues[3].hfname = hf_nds_eid;
                foffset = foffset+pvalues[3].vlength;
                break;
            case 2:
                pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[1].vtype = VTYPE_BITFIELD;
                pvalues[1].vdesc = "Request Flags:";
                pvalues[1].vlength = 2;
                pvalues[1].hfname= hf_nds_rflags;
                pvalues[1].voffset = foffset;
                pvalues[1].bit1 = "Typeless";
                pvalues[1].bit1hfname = hf_bit1rflags;
                pvalues[1].bit2 = "Slashed";
                pvalues[1].bit2hfname = hf_bit2rflags;
                pvalues[1].bit3 = "Dotted";
                pvalues[1].bit3hfname = hf_bit3rflags;
                pvalues[1].bit4 = "Tuned";
                pvalues[1].bit4hfname = hf_bit4rflags;
                pvalues[1].bit5 = "Not Defined";
                pvalues[1].bit5hfname = hf_bit5rflags;
                pvalues[1].bit6 = "Not Defined";
                pvalues[1].bit6hfname = hf_bit6rflags;
                pvalues[1].bit7 = "Not Defined";
                pvalues[1].bit7hfname = hf_bit7rflags;
                pvalues[1].bit8 = "Not Defined";
                pvalues[1].bit8hfname = hf_bit8rflags;
                pvalues[1].bit9 = "Not Defined";
                pvalues[1].bit9hfname = hf_bit9rflags;
                pvalues[1].bit10 = "Not Defined";
                pvalues[1].bit10hfname = hf_bit10rflags;
                pvalues[1].bit11 = "Not Defined";
                pvalues[1].bit11hfname = hf_bit11rflags;
                pvalues[1].bit12 = "Not Defined";
                pvalues[1].bit12hfname = hf_bit12rflags;
                pvalues[1].bit13 = "Not Defined";
                pvalues[1].bit13hfname = hf_bit13rflags;
                pvalues[1].bit14 = "Not Defined";
                pvalues[1].bit14hfname = hf_bit14rflags;
                pvalues[1].bit15 = "Not Defined";
                pvalues[1].bit15hfname = hf_bit15rflags;
                pvalues[1].bit16 = "Not Defined";
                pvalues[1].bit16hfname = hf_bit16rflags;
                if((pvalues[1].vvalue & 0xf000) == 0xc000)
                {
                    pvalues[2].vtype = VTYPE_STRING;
                    pvalues[2].vdesc = "Name Type: %s";
                    pvalues[2].vstring = "Return Partion Name";
                    pvalues[2].vvalue = 0;
                    pvalues[2].vlength = 4;
                    pvalues[2].voffset = pvalues[1].voffset;
                    pvalues[2].mvtype = 0;
                    pvalues[2].hfname= hf_nds_name_type;
                }
                else
                {
                    pvalues[2].vtype = VTYPE_STRING;
                    pvalues[2].vdesc = "Name Type: %s";
                    pvalues[2].vstring = "Return Full Name";
                    pvalues[2].vvalue = 0;
                    pvalues[2].vlength = 4;
                    pvalues[2].mvtype = 0;
                    pvalues[2].voffset = pvalues[1].voffset;
                    pvalues[2].hfname= hf_nds_name_type;
                }
                foffset = foffset+4;
                pvalues[3].vvalue = tvb_get_letohs(tvb, foffset);
                global_flags = tvb_get_letohl(tvb, foffset);
                pvalues[3].vtype = VTYPE_BITFIELD;
                pvalues[3].vdesc = "Information Flags (low) Byte:";
                pvalues[3].vlength = 2;
                pvalues[3].hfname= hf_nds_rflags;
                pvalues[3].voffset = foffset;
                pvalues[3].bit1 = "Output Flags";
                pvalues[3].bit1hfname = hf_bit1infoflagsl;
                pvalues[3].bit2 = "Entry ID";
                pvalues[3].bit2hfname = hf_bit2infoflagsl;
                pvalues[3].bit3 = "Entry Flags";
                pvalues[3].bit3hfname = hf_bit3infoflagsl;
                pvalues[3].bit4 = "Subordinate Count";
                pvalues[3].bit4hfname = hf_bit4infoflagsl;
                pvalues[3].bit5 = "Modification Time";
                pvalues[3].bit5hfname = hf_bit5infoflagsl;
                pvalues[3].bit6 = "Modification Timestamp";
                pvalues[3].bit6hfname = hf_bit6infoflagsl;
                pvalues[3].bit7 = "Creation Timestamp";
                pvalues[3].bit7hfname = hf_bit7infoflagsl;
                pvalues[3].bit8 = "Partition Root ID";
                pvalues[3].bit8hfname = hf_bit8infoflagsl;
                pvalues[3].bit9 = "Parent ID";
                pvalues[3].bit9hfname = hf_bit9infoflagsl;
                pvalues[3].bit10 = "Revision Count";
                pvalues[3].bit10hfname = hf_bit10infoflagsl;
                pvalues[3].bit11 = "Replica Type";
                pvalues[3].bit11hfname = hf_bit11infoflagsl;
                pvalues[3].bit12 = "Base Class";
                pvalues[3].bit12hfname = hf_bit12infoflagsl;
                pvalues[3].bit13 = "Relative Distinguished Name";
                pvalues[3].bit13hfname = hf_bit13infoflagsl;
                pvalues[3].bit14 = "Distinguished Name";
                pvalues[3].bit14hfname = hf_bit14infoflagsl;
                pvalues[3].bit15 = "Root Distinguished Name";
                pvalues[3].bit15hfname = hf_bit15infoflagsl;
                pvalues[3].bit16 = "Parent Distinguished Name";
                pvalues[3].bit16hfname = hf_bit16infoflagsl;
                foffset = foffset+2;
                pvalues[4].vvalue = tvb_get_letohs(tvb, foffset);
                pvalues[4].vtype = VTYPE_BITFIELD;
                pvalues[4].vdesc = "Information Flags (high) Byte:";
                pvalues[4].vlength = 2;
                pvalues[4].hfname= hf_nds_rflags;
                pvalues[4].voffset = foffset;
                pvalues[4].bit1 = "Purge Time";
                pvalues[4].bit1hfname = hf_bit1infoflagsh;
                pvalues[4].bit2 = "Dereference Base Class";
                pvalues[4].bit2hfname = hf_bit2infoflagsh;
                pvalues[4].bit3 = "Replica Number";
                pvalues[4].bit3hfname = hf_bit3infoflagsh;
                pvalues[4].bit4 = "Replica State";
                pvalues[4].bit4hfname = hf_bit4infoflagsh;
                pvalues[4].bit5 = "Federation Boundary";
                pvalues[4].bit5hfname = hf_bit5infoflagsh;
                pvalues[4].bit6 = "Schema Boundary";
                pvalues[4].bit6hfname = hf_bit6infoflagsh;
                pvalues[4].bit7 = "Federation Boundary ID";
                pvalues[4].bit7hfname = hf_bit7infoflagsh;
                pvalues[4].bit8 = "Schema Boundary ID";
                pvalues[4].bit8hfname = hf_bit8infoflagsh;
                pvalues[4].bit9 = "Current Subcount";
                pvalues[4].bit9hfname = hf_bit9infoflagsh;
                pvalues[4].bit10 = "Local Entry Flags";
                pvalues[4].bit10hfname = hf_bit10infoflagsh;
                pvalues[4].bit11 = "Not Defined";
                pvalues[4].bit11hfname = hf_bit11infoflagsh;
                pvalues[4].bit12 = "Not Defined";
                pvalues[4].bit12hfname = hf_bit12infoflagsh;
                pvalues[4].bit13 = "Not Defined";
                pvalues[4].bit13hfname = hf_bit13infoflagsh;
                pvalues[4].bit14 = "Not Defined";
                pvalues[4].bit14hfname = hf_bit14infoflagsh;
                pvalues[4].bit15 = "Not Defined";
                pvalues[4].bit15hfname = hf_bit15infoflagsh;
                pvalues[4].bit16 = "Not Defined";
                pvalues[4].bit16hfname = hf_bit16infoflagsh;
                foffset = foffset+2;
                pvalues[5].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[5].vtype = VTYPE_UINT32;
                pvalues[5].vdesc = "Entry ID: 0x%08x";
                pvalues[5].vlength = 4;
                pvalues[5].voffset = foffset;
                resolve_eid = TRUE;
                global_eid = pvalues[5].vvalue;
                pvalues[5].hfname = hf_nds_eid;
                foffset = foffset+pvalues[5].vlength;
                break;
            default:
                break;
            }

            break;
        case 0x03:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = foffset;
            pvalues[0].hfname= hf_nds_ver;
            foffset = foffset+pvalues[0].vlength;
            if(pvalues[0].vvalue == 0)
            {
                pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[1].vtype = VTYPE_UINT32;
                pvalues[1].vdesc = "Iteration Handle: 0x%08x";
                pvalues[1].vlength = 4;
                pvalues[1].voffset = foffset;
                pvalues[1].hfname= hf_nds_iteration;
                foffset = foffset+pvalues[1].vlength;
                pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[2].vtype = VTYPE_UINT32;
                pvalues[2].vdesc = "Entry ID: 0x%08x";
                pvalues[2].vlength = 4;
                resolve_eid = TRUE;
                global_eid = pvalues[2].vvalue;
                pvalues[2].voffset = foffset;
                pvalues[2].hfname= hf_nds_eid;
                foffset = foffset+pvalues[2].vlength;
                pvalues[3].vvalue = tvb_get_letohl(tvb, foffset);
                global_flags = pvalues[3].vvalue;
                pvalues[3].vstring = val_to_str_const(pvalues[3].vvalue, nds_info_type, "No Info Type Set");
                pvalues[3].vtype = VTYPE_STRING;
                pvalues[3].vdesc = "Info Type: %s";
                pvalues[3].vlength = 4;
                pvalues[3].voffset = foffset;
                pvalues[3].mvtype = MVTYPE_ATTR_REQUEST;
                pvalues[3].hfname= hf_nds_info_type;
                foffset = foffset + pvalues[3].vlength;
                pvalues[4].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[4].vtype = VTYPE_UINT32;
                pvalues[4].vdesc = "All Attributes: %u";
                pvalues[4].vlength = 4;
                pvalues[4].voffset = foffset;
                pvalues[4].hfname= hf_nds_all_attr;
                foffset = foffset+pvalues[4].vlength;
                pvalues[5].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[5].vtype = VTYPE_MULTIVALUE_UINT32;
                pvalues[5].vdesc = "Attributes: %u";
                pvalues[5].vlength = 4;
                pvalues[5].voffset = foffset;
                pvalues[5].mvtype = MVTYPE_ATTR_REQUEST;
                pvalues[5].hfname= hf_nds_attr;
            }
            else
            {
                pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[1].vtype = VTYPE_UINT32;
                pvalues[1].vdesc = "Request Flags: 0x%08x";
                pvalues[1].vlength = 4;
                pvalues[1].voffset = foffset;
                pvalues[1].hfname= hf_nds_req_flags;
                foffset = foffset+pvalues[1].vlength;
                pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[2].vtype = VTYPE_UINT32;
                pvalues[2].vdesc = "Iteration Handle: 0x%08x";
                pvalues[2].vlength = 4;
                pvalues[2].voffset = foffset;
                pvalues[2].hfname= hf_nds_iteration;
                foffset = foffset+pvalues[2].vlength;
                pvalues[3].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[3].vtype = VTYPE_UINT32;
                pvalues[3].vdesc = "Entry ID: 0x%08x";
                pvalues[3].vlength = 4;
                resolve_eid = TRUE;
                global_eid = pvalues[3].vvalue;
                pvalues[3].voffset = foffset;
                pvalues[3].hfname= hf_nds_eid;
                foffset = foffset+pvalues[3].vlength;
                pvalues[4].vvalue = tvb_get_letohl(tvb, foffset);
                global_flags = pvalues[4].vvalue;
                pvalues[4].vstring = val_to_str_const(pvalues[4].vvalue, nds_info_type, "No Info Type Set");
                pvalues[4].vtype = VTYPE_STRING;
                pvalues[4].vdesc = "Info Type: %s";
                pvalues[4].vlength = 4;
                pvalues[4].voffset = foffset;
                pvalues[4].hfname= hf_nds_info_type;
                pvalues[4].mvtype = MVTYPE_ATTR_REQUEST;
                foffset = foffset+pvalues[4].vlength;
                pvalues[5].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[5].vtype = VTYPE_UINT32;
                pvalues[5].vdesc = "All Attributes: %u";
                pvalues[5].vlength = 4;
                pvalues[5].voffset = foffset;
                pvalues[5].hfname= hf_nds_all_attr;
                foffset = foffset+pvalues[5].vlength;
                pvalues[6].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[6].vtype = VTYPE_MULTIVALUE_UINT32;
                pvalues[6].vdesc = "Attributes: %u";
                pvalues[6].vlength = 4;
                pvalues[6].voffset = foffset;
                pvalues[6].mvtype = MVTYPE_ATTR_REQUEST;
                pvalues[6].hfname= hf_nds_attr;
            }
            break;
        case 0x04:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = foffset;
            pvalues[0].hfname= hf_nds_ver;
            foffset = foffset+pvalues[0].vlength;
            if (pvalues[0].vvalue == 1) {
                /* Version 1 specifies for this offset value to always be a value of 1*/
                /* No need to display to user */
                foffset += 4;
            }
            pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[1].vtype = VTYPE_UINT32;
            pvalues[1].vdesc = "Entry ID: 0x%08x";
            pvalues[1].vlength = 4;
            resolve_eid = TRUE;
            global_eid = pvalues[1].vvalue;
            pvalues[1].voffset = foffset;
            pvalues[1].hfname = hf_nds_eid;
            foffset = foffset+pvalues[1].vlength;
            foffset += 4;       /* Attribute Count = 1 */
            pvalues[2].vtype = VTYPE_STRING;
            pvalues[2].vdesc = "Attribute Name Being Compared: %s";
            pvalues[2].mvtype = MVTYPE_ATTR_REQUEST;
            pvalues[2].vvalue = 0;
            pvalues[2].vlength = 256;
            pvalues[2].vlength = tvb_get_letohl(tvb, foffset);
            if (pvalues[2].vlength == 0x00 || !tvb_bytes_exist(tvb, foffset, pvalues[2].vlength))
            {
                pvalues[2].vtype = VTYPE_NONE;
                break;
            }
            pvalues[2].voffset = foffset+4;
            foffset = foffset + 4;
            pvalues[2].vstring = get_string(tvb, pvalues[2].voffset, pvalues[2].vlength);
            g_strlcpy(global_object_name, pvalues[2].vstring, 256);
            pvalues[2].hfname= hf_nds_name;
            foffset = foffset+pvalues[2].vlength;
            foffset += align_4(tvb, foffset);
            foffset += 4;       /* Attribute Value Count = 1 */
            pvalues[3].vtype = VTYPE_STRING;
            pvalues[3].vdesc = "Attribute Value: %s";
            pvalues[3].mvtype = MVTYPE_ATTR_REQUEST;
            pvalues[3].vvalue = 0;
            pvalues[3].vlength = 256;
            pvalues[3].vlength = tvb_get_letohl(tvb, foffset);
            pvalues[3].voffset = foffset+4;
            foffset = foffset + 4;
            pvalues[3].vstring = get_string(tvb, pvalues[3].voffset, pvalues[3].vlength);
            pvalues[3].hfname= hf_value_string;
            foffset = foffset+pvalues[3].vlength;
            break;
        case 0x05:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = foffset;
            pvalues[0].hfname= hf_nds_ver;
            foffset = foffset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[1].vtype = VTYPE_BITFIELD;
            pvalues[1].vdesc = "Request Flags:";
            pvalues[1].vlength = 2;
            pvalues[1].hfname= hf_nds_rflags;
            pvalues[1].voffset = foffset;
            pvalues[1].bit1 = "List Typeless";
            pvalues[1].bit1hfname = hf_bit1lflags;
            pvalues[1].bit2 = "List Containers";
            pvalues[1].bit2hfname = hf_bit2lflags;
            pvalues[1].bit3 = "List Slashed";
            pvalues[1].bit3hfname = hf_bit3lflags;
            pvalues[1].bit4 = "List Dotted";
            pvalues[1].bit4hfname = hf_bit4lflags;
            pvalues[1].bit5 = "Dereference Alias";
            pvalues[1].bit5hfname = hf_bit5lflags;
            pvalues[1].bit6 = "List All Containers";
            pvalues[1].bit6hfname = hf_bit6lflags;
            pvalues[1].bit7 = "List Obsolete";
            pvalues[1].bit7hfname = hf_bit7lflags;
            pvalues[1].bit8 = "List Tuned Output";
            pvalues[1].bit8hfname = hf_bit8lflags;
            pvalues[1].bit9 = "List External Reference";
            pvalues[1].bit9hfname = hf_bit9lflags;
            pvalues[1].bit10 = "Not Defined";
            pvalues[1].bit10hfname = hf_bit10lflags;
            pvalues[1].bit11 = "Not Defined";
            pvalues[1].bit11hfname = hf_bit11lflags;
            pvalues[1].bit12 = "Not Defined";
            pvalues[1].bit12hfname = hf_bit12lflags;
            pvalues[1].bit13 = "Not Defined";
            pvalues[1].bit13hfname = hf_bit13lflags;
            pvalues[1].bit14 = "Not Defined";
            pvalues[1].bit14hfname = hf_bit14lflags;
            pvalues[1].bit15 = "Not Defined";
            pvalues[1].bit15hfname = hf_bit15lflags;
            pvalues[1].bit16 = "Not Defined";
            pvalues[1].bit16hfname = hf_bit16lflags;
            foffset = foffset+pvalues[1].vlength;
            foffset += 2;
            pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[2].vtype = VTYPE_UINT32;
            pvalues[2].vdesc = "Iteration Handle: 0x%08x";
            pvalues[2].vlength = 4;
            pvalues[2].voffset = foffset;
            pvalues[2].hfname= hf_nds_iteration;
            foffset = foffset+pvalues[2].vlength;
            pvalues[3].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[3].vtype = VTYPE_UINT32;
            pvalues[3].vdesc = "Parent ID: 0x%08x";
            pvalues[3].vlength = 4;
            pvalues[3].voffset = foffset;
            pvalues[3].hfname= hf_nds_parent;
            foffset = foffset+pvalues[3].vlength;
            pvalues[4].vvalue = tvb_get_letohs(tvb, foffset);
            global_flags = tvb_get_letohl(tvb, foffset);
            pvalues[4].vtype = VTYPE_BITFIELD;
            pvalues[4].vdesc = "Information Flags (low) Byte:";
            pvalues[4].vlength = 2;
            pvalues[4].hfname= hf_nds_rflags;
            pvalues[4].voffset = foffset;
            pvalues[4].bit1 = "Output Flags";
            pvalues[4].bit1hfname = hf_bit1infoflagsl;
            pvalues[4].bit2 = "Entry ID";
            pvalues[4].bit2hfname = hf_bit2infoflagsl;
            pvalues[4].bit3 = "Entry Flags";
            pvalues[4].bit3hfname = hf_bit3infoflagsl;
            pvalues[4].bit4 = "Subordinate Count";
            pvalues[4].bit4hfname = hf_bit4infoflagsl;
            pvalues[4].bit5 = "Modification Time";
            pvalues[4].bit5hfname = hf_bit5infoflagsl;
            pvalues[4].bit6 = "Modification Timestamp";
            pvalues[4].bit6hfname = hf_bit6infoflagsl;
            pvalues[4].bit7 = "Creation Timestamp";
            pvalues[4].bit7hfname = hf_bit7infoflagsl;
            pvalues[4].bit8 = "Partition Root ID";
            pvalues[4].bit8hfname = hf_bit8infoflagsl;
            pvalues[4].bit9 = "Parent ID";
            pvalues[4].bit9hfname = hf_bit9infoflagsl;
            pvalues[4].bit10 = "Revision Count";
            pvalues[4].bit10hfname = hf_bit10infoflagsl;
            pvalues[4].bit11 = "Replica Type";
            pvalues[4].bit11hfname = hf_bit11infoflagsl;
            pvalues[4].bit12 = "Base Class";
            pvalues[4].bit12hfname = hf_bit12infoflagsl;
            pvalues[4].bit13 = "Relative Distinguished Name";
            pvalues[4].bit13hfname = hf_bit13infoflagsl;
            pvalues[4].bit14 = "Distinguished Name";
            pvalues[4].bit14hfname = hf_bit14infoflagsl;
            pvalues[4].bit15 = "Root Distinguished Name";
            pvalues[4].bit15hfname = hf_bit15infoflagsl;
            pvalues[4].bit16 = "Parent Distinguished Name";
            pvalues[4].bit16hfname = hf_bit16infoflagsl;
            foffset = foffset+2;
            pvalues[5].vvalue = tvb_get_letohs(tvb, foffset);
            pvalues[5].vtype = VTYPE_BITFIELD;
            pvalues[5].vdesc = "Information Flags (high) Byte:";
            pvalues[5].vlength = 2;
            pvalues[5].hfname= hf_nds_rflags;
            pvalues[5].voffset = foffset;
            pvalues[5].bit1 = "Purge Time";
            pvalues[5].bit1hfname = hf_bit1infoflagsh;
            pvalues[5].bit2 = "Dereference Base Class";
            pvalues[5].bit2hfname = hf_bit2infoflagsh;
            pvalues[5].bit3 = "Not Defined";
            pvalues[5].bit3hfname = hf_bit3infoflagsh;
            pvalues[5].bit4 = "Not Defined";
            pvalues[5].bit4hfname = hf_bit4infoflagsh;
            pvalues[5].bit5 = "Not Defined";
            pvalues[5].bit5hfname = hf_bit5infoflagsh;
            pvalues[5].bit6 = "Not Defined";
            pvalues[5].bit6hfname = hf_bit6infoflagsh;
            pvalues[5].bit7 = "Not Defined";
            pvalues[5].bit7hfname = hf_bit7infoflagsh;
            pvalues[5].bit8 = "Not Defined";
            pvalues[5].bit8hfname = hf_bit8infoflagsh;
            pvalues[5].bit9 = "Not Defined";
            pvalues[5].bit9hfname = hf_bit9infoflagsh;
            pvalues[5].bit10 = "Not Defined";
            pvalues[5].bit10hfname = hf_bit10infoflagsh;
            pvalues[5].bit11 = "Not Defined";
            pvalues[5].bit11hfname = hf_bit11infoflagsh;
            pvalues[5].bit12 = "Not Defined";
            pvalues[5].bit12hfname = hf_bit12infoflagsh;
            pvalues[5].bit13 = "Not Defined";
            pvalues[5].bit13hfname = hf_bit13infoflagsh;
            pvalues[5].bit14 = "Not Defined";
            pvalues[5].bit14hfname = hf_bit14infoflagsh;
            pvalues[5].bit15 = "Not Defined";
            pvalues[5].bit15hfname = hf_bit15infoflagsh;
            pvalues[5].bit16 = "Not Defined";
            pvalues[5].bit16hfname = hf_bit16infoflagsh;
            foffset = foffset+2;
            pvalues[6].vtype = VTYPE_STRING;
            pvalues[6].vdesc = "Name Filter: %s";
            pvalues[6].mvtype = MVTYPE_ATTR_REQUEST;
            pvalues[6].vvalue = 0;
            pvalues[6].vlength = 256;
            pvalues[6].vlength = tvb_get_letohl(tvb, foffset);
            pvalues[6].voffset = foffset+4;
            foffset = foffset + 4;
            pvalues[6].vstring = get_string(tvb, pvalues[6].voffset, pvalues[6].vlength);
            pvalues[6].hfname= hf_nds_name_filter;
            foffset = foffset+pvalues[6].vlength;
            if(pvalues[0].vvalue == 0)
            {
                break;
            }
            foffset += align_4(tvb, foffset);
            pvalues[7].vtype = VTYPE_STRING;
            pvalues[7].vdesc = "Class Filter: %s";
            pvalues[7].mvtype = MVTYPE_ATTR_REQUEST;
            pvalues[7].vvalue = 0;
            pvalues[7].vlength = 256;
            pvalues[7].vlength = tvb_get_letohl(tvb, foffset);
            pvalues[7].voffset = foffset+4;
            foffset = foffset + 4;
            pvalues[7].vstring = get_string(tvb, pvalues[7].voffset, pvalues[7].vlength);
            pvalues[7].hfname= hf_nds_class_filter;
            foffset = foffset+pvalues[7].vlength;
            if(pvalues[0].vvalue == 1)
            {
                break;
            }
            foffset += align_4(tvb, foffset);
            pvalues[8].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[8].vtype = VTYPE_MULTIVALUE_UINT32;
            pvalues[8].vdesc = "Seconds: %u";
            pvalues[8].vlength = 4;
            pvalues[8].mvtype = MVTYPE_PRINT_TIMESTAMP;
            pvalues[8].hfname= hf_nds_time_filter;
            pvalues[8].voffset = foffset;
            break;
        case 0x06:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vstring = "";
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = foffset;
            pvalues[0].hfname= hf_nds_ver;
            foffset = foffset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[1].vtype = VTYPE_UINT32;
            pvalues[1].vstring = "";
            pvalues[1].vdesc = "Request Flags: 0x%08x";
            pvalues[1].vlength = 4;
            pvalues[1].hfname= hf_nds_rflags;
            pvalues[1].voffset = foffset;
            foffset = foffset+4;
            pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[2].vtype = VTYPE_UINT32;
            pvalues[2].vdesc = "Iteration Handle: 0x%08x";
            pvalues[2].vlength = 4;
            pvalues[2].voffset = foffset;
            pvalues[2].hfname= hf_nds_iteration;
            foffset = foffset+pvalues[2].vlength;
            pvalues[3].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[3].vstring = "";
            pvalues[3].vtype = VTYPE_UINT32;
            pvalues[3].vdesc = "Base Entry ID: 0x%08x";
            pvalues[3].vlength = 4;
            resolve_eid = FALSE;
            global_eid = pvalues[3].vvalue;
            pvalues[3].voffset = foffset;
            pvalues[3].hfname= hf_nds_eid;
            foffset = foffset+pvalues[3].vlength;
            pvalues[4].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[4].vstring = val_to_str_const(pvalues[4].vvalue, nds_search_scope, "No Search Scope Defined");
            pvalues[4].vtype = VTYPE_STRING;
            pvalues[4].vdesc = "Replica Type: %s";
            pvalues[4].vlength = 4;
            pvalues[4].voffset = foffset;
            pvalues[4].mvtype = 0;
            pvalues[4].hfname= hf_nds_search_scope;
            foffset = foffset + pvalues[4].vlength;
            pvalues[5].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[5].vtype = VTYPE_UINT32;
            pvalues[5].vdesc = "Number of Objects to Search: 0x%08x";
            pvalues[5].vlength = 4;
            pvalues[5].voffset = foffset;
            pvalues[5].hfname= hf_nds_num_objects;
            foffset = foffset+pvalues[5].vlength;
            pvalues[6].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[6].vtype = VTYPE_BITFIELD;
            pvalues[6].vdesc = "Information Types:";
            pvalues[6].vlength = 2;
            pvalues[6].hfname= hf_nds_nflags;
            pvalues[6].voffset = foffset;
            pvalues[6].bit1 = "Names";
            pvalues[6].bit1hfname = hf_bit1siflags;
            pvalues[6].bit2 = "Names and Values";
            pvalues[6].bit2hfname = hf_bit2siflags;
            pvalues[6].bit3 = "Effective Privileges";
            pvalues[6].bit3hfname = hf_bit3siflags;
            pvalues[6].bit4 = "Value Info";
            pvalues[6].bit4hfname = hf_bit4siflags;
            pvalues[6].bit5 = "Abbreviated Value";
            pvalues[6].bit5hfname = hf_bit5siflags;
            pvalues[6].bit6 = "Not Defined";
            pvalues[6].bit6hfname = hf_bit6siflags;
            pvalues[6].bit7 = "Not Defined";
            pvalues[6].bit7hfname = hf_bit7siflags;
            pvalues[6].bit8 = "Not Defined";
            pvalues[6].bit8hfname = hf_bit8siflags;
            pvalues[6].bit9 = "Expanded Class";
            pvalues[6].bit9hfname = hf_bit9siflags;
            pvalues[6].bit10 = "Not Defined";
            pvalues[6].bit10hfname = hf_bit10siflags;
            pvalues[6].bit11= "Not Defined";
            pvalues[6].bit11hfname = hf_bit11siflags;
            pvalues[6].bit12 = "Not Defined";
            pvalues[6].bit12hfname = hf_bit12siflags;
            pvalues[6].bit13 = "Not Defined";
            pvalues[6].bit13hfname = hf_bit13siflags;
            pvalues[6].bit14 = "Not Defined";
            pvalues[6].bit14hfname = hf_bit14siflags;
            pvalues[6].bit15 = "Not Defined";
            pvalues[6].bit15hfname = hf_bit15siflags;
            pvalues[6].bit16 = "Not Defined";
            pvalues[6].bit16hfname = hf_bit16siflags;
            foffset = foffset+4;
            if(pvalues[0].vvalue != 2)
            {
                pvalues[7].vvalue = tvb_get_letohs(tvb, foffset);
                global_flags = tvb_get_letohl(tvb, foffset);
                pvalues[7].vtype = VTYPE_BITFIELD;
                pvalues[7].vdesc = "Information Flags (low) Byte:";
                pvalues[7].vlength = 2;
                pvalues[7].hfname= hf_nds_rflags;
                pvalues[7].voffset = foffset;
                pvalues[7].bit1 = "Output Flags";
                pvalues[7].bit1hfname = hf_bit1infoflagsl;
                pvalues[7].bit2 = "Entry ID";
                pvalues[7].bit2hfname = hf_bit2infoflagsl;
                pvalues[7].bit3 = "Entry Flags";
                pvalues[7].bit3hfname = hf_bit3infoflagsl;
                pvalues[7].bit4 = "Subordinate Count";
                pvalues[7].bit4hfname = hf_bit4infoflagsl;
                pvalues[7].bit5 = "Modification Time";
                pvalues[7].bit5hfname = hf_bit5infoflagsl;
                pvalues[7].bit6 = "Modification Timestamp";
                pvalues[7].bit6hfname = hf_bit6infoflagsl;
                pvalues[7].bit7 = "Creation Timestamp";
                pvalues[7].bit7hfname = hf_bit7infoflagsl;
                pvalues[7].bit8 = "Partition Root ID";
                pvalues[7].bit8hfname = hf_bit8infoflagsl;
                pvalues[7].bit9 = "Parent ID";
                pvalues[7].bit9hfname = hf_bit9infoflagsl;
                pvalues[7].bit10 = "Revision Count";
                pvalues[7].bit10hfname = hf_bit10infoflagsl;
                pvalues[7].bit11 = "Replica Type";
                pvalues[7].bit11hfname = hf_bit11infoflagsl;
                pvalues[7].bit12 = "Base Class";
                pvalues[7].bit12hfname = hf_bit12infoflagsl;
                pvalues[7].bit13 = "Relative Distinguished Name";
                pvalues[7].bit13hfname = hf_bit13infoflagsl;
                pvalues[7].bit14 = "Distinguished Name";
                pvalues[7].bit14hfname = hf_bit14infoflagsl;
                pvalues[7].bit15 = "Root Distinguished Name";
                pvalues[7].bit15hfname = hf_bit15infoflagsl;
                pvalues[7].bit16 = "Parent Distinguished Name";
                pvalues[7].bit16hfname = hf_bit16infoflagsl;
                foffset = foffset+2;
                pvalues[8].vvalue = tvb_get_letohs(tvb, foffset);
                pvalues[8].vtype = VTYPE_BITFIELD;
                pvalues[8].vdesc = "Information Flags (high) Byte:";
                pvalues[8].vlength = 2;
                pvalues[8].hfname= hf_nds_rflags;
                pvalues[8].voffset = foffset;
                pvalues[8].bit1 = "Purge Time";
                pvalues[8].bit1hfname = hf_bit1infoflagsh;
                pvalues[8].bit2 = "Dereference Base Class";
                pvalues[8].bit2hfname = hf_bit2infoflagsh;
                pvalues[8].bit3 = "Not Defined";
                pvalues[8].bit3hfname = hf_bit3infoflagsh;
                pvalues[8].bit4 = "Not Defined";
                pvalues[8].bit4hfname = hf_bit4infoflagsh;
                pvalues[8].bit5 = "Not Defined";
                pvalues[8].bit5hfname = hf_bit5infoflagsh;
                pvalues[8].bit6 = "Not Defined";
                pvalues[8].bit6hfname = hf_bit6infoflagsh;
                pvalues[8].bit7 = "Not Defined";
                pvalues[8].bit7hfname = hf_bit7infoflagsh;
                pvalues[8].bit8 = "Not Defined";
                pvalues[8].bit8hfname = hf_bit8infoflagsh;
                pvalues[8].bit9 = "Not Defined";
                pvalues[8].bit9hfname = hf_bit9infoflagsh;
                pvalues[8].bit10 = "Not Defined";
                pvalues[8].bit10hfname = hf_bit10infoflagsh;
                pvalues[8].bit11 = "Not Defined";
                pvalues[8].bit11hfname = hf_bit11infoflagsh;
                pvalues[8].bit12 = "Not Defined";
                pvalues[8].bit12hfname = hf_bit12infoflagsh;
                pvalues[8].bit13 = "Not Defined";
                pvalues[8].bit13hfname = hf_bit13infoflagsh;
                pvalues[8].bit14 = "Not Defined";
                pvalues[8].bit14hfname = hf_bit14infoflagsh;
                pvalues[8].bit15 = "Not Defined";
                pvalues[8].bit15hfname = hf_bit15infoflagsh;
                pvalues[8].bit16 = "Not Defined";
                pvalues[8].bit16hfname = hf_bit16infoflagsh;
                foffset = foffset+2;
            }
            break;
        case 0x07:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vstring = "";
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = foffset;
            pvalues[0].hfname= hf_nds_ver;
            foffset = foffset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[1].vtype = VTYPE_UINT32;
            pvalues[1].vstring = "";
            pvalues[1].vdesc = "Request Flags: 0x%08x";
            pvalues[1].vlength = 4;
            pvalues[1].hfname= hf_nds_rflags;
            pvalues[1].voffset = foffset;
            foffset = foffset+4;
            if(pvalues[0].vvalue == 0)
            {
                pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[2].vstring = "";
                pvalues[2].vtype = VTYPE_UINT32;
                pvalues[2].vdesc = "Parent Entry ID: 0x%08x";
                pvalues[2].vlength = 4;
                resolve_eid = FALSE;
                global_eid = pvalues[2].vvalue;
                pvalues[2].voffset = foffset;
                pvalues[2].hfname= hf_nds_eid;
                foffset = foffset+pvalues[2].vlength;
                pvalues[3].vtype = VTYPE_STRING;
                pvalues[3].vdesc = "Relative Distinguished Name: %s";
                pvalues[3].vstring = "";
                pvalues[3].mvtype = MVTYPE_ATTR_REQUEST;
                pvalues[3].vvalue = 0;
                pvalues[3].vlength = 256;
                pvalues[3].vlength = tvb_get_letohl(tvb, foffset);
                if (pvalues[3].vlength == 0x00 || !tvb_bytes_exist(tvb, foffset, pvalues[3].vlength))
                {
                    pvalues[3].vtype = VTYPE_NONE;
                    break;
                }
                pvalues[3].voffset = foffset+4;
                foffset = foffset + 4;
                pvalues[3].vstring = get_string(tvb, pvalues[3].voffset, pvalues[3].vlength);
                g_strlcpy(global_object_name, pvalues[3].vstring, 256);
                pvalues[3].hfname= hf_nds_relative_dn;
                foffset = foffset+pvalues[3].vlength;
                foffset += align_4(tvb, foffset);
                pvalues[4].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[4].vtype = VTYPE_MULTIVALUE_UINT32;
                pvalues[4].vstring = "";
                pvalues[4].vdesc = "Attributes: %u";
                pvalues[4].vlength = 4;
                pvalues[4].voffset = foffset;
                pvalues[4].mvtype = MVTYPE_ADD_ATTR_REQUEST;
                pvalues[4].hfname= hf_nds_attr;
            }
            else
            {
                pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[2].vstring = "";
                pvalues[2].vtype = VTYPE_UINT32;
                pvalues[2].vdesc = "Iteration Handle: 0x%08x";
                pvalues[2].vlength = 4;
                pvalues[2].voffset = foffset;
                pvalues[2].hfname= hf_nds_iteration;
                foffset = foffset+pvalues[2].vlength;
                pvalues[3].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[3].vstring = "";
                pvalues[3].vtype = VTYPE_UINT32;
                pvalues[3].vdesc = "Parent Entry ID: 0x%08x";
                pvalues[3].vlength = 4;
                resolve_eid = FALSE;
                global_eid = pvalues[3].vvalue;
                pvalues[3].voffset = foffset;
                pvalues[3].hfname= hf_nds_eid;
                foffset = foffset+pvalues[3].vlength;
                pvalues[4].vtype = VTYPE_STRING;
                pvalues[4].vdesc = "Relative Distinguished Name: %s";
                pvalues[4].vstring = "";
                pvalues[4].mvtype = MVTYPE_ATTR_REQUEST;
                pvalues[4].vvalue = 0;
                pvalues[4].vlength = 256;
                pvalues[4].vlength = tvb_get_letohl(tvb, foffset);
                if (pvalues[4].vlength == 0x00 || !tvb_bytes_exist(tvb, foffset, pvalues[4].vlength))
                {
                    pvalues[4].vtype = VTYPE_NONE;
                    break;
                }
                pvalues[4].voffset = foffset+4;
                foffset = foffset + 4;
                pvalues[4].vstring = get_string(tvb, pvalues[4].voffset, pvalues[4].vlength);
                g_strlcpy(global_object_name, pvalues[4].vstring, 256);
                pvalues[4].hfname= hf_nds_relative_dn;
                foffset = foffset+pvalues[4].vlength;
                foffset += align_4(tvb, foffset);
                pvalues[5].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[5].vtype = VTYPE_MULTIVALUE_UINT32;
                pvalues[5].vstring = "";
                pvalues[5].vdesc = "Attributes: %u";
                pvalues[5].vlength = 4;
                pvalues[5].voffset = foffset;
                pvalues[5].mvtype = MVTYPE_ADD_ATTR_REQUEST;
                pvalues[5].hfname= hf_nds_attr;
            }
            break;
        case 0x08:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = foffset;
            pvalues[0].hfname= hf_nds_ver;
            foffset = foffset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[1].vtype = VTYPE_UINT32;
            pvalues[1].vdesc = "Entry ID: 0x%08x";
            pvalues[1].vlength = 4;
            resolve_eid = TRUE;
            global_eid = pvalues[1].vvalue;
            pvalues[1].voffset = foffset;
            pvalues[1].hfname= hf_nds_eid;
            foffset = foffset+pvalues[1].vlength;
            break;
        case 0x09:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = foffset;
            pvalues[0].hfname= hf_nds_ver;
            foffset = foffset+pvalues[0].vlength;
            if(pvalues[0].vvalue == 0)
            {
                pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[1].vtype = VTYPE_UINT32;
                pvalues[1].vstring = "";
                pvalues[1].vdesc = "Iteration Handle: 0x%08x";  /* always 0 */
                pvalues[1].vlength = 4;
                pvalues[1].hfname= hf_nds_iteration;
                pvalues[1].voffset = foffset;
                foffset = foffset+4;
                pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[2].vstring = "";
                pvalues[2].vtype = VTYPE_UINT32;
                pvalues[2].vdesc = "Entry ID: 0x%08x";
                pvalues[2].vlength = 4;
                pvalues[2].voffset = foffset;
                resolve_eid = TRUE;
                global_eid = pvalues[2].vvalue;
                pvalues[2].hfname = hf_nds_eid;
                foffset = foffset+pvalues[2].vlength;
                pvalues[3].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[3].vtype = VTYPE_MULTIVALUE_UINT32;
                pvalues[3].vstring = "";
                pvalues[3].vdesc = "Number of Attributes to Change %u";
                pvalues[3].vlength = 4;
                pvalues[3].mvtype = MVTYPE_MODIFY_ATTR_REQUEST;
                pvalues[3].hfname= hf_nds_number_of_changes;
                pvalues[3].voffset = foffset;
            }
            else
            {
                pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[1].vtype = VTYPE_UINT32;
                pvalues[1].vstring = "";
                pvalues[1].vdesc = "Request Flags: 0x%08x";  /* always 0 */
                pvalues[1].vlength = 4;
                pvalues[1].hfname= hf_nds_rflags;
                pvalues[1].voffset = foffset;
                foffset = foffset+4;
                pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[2].vtype = VTYPE_UINT32;
                pvalues[2].vstring = "";
                pvalues[2].vdesc = "Iteration Handle: 0x%08x";  /* always 0 */
                pvalues[2].vlength = 4;
                pvalues[2].hfname= hf_nds_iteration;
                pvalues[2].voffset = foffset;
                foffset = foffset+4;
                pvalues[3].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[3].vstring = "";
                pvalues[3].vtype = VTYPE_UINT32;
                pvalues[3].vdesc = "Entry ID: 0x%08x";
                pvalues[3].vlength = 4;
                pvalues[3].voffset = foffset;
                resolve_eid = TRUE;
                global_eid = pvalues[3].vvalue;
                pvalues[3].hfname = hf_nds_eid;
                foffset = foffset+pvalues[3].vlength;
                pvalues[4].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[4].vtype = VTYPE_MULTIVALUE_UINT32;
                pvalues[4].vstring = "";
                pvalues[4].vdesc = "Number of Attributes to Change %u";
                pvalues[4].vlength = 4;
                pvalues[4].mvtype = MVTYPE_MODIFY_ATTR_REQUEST;
                pvalues[4].hfname= hf_nds_number_of_changes;
                pvalues[4].voffset = foffset;
            }
            break;
        case 0x0a:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = foffset;
            pvalues[0].hfname= hf_nds_ver;
            foffset = foffset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[1].vtype = VTYPE_UINT32;
            pvalues[1].vdesc = "Entry ID: 0x%08x";
            pvalues[1].vlength = 4;
            resolve_eid = TRUE;
            global_eid = pvalues[1].vvalue;
            pvalues[1].voffset = foffset;
            pvalues[1].hfname = hf_nds_eid;
            foffset = foffset+pvalues[1].vlength;
            pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[2].vtype = VTYPE_BOOLEAN;
            pvalues[2].vdesc = "Keep Original RDN: %s";
            pvalues[2].vlength = 4;
            pvalues[2].voffset = foffset;
            pvalues[2].mvtype = 0;
            pvalues[2].hfname= hf_nds_keep;
            foffset = foffset+4;
            foffset += align_4(tvb, foffset);
            pvalues[3].vtype = VTYPE_STRING;
            pvalues[3].vdesc = "New RDN: %s";
            pvalues[3].mvtype = 0;
            pvalues[3].vvalue = 0;
            pvalues[3].vlength = 256;
            pvalues[3].vlength = tvb_get_letohl(tvb, foffset);
            pvalues[3].voffset = foffset+4;
            foffset = foffset + 4;
            pvalues[3].vstring = get_string(tvb, pvalues[3].voffset, pvalues[3].vlength);
            pvalues[3].hfname= hf_nds_new_rdn;
            foffset = foffset+pvalues[3].vlength;
            break;
        case 0x0b:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = foffset;
            pvalues[0].hfname= hf_nds_ver;
            foffset = foffset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohs(tvb, foffset);
            global_flags = tvb_get_letohl(tvb, foffset);
            pvalues[1].vtype = VTYPE_BITFIELD;
            pvalues[1].vdesc = "Attribute Constraints:";
            pvalues[1].vlength = 2;
            pvalues[1].hfname= hf_nds_acflags;
            pvalues[1].voffset = foffset;
            pvalues[1].bit1 = "Single Valued";
            pvalues[1].bit1hfname = hf_bit1acflags;
            pvalues[1].bit2 = "Sized";
            pvalues[1].bit2hfname = hf_bit2acflags;
            pvalues[1].bit3 = "Non-Removable";
            pvalues[1].bit3hfname = hf_bit3acflags;
            pvalues[1].bit4 = "Read Only";
            pvalues[1].bit4hfname = hf_bit4acflags;
            pvalues[1].bit5 = "Hidden";
            pvalues[1].bit5hfname = hf_bit5acflags;
            pvalues[1].bit6 = "String";
            pvalues[1].bit6hfname = hf_bit6acflags;
            pvalues[1].bit7 = "Synchronize Immediate";
            pvalues[1].bit7hfname = hf_bit7acflags;
            pvalues[1].bit8 = "Public Read";
            pvalues[1].bit8hfname = hf_bit8acflags;
            pvalues[1].bit9 = "Server Read";
            pvalues[1].bit9hfname = hf_bit9acflags;
            pvalues[1].bit10 = "Write Managed";
            pvalues[1].bit10hfname = hf_bit10acflags;
            pvalues[1].bit11 = "Per Replica";
            pvalues[1].bit11hfname = hf_bit11acflags;
            pvalues[1].bit12 = "Never Schedule Synchronization";
            pvalues[1].bit12hfname = hf_bit12acflags;
            pvalues[1].bit13 = "Operational";
            pvalues[1].bit13hfname = hf_bit13acflags;
            pvalues[1].bit14 = "Not Defined";
            pvalues[1].bit14hfname = hf_bit14acflags;
            pvalues[1].bit15 = "Not Defined";
            pvalues[1].bit15hfname = hf_bit15acflags;
            pvalues[1].bit16 = "Not Defined";
            pvalues[1].bit16hfname = hf_bit16acflags;
            foffset = foffset+4;
            pvalues[2].vtype = VTYPE_STRING;
            pvalues[2].vdesc = "Attribute Name: %s";
            pvalues[2].mvtype = MVTYPE_ATTR_REQUEST;
            pvalues[2].vvalue = 0;
            pvalues[2].vlength = 256;
            pvalues[2].vlength = tvb_get_letohl(tvb, foffset);
            if (pvalues[2].vlength == 0x00 || !tvb_bytes_exist(tvb, foffset, pvalues[2].vlength))
            {
                pvalues[2].vtype = VTYPE_NONE;
                break;
            }
            pvalues[2].voffset = foffset+4;
            foffset = foffset + 4;
            pvalues[2].vstring = get_string(tvb, pvalues[2].voffset, pvalues[2].vlength);
            g_strlcpy(global_object_name, pvalues[2].vstring, 256);
            pvalues[2].hfname= hf_nds_name;
            foffset = foffset+pvalues[2].vlength;
            foffset += align_4(tvb, foffset);
            pvalues[3].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[3].vstring = val_to_str_const(pvalues[3].vvalue, nds_syntax, "No Syntax Found");
            pvalues[3].vtype = VTYPE_STRING;
            pvalues[3].vdesc = "Syntax: %s";
            pvalues[3].vlength = 4;
            pvalues[3].voffset = foffset;
            pvalues[3].hfname= hf_nds_syntax;
            pvalues[3].mvtype = 0;
            foffset = foffset+pvalues[3].vlength;
            pvalues[4].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[4].vtype = VTYPE_UINT32;
            pvalues[4].vdesc = "Lower Limit Value %u";
            pvalues[4].vlength = 4;
            pvalues[4].voffset = foffset;
            pvalues[4].hfname = hf_nds_lower;
            foffset += 4;
            pvalues[5].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[5].vtype = VTYPE_UINT32;
            pvalues[5].vdesc = "Upper Limit Value %u";
            pvalues[5].vlength = 4;
            pvalues[5].voffset = foffset;
            pvalues[5].hfname = hf_nds_upper;
            foffset += 4;
            pvalues[6].vvalue = tvb_get_letohl(tvb, foffset); /* Length of bytes field */
            foffset += 4;
            pvalues[6].vtype = VTYPE_BYTES;
            pvalues[6].vdesc = "ASN.1 ID";
            pvalues[6].vlength = pvalues[6].vvalue;
            pvalues[6].voffset = foffset;
            pvalues[6].hfname = hf_nds_asn1;
            break;
        case 0x0c:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x0d:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = foffset;
            pvalues[0].hfname= hf_nds_ver;
            foffset = foffset+pvalues[0].vlength;
            pvalues[1].vtype = VTYPE_STRING;
            pvalues[1].vdesc = "Attribute Name: %s";
            pvalues[1].mvtype = MVTYPE_ATTR_REQUEST;
            pvalues[1].vvalue = 0;
            pvalues[1].vlength = 256;
            pvalues[1].vlength = tvb_get_letohl(tvb, foffset);
            if (pvalues[1].vlength == 0x00 || !tvb_bytes_exist(tvb, foffset, pvalues[1].vlength))
            {
                pvalues[1].vtype = VTYPE_NONE;
                break;
            }
            pvalues[1].voffset = foffset+4;
            foffset = foffset + 4;
            pvalues[1].vstring = get_string(tvb, pvalues[1].voffset, pvalues[1].vlength);
            g_strlcpy(global_object_name, pvalues[1].vstring, 256);
            pvalues[1].hfname= hf_nds_attribute_dn;
            break;
        case 0x0e:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x0f:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = foffset;
            pvalues[0].hfname= hf_nds_ver;
            foffset = foffset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[1].vtype = VTYPE_UINT32;
            pvalues[1].vdesc = "Iteration Handle: 0x%08x";
            pvalues[1].vlength = 4;
            pvalues[1].voffset = foffset;
            pvalues[1].hfname= hf_nds_iteration;
            foffset = foffset+pvalues[1].vlength;
            pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
            global_flags = pvalues[2].vvalue;
            pvalues[2].vstring = val_to_str_const(pvalues[2].vvalue, class_def_type, "No Class Definition Type Set");
            pvalues[2].vtype = VTYPE_STRING;
            pvalues[2].vdesc = "Class Definition Type: %s";
            pvalues[2].vlength = 4;
            pvalues[2].voffset = foffset;
            pvalues[2].mvtype = 0;
            pvalues[2].hfname= hf_nds_class_def_type;
            foffset = foffset + pvalues[2].vlength;
            pvalues[3].vvalue = tvb_get_letohl(tvb, foffset);
            if (pvalues[3].vvalue == 0x00000000)
            {
                pvalues[3].vstring = "Do Not Return All Classes";
                pvalues[3].mvtype = 0;
            }
            else
            {
                pvalues[3].vstring = "Return All Classes";
                pvalues[3].mvtype = MVTYPE_ATTR_REQUEST;
            }
            pvalues[3].vtype = VTYPE_STRING;
            pvalues[3].vdesc = "%s";
            pvalues[3].vlength = 4;
            pvalues[3].voffset = foffset;
            pvalues[3].hfname= hf_nds_return_all_classes;
            foffset = foffset + pvalues[3].vlength;
            foffset += align_4(tvb, foffset);
            pvalues[4].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[4].vtype = VTYPE_MULTIVALUE_UINT32;
            pvalues[4].vdesc = "Classes: %u";
            pvalues[4].vlength = 4;
            pvalues[4].voffset = foffset;
            pvalues[4].mvtype = MVTYPE_READ_CLASS_REQ;
            pvalues[4].hfname= hf_nds_classes;
            break;
        case 0x10:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = foffset;
            pvalues[0].hfname= hf_nds_ver;
            foffset = foffset+pvalues[0].vlength;
            pvalues[1].vtype = VTYPE_STRING;
            pvalues[1].vdesc = "Class Name: %s";
            pvalues[1].mvtype = MVTYPE_ATTR_REQUEST;
            pvalues[1].vvalue = 0;
            pvalues[1].vlength = 256;
            pvalues[1].vlength = tvb_get_letohl(tvb, foffset);
            if (pvalues[1].vlength == 0x00 || !tvb_bytes_exist(tvb, foffset, pvalues[1].vlength))
            {
                pvalues[1].vtype = VTYPE_NONE;
                break;
            }
            pvalues[1].voffset = foffset+4;
            foffset = foffset + 4;
            pvalues[1].vstring = get_string(tvb, pvalues[1].voffset, pvalues[1].vlength);
            g_strlcpy(global_object_name, pvalues[1].vstring, 256);
            pvalues[1].hfname= hf_nds_base_class;
            foffset = foffset+pvalues[1].vlength;
            foffset += align_4(tvb, foffset);
            pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[2].vtype = VTYPE_MULTIVALUE_UINT32;
            pvalues[2].vdesc = "Number of Attributes to Add: %u";
            pvalues[2].vlength = 4;
            pvalues[2].voffset = foffset;
            pvalues[2].mvtype = MVTYPE_MODIFY_CLASS;
            pvalues[2].hfname= hf_nds_att_add;
            break;
        case 0x11:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = foffset;
            pvalues[0].hfname= hf_nds_ver;
            foffset = foffset+pvalues[0].vlength;
            pvalues[1].vtype = VTYPE_STRING;
            pvalues[1].vdesc = "Class Name: %s";
            pvalues[1].mvtype = MVTYPE_ATTR_REQUEST;
            pvalues[1].vvalue = 0;
            pvalues[1].vlength = 256;
            pvalues[1].vlength = tvb_get_letohl(tvb, foffset);
            if (pvalues[1].vlength == 0x00 || !tvb_bytes_exist(tvb, foffset, pvalues[1].vlength))
            {
                pvalues[1].vtype = VTYPE_NONE;
                break;
            }
            pvalues[1].voffset = foffset+4;
            foffset = foffset + 4;
            pvalues[1].vstring = get_string(tvb, pvalues[1].voffset, pvalues[1].vlength);
            g_strlcpy(global_object_name, pvalues[1].vstring, 256);
            pvalues[1].hfname= hf_nds_base;
            break;
        case 0x12:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = foffset;
            pvalues[0].hfname= hf_nds_ver;
            foffset = foffset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[1].vtype = VTYPE_UINT32;
            pvalues[1].vdesc = "Iteration Handle: 0x%08x";
            pvalues[1].vlength = 4;
            pvalues[1].voffset = foffset;
            pvalues[1].hfname= hf_nds_iteration;
            foffset = foffset+pvalues[1].vlength;
            pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[2].vtype = VTYPE_UINT32;
            pvalues[2].vdesc = "Entry ID: 0x%08x";
            pvalues[2].vlength = 4;
            resolve_eid = TRUE;
            global_eid = pvalues[2].vvalue;
            pvalues[2].voffset = foffset;
            pvalues[2].hfname= hf_nds_eid;
            foffset = foffset+pvalues[2].vlength;
            break;
        case 0x13:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = foffset;
            pvalues[0].hfname= hf_nds_ver;
            foffset = foffset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[1].vtype = VTYPE_UINT32;
            pvalues[1].vdesc = "Entry ID: 0x%08x";
            pvalues[1].vlength = 4;
            resolve_eid = TRUE;
            global_eid = pvalues[1].vvalue;
            pvalues[1].voffset = foffset;
            pvalues[1].hfname= hf_nds_eid;
            foffset = foffset+pvalues[1].vlength;
            pvalues[2].vtype = VTYPE_STRING;
            pvalues[2].vdesc = "Trustee Name: %s";
            pvalues[2].mvtype = MVTYPE_ATTR_REQUEST;
            pvalues[2].vvalue = 0;
            pvalues[2].vlength = 256;
            pvalues[2].vlength = tvb_get_letohl(tvb, foffset);
            if (pvalues[2].vlength == 0x00 || !tvb_bytes_exist(tvb, foffset, pvalues[2].vlength))
            {
                pvalues[2].vtype = VTYPE_NONE;
                break;
            }
            pvalues[2].voffset = foffset+4;
            foffset = foffset + 4;
            pvalues[2].vstring = get_string(tvb, pvalues[2].voffset, pvalues[2].vlength);
            pvalues[2].hfname= hf_nds_name;
            foffset = foffset+pvalues[2].vlength;
            foffset += align_4(tvb, foffset);
            pvalues[3].vtype = VTYPE_STRING;
            pvalues[3].vdesc = "Attribute to be Checked: %s";
            pvalues[3].mvtype = 0;
            pvalues[3].vvalue = 0;
            pvalues[3].vlength = 256;
            pvalues[3].vlength = tvb_get_letohl(tvb, foffset);
            if (pvalues[3].vlength == 0x00 || !tvb_bytes_exist(tvb, foffset, pvalues[3].vlength))
            {
                pvalues[3].vtype = VTYPE_NONE;
                break;
            }
            pvalues[3].voffset = foffset+4;
            foffset = foffset + 4;
            pvalues[3].vstring = get_string(tvb, pvalues[3].voffset, pvalues[3].vlength);
            pvalues[3].hfname= hf_nds_name;
            foffset = foffset+pvalues[3].vlength;
            foffset += align_4(tvb, foffset);
            if(pvalues[0].vvalue != 0)
            {
                pvalues[4].vtype = VTYPE_STRING;
                pvalues[4].vdesc = "Security Equivalence: %s";
                pvalues[4].mvtype = MVTYPE_ATTR_REQUEST;
                pvalues[4].vvalue = 0;
                pvalues[4].vlength = 256;
                pvalues[4].vlength = tvb_get_letohl(tvb, foffset);
                if (pvalues[4].vlength == 0x00 || !tvb_bytes_exist(tvb, foffset, pvalues[4].vlength))
                {
                    pvalues[4].vtype = VTYPE_NONE;
                    break;
                }
                pvalues[4].voffset = foffset+4;
                foffset = foffset + 4;
                pvalues[4].vstring = get_string(tvb, pvalues[4].voffset, pvalues[4].vlength);
                pvalues[4].hfname= hf_nds_name;
                foffset = foffset+pvalues[4].vlength;
                foffset += align_4(tvb, foffset);
            }
            break;
        case 0x14:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x15:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x16:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = foffset;
            pvalues[0].hfname= hf_nds_ver;
            foffset = foffset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[1].vtype = VTYPE_BITFIELD;
            pvalues[1].vdesc = "Request Flags:";
            pvalues[1].vlength = 2;
            pvalues[1].hfname= hf_nds_rflags;
            pvalues[1].voffset = foffset;
            pvalues[1].bit1 = "Typeless";
            pvalues[1].bit1hfname = hf_nds_bit1;
            pvalues[1].bit2 = "All Containers";
            pvalues[1].bit2hfname = hf_nds_bit2;
            pvalues[1].bit3 = "Slashed";
            pvalues[1].bit3hfname = hf_nds_bit3;
            pvalues[1].bit4 = "Dotted";
            pvalues[1].bit4hfname = hf_nds_bit4;
            pvalues[1].bit5 = "Tuned";
            pvalues[1].bit5hfname = hf_nds_bit5;
            pvalues[1].bit6 = "Not Defined";
            pvalues[1].bit6hfname = hf_nds_bit6;
            pvalues[1].bit7 = "Not Defined";
            pvalues[1].bit7hfname = hf_nds_bit7;
            pvalues[1].bit8 = "Not Defined";
            pvalues[1].bit8hfname = hf_nds_bit8;
            pvalues[1].bit9 = "Not Defined";
            pvalues[1].bit9hfname = hf_nds_bit9;
            pvalues[1].bit10 = "Not Defined";
            pvalues[1].bit10hfname = hf_nds_bit10;
            pvalues[1].bit11 = "Not Defined";
            pvalues[1].bit11hfname = hf_nds_bit11;
            pvalues[1].bit12 = "Not Defined";
            pvalues[1].bit12hfname = hf_nds_bit12;
            pvalues[1].bit13 = "Not Defined";
            pvalues[1].bit13hfname = hf_nds_bit13;
            pvalues[1].bit14 = "Not Defined";
            pvalues[1].bit14hfname = hf_nds_bit14;
            pvalues[1].bit15 = "Not Defined";
            pvalues[1].bit15hfname = hf_nds_bit15;
            pvalues[1].bit16 = "Not Defined";
            pvalues[1].bit16hfname = hf_nds_bit16;
            foffset = foffset+pvalues[1].vlength;
            pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[2].vtype = VTYPE_UINT32;
            pvalues[2].vdesc = "Iteration Handle: 0x%08x";
            pvalues[2].vlength = 4;
            pvalues[2].voffset = foffset;
            pvalues[2].hfname= hf_nds_iteration;
            foffset = foffset+pvalues[2].vlength;
            if(pvalues[0].vvalue == 0)
            {
                global_flags = 0x000000c0;
                break;
            }
            pvalues[3].vvalue = tvb_get_letohs(tvb, foffset);
            pvalues[3].vtype = VTYPE_BITFIELD;
            pvalues[3].vdesc = "Information Flags (low) Byte:";
            pvalues[3].vlength = 2;
            pvalues[3].hfname= hf_nds_rflags;
            pvalues[3].voffset = foffset;
            pvalues[3].bit1 = "Output Flags";
            pvalues[3].bit1hfname = hf_bit1l1flagsl;
            pvalues[3].bit2 = "Entry ID";
            pvalues[3].bit2hfname = hf_bit2l1flagsl;
            pvalues[3].bit3 = "Replica State";
            pvalues[3].bit3hfname = hf_bit3l1flagsl;
            pvalues[3].bit4 = "Modification Timestamp";
            pvalues[3].bit4hfname = hf_bit4l1flagsl;
            pvalues[3].bit5 = "Purge Time";
            pvalues[3].bit5hfname = hf_bit5l1flagsl;
            pvalues[3].bit6 = "Local Partition ID";
            pvalues[3].bit6hfname = hf_bit6l1flagsl;
            pvalues[3].bit7 = "Distinguished Name";
            pvalues[3].bit7hfname = hf_bit7l1flagsl;
            pvalues[3].bit8 = "Replica Type";
            pvalues[3].bit8hfname = hf_bit8l1flagsl;
            pvalues[3].bit9 = "Partition Busy";
            pvalues[3].bit9hfname = hf_bit9l1flagsl;
            pvalues[3].bit10 = "Not Defined";
            pvalues[3].bit10hfname = hf_bit10l1flagsl;
            pvalues[3].bit11 = "Not Defined";
            pvalues[3].bit11hfname = hf_bit11l1flagsl;
            pvalues[3].bit12 = "Not Defined";
            pvalues[3].bit12hfname = hf_bit12l1flagsl;
            pvalues[3].bit13 = "Not Defined";
            pvalues[3].bit13hfname = hf_bit13l1flagsl;
            pvalues[3].bit14 = "Not Defined";
            pvalues[3].bit14hfname = hf_bit14l1flagsl;
            pvalues[3].bit15 = "Not Defined";
            pvalues[3].bit15hfname = hf_bit15l1flagsl;
            pvalues[3].bit16 = "Not Defined";
            pvalues[3].bit16hfname = hf_bit16l1flagsl;
            global_flags = pvalues[3].vvalue;
            foffset = foffset+2;
            pvalues[4].vvalue = tvb_get_letohs(tvb, foffset);
            pvalues[4].vtype = VTYPE_BITFIELD;
            pvalues[4].vdesc = "Information Flags (high) Byte:";
            pvalues[4].vlength = 2;
            pvalues[4].hfname= hf_nds_rflags;
            pvalues[4].voffset = foffset;
            pvalues[4].bit1 = "Not Defined";
            pvalues[4].bit1hfname = hf_bit1l1flagsl;
            pvalues[4].bit2 = "Not Defined";
            pvalues[4].bit2hfname = hf_bit2l1flagsl;
            pvalues[4].bit3 = "Not Defined";
            pvalues[4].bit3hfname = hf_bit3l1flagsl;
            pvalues[4].bit4 = "Not Defined";
            pvalues[4].bit4hfname = hf_bit4l1flagsl;
            pvalues[4].bit5 = "Not Defined";
            pvalues[4].bit5hfname = hf_bit5l1flagsl;
            pvalues[4].bit6 = "Not Defined";
            pvalues[4].bit6hfname = hf_bit6l1flagsl;
            pvalues[4].bit7 = "Not Defined";
            pvalues[4].bit7hfname = hf_bit7l1flagsl;
            pvalues[4].bit8 = "Not Defined";
            pvalues[4].bit8hfname = hf_bit8l1flagsl;
            pvalues[4].bit9 = "Not Defined";
            pvalues[4].bit9hfname = hf_bit9l1flagsl;
            pvalues[4].bit10 = "Not Defined";
            pvalues[4].bit10hfname = hf_bit10l1flagsl;
            pvalues[4].bit11 = "Not Defined";
            pvalues[4].bit11hfname = hf_bit11l1flagsl;
            pvalues[4].bit12 = "Not Defined";
            pvalues[4].bit12hfname = hf_bit12l1flagsl;
            pvalues[4].bit13 = "Not Defined";
            pvalues[4].bit13hfname = hf_bit13l1flagsl;
            pvalues[4].bit14 = "Not Defined";
            pvalues[4].bit14hfname = hf_bit14l1flagsl;
            pvalues[4].bit15 = "Not Defined";
            pvalues[4].bit15hfname = hf_bit15l1flagsl;
            pvalues[4].bit16 = "Not Defined";
            pvalues[4].bit16hfname = hf_bit16l1flagsl;
            foffset = foffset+2;
            if(pvalues[0].vvalue == 1)
            {
                break;
            }
            pvalues[5].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[5].vtype = VTYPE_UINT32;
            pvalues[5].vdesc = "Partition Root ID: 0x%08x";
            pvalues[5].vlength = 4;
            pvalues[5].voffset = foffset;
            pvalues[5].hfname= hf_nds_partition_root_id;
            foffset = foffset+pvalues[5].vlength;
            break;
        case 0x17:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].hfname = hf_nds_ver;
            pvalues[0].voffset = foffset;
            foffset = foffset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[1].vtype = VTYPE_UINT32;
            pvalues[1].vdesc = "Flags: 0x%08x";
            pvalues[1].vlength = 4;
            pvalues[1].hfname = hf_nds_req_flags;
            pvalues[1].voffset = foffset;
            foffset = foffset+pvalues[1].vlength;
            pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[2].vtype = VTYPE_UINT32;
            pvalues[2].vdesc = "New Partition Root ID: 0x%08x";
            pvalues[2].vlength = 4;
            pvalues[2].voffset = foffset;
            pvalues[2].hfname= hf_nds_new_part_id;
            foffset = foffset+pvalues[2].vlength;
            break;
        case 0x18:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].hfname = hf_nds_ver;
            pvalues[0].voffset = foffset;
            foffset = foffset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[1].vtype = VTYPE_UINT32;
            pvalues[1].vdesc = "Flags: 0x%08x";
            pvalues[1].vlength = 4;
            pvalues[1].hfname = hf_nds_req_flags;
            pvalues[1].voffset = foffset;
            foffset = foffset+pvalues[1].vlength;
            pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[2].vtype = VTYPE_UINT32;
            pvalues[2].vdesc = "Child Partition Root ID: 0x%08x";
            pvalues[2].vlength = 4;
            pvalues[2].voffset = foffset;
            pvalues[2].hfname= hf_nds_child_part_id;
            foffset = foffset+pvalues[2].vlength;
            break;
        case 0x19:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].hfname = hf_nds_ver;
            pvalues[0].voffset = foffset;
            foffset = foffset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[1].vtype = VTYPE_UINT32;
            pvalues[1].vdesc = "Flags: 0x%08x";
            pvalues[1].vlength = 4;
            pvalues[1].hfname = hf_nds_req_flags;
            pvalues[1].voffset = foffset;
            foffset = foffset+pvalues[1].vlength;
            pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[2].vtype = VTYPE_UINT32;
            pvalues[2].vdesc = "Master Partition Root ID: 0x%08x";
            pvalues[2].vlength = 4;
            pvalues[2].voffset = foffset;
            pvalues[2].hfname= hf_nds_master_part_id;
            foffset = foffset+pvalues[2].vlength;
            pvalues[3].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[3].vstring = val_to_str_const(pvalues[3].vvalue, nds_replica_type, "No Replica Type Found");
            pvalues[3].vtype = VTYPE_STRING;
            pvalues[3].vdesc = "Replica Type: %s";
            pvalues[3].vlength = 4;
            pvalues[3].voffset = foffset;
            pvalues[3].mvtype = 0;
            pvalues[3].hfname= hf_replica_type;
            foffset = foffset + pvalues[3].vlength;
            pvalues[4].vtype = VTYPE_STRING;
            pvalues[4].vdesc = "Target Server Name: %s";
            pvalues[4].mvtype = 0;
            pvalues[4].vvalue = 0;
            pvalues[4].vlength = 256;
            pvalues[4].vlength = tvb_get_letohl(tvb, foffset);
            if (pvalues[4].vlength == 0x00 && !tvb_bytes_exist(tvb, foffset, pvalues[4].vlength))
            {
                pvalues[4].vtype = VTYPE_NONE;
                break;
            }
            pvalues[4].voffset = foffset+4;
            foffset = foffset + 4;
            pvalues[4].vstring = get_string(tvb, pvalues[4].voffset, pvalues[4].vlength);
            pvalues[4].hfname= hf_nds_target_name;
            break;
        case 0x1a:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x1b:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].hfname = hf_nds_ver;
            pvalues[0].voffset = foffset;
            foffset = foffset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[1].vtype = VTYPE_UINT32;
            pvalues[1].vdesc = "Streams Flags: 0x%08x";
            pvalues[1].vlength = 4;
            pvalues[1].hfname = hf_nds_stream_flags;
            pvalues[1].voffset = foffset;
            foffset = foffset+pvalues[1].vlength;
            pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[2].vtype = VTYPE_UINT32;
            pvalues[2].vdesc = "Entry ID: 0x%08x";
            pvalues[2].vlength = 4;
            resolve_eid = TRUE;
            global_eid = pvalues[2].vvalue;
            pvalues[2].voffset = foffset;
            pvalues[2].hfname= hf_nds_eid;
            foffset = foffset+pvalues[2].vlength;
            pvalues[3].vtype = VTYPE_STRING;
            pvalues[3].vdesc = "Stream Name: %s";
            pvalues[3].mvtype = MVTYPE_ATTR_REQUEST;
            pvalues[3].vvalue = 0;
            pvalues[3].vlength = 256;
            pvalues[3].vlength = tvb_get_letohl(tvb, foffset);
            if (pvalues[3].vlength == 0x00 || !tvb_bytes_exist(tvb, foffset, pvalues[3].vlength))
            {
                pvalues[3].vtype = VTYPE_NONE;
                break;
            }
            pvalues[3].voffset = foffset+4;
            foffset += 4;
            pvalues[3].vstring = get_string(tvb, pvalues[3].voffset, pvalues[3].vlength);
            foffset += pvalues[3].vlength;
            foffset += align_4(tvb, foffset);
            pvalues[3].hfname= hf_nds_stream_name;
            break;
        case 0x1c:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x1d:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x1e:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x1f:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x20:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x21:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x22:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x23:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x24:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x25:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x26:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].hfname = hf_nds_ver;
            pvalues[0].voffset = foffset;
            foffset = foffset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[1].vtype = VTYPE_UINT32;
            pvalues[1].vdesc = "Flags: 0x%08x";
            pvalues[1].vlength = 4;
            pvalues[1].hfname = hf_nds_req_flags;
            pvalues[1].voffset = foffset;
            foffset = foffset+pvalues[1].vlength;
            pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[2].vtype = VTYPE_UINT32;
            pvalues[2].vdesc = "Time Delay in Seconds: %u";
            pvalues[2].vlength = 4;
            pvalues[2].voffset = foffset;
            pvalues[2].hfname= hf_nds_time_delay;
            foffset = foffset+pvalues[2].vlength;
            if(pvalues[0].vvalue == 0)
            {
                pvalues[3].vtype = VTYPE_STRING;
                pvalues[3].vdesc = "Root Most Object Name: %s";
                pvalues[3].mvtype = MVTYPE_ATTR_REQUEST;
                pvalues[3].vvalue = 0;
                pvalues[3].vlength = 256;
                pvalues[3].vlength = tvb_get_letohl(tvb, foffset);
                if (pvalues[3].vlength == 0x00 || !tvb_bytes_exist(tvb, foffset, pvalues[3].vlength))
                {
                    pvalues[3].vtype = VTYPE_NONE;
                    break;
                }
                pvalues[3].voffset = foffset+4;
                foffset += 4;
                pvalues[3].vstring = get_string(tvb, pvalues[3].voffset, pvalues[3].vlength);
                foffset += pvalues[3].vlength;
                foffset += align_4(tvb, foffset);
                pvalues[3].hfname= hf_nds_root_name;
            }
            else
            {
                pvalues[3].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[3].vtype = VTYPE_UINT32;
                pvalues[3].vdesc = "Entry ID: 0x%08x";
                pvalues[3].vlength = 4;
                resolve_eid = TRUE;
                global_eid = pvalues[3].vvalue;
                pvalues[3].voffset = foffset;
                pvalues[3].hfname= hf_nds_eid;
                foffset = foffset+pvalues[3].vlength;
                resolve_eid = TRUE;
                global_eid = pvalues[3].vvalue;
            }
            break;
        case 0x27:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x28:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x29:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x2a:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].hfname = hf_nds_ver;
            pvalues[0].voffset = foffset;
            foffset = foffset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[1].vtype = VTYPE_UINT32;
            pvalues[1].vdesc = "Flags: 0x%08x";
            pvalues[1].vlength = 4;
            pvalues[1].hfname = hf_nds_req_flags;
            pvalues[1].voffset = foffset;
            foffset = foffset+pvalues[1].vlength;
            pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[2].vtype = VTYPE_UINT32;
            pvalues[2].vdesc = "Destination Parent Entry ID: 0x%08x";
            pvalues[2].vlength = 4;
            resolve_eid = TRUE;
            global_eid = pvalues[2].vvalue;
            pvalues[2].voffset = foffset;
            pvalues[2].hfname= hf_nds_eid;
            foffset = foffset+pvalues[2].vlength;
            global_eid = pvalues[2].vvalue;
            pvalues[3].vtype = VTYPE_STRING;
            pvalues[3].vdesc = "New RDN: %s";
            pvalues[3].mvtype = 0;
            pvalues[3].vvalue = 0;
            pvalues[3].vlength = 256;
            pvalues[3].vlength = tvb_get_letohl(tvb, foffset);
            pvalues[3].voffset = foffset+4;
            foffset = foffset + 4;
            pvalues[3].vstring = get_string(tvb, pvalues[3].voffset, pvalues[3].vlength);
            pvalues[3].hfname= hf_nds_new_rdn;
            foffset = foffset+pvalues[3].vlength;
            foffset += align_4(tvb, foffset);
            pvalues[4].vtype = VTYPE_STRING;
            pvalues[4].vdesc = "Source Server Name: %s";
            pvalues[4].mvtype = 0;
            pvalues[4].vvalue = 0;
            pvalues[4].vlength = 256;
            pvalues[4].vlength = tvb_get_letohl(tvb, foffset);
            if (pvalues[4].vlength == 0x00 || !tvb_bytes_exist(tvb, foffset, pvalues[3].vlength))
            {
                pvalues[4].vtype = VTYPE_NONE;
                break;
            }
            pvalues[4].voffset = foffset+4;
            foffset = foffset + 4;
            pvalues[4].vstring = get_string(tvb, pvalues[4].voffset, pvalues[4].vlength);
            pvalues[4].hfname= hf_nds_target_name;
            break;
        case 0x2b:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].hfname = hf_nds_ver;
            pvalues[0].voffset = foffset;
            foffset = foffset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[1].vtype = VTYPE_UINT32;
            pvalues[1].vdesc = val_to_str_const(pvalues[1].vvalue, nds_verb2b_flag_vals, "No Flag Definition Found");
            pvalues[1].vlength = 4;
            pvalues[1].hfname = hf_nds_verb2b_req_flags;
            pvalues[1].voffset = foffset;
            foffset = foffset+pvalues[1].vlength;
            pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[2].vtype = VTYPE_UINT32;
            pvalues[2].vdesc = "Source Entry ID: 0x%08x";
            pvalues[2].vlength = 4;
            resolve_eid = TRUE;
            global_eid = pvalues[2].vvalue;
            pvalues[2].voffset = foffset;
            pvalues[2].hfname= hf_nds_eid;
            foffset = foffset+pvalues[2].vlength;
            pvalues[3].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[3].vtype = VTYPE_UINT32;
            pvalues[3].vdesc = "Destination Parent Entry ID: 0x%08x";
            pvalues[3].vlength = 4;
            pvalues[3].voffset = foffset;
            pvalues[3].hfname= hf_nds_eid;
            foffset = foffset+pvalues[3].vlength;
            pvalues[4].vtype = VTYPE_STRING;
            pvalues[4].vdesc = "New RDN: %s";
            pvalues[4].mvtype = 0;
            pvalues[4].vvalue = 0;
            pvalues[4].vlength = 256;
            pvalues[4].vlength = tvb_get_letohl(tvb, foffset);
            pvalues[4].voffset = foffset+4;
            foffset = foffset + 4;
            pvalues[4].vstring = get_string(tvb, pvalues[4].voffset, pvalues[4].vlength);
            pvalues[4].hfname= hf_nds_new_rdn;
            foffset = foffset+pvalues[4].vlength;
            foffset += align_4(tvb, foffset);
            pvalues[5].vtype = VTYPE_STRING;
            pvalues[5].vdesc = "Source Server Name: %s";
            pvalues[5].mvtype = 0;
            pvalues[5].vvalue = 0;
            pvalues[5].vlength = 256;
            pvalues[5].vlength = tvb_get_letohl(tvb, foffset);
            if (pvalues[5].vlength == 0x00 || !tvb_bytes_exist(tvb, foffset, pvalues[3].vlength))
            {
                pvalues[5].vtype = VTYPE_NONE;
                break;
            }
            pvalues[5].voffset = foffset+4;
            foffset = foffset + 4;
            pvalues[5].vstring = get_string(tvb, pvalues[5].voffset, pvalues[5].vlength);
            pvalues[5].hfname= hf_nds_target_name;
            break;
        case 0x2c:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x2d:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x2e:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x2f:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x30:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x31:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x32:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].hfname = hf_nds_ver;
            pvalues[0].voffset = foffset;
            foffset = foffset+pvalues[0].vlength;
            pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[2].vtype = VTYPE_UINT32;
            pvalues[2].vdesc = "Iteration Handle: 0x%08x";
            pvalues[2].vlength = 4;
            pvalues[2].voffset = foffset;
            pvalues[2].hfname= hf_nds_iteration;
            foffset = foffset+pvalues[2].vlength;
            pvalues[3].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[3].vtype = VTYPE_STRING;
            pvalues[3].vdesc = "NDS Verb: %s";
            pvalues[3].vstring = val_to_str_const(pvalues[3].vvalue, ncp_nds_verb_vals, "(No Verb Found)");
            pvalues[3].vlength = 4;
            pvalues[3].voffset = foffset;
            pvalues[3].hfname= hf_mv_string;
            foffset = foffset+pvalues[3].vlength;
            break;
        case 0x33:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x34:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x35:
            if (nds_version != 0)
            {
                pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
                pvalues[0].vtype = VTYPE_UINT32;
                pvalues[0].vdesc = "Version: %u";
                pvalues[0].vlength = 4;
                pvalues[0].hfname = hf_nds_ver;
                pvalues[0].voffset = foffset;
                foffset = foffset+pvalues[0].vlength;
                pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                global_flags = pvalues[1].vvalue;
                pvalues[1].vtype = VTYPE_BITFIELD;
                pvalues[1].vdesc = "Request Flags:";
                pvalues[1].vlength = 2;
                pvalues[1].hfname= hf_nds_rflags;
                pvalues[1].voffset = foffset;
                pvalues[1].bit1 = "Typeless";
                pvalues[1].bit1hfname = hf_bit1rflags;
                pvalues[1].bit2 = "Slashed";
                pvalues[1].bit2hfname = hf_bit2rflags;
                pvalues[1].bit3 = "Dotted";
                pvalues[1].bit3hfname = hf_bit3rflags;
                pvalues[1].bit4 = "Tuned";
                pvalues[1].bit4hfname = hf_bit4rflags;
                pvalues[1].bit5 = "Not Defined";
                pvalues[1].bit5hfname = hf_bit5rflags;
                pvalues[1].bit6 = "Not Defined";
                pvalues[1].bit6hfname = hf_bit6rflags;
                pvalues[1].bit7 = "Not Defined";
                pvalues[1].bit7hfname = hf_bit7rflags;
                pvalues[1].bit8 = "Not Defined";
                pvalues[1].bit8hfname = hf_bit8rflags;
                pvalues[1].bit9 = "Not Defined";
                pvalues[1].bit9hfname = hf_bit9rflags;
                pvalues[1].bit10 = "Not Defined";
                pvalues[1].bit10hfname = hf_bit10rflags;
                pvalues[1].bit11 = "Not Defined";
                pvalues[1].bit11hfname = hf_bit11rflags;
                pvalues[1].bit12 = "Not Defined";
                pvalues[1].bit12hfname = hf_bit12rflags;
                pvalues[1].bit13 = "Not Defined";
                pvalues[1].bit13hfname = hf_bit13rflags;
                pvalues[1].bit14 = "Not Defined";
                pvalues[1].bit14hfname = hf_bit14rflags;
                pvalues[1].bit15 = "Not Defined";
                pvalues[1].bit15hfname = hf_bit15rflags;
                pvalues[1].bit16 = "Not Defined";
                pvalues[1].bit16hfname = hf_bit16rflags;
            }
            break;
        case 0x36:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x37:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x38:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x39:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = foffset;
            pvalues[0].hfname= hf_nds_ver;
            foffset = foffset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[1].vtype = VTYPE_UINT32;
            pvalues[1].vdesc = "Entry ID: 0x%08x";
            pvalues[1].vlength = 4;
            resolve_eid = TRUE;
            global_eid = pvalues[1].vvalue;
            pvalues[1].voffset = foffset;
            pvalues[1].hfname= hf_nds_eid;
            foffset = foffset+pvalues[1].vlength;
            break;
        case 0x3a:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Reply Buffer Size: %u";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = foffset;
            pvalues[0].hfname= hf_nds_buffer_size;
            foffset = foffset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[1].vtype = VTYPE_UINT32;
            pvalues[1].vdesc = "Version: %u";
            pvalues[1].vlength = 4;
            pvalues[1].voffset = foffset;
            pvalues[1].hfname= hf_nds_ver;
            foffset = foffset+pvalues[1].vlength;
            pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[2].vtype = VTYPE_UINT32;
            pvalues[2].vdesc = "Entry ID: 0x%08x";
            pvalues[2].vlength = 4;
            resolve_eid = TRUE;
            global_eid = pvalues[2].vvalue;
            pvalues[2].voffset = foffset;
            pvalues[2].hfname= hf_nds_eid;
            foffset = foffset+pvalues[2].vlength;
            break;
        case 0x3b:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].voffset = foffset;
            pvalues[0].hfname= hf_nds_ver;
            foffset = foffset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[1].vtype = VTYPE_UINT32;
            pvalues[1].vdesc = "Entry ID: 0x%08x";
            pvalues[1].vlength = 4;
            resolve_eid = TRUE;
            global_eid = pvalues[1].vvalue;
            pvalues[1].voffset = foffset;
            pvalues[1].hfname= hf_nds_eid;
            foffset = foffset+pvalues[1].vlength;
            break;
        case 0x3c:
            break;
        case 0x3d:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x3e:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x3f:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x40:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x41:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x42:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x43:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x44:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x45:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x46:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x47:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x48:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x49:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x4a:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x4b:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x4c:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x4d:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        case 0x6e:
            pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[0].vtype = VTYPE_UINT32;
            pvalues[0].vdesc = "Version: %u";
            pvalues[0].vlength = 4;
            pvalues[0].hfname = hf_nds_ver;
            pvalues[0].voffset = foffset;
            foffset = foffset+pvalues[0].vlength;
            pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
            global_flags = pvalues[1].vvalue;
            pvalues[1].vtype = VTYPE_BITFIELD;
            pvalues[1].vdesc = "Request Flags:";
            pvalues[1].vlength = 2;
            pvalues[1].hfname= hf_nds_rflags;
            pvalues[1].voffset = foffset;
            pvalues[1].bit1 = "Typeless";
            pvalues[1].bit1hfname = hf_bit1rflags;
            pvalues[1].bit2 = "Slashed";
            pvalues[1].bit2hfname = hf_bit2rflags;
            pvalues[1].bit3 = "Dotted";
            pvalues[1].bit3hfname = hf_bit3rflags;
            pvalues[1].bit4 = "Tuned";
            pvalues[1].bit4hfname = hf_bit4rflags;
            pvalues[1].bit5 = "Not Defined";
            pvalues[1].bit5hfname = hf_bit5rflags;
            pvalues[1].bit6 = "Not Defined";
            pvalues[1].bit6hfname = hf_bit6rflags;
            pvalues[1].bit7 = "Not Defined";
            pvalues[1].bit7hfname = hf_bit7rflags;
            pvalues[1].bit8 = "Not Defined";
            pvalues[1].bit8hfname = hf_bit8rflags;
            pvalues[1].bit9 = "Not Defined";
            pvalues[1].bit9hfname = hf_bit9rflags;
            pvalues[1].bit10 = "Not Defined";
            pvalues[1].bit10hfname = hf_bit10rflags;
            pvalues[1].bit11 = "Not Defined";
            pvalues[1].bit11hfname = hf_bit11rflags;
            pvalues[1].bit12 = "Not Defined";
            pvalues[1].bit12hfname = hf_bit12rflags;
            pvalues[1].bit13 = "Not Defined";
            pvalues[1].bit13hfname = hf_bit13rflags;
            pvalues[1].bit14 = "Not Defined";
            pvalues[1].bit14hfname = hf_bit14rflags;
            pvalues[1].bit15 = "Not Defined";
            pvalues[1].bit15hfname = hf_bit15rflags;
            pvalues[1].bit16 = "Not Defined";
            pvalues[1].bit16hfname = hf_bit16rflags;
            foffset = foffset+pvalues[1].vlength+2;
            pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[2].vtype = VTYPE_UINT32;
            pvalues[2].vdesc = "Iteration Handle: 0x%08x";
            pvalues[2].vlength = 4;
            pvalues[2].voffset = foffset;
            pvalues[2].hfname= hf_nds_iteration;
            foffset = foffset+pvalues[2].vlength;
            pvalues[3].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[3].vtype = VTYPE_UINT32;
            pvalues[3].vdesc = "Base Entry ID: 0x%08x";
            pvalues[3].vlength = 4;
            resolve_eid = TRUE;
            global_eid = pvalues[3].vvalue;
            pvalues[3].voffset = foffset;
            pvalues[3].hfname= hf_nds_eid;
            foffset = foffset+pvalues[3].vlength;
            pvalues[4].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[4].vtype = VTYPE_UINT32;
            pvalues[4].vdesc = val_to_str_const(pvalues[4].vvalue, nds_scope_vals, "Unknown Scope Defined");
            pvalues[4].vlength = 4;
            pvalues[4].hfname = hf_nds_scope;
            pvalues[4].voffset = foffset;
            foffset = foffset+pvalues[4].vlength;
            pvalues[5].vvalue = tvb_get_letohl(tvb, foffset);
            pvalues[5].vtype = VTYPE_MULTIVALUE_UINT32;
            pvalues[5].vdesc = "Iterator: 0x%08x";
            pvalues[5].vlength = 4;
            pvalues[5].voffset = foffset;
            pvalues[5].hfname= hf_nds_iterator;
            pvalues[5].mvtype = MVTYPE_PROCESS_ITERATOR;
            foffset = foffset+pvalues[5].vlength;
            break;
        default:
            pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
            break;
        }
    }
    /* Fill in the INFO column. */
    if (check_col(pinfo->cinfo, COL_INFO)) {
        if (ncp_rec) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "NDS");
            if (nds_frag != 0xffffffff) {
                col_add_fstr(pinfo->cinfo, COL_INFO, "C Continue NDS Fragment 0x%08x", nds_frag);
            }
            else {
                col_add_fstr(pinfo->cinfo, COL_INFO, "C NDS %s", verb_string);
            }
            run_info_str = TRUE;
        }
        else {
            col_add_fstr(pinfo->cinfo, COL_INFO,
                         "C Unknown Function %d (0x%02x)",
                         func, func);
        }

    }
    /* Keep track of the address and connection whence the request
       came, and the address and connection to which the request
       is being sent, so that we can match up calls with replies.
       (We don't include the sequence number, as we may want
       to have all packets over the same connection treated
       as being part of a single conversation so that we can
       let the user select that conversation to be displayed.) */

    conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                     PT_NCP, nw_connection, nw_connection, 0);
    if (conversation == NULL) {
        /* It's not part of any conversation - create a new one. */
        conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                        PT_NCP, nw_connection, nw_connection, 0);
    }

    if (!pinfo->fd->flags.visited) {
        request_value = ncp_hash_insert(conversation, sequence, ncp_rec, pinfo->fd->num);
        request_value->req_frame_num = pinfo->fd->num;
        request_value->req_frame_time=pinfo->fd->abs_ts;

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
    if ((run_info_str || run_req_cond) && !ncp_tree) {
        proto_item *ti;

        temp_tree = proto_tree_create_root(pinfo);
        proto_tree_set_visible(temp_tree, FALSE);
        ti = proto_tree_add_item(temp_tree, proto_ncp, tvb, 0, -1, FALSE);
        ncp_tree = proto_item_add_subtree(ti, ett_ncp);
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

        request_value = ncp_hash_lookup(conversation, sequence, pinfo->fd->num);
        switch (type) {
        case NCP_BROADCAST_SLOT:
            ; /* nothing */
            break;

        case NCP_SERVICE_REQUEST:

            ptvc = ptvcursor_new(ncp_tree, tvb, 7);
            if (ncp_rec && ncp_rec->request_ptvc)
            {
                clear_repeat_vars();
                process_ptvc_record(ptvc, ncp_rec->request_ptvc, NULL, TRUE, ncp_rec);
            }
            proto_tree_add_uint_format(ncp_tree, hf_ncp_func, tvb, 6, 1,
                                       func, "Function: %d (0x%02X), %s",
                                       func, func, ncp_rec ? ncp_rec->name : "Unknown");

            proto_tree_add_uint_format(ncp_tree, hf_ncp_subfunc, tvb, 7, 1,
                                       subfunc, "SubFunction: %d (0x%02x)",
                                       subfunc, subfunc);

            proto_tree_add_uint(ncp_tree, hf_ncp_fragment_handle, tvb, 8, 4,
                                nds_frag);

            if (nds_frag == 0xffffffff) {

                proto_tree_add_item(ncp_tree, hf_ncp_fragment_size, tvb, 12, 4, TRUE);

                proto_tree_add_item(ncp_tree, hf_ncp_message_size, tvb, 16, 4, TRUE);

                nds_prot_flags = tvb_get_letohs(tvb, 22);
                prot_flags[0].vvalue = nds_prot_flags;
                prot_flags[0].vtype = VTYPE_BITFIELD;
                prot_flags[0].vdesc = "NDS Protocol Flags:";
                prot_flags[0].vlength = 2;
                prot_flags[0].hfname= hf_ncp_nds_flag;
                prot_flags[0].voffset = 22;
                prot_flags[0].bit1 = "Not Defined";
                prot_flags[0].bit1hfname = hf_ndsprot1flag;
                prot_flags[0].bit2 = "Not Defined";
                prot_flags[0].bit2hfname = hf_ndsprot2flag;
                prot_flags[0].bit3 = "Not Defined";
                prot_flags[0].bit3hfname = hf_ndsprot3flag;
                prot_flags[0].bit4 = "Not Defined";
                prot_flags[0].bit4hfname = hf_ndsprot4flag;
                prot_flags[0].bit5 = "Not Defined";
                prot_flags[0].bit5hfname = hf_ndsprot5flag;
                prot_flags[0].bit6 = "Not Defined";
                prot_flags[0].bit6hfname = hf_ndsprot6flag;
                prot_flags[0].bit7 = "Not Defined";
                prot_flags[0].bit7hfname = hf_ndsprot7flag;
                prot_flags[0].bit8 = "Not Defined";
                prot_flags[0].bit8hfname = hf_ndsprot8flag;
                prot_flags[0].bit9 = "Not Defined";
                prot_flags[0].bit9hfname = hf_ndsprot9flag;
                prot_flags[0].bit10 = "Not Defined";
                prot_flags[0].bit10hfname = hf_ndsprot10flag;
                prot_flags[0].bit11= "Not Defined";
                prot_flags[0].bit11hfname = hf_ndsprot11flag;
                prot_flags[0].bit12 = "Not Defined";
                prot_flags[0].bit12hfname = hf_ndsprot12flag;
                prot_flags[0].bit13 = "Not Defined";
                prot_flags[0].bit13hfname = hf_ndsprot13flag;
                prot_flags[0].bit14 = "Not Defined";
                prot_flags[0].bit14hfname = hf_ndsprot14flag;
                prot_flags[0].bit15 = "Include CRC in NDS Header";
                prot_flags[0].bit15hfname = hf_ndsprot15flag;
                prot_flags[0].bit16 = "Client is a Server";
                prot_flags[0].bit16hfname = hf_ndsprot16flag;

                process_bitfield(ncp_tree, tvb, &prot_flags[0]);

                if (nds_version == 0) {
                    proto_tree_add_uint_format(ncp_tree, hf_ncp_nds_verb, tvb, 24, 4,
                                               nds_verb, "NDS Verb: %d, (0x%02x), %s",
                                               nds_verb, nds_verb, verb_string);
                }
                else {
                    proto_tree_add_uint_format(ncp_tree, hf_ncp_nds_verb, tvb, 32, 4,
                                               nds_verb, "NDS Verb: %d, (0x%02x), %s",
                                               nds_verb, nds_verb, verb_string);
                }
                added_arrow = FALSE;
                for (i = 0; i < 9; i++) {
                    switch (pvalues[i].vtype) {

                    case VTYPE_NONE: /* no value */
                        break;

                    case VTYPE_UINT8:
                        proto_tree_add_uint_format(ncp_tree, pvalues[i].hfname, tvb, pvalues[i].voffset,
                                                   pvalues[i].vlength, pvalues[i].vtype, "NDS Parameter not defined %u",
                                                   pvalues[i].vtype);
                        break;

                    case VTYPE_UINT16:
                        proto_tree_add_uint_format(ncp_tree, pvalues[i].hfname, tvb, pvalues[i].voffset,
                                                   pvalues[i].vlength, pvalues[i].vtype, "NDS Parameter not defined %u",
                                                   pvalues[i].vtype);
                        break;

                    case VTYPE_UINT32:
                        proto_tree_add_uint_format(ncp_tree, pvalues[i].hfname, tvb, pvalues[i].voffset,
                                                   pvalues[i].vlength, pvalues[i].vvalue, pvalues[i].vdesc,
                                                   pvalues[i].vvalue);
                        break;

                    case VTYPE_STRING:
                        proto_tree_add_string_format(ncp_tree, pvalues[i].hfname, tvb, pvalues[i].voffset,
                                                     pvalues[i].vlength, pvalues[i].vstring, pvalues[i].vdesc, pvalues[i].vstring);
                        if (pvalues[i].mvtype == MVTYPE_ATTR_REQUEST) {
                            /*
                             * The "vstring" value is set to the input ES type
                             * for MVTYPE_PROC_ENTRY_SPECIFIERS,
                             * to add string to columninfo
                             */
                            if (check_col(pinfo->cinfo, COL_INFO)) {
                                if (!added_arrow) {
                                    col_append_str(pinfo->cinfo, COL_INFO, " -> ");
                                    added_arrow = TRUE;
                                }
                                col_append_str(pinfo->cinfo, COL_INFO, pvalues[i].vstring);
                            }
                        }
                        break;

                    case VTYPE_BITFIELD:
                        process_bitfield(ncp_tree, tvb, &pvalues[i]);
                        break;

                    case VTYPE_MULTIVALUE_UINT32:
                        process_multivalues(ncp_tree, tvb, pinfo, &pvalues[i]);
                        if (pvalues[i].mvtype == MVTYPE_PROC_ENTRY_SPECIFIERS) {
                            /*
                             * The "vstring" value is set to the input ES type
                             * by "process_multivalues()".
                             */
                            g_strlcpy(global_object_name, mv_resolve_name_string, 256);
                        }
                        if (pvalues[i].mvtype == MVTYPE_ATTR_REQUEST || pvalues[i].mvtype == MVTYPE_PROC_ENTRY_SPECIFIERS || pvalues[i].mvtype == MVTYPE_PROCESS_ITERATOR) {
                            /*
                             * The "vstring" value is set to the input ES type
                             * for MVTYPE_PROC_ENTRY_SPECIFIERS,
                             * and the last string for MVTYPE_ATTR_REQUEST,
                             * by "process_multivalues()".
                             */
                            if (check_col(pinfo->cinfo, COL_INFO)) {
                                col_append_str(pinfo->cinfo, COL_INFO, pvalues[i].vstring);
                                if (pvalues[i].mvtype != MVTYPE_PROCESS_ITERATOR) {
                                    if (!added_arrow) {
                                        col_append_str(pinfo->cinfo, COL_INFO, " -> ");
                                        added_arrow = TRUE;
                                    }
                                    col_append_str(pinfo->cinfo, COL_INFO, mv_resolve_name_string);
                                }
                            }
                        }
                        break;

                    case VTYPE_BYTES:
                        proto_tree_add_bytes(ncp_tree, pvalues[i].hfname, tvb, pvalues[i].voffset,
                                             pvalues[i].vlength, tvb_get_ptr(tvb, pvalues[i].voffset, pvalues[i].vvalue));
                        break;

                    case VTYPE_BOOLEAN:
                        proto_tree_add_item(ncp_tree, pvalues[i].hfname, tvb, pvalues[i].voffset, pvalues[i].vlength, TRUE);
                        break;

                    default:
                        proto_tree_add_uint_format(ncp_tree, hf_nds_p1type, tvb, pvalues[i].voffset,
                                                   pvalues[i].vlength, pvalues[i].vtype, "NDS Parameter not defined %u",
                                                   pvalues[i].vtype);
                        break;
                    }
                }
                /* For NDS requests with just an EID, resolve name from hash table. */
                request_eid_value = ncp_eid_hash_lookup(conversation, global_eid);
                if(resolve_eid) {
                    if (request_eid_value) {
                        g_strlcpy(global_object_name, request_eid_value->object_name, 256);
                        if (check_col(pinfo->cinfo, COL_INFO))
                        {
                            col_append_str(pinfo->cinfo, COL_INFO, ", Object Name - ");
                            col_append_str(pinfo->cinfo, COL_INFO, global_object_name);
                        }
                    }
                }
                if (request_value)
                {
                    request_value->nds_request_verb = nds_verb;
                    request_value->nds_version = nds_version;
                    g_strlcpy(request_value->object_name, global_object_name, 256);
                    request_value->req_nds_flags = global_flags;
                    request_value->req_nds_prot_flags = nds_prot_flags;
                }
            }
            break;

        default:
            ; /* nothing */
            break;
        }
        ptvcursor_free(ptvc);

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
    nds_val              pvalue;

#ifdef FAKE_TREE_IS_VISIBLE
    if (ncp_tree) {
        PTREE_DATA(ncp_tree)->visible=1;
    }
#endif

    pvalue.vvalue = 0;
    pvalue.vlength = 0;
    pvalue.voffset = 0;
    pvalue.hfname = 0;
    pvalue.vdesc = "";
    pvalue.vstring = NULL;
    pvalue.mvtype = 0;

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

        conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                         PT_NCP, nw_connection, nw_connection, 0);

        if (conversation == NULL)
        {
            /* It's not part of any conversation - create a new one. */
            conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                            PT_NCP, nw_connection, nw_connection, 0);
        }

        request_value = ncp_hash_insert(conversation, sequence, ncp_rec, pinfo->fd->num);
        request_value->req_frame_num = pinfo->fd->num;
        request_value->req_frame_time=pinfo->fd->abs_ts;

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
            ti = proto_tree_add_item(temp_tree, proto_ncp, tvb, 0, -1, FALSE);
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
            proto_tree_add_uint_format(ncp_tree, hf_ncp_func, tvb, 6, 1,
                                       func, "Function: %u (0x%02X), %s",
                                       func, func, ncp_rec ? ncp_rec->name : "Unknown");

            proto_tree_add_uint_format(ncp_tree, hf_ncp_subfunc, tvb, 7, 1,
                                       subfunc, "SubFunction: %u (0x%02x)",
                                       subfunc, subfunc);

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

                pvalue.vvalue = tvb_get_letohs(tvb, 12);
                pvalue.vtype = VTYPE_BITFIELD;
                pvalue.vstring = "";
                pvalue.vdesc = "Ping (low) Request Flags:";
                pvalue.vlength = 2;
                pvalue.hfname= hf_nds_rflags;
                pvalue.voffset = 12;
                pvalue.bit1 = "Supported Fields";   /* 0x0001 */
                pvalue.bit1hfname = hf_bit1pingflags1;
                pvalue.bit2 = "Depth";              /* 0x0002 */
                pvalue.bit2hfname = hf_bit2pingflags1;
                pvalue.bit3 = "Build Number";       /* 0x0004 */
                pvalue.bit3hfname = hf_bit3pingflags1;
                pvalue.bit4 = "Flags";              /* 0x0008 */
                pvalue.bit4hfname = hf_bit4pingflags1;
                pvalue.bit5 = "Verification Flags"; /* 0x0010 */
                pvalue.bit5hfname = hf_bit5pingflags1;
                pvalue.bit6 = "Letter Version";     /* 0x0020 */
                pvalue.bit6hfname = hf_bit6pingflags1;
                pvalue.bit7 = "OS Version";         /* 0x0040 */
                pvalue.bit7hfname = hf_bit7pingflags1;
                pvalue.bit8 = "Not Defined";        /* 0x0080 */
                pvalue.bit8hfname = hf_bit8pingflags1;
                pvalue.bit9 = "License Flags";      /* 0x0100 */
                pvalue.bit9hfname = hf_bit9pingflags1;
                pvalue.bit10 = "DS Time";           /* 0x0200 */
                pvalue.bit10hfname = hf_bit10pingflags1;
                pvalue.bit11 = "Server Time";       /* 0x0400 */
                pvalue.bit11hfname = hf_bit11pingflags1;
                pvalue.bit12 = "Create Time";       /* 0x0800 */
                pvalue.bit12hfname = hf_bit12pingflags1;
                pvalue.bit13 = "Not Defined";
                pvalue.bit13hfname = hf_bit13pingflags1;
                pvalue.bit14 = "Not Defined";
                pvalue.bit14hfname = hf_bit14pingflags1;
                pvalue.bit15 = "Not Defined";
                pvalue.bit15hfname = hf_bit15pingflags1;
                pvalue.bit16 = "Not Defined";
                pvalue.bit16hfname = hf_bit16pingflags1;

                process_bitfield(ncp_tree, tvb, &pvalue);

                pvalue.vvalue = tvb_get_letohs(tvb, 14);
                pvalue.vtype = VTYPE_BITFIELD;
                pvalue.vstring = "";
                pvalue.vdesc = "Ping (high) Request Flags:";
                pvalue.vlength = 2;
                pvalue.hfname= hf_nds_rflags;
                pvalue.voffset = 14;
                pvalue.bit1 = "Sap Name";           /* 0x0001 */
                pvalue.bit1hfname = hf_bit1pingflags2;
                pvalue.bit2 = "Tree Name";          /* 0x0002 */
                pvalue.bit2hfname = hf_bit2pingflags2;
                pvalue.bit3 = "OS Name";            /* 0x0004 */
                pvalue.bit3hfname = hf_bit3pingflags2;
                pvalue.bit4 = "Hardware Name";      /* 0x0008 */
                pvalue.bit4hfname = hf_bit4pingflags2;
                pvalue.bit5 = "Vendor Name";        /* 0x0010 */
                pvalue.bit5hfname = hf_bit5pingflags2;
                pvalue.bit6 = "Not Defined";
                pvalue.bit6hfname = hf_bit6pingflags2;
                pvalue.bit7 = "Not Defined";
                pvalue.bit7hfname = hf_bit7pingflags2;
                pvalue.bit8 = "Not Defined";
                pvalue.bit8hfname = hf_bit8pingflags2;
                pvalue.bit9 = "Not Defined";
                pvalue.bit9hfname = hf_bit9pingflags2;
                pvalue.bit10 = "Not Defined";
                pvalue.bit10hfname = hf_bit10pingflags2;
                pvalue.bit11 = "Not Defined";
                pvalue.bit11hfname = hf_bit11pingflags2;
                pvalue.bit12 = "Not Defined";
                pvalue.bit12hfname = hf_bit12pingflags2;
                pvalue.bit13 = "Not Defined";
                pvalue.bit13hfname = hf_bit13pingflags2;
                pvalue.bit14 = "Not Defined";
                pvalue.bit14hfname = hf_bit14pingflags2;
                pvalue.bit15 = "Not Defined";
                pvalue.bit15hfname = hf_bit15pingflags2;
                pvalue.bit16 = "Not Defined";
                pvalue.bit16hfname = hf_bit16pingflags2;

                process_bitfield(ncp_tree, tvb, &pvalue);
            }
            break;

        default:
            ; /* nothing */
            break;
        }
        ptvc = ptvcursor_new(ncp_tree, tvb, 7);
        if (ncp_rec && ncp_rec->request_ptvc) {
            clear_repeat_vars();
            process_ptvc_record(ptvc, ncp_rec->request_ptvc, NULL, TRUE, ncp_rec);
        }
        ptvcursor_free(ptvc);

        /* Free the temporary proto_tree */
        CLEANUP_CALL_AND_POP;
    }
}
