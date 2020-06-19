/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-z3950.c                                                             */
/* asn2wrs.py -b -p z3950 -c ./z3950.cnf -s ./packet-z3950-template -D . -O ../.. z3950.asn z3950-oclc.asn z3950-externals.asn */

/* Input file: packet-z3950-template.c */

#line 1 "./asn1/z3950/packet-z3950-template.c"
/* packet-z3950.c
 * Routines for dissection of the NISO Z39.50 Information Retrieval protocol
 * Also contains a dissector for the MARC Machine Readable Cataloging file
 * format. The general format is specified by ISO 2709 and the specific
 * instance is MARC21.
 *
 * Copyright 2018, Craig Jackson <cejackson51@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References:
 * ISO 2709: https://www.iso.org/standard/41319.html
 * MARC21: http://www.loc.gov/marc/bibliographic/
 * Z39.50 Maintenance Agency: http://www.loc.gov/z3950/agency/
 * Z39.50 2003 standard: http://www.loc.gov/z3950/agency/Z39-50-2003.pdf
 * Z39.50 1995 ASN.1: https://www.loc.gov/z3950/agency/asn1.html
 * Registered Z39.50 Object Identifiers:
 *   http://www.loc.gov/z3950/agency/defns/oids.html
 * Bib-1 Attribute Set: https://www.loc.gov/z3950/agency/defns/bib1.html
 * Bib-1 Diagnostics: https://www.loc.gov/z3950/agency/defns/bib1diag.html
 * RFC for Z39.50 over TCP/IP: https://tools.ietf.org/html/rfc1729
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/oids.h>
#include <epan/proto_data.h>
#include <wsutil/str_util.h>

#include <string.h>

#include "packet-ber.h"
#include "packet-tcp.h"

typedef struct z3950_atinfo_t {
    gint     atsetidx;
    gint     attype;
} z3950_atinfo_t;

typedef struct z3950_diaginfo_t {
    gint     diagsetidx;
    gint     diagcondition;
} z3950_diaginfo_t;

#define PNAME  "Z39.50 Protocol"
#define PSNAME "Z39.50"
#define PFNAME "z3950"
#define Z3950_PORT 210    /* UDP port */

/* Known attribute set ids */
#define Z3950_ATSET_BIB1_OID              "1.2.840.10003.3.1"

/* Known diagnostic set ids */
#define Z3950_DIAGSET_BIB1_OID            "1.2.840.10003.4.1"

/* Known record syntax ids */
#define Z3950_RECORDSYNTAX_MARC21_OID     "1.2.840.10003.5.10"

/* Indexes of known attribute set ids */
#define Z3950_ATSET_UNKNOWN         0
#define Z3950_ATSET_BIB1            1

/* bib-1 Attribute Types */
#define Z3950_BIB1_AT_USE           1
#define Z3950_BIB1_AT_RELATION      2
#define Z3950_BIB1_AT_POSITION      3
#define Z3950_BIB1_AT_STRUCTURE     4
#define Z3950_BIB1_AT_TRUNCATION    5
#define Z3950_BIB1_AT_COMPLETENESS  6

/* Indexes of known diagnostic set ids */
#define Z3950_DIAGSET_UNKNOWN       0
#define Z3950_DIAGSET_BIB1          1

/* Per-packet data keys */
#define Z3950_ATINFO_KEY            1
#define Z3950_DIAGSET_KEY           2

/* MARC defines */
#define MARC_SUBFIELD_INDICATOR     '\x1f'
#define MARC_LEADER_LENGTH          24
#define MARC_CHAR_UNINITIALIZED     256

#define marc_isdigit(x)            (((x) >='0') && ((x) <= '9'))
#define marc_char_to_int(x)        ((x) - '0')

typedef struct marc_directory_entry {
    guint32 tag;
    guint32 length;
    guint32 starting_character;
} marc_directory_entry;

static dissector_handle_t z3950_handle=NULL;

void proto_reg_handoff_z3950(void);
void proto_register_z3950(void);

/* Initialize the protocol and registered fields */
static int proto_z3950 = -1;
static int global_z3950_port = Z3950_PORT;
static gboolean z3950_desegment = TRUE;

static const value_string z3950_bib1_att_types[] = {
    { Z3950_BIB1_AT_USE, "Use" },
    { Z3950_BIB1_AT_RELATION, "Relation" },
    { Z3950_BIB1_AT_POSITION, "Position" },
    { Z3950_BIB1_AT_STRUCTURE, "Structure" },
    { Z3950_BIB1_AT_TRUNCATION, "Truncation" },
    { Z3950_BIB1_AT_COMPLETENESS, "Completeness"},
    { 0, NULL}
};

static const value_string z3950_bib1_at_use[] = {
    { 1, "Personal name" },
    { 2, "Corporate name" },
    { 3, "Conference name" },
    { 4, "Title" },
    { 5, "Title series" },
    { 6, "Title uniform" },
    { 7, "ISBN" },
    { 8, "ISSN" },
    { 9, "LC card number" },
    { 10, "BNB card number" },
    { 11, "BGF card number" },
    { 12, "Local number" },
    { 13, "Dewey classification" },
    { 14, "UDC classification" },
    { 15, "Bliss classification" },
    { 16, "LC call number" },
    { 17, "NLM call number" },
    { 18, "NAL call number" },
    { 19, "MOS call number" },
    { 20, "Local classification" },
    { 21, "Subject heading" },
    { 22, "Subject Rameau" },
    { 23, "BDI index subject" },
    { 24, "INSPEC subject" },
    { 25, "MESH subject" },
    { 26, "PA subject" },
    { 27, "LC subject heading" },
    { 28, "RVM subject heading" },
    { 29, "Local subject index" },
    { 30, "Date" },
    { 31, "Date of publication" },
    { 32, "Date of acquisition" },
    { 33, "Title key" },
    { 34, "Title collective" },
    { 35, "Title parallel" },
    { 36, "Title cover" },
    { 37, "Title added title pagw" },
    { 38, "Title caption" },
    { 39, "Title running" },
    { 40, "Title spine" },
    { 41, "Title other variant" },
    { 42, "Title former" },
    { 43, "Title abbreviated" },
    { 44, "Title expanded" },
    { 45, "Subject precis" },
    { 46, "Subject rswk" },
    { 47, "Subject subdivision" },
    { 48, "No. nat'l biblio." },
    { 49, "No. legal deposit" },
    { 50, "No. govt pub." },
    { 51, "No. music publisher" },
    { 52, "Number db" },
    { 53, "Number local call" },
    { 54, "Code-language" },
    { 55, "Code-geographic area" },
    { 56, "Code-institution" },
    { 57, "Name and title *" },
    { 58, "Name geographic" },
    { 59, "Place publication" },
    { 60, "CODEN" },
    { 61, "Microform generation" },
    { 62, "Abstract" },
    { 63, "Note" },
    { 1000, "Author-title" },
    { 1001, "Record type" },
    { 1002, "Name" },
    { 1003, "Author" },
    { 1004, "Author-name personal" },
    { 1005, "Author-name corporate" },
    { 1006, "Author-name conference" },
    { 1007, "Identifier-standard" },
    { 1008, "Subject-LC children's" },
    { 1009, "Subject name-personal" },
    { 1010, "Body of text" },
    { 1011, "Date/time added to db" },
    { 1012, "Date/time last modified" },
    { 1013, "Authority/format id" },
    { 1014, "Concept-text" },
    { 1015, "Concept-reference" },
    { 1016, "Any" },
    { 1017, "Server-choice" },
    { 1018, "Publisher" },
    { 1019, "Record-source" },
    { 1020, "Editor" },
    { 1021, "Bib-level" },
    { 1022, "Geographic class" },
    { 1023, "Indexed-by" },
    { 1024, "Map-scale" },
    { 1025, "Music-key" },
    { 1026, "Related-periodical" },
    { 1027, "Report-number" },
    { 1028, "Stock-number" },
    { 1030, "Thematic-number" },
    { 1031, "Material-type" },
    { 1032, "Doc-id" },
    { 1033, "Host-item" },
    { 1034, "Content-type" },
    { 1035, "Anywhere" },
    { 1036, "Author-Title-Subject" },
    { 1037, "Serial Item and Contribution Identifer (SICI)" },
    { 1038, "Abstract-language" },
    { 1039, "Application-kind" },
    { 1040, "Classification" },
    { 1041, "Classification-basic" },
    { 1042, "Classification-local-record" },
    { 1043, "Enzyme" },
    { 1044, "Possessing-institution" },
    { 1045, "Record-linking" },
    { 1046, "Record-status" },
    { 1047, "Treatment" },
    { 1048, "Control-number-GKD" },
    { 1049, "Control-number-linking" },
    { 1050, "Control-number-PND" },
    { 1051, "Control-number-SWD" },
    { 1052, "Control-number-ZDB" },
    { 1053, "Country-publication" },
    { 1054, "Date-conference" },
    { 1055, "Date-record-status" },
    { 1056, "Dissertation-information" },
    { 1057, "Meeting-organizer" },
    { 1058, "Note-availability" },
    { 1059, "Number-CAS-registry" },
    { 1060, "Number-document" },
    { 1061, "Number-local-accounting" },
    { 1062, "Number-local-acquisition" },
    { 1063, "Number-local-call-copy-specific" },
    { 1064, "Number-of-reference" },
    { 1065, "Number-norm" },
    { 1066, "Number-volume" },
    { 1067, "Place-conference (meeting location)" },
    { 1068, "Reference (references and footnotes)" },
    { 1069, "Referenced-journal" },
    { 1070, "Section-code" },
    { 1071, "Section-heading" },
    { 1072, "Subject-GOO" },
    { 1073, "Subject-name-conference" },
    { 1074, "Subject-name-corporate" },
    { 1075, "Subject-genre/form" },
    { 1076, "Subject-name-geographical" },
    { 1077, "Subject-chronological" },
    { 1078, "Subject-title" },
    { 1079, "Subject-topical" },
    { 1080, "Subject-uncontrolled" },
    { 1081, "Terminology-chemical" },
    { 1082, "Title-translated" },
    { 1083, "Year-of-beginning" },
    { 1084, "Year-of-ending" },
    { 1085, "Subject-AGROVOC" },
    { 1086, "Subject-COMPASS" },
    { 1087, "Subject-EPT" },
    { 1088, "Subject-NAL" },
    { 1089, "Classification-BCM" },
    { 1090, "Classification-DB" },
    { 1091, "Identifier-ISRC" },
    { 1092, "Identifier-ISMN" },
    { 1093, "Identifier-ISRN" },
    { 1094, "Identifier-DOI" },
    { 1095, "Code-language-original" },
    { 1096, "Title-later" },
    { 1097, "DC-Title" },
    { 1098, "DC-Creator" },
    { 1099, "DC-Subject" },
    { 1100, "DC-Description" },
    { 1101, "DC-Publisher" },
    { 1102, "DC-Date" },
    { 1103, "DC-ResourceType" },
    { 1104, "DC-ResourceIdentifier" },
    { 1105, "DC-Language" },
    { 1106, "DC-OtherContributor" },
    { 1107, "DC-Format" },
    { 1108, "DC-Source" },
    { 1109, "DC-Relation" },
    { 1110, "DC-Coverage" },
    { 1111, "DC-RightsManagment" },
    { 1112, "GILS Controlled Subject Index" },
    { 1113, "GILS Subject Thesaurus" },
    { 1114, "GILS Index Terms -- Controlled" },
    { 1115, "GILS Controlled Term" },
    { 1116, "GILS Spacial Domain" },
    { 1117, "GILS Bounding Coordinates" },
    { 1118, "GILS West Bounding Coordinate" },
    { 1119, "GILS East Bounding Coordinate" },
    { 1120, "GILS North Bounding Coordinate" },
    { 1121, "GILS South Bounding Coordinate" },
    { 1122, "GILS Place" },
    { 1123, "GILS Place Keyword Thesaurus" },
    { 1124, "GILS Place Keyword" },
    { 1125, "GILS Time Period" },
    { 1126, "GILS Time Period Textual" },
    { 1127, "GILS Time Period Structured" },
    { 1128, "GILS Beginning Date" },
    { 1129, "GILS Ending Date" },
    { 1130, "GILS Availability" },
    { 1131, "GILS Distributor" },
    { 1132, "GILS Distributor Name" },
    { 1133, "GILS Distributor Organization" },
    { 1134, "GILS Distributor Street Address" },
    { 1135, "GILS Distributor City" },
    { 1136, "GILS Distributor State or Province" },
    { 1137, "GILS Distributor Zip or Postal Code" },
    { 1138, "GILS Distributor Country" },
    { 1139, "GILS Distributor Network Address" },
    { 1140, "GILS Distributor Hours of Service" },
    { 1141, "GILS Distributor Telephone" },
    { 1142, "GILS Distributor Fax" },
    { 1143, "GILS Resource Description" },
    { 1144, "GILS Order Process" },
    { 1145, "GILS Order Information" },
    { 1146, "GILS Cost" },
    { 1147, "GILS Cost Information" },
    { 1148, "GILS Technical Prerequisites" },
    { 1149, "GILS Available Time Period" },
    { 1150, "GILS Available Time Textual" },
    { 1151, "GILS Available Time Structured" },
    { 1152, "GILS Available Linkage" },
    { 1153, "GILS Linkage Type" },
    { 1154, "GILS Linkage" },
    { 1155, "GILS Sources of Data" },
    { 1156, "GILS Methodology" },
    { 1157, "GILS Access Constraints" },
    { 1158, "GILS General Access Constraints" },
    { 1159, "GILS Originator Dissemination Control" },
    { 1160, "GILS Security Classification Control" },
    { 1161, "GILS Use Constraints" },
    { 1162, "GILS Point of Contact" },
    { 1163, "GILS Contact Name" },
    { 1164, "GILS Contact Organization" },
    { 1165, "GILS Contact Street Address" },
    { 1166, "GILS Contact City" },
    { 1167, "GILS Contact State or Province" },
    { 1168, "GILS Contact Zip or Postal Code" },
    { 1169, "GILS Contact Country" },
    { 1170, "GILS Contact Network Address" },
    { 1171, "GILS Contact Hours of Service" },
    { 1172, "GILS Contact Telephone" },
    { 1173, "GILS Contact Fax" },
    { 1174, "GILS Supplemental Information" },
    { 1175, "GILS Purpose" },
    { 1176, "GILS Agency Program" },
    { 1177, "GILS Cross Reference" },
    { 1178, "GILS Cross Reference Title" },
    { 1179, "GILS Cross Reference Relationship" },
    { 1180, "GILS Cross Reference Linkage" },
    { 1181, "GILS Schedule Number" },
    { 1182, "GILS Original Control Identifier" },
    { 1183, "GILS Language of Record" },
    { 1184, "GILS Record Review Date" },
    { 1185, "Performer" },
    { 1186, "Performer-Individual" },
    { 1187, "Performer-Group" },
    { 1188, "Instrumentation" },
    { 1189, "Instrumentation-Original" },
    { 1190, "Instrumentation-Current" },
    { 1191, "Arrangement" },
    { 1192, "Arrangement-Original" },
    { 1193, "Arrangement-Current" },
    { 1194, "Musical Key-Original" },
    { 1195, "Musical Key-Current" },
    { 1196, "Date-Composition" },
    { 1197, "Date-Recording" },
    { 1198, "Place-Recording" },
    { 1199, "Country-Recording" },
    { 1200, "Number-ISWC" },
    { 1201, "Number-Matrix" },
    { 1202, "Number-Plate" },
    { 1203, "Classification-McColvin" },
    { 1204, "Duration" },
    { 1205, "Number-Copies" },
    { 1206, "Musical Theme" },
    { 1207, "Instruments - total number" },
    { 1208, "Instruments - distinct number" },
    { 1209, "Identifier - URN" },
    { 1210, "Sears Subject Heading" },
    { 1211, "OCLC Number" },
    { 1212, "NORZIG Composition" },
    { 1213, "NORZIG Intellectual level" },
    { 1214, "NORZIG EAN" },
    { 1215, "NORZIG NLC" },
    { 1216, "NORZIG CRCS" },
    { 1217, "NORZIG Nationality" },
    { 1218, "NORZIG Equinox" },
    { 1219, "NORZIG Compression" },
    { 1220, "NORZIG Format" },
    { 1221, "NORZIG Subject - occupation" },
    { 1222, "NORZIG Subject - function" },
    { 1223, "NORZIG Edition" },
    { 1224, "GPO Item Number" },
    { 1225, "Provider" },
    { 0, NULL}
};

static const value_string z3950_bib1_at_relation[] = {
    { 1, "Less than" },
    { 2, "Less than or equal" },
    { 3, "Equal" },
    { 4, "Greater than or equal" },
    { 5, "Greater than" },
    { 6, "Not equal" },
    { 100, "Phonetic" },
    { 101, "Stem" },
    { 102, "Relevance" },
    { 103, "Always Matches" },
    { 0, NULL}
};

static const value_string z3950_bib1_at_position[] = {
    { 1, "First in field" },
    { 2, "First in subfield" },
    { 3, "Any position in field" },
    { 0, NULL}
};

static const value_string z3950_bib1_at_structure[] = {
    { 1, "Phrase" },
    { 2, "Word" },
    { 3, "Key" },
    { 4, "Year" },
    { 5, "Date (normalized)" },
    { 6, "Word list" },
    { 100, "Date (un-normalized)" },
    { 101, "Name (normalized)" },
    { 102, "Name (un-normalized)" },
    { 103, "Structure" },
    { 104, "Urx" },
    { 105, "Free-form-text" },
    { 106, "Document-text" },
    { 107, "Local" },
    { 108, "String" },
    { 109, "Numeric" },
    { 0, NULL}
};

static const value_string z3950_bib1_at_truncation[] = {
    { 1, "Right truncation" },
    { 2, "Left truncation" },
    { 3, "Left and right truncation" },
    { 100, "Do not truncate" },
    { 101, "Process # in search term" },
    { 102, "regExpr-1" },
    { 103, "regExpr-2" },
    { 104, "Z39.58-1992 Character masking" },
    { 0, NULL}
};

static const value_string z3950_bib1_at_completeness[] = {
    { 1, "Incomplete subfield" },
    { 2, "Complete subfield" },
    { 3, "Complete field" },
    { 0, NULL}
};

static const value_string z3950_bib1_diagconditions[] = {
    { 1, "Permanent system error" },
    { 2, "Temporary system error" },
    { 3, "Unsupported search" },
    { 4, "Terms only exclusion (stop) words" },
    { 5, "Too many argument words" },
    { 6, "Too many boolean operators" },
    { 7, "Too many truncated words" },
    { 8, "Too many incomplete subfields" },
    { 9, "Truncated words too short" },
    { 10, "Invalid format for record number (search term)" },
    { 11, "Too many characters in search statement" },
    { 12, "Too many records retrieved" },
    { 13, "Present request out of range" },
    { 14, "System error in presenting records" },
    { 15, "Record no authorized to be sent intersystem" },
    { 16, "Record exceeds Preferred-message-size" },
    { 17, "Record exceeds Maximum-record-size" },
    { 18, "Result set not supported as a search term" },
    { 19, "Only single result set as search term supported" },
    { 20, "Only ANDing of a single result set as search term supported" },
    { 21, "Result set exists and replace indicator off" },
    { 22, "Result set naming not supported" },
    { 23, "Combination of specified databases not supported" },
    { 24, "Element set names not supported" },
    { 25, "Specified element set name not valid for specified database" },
    { 26, "Only a single element set name supported" },
    { 27, "Result set no longer exists - unilaterally deleted by target" },
    { 28, "Result set is in use" },
    { 29, "One of the specified databases is locked" },
    { 30, "Specified result set does not exist" },
    { 31, "Resources exhausted - no results available" },
    { 32, "Resources exhausted - unpredictable partial results available" },
    { 33, "Resources exhausted - valid subset of results available" },
    { 100, "Unspecified error" },
    { 101, "Access-control failure" },
    { 102, "Security challenge required but could not be issued - request terminated" },
    { 103, "Security challenge required but could not be issued - record not included" },
    { 104, "Security challenge failed - record not included" },
    { 105, "Terminated by negative continue response" },
    { 106, "No abstract syntaxes agreed to for this record" },
    { 107, "Query type not supported" },
    { 108, "Malformed query" },
    { 109, "Database unavailable" },
    { 110, "Operator unsupported" },
    { 111, "Too many databases specified" },
    { 112, "Too many result sets created" },
    { 113, "Unsupported attribute type" },
    { 114, "Unsupported Use attribute" },
    { 115, "Unsupported value for Use attribute" },
    { 116, "Use attribute required but not supplied" },
    { 117, "Unsupported Relation attribute" },
    { 118, "Unsupported Structure attribute" },
    { 119, "Unsupported Position attribute" },
    { 120, "Unsupported Truncation attribute" },
    { 121, "Unsupported Attribute Set" },
    { 122, "Unsupported Completeness attribute" },
    { 123, "Unsupported attribute combination" },
    { 124, "Unsupported coded value for term" },
    { 125, "Malformed search term" },
    { 126, "Illegal term value for attribute" },
    { 127, "Unparsable format for un-normalized value" },
    { 128, "Illegal result set name" },
    { 129, "Proximity search of sets not supported" },
    { 130, "Illegal result set in proximity search" },
    { 131, "Unsupported proximity relation" },
    { 132, "Unsupported proximity unit code" },
    { 201, "Proximity not supported with this attribute combination" },
    { 202, "Unsupported distance for proximity" },
    { 203, "Ordered flag not supported for proximity" },
    { 205, "Only zero step size supported for Scan" },
    { 206, "Specified step size not supported for Scan" },
    { 207, "Cannot sort according to sequence" },
    { 208, "No result set name supplied on Sort" },
    { 209, "Generic sort not supported (database-specific sort only supported)" },
    { 210, "Database specific sort not supported" },
    { 211, "Too many sort keys" },
    { 212, "Duplicate sort keys" },
    { 213, "Unsupported missing data action" },
    { 214, "Illegal sort relation" },
    { 215, "Illegal case value" },
    { 216, "Illegal missing data action" },
    { 217, "Segmentation: Cannot guarantee records will fit in specified segments" },
    { 218, "ES: Package name already in use" },
    { 219, "ES: no such package, on modify/delete" },
    { 220, "ES: quota exceeded" },
    { 221, "ES: extended service type not supported" },
    { 222, "ES: permission denied on ES - id not authorized" },
    { 223, "ES: permission denied on ES - cannot modify or delete" },
    { 224, "ES: immediate execution failed" },
    { 225, "ES: immediate execution not supported for this service" },
    { 226, "ES: immediate execution not supported for these parameters" },
    { 227, "No data available in requested record syntax" },
    { 228, "Scan: malformed scan" },
    { 229, "Term type not supported" },
    { 230, "Sort: too many input results" },
    { 231, "Sort: incompatible record formats" },
    { 232, "Scan: term list not supported" },
    { 233, "Scan: unsupported value of position-in-response" },
    { 234, "Too many index terms processed" },
    { 235, "Database does not exist" },
    { 236, "Access to specified database denied" },
    { 237, "Sort: illegal sort" },
    { 238, "Record not available in requested syntax" },
    { 239, "Record syntax not supported" },
    { 240, "Scan: Resources exhausted looking for satisfying terms" },
    { 241, "Scan: Beginning or end of term list" },
    { 242, "Segmentation: max-segment-size too small to segment record" },
    { 243, "Present:  additional-ranges parameter not supported" },
    { 244, "Present:  comp-spec parameter not supported" },
    { 245, "Type-1 query: restriction ('resultAttr') operand not supported" },
    { 246, "Type-1 query: 'complex' attributeValue not supported" },
    { 247, "Type-1 query: 'attributeSet' as part of AttributeElement not supported" },
    { 1001, "Malformed APDU"  },
    { 1002, "ES: EXTERNAL form of Item Order request not supported" },
    { 1003, "ES: Result set item form of Item Order request not supported" },
    { 1004, "ES: Extended services not supported unless access control is in effect" },
    { 1005, "Response records in Search response not supported" },
    { 1006, "Response records in Search response not possible for specified database (or database combination)" },
    { 1007, "No Explain server. Addinfo: pointers to servers that have a surrogate Explain database for this server" },
    { 1008, "ES: missing mandatory parameter for specified function. Addinfo: parameter" },
    { 1009, "ES: Item Order, unsupported OID in itemRequest. Addinfo: OID" },
    { 1010, "Init/AC: Bad Userid" },
    { 1011, "Init/AC: Bad Userid and/or Password" },
    { 1012, "Init/AC: No searches remaining (pre-purchased searches exhausted)" },
    { 1013, "Init/AC: Incorrect interface type (specified id valid only when used with a particular access method or client)" },
    { 1014, "Init/AC: Authentication System error" },
    { 1015, "Init/AC: Maximum number of simultaneous sessions for Userid" },
    { 1016, "Init/AC: Blocked network address" },
    { 1017, "Init/AC: No databases available for specified userId" },
    { 1018, "Init/AC: System temporarily out of resources" },
    { 1019, "Init/AC: System not available due to maintenance" },
    { 1020, "Init/AC: System temporarily unavailable (Addinfo: when it's expected back up)" },
    { 1021, "Init/AC: Account has expired" },
    { 1022, "Init/AC: Password has expired so a new one must be supplied" },
    { 1023, "Init/AC: Password has been changed by an administrator so a new one must be supplied" },
    { 1024, "Unsupported Attribute" },
    { 1025, "Service not supported for this database" },
    { 1026, "Record cannot be opened because it is locked" },
    { 1027, "SQL error" },
    { 1028, "Record deleted" },
    { 1029, "Scan: too many terms requested. Addinfo: max terms supported" },
    { 1040, "ES: Invalid function" },
    { 1041, "ES: Error in retention time" },
    { 1042, "ES: Permissions data not understood" },
    { 1043, "ES: Invalid OID for task specific parameters" },
    { 1044, "ES: Invalid action" },
    { 1045, "ES: Unknown schema" },
    { 1046, "ES: Too many records in package" },
    { 1047, "ES: Invalid wait action" },
    { 1048, "ES: Cannot create task package -- exceeds maximum permissable size" },
    { 1049, "ES: Cannot return task package -- exceeds maximum permissable size" },
    { 1050, "ES: Extended services request too large" },
    { 1051, "Scan: Attribute set id required -- not supplied" },
    { 1052, "ES: Cannot process task package record -- exceeds maximum permissible record size for ES" },
    { 1053, "ES: Cannot return task package record -- exceeds maximum permissible record size for ES response" },
    { 1054, "Init: Required negotiation record not included" },
    { 1055, "Init: negotiation option required" },
    { 1056, "Attribute not supported for database" },
    { 1057, "ES: Unsupported value of task package parameter" },
    { 1058, "Duplicate Detection: Cannot dedup on requested record portion"   },
    { 1059, "Duplicate Detection: Requested detection criterion not supported" },
    { 1060, "Duplicate Detection: Requested level of match not supported" },
    { 1061, "Duplicate Detection: Requested regular expression not supported" },
    { 1062, "Duplicate Detection: Cannot do clustering" },
    { 1063, "Duplicate Detection: Retention criterion not supported" },
    { 1064, "Duplicate Detection: Requested number (or percentage) of entries for retention too large" },
    { 1065, "Duplicate Detection: Requested sort criterion not supported" },
    { 1066, "CompSpec: Unknown schema, or schema not supported." },
    { 1067, "Encapsulation: Encapsulated sequence of PDUs not supported" },
    { 1068, "Encapsulation: Base operation (and encapsulated PDUs) not executed based on pre-screening analysis" },
    { 1069, "No syntaxes available for this request" },
    { 1070, "user not authorized to receive record(s) in requested syntax" },
    { 1071, "preferredRecordSyntax not supplied" },
    { 1072, "Query term includes characters that do not translate into the target character set" },
    { 1073, "Database records do not contain data associated with access point" },
    { 1074, "Proxy failure" },
    { 0, NULL}
};


/*--- Included file: packet-z3950-hf.c ---*/
#line 1 "./asn1/z3950/packet-z3950-hf.c"
static int hf_z3950_OCLC_UserInformation_PDU = -1;  /* OCLC_UserInformation */
static int hf_z3950_SutrsRecord_PDU = -1;         /* SutrsRecord */
static int hf_z3950_OPACRecord_PDU = -1;          /* OPACRecord */
static int hf_z3950_DiagnosticFormat_PDU = -1;    /* DiagnosticFormat */
static int hf_z3950_Explain_Record_PDU = -1;      /* Explain_Record */
static int hf_z3950_BriefBib_PDU = -1;            /* BriefBib */
static int hf_z3950_GenericRecord_PDU = -1;       /* GenericRecord */
static int hf_z3950_TaskPackage_PDU = -1;         /* TaskPackage */
static int hf_z3950_PromptObject_PDU = -1;        /* PromptObject */
static int hf_z3950_DES_RN_Object_PDU = -1;       /* DES_RN_Object */
static int hf_z3950_KRBObject_PDU = -1;           /* KRBObject */
static int hf_z3950_SearchInfoReport_PDU = -1;    /* SearchInfoReport */
static int hf_z3950_initRequest = -1;             /* InitializeRequest */
static int hf_z3950_initResponse = -1;            /* InitializeResponse */
static int hf_z3950_searchRequest = -1;           /* SearchRequest */
static int hf_z3950_searchResponse = -1;          /* SearchResponse */
static int hf_z3950_presentRequest = -1;          /* PresentRequest */
static int hf_z3950_presentResponse = -1;         /* PresentResponse */
static int hf_z3950_deleteResultSetRequest = -1;  /* DeleteResultSetRequest */
static int hf_z3950_deleteResultSetResponse = -1;  /* DeleteResultSetResponse */
static int hf_z3950_accessControlRequest = -1;    /* AccessControlRequest */
static int hf_z3950_accessControlResponse = -1;   /* AccessControlResponse */
static int hf_z3950_resourceControlRequest = -1;  /* ResourceControlRequest */
static int hf_z3950_resourceControlResponse = -1;  /* ResourceControlResponse */
static int hf_z3950_triggerResourceControlRequest = -1;  /* TriggerResourceControlRequest */
static int hf_z3950_resourceReportRequest = -1;   /* ResourceReportRequest */
static int hf_z3950_resourceReportResponse = -1;  /* ResourceReportResponse */
static int hf_z3950_scanRequest = -1;             /* ScanRequest */
static int hf_z3950_scanResponse = -1;            /* ScanResponse */
static int hf_z3950_sortRequest = -1;             /* SortRequest */
static int hf_z3950_sortResponse = -1;            /* SortResponse */
static int hf_z3950_segmentRequest = -1;          /* Segment */
static int hf_z3950_extendedServicesRequest = -1;  /* ExtendedServicesRequest */
static int hf_z3950_extendedServicesResponse = -1;  /* ExtendedServicesResponse */
static int hf_z3950_close = -1;                   /* Close */
static int hf_z3950_referenceId = -1;             /* ReferenceId */
static int hf_z3950_protocolVersion = -1;         /* ProtocolVersion */
static int hf_z3950_options = -1;                 /* Options */
static int hf_z3950_preferredMessageSize = -1;    /* INTEGER */
static int hf_z3950_exceptionalRecordSize = -1;   /* INTEGER */
static int hf_z3950_idAuthentication = -1;        /* T_idAuthentication */
static int hf_z3950_open = -1;                    /* VisibleString */
static int hf_z3950_idPass = -1;                  /* T_idPass */
static int hf_z3950_groupId = -1;                 /* InternationalString */
static int hf_z3950_userId = -1;                  /* InternationalString */
static int hf_z3950_password = -1;                /* InternationalString */
static int hf_z3950_anonymous = -1;               /* NULL */
static int hf_z3950_other = -1;                   /* EXTERNAL */
static int hf_z3950_implementationId = -1;        /* InternationalString */
static int hf_z3950_implementationName = -1;      /* InternationalString */
static int hf_z3950_implementationVersion = -1;   /* InternationalString */
static int hf_z3950_userInformationField = -1;    /* EXTERNAL */
static int hf_z3950_otherInfo = -1;               /* OtherInformation */
static int hf_z3950_result = -1;                  /* BOOLEAN */
static int hf_z3950_smallSetUpperBound = -1;      /* INTEGER */
static int hf_z3950_largeSetLowerBound = -1;      /* INTEGER */
static int hf_z3950_mediumSetPresentNumber = -1;  /* INTEGER */
static int hf_z3950_replaceIndicator = -1;        /* BOOLEAN */
static int hf_z3950_resultSetName = -1;           /* InternationalString */
static int hf_z3950_databaseNames = -1;           /* SEQUENCE_OF_DatabaseName */
static int hf_z3950_databaseNames_item = -1;      /* DatabaseName */
static int hf_z3950_smallSetElementSetNames = -1;  /* ElementSetNames */
static int hf_z3950_mediumSetElementSetNames = -1;  /* ElementSetNames */
static int hf_z3950_preferredRecordSyntax = -1;   /* OBJECT_IDENTIFIER */
static int hf_z3950_query = -1;                   /* Query */
static int hf_z3950_additionalSearchInfo = -1;    /* OtherInformation */
static int hf_z3950_type_0 = -1;                  /* T_type_0 */
static int hf_z3950_type_1 = -1;                  /* RPNQuery */
static int hf_z3950_type_2 = -1;                  /* OCTET_STRING */
static int hf_z3950_type_100 = -1;                /* OCTET_STRING */
static int hf_z3950_type_101 = -1;                /* RPNQuery */
static int hf_z3950_type_102 = -1;                /* OCTET_STRING */
static int hf_z3950_attributeSet = -1;            /* AttributeSetId */
static int hf_z3950_rpn = -1;                     /* RPNStructure */
static int hf_z3950_operandRpnOp = -1;            /* Operand */
static int hf_z3950_rpnRpnOp = -1;                /* T_rpnRpnOp */
static int hf_z3950_rpn1 = -1;                    /* RPNStructure */
static int hf_z3950_rpn2 = -1;                    /* RPNStructure */
static int hf_z3950_operatorRpnOp = -1;           /* Operator */
static int hf_z3950_attrTerm = -1;                /* AttributesPlusTerm */
static int hf_z3950_resultSet = -1;               /* ResultSetId */
static int hf_z3950_resultAttr = -1;              /* ResultSetPlusAttributes */
static int hf_z3950_attributes = -1;              /* AttributeList */
static int hf_z3950_term = -1;                    /* Term */
static int hf_z3950_attributeList_item = -1;      /* AttributeElement */
static int hf_z3950_general = -1;                 /* T_general */
static int hf_z3950_numeric = -1;                 /* INTEGER */
static int hf_z3950_characterString = -1;         /* InternationalString */
static int hf_z3950_oid = -1;                     /* OBJECT_IDENTIFIER */
static int hf_z3950_dateTime = -1;                /* GeneralizedTime */
static int hf_z3950_external = -1;                /* EXTERNAL */
static int hf_z3950_integerAndUnit = -1;          /* IntUnit */
static int hf_z3950_null = -1;                    /* NULL */
static int hf_z3950_and = -1;                     /* NULL */
static int hf_z3950_or = -1;                      /* NULL */
static int hf_z3950_and_not = -1;                 /* NULL */
static int hf_z3950_prox = -1;                    /* ProximityOperator */
static int hf_z3950_attributeElement_attributeType = -1;  /* T_attributeElement_attributeType */
static int hf_z3950_attributeValue = -1;          /* T_attributeValue */
static int hf_z3950_attributeValue_numeric = -1;  /* T_attributeValue_numeric */
static int hf_z3950_attributeValue_complex = -1;  /* T_attributeValue_complex */
static int hf_z3950_attributeValue_complex_list = -1;  /* SEQUENCE_OF_StringOrNumeric */
static int hf_z3950_attributeValue_complex_list_item = -1;  /* StringOrNumeric */
static int hf_z3950_semanticAction = -1;          /* T_semanticAction */
static int hf_z3950_semanticAction_item = -1;     /* INTEGER */
static int hf_z3950_exclusion = -1;               /* BOOLEAN */
static int hf_z3950_distance = -1;                /* INTEGER */
static int hf_z3950_ordered = -1;                 /* BOOLEAN */
static int hf_z3950_relationType = -1;            /* T_relationType */
static int hf_z3950_proximityUnitCode = -1;       /* T_proximityUnitCode */
static int hf_z3950_known = -1;                   /* KnownProximityUnit */
static int hf_z3950_private = -1;                 /* INTEGER */
static int hf_z3950_resultCount = -1;             /* INTEGER */
static int hf_z3950_numberOfRecordsReturned = -1;  /* INTEGER */
static int hf_z3950_nextResultSetPosition = -1;   /* INTEGER */
static int hf_z3950_searchStatus = -1;            /* BOOLEAN */
static int hf_z3950_search_resultSetStatus = -1;  /* T_search_resultSetStatus */
static int hf_z3950_presentStatus = -1;           /* PresentStatus */
static int hf_z3950_records = -1;                 /* Records */
static int hf_z3950_resultSetId = -1;             /* ResultSetId */
static int hf_z3950_resultSetStartPoint = -1;     /* INTEGER */
static int hf_z3950_numberOfRecordsRequested = -1;  /* INTEGER */
static int hf_z3950_additionalRanges = -1;        /* SEQUENCE_OF_Range */
static int hf_z3950_additionalRanges_item = -1;   /* Range */
static int hf_z3950_recordComposition = -1;       /* T_recordComposition */
static int hf_z3950_simple = -1;                  /* ElementSetNames */
static int hf_z3950_recordComposition_complex = -1;  /* CompSpec */
static int hf_z3950_maxSegmentCount = -1;         /* INTEGER */
static int hf_z3950_maxRecordSize = -1;           /* INTEGER */
static int hf_z3950_maxSegmentSize = -1;          /* INTEGER */
static int hf_z3950_segmentRecords = -1;          /* SEQUENCE_OF_NamePlusRecord */
static int hf_z3950_segmentRecords_item = -1;     /* NamePlusRecord */
static int hf_z3950_responseRecords = -1;         /* SEQUENCE_OF_NamePlusRecord */
static int hf_z3950_responseRecords_item = -1;    /* NamePlusRecord */
static int hf_z3950_nonSurrogateDiagnostic = -1;  /* DefaultDiagFormat */
static int hf_z3950_multipleNonSurDiagnostics = -1;  /* SEQUENCE_OF_DiagRec */
static int hf_z3950_multipleNonSurDiagnostics_item = -1;  /* DiagRec */
static int hf_z3950_namePlusRecord_name = -1;     /* DatabaseName */
static int hf_z3950_record = -1;                  /* T_record */
static int hf_z3950_retrievalRecord = -1;         /* EXTERNAL */
static int hf_z3950_surrogateDiagnostic = -1;     /* DiagRec */
static int hf_z3950_startingFragment = -1;        /* FragmentSyntax */
static int hf_z3950_intermediateFragment = -1;    /* FragmentSyntax */
static int hf_z3950_finalFragment = -1;           /* FragmentSyntax */
static int hf_z3950_externallyTagged = -1;        /* EXTERNAL */
static int hf_z3950_notExternallyTagged = -1;     /* OCTET_STRING */
static int hf_z3950_defaultFormat = -1;           /* DefaultDiagFormat */
static int hf_z3950_externallyDefined = -1;       /* EXTERNAL */
static int hf_z3950_diagnosticSetId = -1;         /* T_diagnosticSetId */
static int hf_z3950_condition = -1;               /* T_condition */
static int hf_z3950_addinfo = -1;                 /* T_addinfo */
static int hf_z3950_v2Addinfo = -1;               /* VisibleString */
static int hf_z3950_v3Addinfo = -1;               /* InternationalString */
static int hf_z3950_startingPosition = -1;        /* INTEGER */
static int hf_z3950_numberOfRecords = -1;         /* INTEGER */
static int hf_z3950_genericElementSetName = -1;   /* InternationalString */
static int hf_z3950_databaseSpecific = -1;        /* T_databaseSpecific */
static int hf_z3950_databaseSpecific_item = -1;   /* T_databaseSpecific_item */
static int hf_z3950_dbName = -1;                  /* DatabaseName */
static int hf_z3950_esn = -1;                     /* ElementSetName */
static int hf_z3950_selectAlternativeSyntax = -1;  /* BOOLEAN */
static int hf_z3950_compSpec_generic = -1;        /* Specification */
static int hf_z3950_dbSpecific = -1;              /* T_dbSpecific */
static int hf_z3950_dbSpecific_item = -1;         /* T_dbSpecific_item */
static int hf_z3950_db = -1;                      /* DatabaseName */
static int hf_z3950_spec = -1;                    /* Specification */
static int hf_z3950_compSpec_recordSyntax = -1;   /* T_compSpec_recordSyntax */
static int hf_z3950_compSpec_recordSyntax_item = -1;  /* OBJECT_IDENTIFIER */
static int hf_z3950_schema = -1;                  /* OBJECT_IDENTIFIER */
static int hf_z3950_specification_elementSpec = -1;  /* T_specification_elementSpec */
static int hf_z3950_elementSetName = -1;          /* InternationalString */
static int hf_z3950_externalEspec = -1;           /* EXTERNAL */
static int hf_z3950_deleteFunction = -1;          /* T_deleteFunction */
static int hf_z3950_resultSetList = -1;           /* SEQUENCE_OF_ResultSetId */
static int hf_z3950_resultSetList_item = -1;      /* ResultSetId */
static int hf_z3950_deleteOperationStatus = -1;   /* DeleteSetStatus */
static int hf_z3950_deleteListStatuses = -1;      /* ListStatuses */
static int hf_z3950_numberNotDeleted = -1;        /* INTEGER */
static int hf_z3950_bulkStatuses = -1;            /* ListStatuses */
static int hf_z3950_deleteMessage = -1;           /* InternationalString */
static int hf_z3950_ListStatuses_item = -1;       /* ListStatuses_item */
static int hf_z3950_listStatuses_id = -1;         /* ResultSetId */
static int hf_z3950_status = -1;                  /* DeleteSetStatus */
static int hf_z3950_securityChallenge = -1;       /* T_securityChallenge */
static int hf_z3950_simpleForm = -1;              /* OCTET_STRING */
static int hf_z3950_securityChallengeResponse = -1;  /* T_securityChallengeResponse */
static int hf_z3950_diagnostic = -1;              /* DiagRec */
static int hf_z3950_suspendedFlag = -1;           /* BOOLEAN */
static int hf_z3950_resourceReport = -1;          /* ResourceReport */
static int hf_z3950_partialResultsAvailable = -1;  /* T_partialResultsAvailable */
static int hf_z3950_resourceControlRequest_responseRequired = -1;  /* BOOLEAN */
static int hf_z3950_triggeredRequestFlag = -1;    /* BOOLEAN */
static int hf_z3950_continueFlag = -1;            /* BOOLEAN */
static int hf_z3950_resultSetWanted = -1;         /* BOOLEAN */
static int hf_z3950_requestedAction = -1;         /* T_requestedAction */
static int hf_z3950_prefResourceReportFormat = -1;  /* ResourceReportId */
static int hf_z3950_opId = -1;                    /* ReferenceId */
static int hf_z3950_resourceReportStatus = -1;    /* T_resourceReportStatus */
static int hf_z3950_termListAndStartPoint = -1;   /* AttributesPlusTerm */
static int hf_z3950_stepSize = -1;                /* INTEGER */
static int hf_z3950_numberOfTermsRequested = -1;  /* INTEGER */
static int hf_z3950_preferredPositionInResponse = -1;  /* INTEGER */
static int hf_z3950_scanStatus = -1;              /* T_scanStatus */
static int hf_z3950_numberOfEntriesReturned = -1;  /* INTEGER */
static int hf_z3950_positionOfTerm = -1;          /* INTEGER */
static int hf_z3950_scanResponse_entries = -1;    /* ListEntries */
static int hf_z3950_listEntries_entries = -1;     /* SEQUENCE_OF_Entry */
static int hf_z3950_listEntries_entries_item = -1;  /* Entry */
static int hf_z3950_nonsurrogateDiagnostics = -1;  /* SEQUENCE_OF_DiagRec */
static int hf_z3950_nonsurrogateDiagnostics_item = -1;  /* DiagRec */
static int hf_z3950_termInfo = -1;                /* TermInfo */
static int hf_z3950_displayTerm = -1;             /* InternationalString */
static int hf_z3950_suggestedAttributes = -1;     /* AttributeList */
static int hf_z3950_alternativeTerm = -1;         /* SEQUENCE_OF_AttributesPlusTerm */
static int hf_z3950_alternativeTerm_item = -1;    /* AttributesPlusTerm */
static int hf_z3950_globalOccurrences = -1;       /* INTEGER */
static int hf_z3950_byAttributes = -1;            /* OccurrenceByAttributes */
static int hf_z3950_otherTermInfo = -1;           /* OtherInformation */
static int hf_z3950_OccurrenceByAttributes_item = -1;  /* OccurrenceByAttributes_item */
static int hf_z3950_occurrences = -1;             /* T_occurrences */
static int hf_z3950_global = -1;                  /* INTEGER */
static int hf_z3950_byDatabase = -1;              /* T_byDatabase */
static int hf_z3950_byDatabase_item = -1;         /* T_byDatabase_item */
static int hf_z3950_num = -1;                     /* INTEGER */
static int hf_z3950_otherDbInfo = -1;             /* OtherInformation */
static int hf_z3950_otherOccurInfo = -1;          /* OtherInformation */
static int hf_z3950_inputResultSetNames = -1;     /* SEQUENCE_OF_InternationalString */
static int hf_z3950_inputResultSetNames_item = -1;  /* InternationalString */
static int hf_z3950_sortedResultSetName = -1;     /* InternationalString */
static int hf_z3950_sortSequence = -1;            /* SEQUENCE_OF_SortKeySpec */
static int hf_z3950_sortSequence_item = -1;       /* SortKeySpec */
static int hf_z3950_sortStatus = -1;              /* T_sortStatus */
static int hf_z3950_sort_resultSetStatus = -1;    /* T_sort_resultSetStatus */
static int hf_z3950_diagnostics = -1;             /* SEQUENCE_OF_DiagRec */
static int hf_z3950_diagnostics_item = -1;        /* DiagRec */
static int hf_z3950_sortElement = -1;             /* SortElement */
static int hf_z3950_sortRelation = -1;            /* T_sortRelation */
static int hf_z3950_caseSensitivity = -1;         /* T_caseSensitivity */
static int hf_z3950_missingValueAction = -1;      /* T_missingValueAction */
static int hf_z3950_abort = -1;                   /* NULL */
static int hf_z3950_missingValueData = -1;        /* OCTET_STRING */
static int hf_z3950_sortElement_generic = -1;     /* SortKey */
static int hf_z3950_datbaseSpecific = -1;         /* T_datbaseSpecific */
static int hf_z3950_datbaseSpecific_item = -1;    /* T_datbaseSpecific_item */
static int hf_z3950_databaseName = -1;            /* DatabaseName */
static int hf_z3950_dbSort = -1;                  /* SortKey */
static int hf_z3950_sortfield = -1;               /* InternationalString */
static int hf_z3950_sortKey_elementSpec = -1;     /* Specification */
static int hf_z3950_sortAttributes = -1;          /* T_sortAttributes */
static int hf_z3950_sortAttributes_id = -1;       /* AttributeSetId */
static int hf_z3950_sortAttributes_list = -1;     /* AttributeList */
static int hf_z3950_function = -1;                /* T_function */
static int hf_z3950_packageType = -1;             /* OBJECT_IDENTIFIER */
static int hf_z3950_packageName = -1;             /* InternationalString */
static int hf_z3950_retentionTime = -1;           /* IntUnit */
static int hf_z3950_permissions = -1;             /* Permissions */
static int hf_z3950_extendedServicesRequest_description = -1;  /* InternationalString */
static int hf_z3950_taskSpecificParameters = -1;  /* EXTERNAL */
static int hf_z3950_waitAction = -1;              /* T_waitAction */
static int hf_z3950_elements = -1;                /* ElementSetName */
static int hf_z3950_operationStatus = -1;         /* T_operationStatus */
static int hf_z3950_taskPackage = -1;             /* EXTERNAL */
static int hf_z3950_Permissions_item = -1;        /* Permissions_item */
static int hf_z3950_allowableFunctions = -1;      /* T_allowableFunctions */
static int hf_z3950_allowableFunctions_item = -1;  /* T_allowableFunctions_item */
static int hf_z3950_closeReason = -1;             /* CloseReason */
static int hf_z3950_diagnosticInformation = -1;   /* InternationalString */
static int hf_z3950_resourceReportFormat = -1;    /* ResourceReportId */
static int hf_z3950_otherInformation_item = -1;   /* T__untag_item */
static int hf_z3950_category = -1;                /* InfoCategory */
static int hf_z3950_information = -1;             /* T_information */
static int hf_z3950_characterInfo = -1;           /* InternationalString */
static int hf_z3950_binaryInfo = -1;              /* OCTET_STRING */
static int hf_z3950_externallyDefinedInfo = -1;   /* EXTERNAL */
static int hf_z3950_categoryTypeId = -1;          /* OBJECT_IDENTIFIER */
static int hf_z3950_categoryValue = -1;           /* INTEGER */
static int hf_z3950_value = -1;                   /* INTEGER */
static int hf_z3950_unitUsed = -1;                /* Unit */
static int hf_z3950_unitSystem = -1;              /* InternationalString */
static int hf_z3950_unitType = -1;                /* StringOrNumeric */
static int hf_z3950_unit = -1;                    /* StringOrNumeric */
static int hf_z3950_scaleFactor = -1;             /* INTEGER */
static int hf_z3950_string = -1;                  /* InternationalString */
static int hf_z3950_motd = -1;                    /* VisibleString */
static int hf_z3950_dblist = -1;                  /* SEQUENCE_OF_DBName */
static int hf_z3950_dblist_item = -1;             /* DBName */
static int hf_z3950_failReason = -1;              /* BOOLEAN */
static int hf_z3950_oCLC_UserInformation_text = -1;  /* VisibleString */
static int hf_z3950_bibliographicRecord = -1;     /* EXTERNAL */
static int hf_z3950_holdingsData = -1;            /* SEQUENCE_OF_HoldingsRecord */
static int hf_z3950_holdingsData_item = -1;       /* HoldingsRecord */
static int hf_z3950_marcHoldingsRecord = -1;      /* EXTERNAL */
static int hf_z3950_holdingsAndCirc = -1;         /* HoldingsAndCircData */
static int hf_z3950_typeOfRecord = -1;            /* InternationalString */
static int hf_z3950_encodingLevel = -1;           /* InternationalString */
static int hf_z3950_format = -1;                  /* InternationalString */
static int hf_z3950_receiptAcqStatus = -1;        /* InternationalString */
static int hf_z3950_generalRetention = -1;        /* InternationalString */
static int hf_z3950_completeness = -1;            /* InternationalString */
static int hf_z3950_dateOfReport = -1;            /* InternationalString */
static int hf_z3950_nucCode = -1;                 /* InternationalString */
static int hf_z3950_localLocation = -1;           /* InternationalString */
static int hf_z3950_shelvingLocation = -1;        /* InternationalString */
static int hf_z3950_callNumber = -1;              /* InternationalString */
static int hf_z3950_shelvingData = -1;            /* InternationalString */
static int hf_z3950_copyNumber = -1;              /* InternationalString */
static int hf_z3950_publicNote = -1;              /* InternationalString */
static int hf_z3950_reproductionNote = -1;        /* InternationalString */
static int hf_z3950_termsUseRepro = -1;           /* InternationalString */
static int hf_z3950_enumAndChron = -1;            /* InternationalString */
static int hf_z3950_volumes = -1;                 /* SEQUENCE_OF_Volume */
static int hf_z3950_volumes_item = -1;            /* Volume */
static int hf_z3950_circulationData = -1;         /* SEQUENCE_OF_CircRecord */
static int hf_z3950_circulationData_item = -1;    /* CircRecord */
static int hf_z3950_enumeration = -1;             /* InternationalString */
static int hf_z3950_chronology = -1;              /* InternationalString */
static int hf_z3950_availableNow = -1;            /* BOOLEAN */
static int hf_z3950_availablityDate = -1;         /* InternationalString */
static int hf_z3950_availableThru = -1;           /* InternationalString */
static int hf_z3950_circRecord_restrictions = -1;  /* InternationalString */
static int hf_z3950_itemId = -1;                  /* InternationalString */
static int hf_z3950_renewable = -1;               /* BOOLEAN */
static int hf_z3950_onHold = -1;                  /* BOOLEAN */
static int hf_z3950_midspine = -1;                /* InternationalString */
static int hf_z3950_temporaryLocation = -1;       /* InternationalString */
static int hf_z3950_DiagnosticFormat_item = -1;   /* DiagnosticFormat_item */
static int hf_z3950_diagnosticFormat_item_diagnostic = -1;  /* T_diagnosticFormat_item_diagnostic */
static int hf_z3950_defaultDiagRec = -1;          /* DefaultDiagFormat */
static int hf_z3950_explicitDiagnostic = -1;      /* DiagFormat */
static int hf_z3950_message = -1;                 /* InternationalString */
static int hf_z3950_tooMany = -1;                 /* T_tooMany */
static int hf_z3950_tooManyWhat = -1;             /* T_tooManyWhat */
static int hf_z3950_max = -1;                     /* INTEGER */
static int hf_z3950_badSpec = -1;                 /* T_badSpec */
static int hf_z3950_goodOnes = -1;                /* SEQUENCE_OF_Specification */
static int hf_z3950_goodOnes_item = -1;           /* Specification */
static int hf_z3950_dbUnavail = -1;               /* T_dbUnavail */
static int hf_z3950_why = -1;                     /* T_why */
static int hf_z3950_reasonCode = -1;              /* T_reasonCode */
static int hf_z3950_unSupOp = -1;                 /* T_unSupOp */
static int hf_z3950_attribute = -1;               /* T_attribute */
static int hf_z3950_id = -1;                      /* OBJECT_IDENTIFIER */
static int hf_z3950_type = -1;                    /* INTEGER */
static int hf_z3950_attCombo = -1;                /* T_attCombo */
static int hf_z3950_unsupportedCombination = -1;  /* AttributeList */
static int hf_z3950_recommendedAlternatives = -1;  /* SEQUENCE_OF_AttributeList */
static int hf_z3950_recommendedAlternatives_item = -1;  /* AttributeList */
static int hf_z3950_diagFormat_term = -1;         /* T_diagFormat_term */
static int hf_z3950_problem = -1;                 /* T_problem */
static int hf_z3950_diagFormat_proximity = -1;    /* T_diagFormat_proximity */
static int hf_z3950_resultSets = -1;              /* NULL */
static int hf_z3950_badSet = -1;                  /* InternationalString */
static int hf_z3950_relation = -1;                /* INTEGER */
static int hf_z3950_diagFormat_proximity_unit = -1;  /* INTEGER */
static int hf_z3950_diagFormat_proximity_ordered = -1;  /* NULL */
static int hf_z3950_diagFormat_proximity_exclusion = -1;  /* NULL */
static int hf_z3950_scan = -1;                    /* T_scan */
static int hf_z3950_nonZeroStepSize = -1;         /* NULL */
static int hf_z3950_specifiedStepSize = -1;       /* NULL */
static int hf_z3950_termList1 = -1;               /* NULL */
static int hf_z3950_termList2 = -1;               /* SEQUENCE_OF_AttributeList */
static int hf_z3950_termList2_item = -1;          /* AttributeList */
static int hf_z3950_posInResponse = -1;           /* T_posInResponse */
static int hf_z3950_resources = -1;               /* NULL */
static int hf_z3950_endOfList = -1;               /* NULL */
static int hf_z3950_sort = -1;                    /* T_sort */
static int hf_z3950_sequence = -1;                /* NULL */
static int hf_z3950_noRsName = -1;                /* NULL */
static int hf_z3950_diagFormat_sort_tooMany = -1;  /* INTEGER */
static int hf_z3950_incompatible = -1;            /* NULL */
static int hf_z3950_generic = -1;                 /* NULL */
static int hf_z3950_diagFormat_sort_dbSpecific = -1;  /* NULL */
static int hf_z3950_key = -1;                     /* T_key */
static int hf_z3950_action = -1;                  /* NULL */
static int hf_z3950_illegal = -1;                 /* T_illegal */
static int hf_z3950_inputTooLarge = -1;           /* SEQUENCE_OF_InternationalString */
static int hf_z3950_inputTooLarge_item = -1;      /* InternationalString */
static int hf_z3950_aggregateTooLarge = -1;       /* NULL */
static int hf_z3950_segmentation = -1;            /* T_segmentation */
static int hf_z3950_segmentCount = -1;            /* NULL */
static int hf_z3950_segmentSize = -1;             /* INTEGER */
static int hf_z3950_extServices = -1;             /* T_extServices */
static int hf_z3950_req = -1;                     /* T_req */
static int hf_z3950_permission = -1;              /* T_permission */
static int hf_z3950_immediate = -1;               /* T_immediate */
static int hf_z3950_accessCtrl = -1;              /* T_accessCtrl */
static int hf_z3950_noUser = -1;                  /* NULL */
static int hf_z3950_refused = -1;                 /* NULL */
static int hf_z3950_diagFormat_accessCtrl_simple = -1;  /* NULL */
static int hf_z3950_diagFormat_accessCtrl_oid = -1;  /* T_diagFormat_accessCtrl_oid */
static int hf_z3950_diagFormat_accessCtrl_oid_item = -1;  /* OBJECT_IDENTIFIER */
static int hf_z3950_alternative = -1;             /* T_alternative */
static int hf_z3950_alternative_item = -1;        /* OBJECT_IDENTIFIER */
static int hf_z3950_pwdInv = -1;                  /* NULL */
static int hf_z3950_pwdExp = -1;                  /* NULL */
static int hf_z3950_diagFormat_recordSyntax = -1;  /* T_diagFormat_recordSyntax */
static int hf_z3950_unsupportedSyntax = -1;       /* OBJECT_IDENTIFIER */
static int hf_z3950_suggestedAlternatives = -1;   /* T_suggestedAlternatives */
static int hf_z3950_suggestedAlternatives_item = -1;  /* OBJECT_IDENTIFIER */
static int hf_z3950_targetInfo = -1;              /* TargetInfo */
static int hf_z3950_databaseInfo = -1;            /* DatabaseInfo */
static int hf_z3950_schemaInfo = -1;              /* SchemaInfo */
static int hf_z3950_tagSetInfo = -1;              /* TagSetInfo */
static int hf_z3950_recordSyntaxInfo = -1;        /* RecordSyntaxInfo */
static int hf_z3950_attributeSetInfo = -1;        /* AttributeSetInfo */
static int hf_z3950_termListInfo = -1;            /* TermListInfo */
static int hf_z3950_extendedServicesInfo = -1;    /* ExtendedServicesInfo */
static int hf_z3950_attributeDetails = -1;        /* AttributeDetails */
static int hf_z3950_termListDetails = -1;         /* TermListDetails */
static int hf_z3950_elementSetDetails = -1;       /* ElementSetDetails */
static int hf_z3950_retrievalRecordDetails = -1;  /* RetrievalRecordDetails */
static int hf_z3950_sortDetails = -1;             /* SortDetails */
static int hf_z3950_processing = -1;              /* ProcessingInformation */
static int hf_z3950_variants = -1;                /* VariantSetInfo */
static int hf_z3950_units = -1;                   /* UnitInfo */
static int hf_z3950_categoryList = -1;            /* CategoryList */
static int hf_z3950_commonInfo = -1;              /* CommonInfo */
static int hf_z3950_name = -1;                    /* InternationalString */
static int hf_z3950_recent_news = -1;             /* HumanString */
static int hf_z3950_icon = -1;                    /* IconObject */
static int hf_z3950_namedResultSets = -1;         /* BOOLEAN */
static int hf_z3950_multipleDBsearch = -1;        /* BOOLEAN */
static int hf_z3950_maxResultSets = -1;           /* INTEGER */
static int hf_z3950_maxResultSize = -1;           /* INTEGER */
static int hf_z3950_maxTerms = -1;                /* INTEGER */
static int hf_z3950_timeoutInterval = -1;         /* IntUnit */
static int hf_z3950_welcomeMessage = -1;          /* HumanString */
static int hf_z3950_contactInfo = -1;             /* ContactInfo */
static int hf_z3950_description = -1;             /* HumanString */
static int hf_z3950_nicknames = -1;               /* SEQUENCE_OF_InternationalString */
static int hf_z3950_nicknames_item = -1;          /* InternationalString */
static int hf_z3950_usage_restrictions = -1;      /* HumanString */
static int hf_z3950_paymentAddr = -1;             /* HumanString */
static int hf_z3950_hours = -1;                   /* HumanString */
static int hf_z3950_dbCombinations = -1;          /* SEQUENCE_OF_DatabaseList */
static int hf_z3950_dbCombinations_item = -1;     /* DatabaseList */
static int hf_z3950_addresses = -1;               /* SEQUENCE_OF_NetworkAddress */
static int hf_z3950_addresses_item = -1;          /* NetworkAddress */
static int hf_z3950_languages = -1;               /* SEQUENCE_OF_InternationalString */
static int hf_z3950_languages_item = -1;          /* InternationalString */
static int hf_z3950_commonAccessInfo = -1;        /* AccessInfo */
static int hf_z3950_databaseInfo_name = -1;       /* DatabaseName */
static int hf_z3950_explainDatabase = -1;         /* NULL */
static int hf_z3950_databaseInfo_nicknames = -1;  /* SEQUENCE_OF_DatabaseName */
static int hf_z3950_databaseInfo_nicknames_item = -1;  /* DatabaseName */
static int hf_z3950_user_fee = -1;                /* BOOLEAN */
static int hf_z3950_available = -1;               /* BOOLEAN */
static int hf_z3950_titleString = -1;             /* HumanString */
static int hf_z3950_keywords = -1;                /* SEQUENCE_OF_HumanString */
static int hf_z3950_keywords_item = -1;           /* HumanString */
static int hf_z3950_associatedDbs = -1;           /* DatabaseList */
static int hf_z3950_subDbs = -1;                  /* DatabaseList */
static int hf_z3950_disclaimers = -1;             /* HumanString */
static int hf_z3950_news = -1;                    /* HumanString */
static int hf_z3950_recordCount = -1;             /* T_recordCount */
static int hf_z3950_actualNumber = -1;            /* INTEGER */
static int hf_z3950_approxNumber = -1;            /* INTEGER */
static int hf_z3950_defaultOrder = -1;            /* HumanString */
static int hf_z3950_avRecordSize = -1;            /* INTEGER */
static int hf_z3950_bestTime = -1;                /* HumanString */
static int hf_z3950_lastUpdate = -1;              /* GeneralizedTime */
static int hf_z3950_updateInterval = -1;          /* IntUnit */
static int hf_z3950_coverage = -1;                /* HumanString */
static int hf_z3950_proprietary = -1;             /* BOOLEAN */
static int hf_z3950_copyrightText = -1;           /* HumanString */
static int hf_z3950_copyrightNotice = -1;         /* HumanString */
static int hf_z3950_producerContactInfo = -1;     /* ContactInfo */
static int hf_z3950_supplierContactInfo = -1;     /* ContactInfo */
static int hf_z3950_submissionContactInfo = -1;   /* ContactInfo */
static int hf_z3950_accessInfo = -1;              /* AccessInfo */
static int hf_z3950_tagTypeMapping = -1;          /* T_tagTypeMapping */
static int hf_z3950_tagTypeMapping_item = -1;     /* T_tagTypeMapping_item */
static int hf_z3950_tagType = -1;                 /* INTEGER */
static int hf_z3950_tagSet = -1;                  /* OBJECT_IDENTIFIER */
static int hf_z3950_defaultTagType = -1;          /* NULL */
static int hf_z3950_recordStructure = -1;         /* SEQUENCE_OF_ElementInfo */
static int hf_z3950_recordStructure_item = -1;    /* ElementInfo */
static int hf_z3950_elementName = -1;             /* InternationalString */
static int hf_z3950_elementTagPath = -1;          /* Path */
static int hf_z3950_elementInfo_dataType = -1;    /* ElementDataType */
static int hf_z3950_required = -1;                /* BOOLEAN */
static int hf_z3950_repeatable = -1;              /* BOOLEAN */
static int hf_z3950_Path_item = -1;               /* Path_item */
static int hf_z3950_tagValue = -1;                /* StringOrNumeric */
static int hf_z3950_primitive = -1;               /* PrimitiveDataType */
static int hf_z3950_structured = -1;              /* SEQUENCE_OF_ElementInfo */
static int hf_z3950_structured_item = -1;         /* ElementInfo */
static int hf_z3950_tagSetInfo_elements = -1;     /* T_tagSetInfo_elements */
static int hf_z3950_tagSetInfo_elements_item = -1;  /* T_tagSetInfo_elements_item */
static int hf_z3950_elementname = -1;             /* InternationalString */
static int hf_z3950_elementTag = -1;              /* StringOrNumeric */
static int hf_z3950_dataType = -1;                /* PrimitiveDataType */
static int hf_z3950_otherTagInfo = -1;            /* OtherInformation */
static int hf_z3950_recordSyntax = -1;            /* OBJECT_IDENTIFIER */
static int hf_z3950_transferSyntaxes = -1;        /* T_transferSyntaxes */
static int hf_z3950_transferSyntaxes_item = -1;   /* OBJECT_IDENTIFIER */
static int hf_z3950_asn1Module = -1;              /* InternationalString */
static int hf_z3950_abstractStructure = -1;       /* SEQUENCE_OF_ElementInfo */
static int hf_z3950_abstractStructure_item = -1;  /* ElementInfo */
static int hf_z3950_attributeSetInfo_attributes = -1;  /* SEQUENCE_OF_AttributeType */
static int hf_z3950_attributeSetInfo_attributes_item = -1;  /* AttributeType */
static int hf_z3950_attributeType = -1;           /* INTEGER */
static int hf_z3950_attributeValues = -1;         /* SEQUENCE_OF_AttributeDescription */
static int hf_z3950_attributeValues_item = -1;    /* AttributeDescription */
static int hf_z3950_attributeDescription_attributeValue = -1;  /* StringOrNumeric */
static int hf_z3950_equivalentAttributes = -1;    /* SEQUENCE_OF_StringOrNumeric */
static int hf_z3950_equivalentAttributes_item = -1;  /* StringOrNumeric */
static int hf_z3950_termLists = -1;               /* T_termLists */
static int hf_z3950_termLists_item = -1;          /* T_termLists_item */
static int hf_z3950_title = -1;                   /* HumanString */
static int hf_z3950_searchCost = -1;              /* T_searchCost */
static int hf_z3950_scanable = -1;                /* BOOLEAN */
static int hf_z3950_broader = -1;                 /* SEQUENCE_OF_InternationalString */
static int hf_z3950_broader_item = -1;            /* InternationalString */
static int hf_z3950_narrower = -1;                /* SEQUENCE_OF_InternationalString */
static int hf_z3950_narrower_item = -1;           /* InternationalString */
static int hf_z3950_extendedServicesInfo_type = -1;  /* OBJECT_IDENTIFIER */
static int hf_z3950_privateType = -1;             /* BOOLEAN */
static int hf_z3950_restrictionsApply = -1;       /* BOOLEAN */
static int hf_z3950_feeApply = -1;                /* BOOLEAN */
static int hf_z3950_retentionSupported = -1;      /* BOOLEAN */
static int hf_z3950_extendedServicesInfo_waitAction = -1;  /* T_extendedServicesInfo_waitAction */
static int hf_z3950_specificExplain = -1;         /* EXTERNAL */
static int hf_z3950_esASN = -1;                   /* InternationalString */
static int hf_z3950_attributesBySet = -1;         /* SEQUENCE_OF_AttributeSetDetails */
static int hf_z3950_attributesBySet_item = -1;    /* AttributeSetDetails */
static int hf_z3950_attributeCombinations = -1;   /* AttributeCombinations */
static int hf_z3950_attributesByType = -1;        /* SEQUENCE_OF_AttributeTypeDetails */
static int hf_z3950_attributesByType_item = -1;   /* AttributeTypeDetails */
static int hf_z3950_defaultIfOmitted = -1;        /* OmittedAttributeInterpretation */
static int hf_z3950_attributeTypeDetails_attributeValues = -1;  /* SEQUENCE_OF_AttributeValue */
static int hf_z3950_attributeTypeDetails_attributeValues_item = -1;  /* AttributeValue */
static int hf_z3950_defaultValue = -1;            /* StringOrNumeric */
static int hf_z3950_defaultDescription = -1;      /* HumanString */
static int hf_z3950_attributeValue_value = -1;    /* StringOrNumeric */
static int hf_z3950_subAttributes = -1;           /* SEQUENCE_OF_StringOrNumeric */
static int hf_z3950_subAttributes_item = -1;      /* StringOrNumeric */
static int hf_z3950_superAttributes = -1;         /* SEQUENCE_OF_StringOrNumeric */
static int hf_z3950_superAttributes_item = -1;    /* StringOrNumeric */
static int hf_z3950_partialSupport = -1;          /* NULL */
static int hf_z3950_termListName = -1;            /* InternationalString */
static int hf_z3950_termListDetails_attributes = -1;  /* AttributeCombinations */
static int hf_z3950_scanInfo = -1;                /* T_scanInfo */
static int hf_z3950_maxStepSize = -1;             /* INTEGER */
static int hf_z3950_collatingSequence = -1;       /* HumanString */
static int hf_z3950_increasing = -1;              /* BOOLEAN */
static int hf_z3950_estNumberTerms = -1;          /* INTEGER */
static int hf_z3950_sampleTerms = -1;             /* SEQUENCE_OF_Term */
static int hf_z3950_sampleTerms_item = -1;        /* Term */
static int hf_z3950_elementSetDetails_elementSetName = -1;  /* ElementSetName */
static int hf_z3950_detailsPerElement = -1;       /* SEQUENCE_OF_PerElementDetails */
static int hf_z3950_detailsPerElement_item = -1;  /* PerElementDetails */
static int hf_z3950_recordTag = -1;               /* RecordTag */
static int hf_z3950_schemaTags = -1;              /* SEQUENCE_OF_Path */
static int hf_z3950_schemaTags_item = -1;         /* Path */
static int hf_z3950_maxSize = -1;                 /* INTEGER */
static int hf_z3950_minSize = -1;                 /* INTEGER */
static int hf_z3950_avgSize = -1;                 /* INTEGER */
static int hf_z3950_fixedSize = -1;               /* INTEGER */
static int hf_z3950_contents = -1;                /* HumanString */
static int hf_z3950_billingInfo = -1;             /* HumanString */
static int hf_z3950_restrictions = -1;            /* HumanString */
static int hf_z3950_alternateNames = -1;          /* SEQUENCE_OF_InternationalString */
static int hf_z3950_alternateNames_item = -1;     /* InternationalString */
static int hf_z3950_genericNames = -1;            /* SEQUENCE_OF_InternationalString */
static int hf_z3950_genericNames_item = -1;       /* InternationalString */
static int hf_z3950_searchAccess = -1;            /* AttributeCombinations */
static int hf_z3950_qualifier = -1;               /* StringOrNumeric */
static int hf_z3950_sortKeys = -1;                /* SEQUENCE_OF_SortKeyDetails */
static int hf_z3950_sortKeys_item = -1;           /* SortKeyDetails */
static int hf_z3950_elementSpecifications = -1;   /* SEQUENCE_OF_Specification */
static int hf_z3950_elementSpecifications_item = -1;  /* Specification */
static int hf_z3950_attributeSpecifications = -1;  /* AttributeCombinations */
static int hf_z3950_sortType = -1;                /* T_sortType */
static int hf_z3950_character = -1;               /* NULL */
static int hf_z3950_sortKeyDetails_sortType_numeric = -1;  /* NULL */
static int hf_z3950_sortKeyDetails_sortType_structured = -1;  /* HumanString */
static int hf_z3950_sortKeyDetails_caseSensitivity = -1;  /* T_sortKeyDetails_caseSensitivity */
static int hf_z3950_processingContext = -1;       /* T_processingContext */
static int hf_z3950_instructions = -1;            /* EXTERNAL */
static int hf_z3950_variantSet = -1;              /* OBJECT_IDENTIFIER */
static int hf_z3950_variantSetInfo_variants = -1;  /* SEQUENCE_OF_VariantClass */
static int hf_z3950_variantSetInfo_variants_item = -1;  /* VariantClass */
static int hf_z3950_variantClass = -1;            /* INTEGER */
static int hf_z3950_variantTypes = -1;            /* SEQUENCE_OF_VariantType */
static int hf_z3950_variantTypes_item = -1;       /* VariantType */
static int hf_z3950_variantType = -1;             /* INTEGER */
static int hf_z3950_variantValue = -1;            /* VariantValue */
static int hf_z3950_values = -1;                  /* ValueSet */
static int hf_z3950_range = -1;                   /* ValueRange */
static int hf_z3950_enumerated = -1;              /* SEQUENCE_OF_ValueDescription */
static int hf_z3950_enumerated_item = -1;         /* ValueDescription */
static int hf_z3950_lower = -1;                   /* ValueDescription */
static int hf_z3950_upper = -1;                   /* ValueDescription */
static int hf_z3950_integer = -1;                 /* INTEGER */
static int hf_z3950_octets = -1;                  /* OCTET_STRING */
static int hf_z3950_valueDescription_unit = -1;   /* Unit */
static int hf_z3950_valueAndUnit = -1;            /* IntUnit */
static int hf_z3950_unitInfo_units = -1;          /* SEQUENCE_OF_UnitType */
static int hf_z3950_unitInfo_units_item = -1;     /* UnitType */
static int hf_z3950_unitType_units = -1;          /* SEQUENCE_OF_Units */
static int hf_z3950_unitType_units_item = -1;     /* Units */
static int hf_z3950_categories = -1;              /* SEQUENCE_OF_CategoryInfo */
static int hf_z3950_categories_item = -1;         /* CategoryInfo */
static int hf_z3950_categoryInfo_category = -1;   /* InternationalString */
static int hf_z3950_originalCategory = -1;        /* InternationalString */
static int hf_z3950_dateAdded = -1;               /* GeneralizedTime */
static int hf_z3950_dateChanged = -1;             /* GeneralizedTime */
static int hf_z3950_expiry = -1;                  /* GeneralizedTime */
static int hf_z3950_humanString_Language = -1;    /* LanguageCode */
static int hf_z3950_HumanString_item = -1;        /* HumanString_item */
static int hf_z3950_language = -1;                /* LanguageCode */
static int hf_z3950_text = -1;                    /* InternationalString */
static int hf_z3950_IconObject_item = -1;         /* IconObject_item */
static int hf_z3950_bodyType = -1;                /* T_bodyType */
static int hf_z3950_ianaType = -1;                /* InternationalString */
static int hf_z3950_z3950type = -1;               /* InternationalString */
static int hf_z3950_otherType = -1;               /* InternationalString */
static int hf_z3950_content = -1;                 /* OCTET_STRING */
static int hf_z3950_address = -1;                 /* HumanString */
static int hf_z3950_email = -1;                   /* InternationalString */
static int hf_z3950_phone = -1;                   /* InternationalString */
static int hf_z3950_internetAddress = -1;         /* T_internetAddress */
static int hf_z3950_hostAddress = -1;             /* InternationalString */
static int hf_z3950_port = -1;                    /* INTEGER */
static int hf_z3950_osiPresentationAddress = -1;  /* T_osiPresentationAddress */
static int hf_z3950_pSel = -1;                    /* InternationalString */
static int hf_z3950_sSel = -1;                    /* InternationalString */
static int hf_z3950_tSel = -1;                    /* InternationalString */
static int hf_z3950_nSap = -1;                    /* InternationalString */
static int hf_z3950_networkAddress_other = -1;    /* T_networkAddress_other */
static int hf_z3950_networkAddress_other_type = -1;  /* InternationalString */
static int hf_z3950_networkAddress_other_address = -1;  /* InternationalString */
static int hf_z3950_queryTypesSupported = -1;     /* SEQUENCE_OF_QueryTypeDetails */
static int hf_z3950_queryTypesSupported_item = -1;  /* QueryTypeDetails */
static int hf_z3950_diagnosticsSets = -1;         /* T_diagnosticsSets */
static int hf_z3950_diagnosticsSets_item = -1;    /* OBJECT_IDENTIFIER */
static int hf_z3950_attributeSetIds = -1;         /* SEQUENCE_OF_AttributeSetId */
static int hf_z3950_attributeSetIds_item = -1;    /* AttributeSetId */
static int hf_z3950_schemas = -1;                 /* T_schemas */
static int hf_z3950_schemas_item = -1;            /* OBJECT_IDENTIFIER */
static int hf_z3950_recordSyntaxes = -1;          /* T_recordSyntaxes */
static int hf_z3950_recordSyntaxes_item = -1;     /* OBJECT_IDENTIFIER */
static int hf_z3950_resourceChallenges = -1;      /* T_resourceChallenges */
static int hf_z3950_resourceChallenges_item = -1;  /* OBJECT_IDENTIFIER */
static int hf_z3950_restrictedAccess = -1;        /* AccessRestrictions */
static int hf_z3950_costInfo = -1;                /* Costs */
static int hf_z3950_variantSets = -1;             /* T_variantSets */
static int hf_z3950_variantSets_item = -1;        /* OBJECT_IDENTIFIER */
static int hf_z3950_elementSetNames = -1;         /* SEQUENCE_OF_ElementSetName */
static int hf_z3950_elementSetNames_item = -1;    /* ElementSetName */
static int hf_z3950_unitSystems = -1;             /* SEQUENCE_OF_InternationalString */
static int hf_z3950_unitSystems_item = -1;        /* InternationalString */
static int hf_z3950_queryTypeDetails_private = -1;  /* PrivateCapabilities */
static int hf_z3950_queryTypeDetails_rpn = -1;    /* RpnCapabilities */
static int hf_z3950_iso8777 = -1;                 /* Iso8777Capabilities */
static int hf_z3950_z39_58 = -1;                  /* HumanString */
static int hf_z3950_erpn = -1;                    /* RpnCapabilities */
static int hf_z3950_rankedList = -1;              /* HumanString */
static int hf_z3950_privateCapabilities_operators = -1;  /* T_privateCapabilities_operators */
static int hf_z3950_privateCapabilities_operators_item = -1;  /* T_privateCapabilities_operators_item */
static int hf_z3950_operator = -1;                /* InternationalString */
static int hf_z3950_searchKeys = -1;              /* SEQUENCE_OF_SearchKey */
static int hf_z3950_searchKeys_item = -1;         /* SearchKey */
static int hf_z3950_privateCapabilities_description = -1;  /* SEQUENCE_OF_HumanString */
static int hf_z3950_privateCapabilities_description_item = -1;  /* HumanString */
static int hf_z3950_operators = -1;               /* T_operators */
static int hf_z3950_operators_item = -1;          /* INTEGER */
static int hf_z3950_resultSetAsOperandSupported = -1;  /* BOOLEAN */
static int hf_z3950_restrictionOperandSupported = -1;  /* BOOLEAN */
static int hf_z3950_proximity = -1;               /* ProximitySupport */
static int hf_z3950_anySupport = -1;              /* BOOLEAN */
static int hf_z3950_unitsSupported = -1;          /* T_unitsSupported */
static int hf_z3950_unitsSupported_item = -1;     /* T_unitsSupported_item */
static int hf_z3950_proximitySupport_unitsSupported_item_known = -1;  /* INTEGER */
static int hf_z3950_proximitySupport_unitsSupported_item_private = -1;  /* T_proximitySupport_unitsSupported_item_private */
static int hf_z3950_proximitySupport_unitsSupported_item_private_unit = -1;  /* INTEGER */
static int hf_z3950_searchKey = -1;               /* InternationalString */
static int hf_z3950_AccessRestrictions_item = -1;  /* AccessRestrictions_item */
static int hf_z3950_accessType = -1;              /* T_accessType */
static int hf_z3950_accessText = -1;              /* HumanString */
static int hf_z3950_accessChallenges = -1;        /* T_accessChallenges */
static int hf_z3950_accessChallenges_item = -1;   /* OBJECT_IDENTIFIER */
static int hf_z3950_connectCharge = -1;           /* Charge */
static int hf_z3950_connectTime = -1;             /* Charge */
static int hf_z3950_displayCharge = -1;           /* Charge */
static int hf_z3950_searchCharge = -1;            /* Charge */
static int hf_z3950_subscriptCharge = -1;         /* Charge */
static int hf_z3950_otherCharges = -1;            /* T_otherCharges */
static int hf_z3950_otherCharges_item = -1;       /* T_otherCharges_item */
static int hf_z3950_forWhat = -1;                 /* HumanString */
static int hf_z3950_charge = -1;                  /* Charge */
static int hf_z3950_cost = -1;                    /* IntUnit */
static int hf_z3950_perWhat = -1;                 /* Unit */
static int hf_z3950_charge_text = -1;             /* HumanString */
static int hf_z3950_DatabaseList_item = -1;       /* DatabaseName */
static int hf_z3950_defaultAttributeSet = -1;     /* AttributeSetId */
static int hf_z3950_legalCombinations = -1;       /* SEQUENCE_OF_AttributeCombination */
static int hf_z3950_legalCombinations_item = -1;  /* AttributeCombination */
static int hf_z3950_AttributeCombination_item = -1;  /* AttributeOccurrence */
static int hf_z3950_mustBeSupplied = -1;          /* NULL */
static int hf_z3950_attributeOccurrence_attributeValues = -1;  /* T_attributeOccurrence_attributeValues */
static int hf_z3950_any_or_none = -1;             /* NULL */
static int hf_z3950_specific = -1;                /* SEQUENCE_OF_StringOrNumeric */
static int hf_z3950_specific_item = -1;           /* StringOrNumeric */
static int hf_z3950_briefBib_title = -1;          /* InternationalString */
static int hf_z3950_author = -1;                  /* InternationalString */
static int hf_z3950_recordType = -1;              /* InternationalString */
static int hf_z3950_bibliographicLevel = -1;      /* InternationalString */
static int hf_z3950_briefBib_format = -1;         /* SEQUENCE_OF_FormatSpec */
static int hf_z3950_briefBib_format_item = -1;    /* FormatSpec */
static int hf_z3950_publicationPlace = -1;        /* InternationalString */
static int hf_z3950_publicationDate = -1;         /* InternationalString */
static int hf_z3950_targetSystemKey = -1;         /* InternationalString */
static int hf_z3950_satisfyingElement = -1;       /* InternationalString */
static int hf_z3950_rank = -1;                    /* INTEGER */
static int hf_z3950_documentId = -1;              /* InternationalString */
static int hf_z3950_abstract = -1;                /* InternationalString */
static int hf_z3950_formatSpec_type = -1;         /* InternationalString */
static int hf_z3950_size = -1;                    /* INTEGER */
static int hf_z3950_bestPosn = -1;                /* INTEGER */
static int hf_z3950_GenericRecord_item = -1;      /* TaggedElement */
static int hf_z3950_tagOccurrence = -1;           /* INTEGER */
static int hf_z3950_taggedElement_content = -1;   /* ElementData */
static int hf_z3950_metaData = -1;                /* ElementMetaData */
static int hf_z3950_appliedVariant = -1;          /* Variant */
static int hf_z3950_date = -1;                    /* GeneralizedTime */
static int hf_z3950_ext = -1;                     /* EXTERNAL */
static int hf_z3950_trueOrFalse = -1;             /* BOOLEAN */
static int hf_z3950_intUnit = -1;                 /* IntUnit */
static int hf_z3950_elementNotThere = -1;         /* NULL */
static int hf_z3950_elementEmpty = -1;            /* NULL */
static int hf_z3950_noDataRequested = -1;         /* NULL */
static int hf_z3950_elementData_diagnostic = -1;  /* EXTERNAL */
static int hf_z3950_subtree = -1;                 /* SEQUENCE_OF_TaggedElement */
static int hf_z3950_subtree_item = -1;            /* TaggedElement */
static int hf_z3950_seriesOrder = -1;             /* Order */
static int hf_z3950_usageRight = -1;              /* Usage */
static int hf_z3950_hits = -1;                    /* SEQUENCE_OF_HitVector */
static int hf_z3950_hits_item = -1;               /* HitVector */
static int hf_z3950_displayName = -1;             /* InternationalString */
static int hf_z3950_supportedVariants = -1;       /* SEQUENCE_OF_Variant */
static int hf_z3950_supportedVariants_item = -1;  /* Variant */
static int hf_z3950_elementDescriptor = -1;       /* OCTET_STRING */
static int hf_z3950_surrogateFor = -1;            /* TagPath */
static int hf_z3950_surrogateElement = -1;        /* TagPath */
static int hf_z3950_TagPath_item = -1;            /* TagPath_item */
static int hf_z3950_ascending = -1;               /* BOOLEAN */
static int hf_z3950_order = -1;                   /* INTEGER */
static int hf_z3950_usage_type = -1;              /* T_usage_type */
static int hf_z3950_restriction = -1;             /* InternationalString */
static int hf_z3950_satisfier = -1;               /* Term */
static int hf_z3950_offsetIntoElement = -1;       /* IntUnit */
static int hf_z3950_length = -1;                  /* IntUnit */
static int hf_z3950_hitRank = -1;                 /* INTEGER */
static int hf_z3950_targetToken = -1;             /* OCTET_STRING */
static int hf_z3950_globalVariantSetId = -1;      /* OBJECT_IDENTIFIER */
static int hf_z3950_triples = -1;                 /* T_triples */
static int hf_z3950_triples_item = -1;            /* T_triples_item */
static int hf_z3950_variantSetId = -1;            /* OBJECT_IDENTIFIER */
static int hf_z3950_class = -1;                   /* INTEGER */
static int hf_z3950_variant_triples_item_value = -1;  /* T_variant_triples_item_value */
static int hf_z3950_octetString = -1;             /* OCTET_STRING */
static int hf_z3950_boolean = -1;                 /* BOOLEAN */
static int hf_z3950_variant_triples_item_value_unit = -1;  /* Unit */
static int hf_z3950_taskPackage_description = -1;  /* InternationalString */
static int hf_z3950_targetReference = -1;         /* OCTET_STRING */
static int hf_z3950_creationDateTime = -1;        /* GeneralizedTime */
static int hf_z3950_taskStatus = -1;              /* T_taskStatus */
static int hf_z3950_packageDiagnostics = -1;      /* SEQUENCE_OF_DiagRec */
static int hf_z3950_packageDiagnostics_item = -1;  /* DiagRec */
static int hf_z3950_challenge = -1;               /* Challenge */
static int hf_z3950_response = -1;                /* Response */
static int hf_z3950_Challenge_item = -1;          /* Challenge_item */
static int hf_z3950_promptId = -1;                /* PromptId */
static int hf_z3950_defaultResponse = -1;         /* InternationalString */
static int hf_z3950_promptInfo = -1;              /* T_promptInfo */
static int hf_z3950_challenge_item_promptInfo_character = -1;  /* InternationalString */
static int hf_z3950_encrypted = -1;               /* Encryption */
static int hf_z3950_regExpr = -1;                 /* InternationalString */
static int hf_z3950_responseRequired = -1;        /* NULL */
static int hf_z3950_allowedValues = -1;           /* SEQUENCE_OF_InternationalString */
static int hf_z3950_allowedValues_item = -1;      /* InternationalString */
static int hf_z3950_shouldSave = -1;              /* NULL */
static int hf_z3950_challenge_item_dataType = -1;  /* T_challenge_item_dataType */
static int hf_z3950_challenge_item_diagnostic = -1;  /* EXTERNAL */
static int hf_z3950_Response_item = -1;           /* Response_item */
static int hf_z3950_promptResponse = -1;          /* T_promptResponse */
static int hf_z3950_accept = -1;                  /* BOOLEAN */
static int hf_z3950_acknowledge = -1;             /* NULL */
static int hf_z3950_enummeratedPrompt = -1;       /* T_enummeratedPrompt */
static int hf_z3950_promptId_enummeratedPrompt_type = -1;  /* T_promptId_enummeratedPrompt_type */
static int hf_z3950_suggestedString = -1;         /* InternationalString */
static int hf_z3950_nonEnumeratedPrompt = -1;     /* InternationalString */
static int hf_z3950_cryptType = -1;               /* OCTET_STRING */
static int hf_z3950_credential = -1;              /* OCTET_STRING */
static int hf_z3950_data = -1;                    /* OCTET_STRING */
static int hf_z3950_dES_RN_Object_challenge = -1;  /* DRNType */
static int hf_z3950_rES_RN_Object_response = -1;  /* DRNType */
static int hf_z3950_dRNType_userId = -1;          /* OCTET_STRING */
static int hf_z3950_salt = -1;                    /* OCTET_STRING */
static int hf_z3950_randomNumber = -1;            /* OCTET_STRING */
static int hf_z3950_kRBObject_challenge = -1;     /* KRBRequest */
static int hf_z3950_kRBObject_response = -1;      /* KRBResponse */
static int hf_z3950_service = -1;                 /* InternationalString */
static int hf_z3950_instance = -1;                /* InternationalString */
static int hf_z3950_realm = -1;                   /* InternationalString */
static int hf_z3950_userid = -1;                  /* InternationalString */
static int hf_z3950_ticket = -1;                  /* OCTET_STRING */
static int hf_z3950_SearchInfoReport_item = -1;   /* SearchInfoReport_item */
static int hf_z3950_subqueryId = -1;              /* InternationalString */
static int hf_z3950_fullQuery = -1;               /* BOOLEAN */
static int hf_z3950_subqueryExpression = -1;      /* QueryExpression */
static int hf_z3950_subqueryInterpretation = -1;  /* QueryExpression */
static int hf_z3950_subqueryRecommendation = -1;  /* QueryExpression */
static int hf_z3950_subqueryCount = -1;           /* INTEGER */
static int hf_z3950_subqueryWeight = -1;          /* IntUnit */
static int hf_z3950_resultsByDB = -1;             /* ResultsByDB */
static int hf_z3950_ResultsByDB_item = -1;        /* ResultsByDB_item */
static int hf_z3950_databases = -1;               /* T_databases */
static int hf_z3950_all = -1;                     /* NULL */
static int hf_z3950_list = -1;                    /* SEQUENCE_OF_DatabaseName */
static int hf_z3950_list_item = -1;               /* DatabaseName */
static int hf_z3950_count = -1;                   /* INTEGER */
static int hf_z3950_queryExpression_term = -1;    /* T_queryExpression_term */
static int hf_z3950_queryTerm = -1;               /* Term */
static int hf_z3950_termComment = -1;             /* InternationalString */
/* named bits */
static int hf_z3950_ProtocolVersion_U_version_1 = -1;
static int hf_z3950_ProtocolVersion_U_version_2 = -1;
static int hf_z3950_ProtocolVersion_U_version_3 = -1;
static int hf_z3950_Options_U_search = -1;
static int hf_z3950_Options_U_present = -1;
static int hf_z3950_Options_U_delSet = -1;
static int hf_z3950_Options_U_resourceReport = -1;
static int hf_z3950_Options_U_triggerResourceCtrl = -1;
static int hf_z3950_Options_U_resourceCtrl = -1;
static int hf_z3950_Options_U_accessCtrl = -1;
static int hf_z3950_Options_U_scan = -1;
static int hf_z3950_Options_U_sort = -1;
static int hf_z3950_Options_U_spare_bit9 = -1;
static int hf_z3950_Options_U_extendedServices = -1;
static int hf_z3950_Options_U_level_1Segmentation = -1;
static int hf_z3950_Options_U_level_2Segmentation = -1;
static int hf_z3950_Options_U_concurrentOperations = -1;
static int hf_z3950_Options_U_namedResultSets = -1;

/*--- End of included file: packet-z3950-hf.c ---*/
#line 655 "./asn1/z3950/packet-z3950-template.c"

static int hf_z3950_referenceId_printable = -1;
static int hf_z3950_general_printable = -1;

/* Initialize the subtree pointers */
static int ett_z3950 = -1;


/*--- Included file: packet-z3950-ett.c ---*/
#line 1 "./asn1/z3950/packet-z3950-ett.c"
static gint ett_z3950_PDU = -1;
static gint ett_z3950_InitializeRequest = -1;
static gint ett_z3950_T_idAuthentication = -1;
static gint ett_z3950_T_idPass = -1;
static gint ett_z3950_InitializeResponse = -1;
static gint ett_z3950_ProtocolVersion_U = -1;
static gint ett_z3950_Options_U = -1;
static gint ett_z3950_SearchRequest = -1;
static gint ett_z3950_SEQUENCE_OF_DatabaseName = -1;
static gint ett_z3950_Query = -1;
static gint ett_z3950_RPNQuery = -1;
static gint ett_z3950_RPNStructure = -1;
static gint ett_z3950_T_rpnRpnOp = -1;
static gint ett_z3950_Operand = -1;
static gint ett_z3950_AttributesPlusTerm_U = -1;
static gint ett_z3950_ResultSetPlusAttributes_U = -1;
static gint ett_z3950_SEQUENCE_OF_AttributeElement = -1;
static gint ett_z3950_Term = -1;
static gint ett_z3950_Operator_U = -1;
static gint ett_z3950_AttributeElement = -1;
static gint ett_z3950_T_attributeValue = -1;
static gint ett_z3950_T_attributeValue_complex = -1;
static gint ett_z3950_SEQUENCE_OF_StringOrNumeric = -1;
static gint ett_z3950_T_semanticAction = -1;
static gint ett_z3950_ProximityOperator = -1;
static gint ett_z3950_T_proximityUnitCode = -1;
static gint ett_z3950_SearchResponse = -1;
static gint ett_z3950_PresentRequest = -1;
static gint ett_z3950_SEQUENCE_OF_Range = -1;
static gint ett_z3950_T_recordComposition = -1;
static gint ett_z3950_Segment = -1;
static gint ett_z3950_SEQUENCE_OF_NamePlusRecord = -1;
static gint ett_z3950_PresentResponse = -1;
static gint ett_z3950_Records = -1;
static gint ett_z3950_SEQUENCE_OF_DiagRec = -1;
static gint ett_z3950_NamePlusRecord = -1;
static gint ett_z3950_T_record = -1;
static gint ett_z3950_FragmentSyntax = -1;
static gint ett_z3950_DiagRec = -1;
static gint ett_z3950_DefaultDiagFormat = -1;
static gint ett_z3950_T_addinfo = -1;
static gint ett_z3950_Range = -1;
static gint ett_z3950_ElementSetNames = -1;
static gint ett_z3950_T_databaseSpecific = -1;
static gint ett_z3950_T_databaseSpecific_item = -1;
static gint ett_z3950_CompSpec = -1;
static gint ett_z3950_T_dbSpecific = -1;
static gint ett_z3950_T_dbSpecific_item = -1;
static gint ett_z3950_T_compSpec_recordSyntax = -1;
static gint ett_z3950_Specification = -1;
static gint ett_z3950_T_specification_elementSpec = -1;
static gint ett_z3950_DeleteResultSetRequest = -1;
static gint ett_z3950_SEQUENCE_OF_ResultSetId = -1;
static gint ett_z3950_DeleteResultSetResponse = -1;
static gint ett_z3950_ListStatuses = -1;
static gint ett_z3950_ListStatuses_item = -1;
static gint ett_z3950_AccessControlRequest = -1;
static gint ett_z3950_T_securityChallenge = -1;
static gint ett_z3950_AccessControlResponse = -1;
static gint ett_z3950_T_securityChallengeResponse = -1;
static gint ett_z3950_ResourceControlRequest = -1;
static gint ett_z3950_ResourceControlResponse = -1;
static gint ett_z3950_TriggerResourceControlRequest = -1;
static gint ett_z3950_ResourceReportRequest = -1;
static gint ett_z3950_ResourceReportResponse = -1;
static gint ett_z3950_ScanRequest = -1;
static gint ett_z3950_ScanResponse = -1;
static gint ett_z3950_ListEntries = -1;
static gint ett_z3950_SEQUENCE_OF_Entry = -1;
static gint ett_z3950_Entry = -1;
static gint ett_z3950_TermInfo = -1;
static gint ett_z3950_SEQUENCE_OF_AttributesPlusTerm = -1;
static gint ett_z3950_OccurrenceByAttributes = -1;
static gint ett_z3950_OccurrenceByAttributes_item = -1;
static gint ett_z3950_T_occurrences = -1;
static gint ett_z3950_T_byDatabase = -1;
static gint ett_z3950_T_byDatabase_item = -1;
static gint ett_z3950_SortRequest = -1;
static gint ett_z3950_SEQUENCE_OF_InternationalString = -1;
static gint ett_z3950_SEQUENCE_OF_SortKeySpec = -1;
static gint ett_z3950_SortResponse = -1;
static gint ett_z3950_SortKeySpec = -1;
static gint ett_z3950_T_missingValueAction = -1;
static gint ett_z3950_SortElement = -1;
static gint ett_z3950_T_datbaseSpecific = -1;
static gint ett_z3950_T_datbaseSpecific_item = -1;
static gint ett_z3950_SortKey = -1;
static gint ett_z3950_T_sortAttributes = -1;
static gint ett_z3950_ExtendedServicesRequest = -1;
static gint ett_z3950_ExtendedServicesResponse = -1;
static gint ett_z3950_Permissions = -1;
static gint ett_z3950_Permissions_item = -1;
static gint ett_z3950_T_allowableFunctions = -1;
static gint ett_z3950_Close = -1;
static gint ett_z3950_OtherInformation_U = -1;
static gint ett_z3950_T__untag_item = -1;
static gint ett_z3950_T_information = -1;
static gint ett_z3950_InfoCategory = -1;
static gint ett_z3950_IntUnit = -1;
static gint ett_z3950_Unit = -1;
static gint ett_z3950_StringOrNumeric = -1;
static gint ett_z3950_OCLC_UserInformation = -1;
static gint ett_z3950_SEQUENCE_OF_DBName = -1;
static gint ett_z3950_OPACRecord = -1;
static gint ett_z3950_SEQUENCE_OF_HoldingsRecord = -1;
static gint ett_z3950_HoldingsRecord = -1;
static gint ett_z3950_HoldingsAndCircData = -1;
static gint ett_z3950_SEQUENCE_OF_Volume = -1;
static gint ett_z3950_SEQUENCE_OF_CircRecord = -1;
static gint ett_z3950_Volume = -1;
static gint ett_z3950_CircRecord = -1;
static gint ett_z3950_DiagnosticFormat = -1;
static gint ett_z3950_DiagnosticFormat_item = -1;
static gint ett_z3950_T_diagnosticFormat_item_diagnostic = -1;
static gint ett_z3950_DiagFormat = -1;
static gint ett_z3950_T_tooMany = -1;
static gint ett_z3950_T_badSpec = -1;
static gint ett_z3950_SEQUENCE_OF_Specification = -1;
static gint ett_z3950_T_dbUnavail = -1;
static gint ett_z3950_T_why = -1;
static gint ett_z3950_T_attribute = -1;
static gint ett_z3950_T_attCombo = -1;
static gint ett_z3950_SEQUENCE_OF_AttributeList = -1;
static gint ett_z3950_T_diagFormat_term = -1;
static gint ett_z3950_T_diagFormat_proximity = -1;
static gint ett_z3950_T_scan = -1;
static gint ett_z3950_T_sort = -1;
static gint ett_z3950_T_segmentation = -1;
static gint ett_z3950_T_extServices = -1;
static gint ett_z3950_T_accessCtrl = -1;
static gint ett_z3950_T_diagFormat_accessCtrl_oid = -1;
static gint ett_z3950_T_alternative = -1;
static gint ett_z3950_T_diagFormat_recordSyntax = -1;
static gint ett_z3950_T_suggestedAlternatives = -1;
static gint ett_z3950_Explain_Record = -1;
static gint ett_z3950_TargetInfo = -1;
static gint ett_z3950_SEQUENCE_OF_DatabaseList = -1;
static gint ett_z3950_SEQUENCE_OF_NetworkAddress = -1;
static gint ett_z3950_DatabaseInfo = -1;
static gint ett_z3950_SEQUENCE_OF_HumanString = -1;
static gint ett_z3950_T_recordCount = -1;
static gint ett_z3950_SchemaInfo = -1;
static gint ett_z3950_T_tagTypeMapping = -1;
static gint ett_z3950_T_tagTypeMapping_item = -1;
static gint ett_z3950_SEQUENCE_OF_ElementInfo = -1;
static gint ett_z3950_ElementInfo = -1;
static gint ett_z3950_Path = -1;
static gint ett_z3950_Path_item = -1;
static gint ett_z3950_ElementDataType = -1;
static gint ett_z3950_TagSetInfo = -1;
static gint ett_z3950_T_tagSetInfo_elements = -1;
static gint ett_z3950_T_tagSetInfo_elements_item = -1;
static gint ett_z3950_RecordSyntaxInfo = -1;
static gint ett_z3950_T_transferSyntaxes = -1;
static gint ett_z3950_AttributeSetInfo = -1;
static gint ett_z3950_SEQUENCE_OF_AttributeType = -1;
static gint ett_z3950_AttributeType = -1;
static gint ett_z3950_SEQUENCE_OF_AttributeDescription = -1;
static gint ett_z3950_AttributeDescription = -1;
static gint ett_z3950_TermListInfo = -1;
static gint ett_z3950_T_termLists = -1;
static gint ett_z3950_T_termLists_item = -1;
static gint ett_z3950_ExtendedServicesInfo = -1;
static gint ett_z3950_AttributeDetails = -1;
static gint ett_z3950_SEQUENCE_OF_AttributeSetDetails = -1;
static gint ett_z3950_AttributeSetDetails = -1;
static gint ett_z3950_SEQUENCE_OF_AttributeTypeDetails = -1;
static gint ett_z3950_AttributeTypeDetails = -1;
static gint ett_z3950_SEQUENCE_OF_AttributeValue = -1;
static gint ett_z3950_OmittedAttributeInterpretation = -1;
static gint ett_z3950_AttributeValue = -1;
static gint ett_z3950_TermListDetails = -1;
static gint ett_z3950_T_scanInfo = -1;
static gint ett_z3950_SEQUENCE_OF_Term = -1;
static gint ett_z3950_ElementSetDetails = -1;
static gint ett_z3950_SEQUENCE_OF_PerElementDetails = -1;
static gint ett_z3950_RetrievalRecordDetails = -1;
static gint ett_z3950_PerElementDetails = -1;
static gint ett_z3950_SEQUENCE_OF_Path = -1;
static gint ett_z3950_RecordTag = -1;
static gint ett_z3950_SortDetails = -1;
static gint ett_z3950_SEQUENCE_OF_SortKeyDetails = -1;
static gint ett_z3950_SortKeyDetails = -1;
static gint ett_z3950_T_sortType = -1;
static gint ett_z3950_ProcessingInformation = -1;
static gint ett_z3950_VariantSetInfo = -1;
static gint ett_z3950_SEQUENCE_OF_VariantClass = -1;
static gint ett_z3950_VariantClass = -1;
static gint ett_z3950_SEQUENCE_OF_VariantType = -1;
static gint ett_z3950_VariantType = -1;
static gint ett_z3950_VariantValue = -1;
static gint ett_z3950_ValueSet = -1;
static gint ett_z3950_SEQUENCE_OF_ValueDescription = -1;
static gint ett_z3950_ValueRange = -1;
static gint ett_z3950_ValueDescription = -1;
static gint ett_z3950_UnitInfo = -1;
static gint ett_z3950_SEQUENCE_OF_UnitType = -1;
static gint ett_z3950_UnitType = -1;
static gint ett_z3950_SEQUENCE_OF_Units = -1;
static gint ett_z3950_Units = -1;
static gint ett_z3950_CategoryList = -1;
static gint ett_z3950_SEQUENCE_OF_CategoryInfo = -1;
static gint ett_z3950_CategoryInfo = -1;
static gint ett_z3950_CommonInfo = -1;
static gint ett_z3950_HumanString = -1;
static gint ett_z3950_HumanString_item = -1;
static gint ett_z3950_IconObject = -1;
static gint ett_z3950_IconObject_item = -1;
static gint ett_z3950_T_bodyType = -1;
static gint ett_z3950_ContactInfo = -1;
static gint ett_z3950_NetworkAddress = -1;
static gint ett_z3950_T_internetAddress = -1;
static gint ett_z3950_T_osiPresentationAddress = -1;
static gint ett_z3950_T_networkAddress_other = -1;
static gint ett_z3950_AccessInfo = -1;
static gint ett_z3950_SEQUENCE_OF_QueryTypeDetails = -1;
static gint ett_z3950_T_diagnosticsSets = -1;
static gint ett_z3950_SEQUENCE_OF_AttributeSetId = -1;
static gint ett_z3950_T_schemas = -1;
static gint ett_z3950_T_recordSyntaxes = -1;
static gint ett_z3950_T_resourceChallenges = -1;
static gint ett_z3950_T_variantSets = -1;
static gint ett_z3950_SEQUENCE_OF_ElementSetName = -1;
static gint ett_z3950_QueryTypeDetails = -1;
static gint ett_z3950_PrivateCapabilities = -1;
static gint ett_z3950_T_privateCapabilities_operators = -1;
static gint ett_z3950_T_privateCapabilities_operators_item = -1;
static gint ett_z3950_SEQUENCE_OF_SearchKey = -1;
static gint ett_z3950_RpnCapabilities = -1;
static gint ett_z3950_T_operators = -1;
static gint ett_z3950_Iso8777Capabilities = -1;
static gint ett_z3950_ProximitySupport = -1;
static gint ett_z3950_T_unitsSupported = -1;
static gint ett_z3950_T_unitsSupported_item = -1;
static gint ett_z3950_T_proximitySupport_unitsSupported_item_private = -1;
static gint ett_z3950_SearchKey = -1;
static gint ett_z3950_AccessRestrictions = -1;
static gint ett_z3950_AccessRestrictions_item = -1;
static gint ett_z3950_T_accessChallenges = -1;
static gint ett_z3950_Costs = -1;
static gint ett_z3950_T_otherCharges = -1;
static gint ett_z3950_T_otherCharges_item = -1;
static gint ett_z3950_Charge = -1;
static gint ett_z3950_DatabaseList = -1;
static gint ett_z3950_AttributeCombinations = -1;
static gint ett_z3950_SEQUENCE_OF_AttributeCombination = -1;
static gint ett_z3950_AttributeCombination = -1;
static gint ett_z3950_AttributeOccurrence = -1;
static gint ett_z3950_T_attributeOccurrence_attributeValues = -1;
static gint ett_z3950_BriefBib = -1;
static gint ett_z3950_SEQUENCE_OF_FormatSpec = -1;
static gint ett_z3950_FormatSpec = -1;
static gint ett_z3950_GenericRecord = -1;
static gint ett_z3950_TaggedElement = -1;
static gint ett_z3950_ElementData = -1;
static gint ett_z3950_SEQUENCE_OF_TaggedElement = -1;
static gint ett_z3950_ElementMetaData = -1;
static gint ett_z3950_SEQUENCE_OF_HitVector = -1;
static gint ett_z3950_SEQUENCE_OF_Variant = -1;
static gint ett_z3950_TagPath = -1;
static gint ett_z3950_TagPath_item = -1;
static gint ett_z3950_Order = -1;
static gint ett_z3950_Usage = -1;
static gint ett_z3950_HitVector = -1;
static gint ett_z3950_Variant = -1;
static gint ett_z3950_T_triples = -1;
static gint ett_z3950_T_triples_item = -1;
static gint ett_z3950_T_variant_triples_item_value = -1;
static gint ett_z3950_TaskPackage = -1;
static gint ett_z3950_PromptObject = -1;
static gint ett_z3950_Challenge = -1;
static gint ett_z3950_Challenge_item = -1;
static gint ett_z3950_T_promptInfo = -1;
static gint ett_z3950_Response = -1;
static gint ett_z3950_Response_item = -1;
static gint ett_z3950_T_promptResponse = -1;
static gint ett_z3950_PromptId = -1;
static gint ett_z3950_T_enummeratedPrompt = -1;
static gint ett_z3950_Encryption = -1;
static gint ett_z3950_DES_RN_Object = -1;
static gint ett_z3950_DRNType = -1;
static gint ett_z3950_KRBObject = -1;
static gint ett_z3950_KRBRequest = -1;
static gint ett_z3950_KRBResponse = -1;
static gint ett_z3950_SearchInfoReport = -1;
static gint ett_z3950_SearchInfoReport_item = -1;
static gint ett_z3950_ResultsByDB = -1;
static gint ett_z3950_ResultsByDB_item = -1;
static gint ett_z3950_T_databases = -1;
static gint ett_z3950_QueryExpression = -1;
static gint ett_z3950_T_queryExpression_term = -1;

/*--- End of included file: packet-z3950-ett.c ---*/
#line 663 "./asn1/z3950/packet-z3950-template.c"

/* MARC variables and forwards */

static int dissect_marc_record(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_);

/* MARC fields */
static int hf_marc_record = -1;
static int hf_marc_record_terminator = -1;
static int hf_marc_leader = -1;
static int hf_marc_leader_length = -1;
static int hf_marc_leader_status = -1;
static int hf_marc_leader_type = -1;
static int hf_marc_leader_biblevel = -1;
static int hf_marc_leader_control = -1;
static int hf_marc_leader_encoding = -1;
static int hf_marc_leader_indicator_count = -1;
static int hf_marc_leader_subfield_count = -1;
static int hf_marc_leader_data_offset = -1;
static int hf_marc_leader_encoding_level = -1;
static int hf_marc_leader_descriptive_cataloging = -1;
static int hf_marc_leader_multipart_level = -1;
static int hf_marc_leader_length_of_field_length = -1;
static int hf_marc_leader_starting_character_position_length = -1;
static int hf_marc_leader_implementation_defined_length = -1;
static int hf_marc_directory = -1;
static int hf_marc_directory_entry = -1;
static int hf_marc_directory_entry_tag = -1;
static int hf_marc_directory_entry_length = -1;
static int hf_marc_directory_entry_starting_position = -1;
static int hf_marc_directory_terminator = -1;
static int hf_marc_fields = -1;
static int hf_marc_field = -1;
static int hf_marc_field_control = -1;
static int hf_marc_field_terminator = -1;
static int hf_marc_field_indicator1 = -1;
static int hf_marc_field_indicator2 = -1;
static int hf_marc_field_subfield_indicator = -1;
static int hf_marc_field_subfield_tag = -1;
static int hf_marc_field_subfield = -1;

/* MARC subtree pointers */
static int ett_marc_record = -1;
static int ett_marc_leader = -1;
static int ett_marc_directory = -1;
static int ett_marc_directory_entry = -1;
static int ett_marc_fields = -1;
static int ett_marc_field = -1;

/* MARC expert fields */
static expert_field ei_marc_invalid_length = EI_INIT;
static expert_field ei_marc_invalid_value = EI_INIT;
static expert_field ei_marc_invalid_record_length = EI_INIT;

/* MARC value strings */

static const value_string marc_tag_names[] = {
    { 1, "Control Number" },
    { 3, "Control Number Identifier" },
    { 5, "Date and Time of Latest Transaction" },
    { 6, "Fixed-length Data Elements - Addiional Matieral Characteristics" },
    { 8, "Fixed-length Data Elements" },
    { 7, "Physical Description Fixed Field" },
    { 10, "Library of Congress Control Number" },
    { 15, "National Bibliography Number" },
    { 16, "National Bibliographic Agency Control Number" },
    { 17, "Copyright or Legal Deposit Number" },
    { 20, "International Standard Book Number (ISBN)" },
    { 22, "International Standard Serial Number (ISSN)" },
    { 24, "Other Standard Identifier" },
    { 25, "Overseas Acquisition Number" },
    { 26, "Fingerprint Identifier" },
    { 27, "Standard Technical Report Number" },
    { 28, "Publisher or Distributor Number" },
    { 30, "CODEN Designation" },
    { 32, "Postal Registration Number" },
    { 33, "Date/Time and Place of an Event" },
    { 35, "System Control Number" },
    { 37, "Source of Acquisition" },
    { 38, "Record Content Licensor" },
    { 40, "Cataloging Source" },
    { 41, "Language Code" },
    { 42, "Authentication Code" },
    { 43, "Geographic Area Code" },
    { 44, "Country of Publishing/Producing Entity Code" },
    { 45, "Time Period of Content" },
    { 47, "Form of Musical Composition Code" },
    { 50, "Library of Congress Call Number" },
    { 51, "Library of Congress Copy, Issue, Offprint Statement" },
    { 60, "National Library of Medicine Call Number" },
    { 66, "Character Sets Present" },
    { 80, "Universal Decimal Classification Number" },
    { 82, "Dewey Decimal Classification Number" },
    { 83, "Additional Dewey Decimal Classification Number" },
    { 84, "Other Classification Number" },
    { 100, "Main Entry - Personal Name" },
    { 110, "Main Entry - Corporate Name" },
    { 111, "Main Entry - Meeting Name" },
    { 130, "Main Entry - Uniform Title" },
    { 210, "Abbreviated Title" },
    { 222, "Key Title" },
    { 240, "Uniform Title" },
    { 242, "Translation of Title by Cataloging Agency" },
    { 243, "Collective Uniform Title" },
    { 245, "Title Statement" },
    { 246, "Varying Form of Title" },
    { 247, "Former Title" },
    { 249, "Local LoC Varying Form of Title" },
    { 250, "Edition Statement" },
    { 260, "Publication, Distribution, etc. (Imprint)" },
    { 264, "Production, Publication, Distribution, Manufacture, and Copyright Notice" },
    { 300, "Physical Description" },
    { 310, "Current Publication Frequency" },
    { 321, "former Publication Frequency" },
    { 336, "Content Type" },
    { 337, "Media Type" },
    { 338, "Carrier Type" },
    { 340, "Physical Medium" },
    { 362, "Dates of Publication and/or Sequential Designation" },
    { 400, "Series Statement/Added Entry-Personal Name" },
    { 410, "Series Statement/Added Entry-Corporate Name" },
    { 411, "Series Statement/Added Entry-Meeting Name" },
    { 440, "Series Statement/Added Entry-Title" },
    { 490, "Series Statement" },
    { 500, "General Note" },
    { 504, "Bibliography, etc. Note" },
    { 505, "Formatted Contents Note" },
    { 506, "Restrictions on Access Note" },
    { 508, "Creation/Production Credits Note" },
    { 510, "Citation/References Note" },
    { 511, "Participant or Performer Note" },
    { 515, "Numbering Peculiarities Note" },
    { 518, "Date/Time and Place of an Event Note" },
    { 520, "Summary, etc." },
    { 521, "Target Audience Note" },
    { 522, "Geographic Coverage Note" },
    { 524, "Preferred Citation of Described Materials Note" },
    { 525, "Supplement Note" },
    { 530, "Additional Physical Form available Note" },
    { 532, "Accessibility Note" },
    { 533, "Reproduction Note" },
    { 534, "Original Version Note" },
    { 538, "System Details Note" },
    { 540, "Terms Governing Use and Reproduction Note" },
    { 541, "Immediate Source of Acquisition Note" },
    { 542, "Information Relating to Copyright Status" },
    { 546, "Language Note" },
    { 550, "Issuing Body Note" },
    { 555, "Cumulative Index/Finding Aids Note" },
    { 583, "Action Note" },
    { 588, "Source of Description, Etc. Note" },
    { 590, "Local LoC Note" },
    { 591, "Local LoC \"With\" Note" },
    { 592, "Local LoC Acquisition Note" },
    { 600, "Subject Added Entry - Personal Name" },
    { 610, "Subject Added Entry - Corporate Name" },
    { 611, "Subject Added Entry - Meeting Name" },
    { 630, "Subject Added Entry - Uniform Title" },
    { 647, "Subject Added Entry - Named Event" },
    { 648, "Subject Added Entry - Chronological Term" },
    { 650, "Subject Added Entry - Topical Term" },
    { 651, "Subject Added Entry - Geographic Name" },
    { 653, "Index Term - Uncontrolled" },
    { 654, "Subject Added Entry - Faceted Topical Terms" },
    { 655, "Index Term - Genre/Form" },
    { 656, "Index Term - Occupation" },
    { 657, "Index Term - Function" },
    { 658, "Index Term - Curriculum Objective" },
    { 662, "Subject Added Entry - Hierarchical Place Name" },
    { 700, "Added Entry - Personal Name" },
    { 710, "Added Entry - Corporate Name" },
    { 711, "Added Entry - Meeting Name" },
    { 720, "Added Entry - Uncontrolled Name" },
    { 730, "Added Entry - Uniform Title" },
    { 740, "Added Entry - Uncontrolled Related/Analytical Title" },
    { 751, "Added Entry - Geographic Name" },
    { 752, "Added Entry - Hierarchical Place Name" },
    { 753, "System Details Access to Computer Files" },
    { 754, "Added Entry - Taxonomic Identification" },
    { 758, "Resource Identifier" },
    { 760, "Main Series Entry" },
    { 762, "Subseries Entry" },
    { 765, "Original Language Entry" },
    { 767, "Translation Entry" },
    { 770, "Supplement/Special Issue Entry" },
    { 772, "Supplement Parent Entry" },
    { 773, "Host Item Entry" },
    { 774, "Constituent Unit Entry" },
    { 775, "Other Edition Entry" },
    { 776, "Additional Physical Form Entry" },
    { 777, "Issued With Entry" },
    { 780, "Preceding Entry" },
    { 785, "Succeeding Entry" },
    { 786, "Data Source Entry" },
    { 787, "Other Relationship Entry" },
    { 800, "Series Added Entry - Personal Name" },
    { 810, "Series Added Entry - Corporate Name" },
    { 811, "Series Added Entry - Meeting Name" },
    { 830, "Series Added Entry - Uniform Title" },
    { 850, "Holding Institution" },
    { 852, "Location" },
    { 853, "Captions and Pattern - Basic Bibliographic Unit" },
    { 856, "Electronic Location and Access" },
    { 859, "Local LoC Electronic Location and Access" },
    { 863, "Enumeration and Chronology - Basic Bibliographic Unit" },
    { 880, "Alternate Graphic Representation" },
    { 890, "Local LoC Visible File Entry" },
    { 906, "Local LoC Processing Data" },
    { 920, "Local LoC Selection Decision" },
    { 922, "Local LoC Book Source" },
    { 923, "Local LoC Supplier Invoice or Shipment Id" },
    { 925, "Local LoC Selection Decision" },
    { 952, "Local LoC Cataloger's Permanent Note" },
    { 955, "Local LoC Functional Identifying Information" },
    { 984, "Local LoC Shelflist Compare Status" },
    { 985, "Local LoC Record History" },
    { 987, "Local LoC Converstion History" },
    { 991, "Local LoC Location Information" },
    { 992, "Local LoC Location Information" },
    { 0, NULL}
};

static int
dissect_z3950_printable_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    tvbuff_t *next_tvb = NULL;
    int hf_alternate = -1;
    guint old_offset = offset;

    if (hf_index == hf_z3950_referenceId) {
        hf_alternate = hf_z3950_referenceId_printable;
    }
    else if ( hf_index == hf_z3950_general) {
        hf_alternate = hf_z3950_general_printable;
    }

    if (hf_alternate > 0) {
        /* extract the value of the octet string so we can look at it. */
        /* This does not display anything because tree is NULL. */
        offset = dissect_ber_octet_string(implicit_tag, actx, NULL, tvb, offset, hf_index, &next_tvb);

        if (next_tvb &&
            tvb_ascii_isprint(next_tvb, 0, tvb_reported_length(next_tvb))) {
                proto_tree_add_item(tree, hf_alternate, next_tvb,
                    0, tvb_reported_length(next_tvb), ENC_ASCII|ENC_NA);
        }
        else {
            offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb,
                         old_offset, hf_index, NULL);
        }
    }
    else {
        offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb,
                     old_offset, hf_index, NULL);
    }

    return offset;
}


/*--- Included file: packet-z3950-fn.c ---*/
#line 1 "./asn1/z3950/packet-z3950-fn.c"
/*--- Cyclic dependencies ---*/

/* RPNStructure -> RPNStructure/rpnRpnOp -> RPNStructure */
/* RPNStructure -> RPNStructure/rpnRpnOp -> RPNStructure */
static int dissect_z3950_RPNStructure(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* ElementInfo -> ElementDataType -> ElementDataType/structured -> ElementInfo */
static int dissect_z3950_ElementInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* TaggedElement -> ElementData -> ElementData/subtree -> TaggedElement */
static int dissect_z3950_TaggedElement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);




static int
dissect_z3950_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_z3950_ReferenceId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 142 "./asn1/z3950/z3950.cnf"
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
              hf_index, BER_CLASS_CON, 2, TRUE,
              dissect_z3950_printable_OCTET_STRING);



  return offset;
}


static int * const ProtocolVersion_U_bits[] = {
  &hf_z3950_ProtocolVersion_U_version_1,
  &hf_z3950_ProtocolVersion_U_version_2,
  &hf_z3950_ProtocolVersion_U_version_3,
  NULL
};

static int
dissect_z3950_ProtocolVersion_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    ProtocolVersion_U_bits, 3, hf_index, ett_z3950_ProtocolVersion_U,
                                    NULL);

  return offset;
}



static int
dissect_z3950_ProtocolVersion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 3, TRUE, dissect_z3950_ProtocolVersion_U);

  return offset;
}


static int * const Options_U_bits[] = {
  &hf_z3950_Options_U_search,
  &hf_z3950_Options_U_present,
  &hf_z3950_Options_U_delSet,
  &hf_z3950_Options_U_resourceReport,
  &hf_z3950_Options_U_triggerResourceCtrl,
  &hf_z3950_Options_U_resourceCtrl,
  &hf_z3950_Options_U_accessCtrl,
  &hf_z3950_Options_U_scan,
  &hf_z3950_Options_U_sort,
  &hf_z3950_Options_U_spare_bit9,
  &hf_z3950_Options_U_extendedServices,
  &hf_z3950_Options_U_level_1Segmentation,
  &hf_z3950_Options_U_level_2Segmentation,
  &hf_z3950_Options_U_concurrentOperations,
  &hf_z3950_Options_U_namedResultSets,
  NULL
};

static int
dissect_z3950_Options_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Options_U_bits, 15, hf_index, ett_z3950_Options_U,
                                    NULL);

  return offset;
}



static int
dissect_z3950_Options(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 4, TRUE, dissect_z3950_Options_U);

  return offset;
}



static int
dissect_z3950_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_z3950_VisibleString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_z3950_InternationalString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GeneralString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t T_idPass_sequence[] = {
  { &hf_z3950_groupId       , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_userId        , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_password      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_idPass(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_idPass_sequence, hf_index, ett_z3950_T_idPass);

  return offset;
}



static int
dissect_z3950_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_z3950_EXTERNAL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_external_type(implicit_tag, tree, tvb, offset, actx, hf_index, NULL);

  return offset;
}


static const value_string z3950_T_idAuthentication_vals[] = {
  {   0, "open" },
  {   1, "idPass" },
  {   2, "anonymous" },
  {   3, "other" },
  { 0, NULL }
};

static const ber_choice_t T_idAuthentication_choice[] = {
  {   0, &hf_z3950_open          , BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_z3950_VisibleString },
  {   1, &hf_z3950_idPass        , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_T_idPass },
  {   2, &hf_z3950_anonymous     , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_z3950_NULL },
  {   3, &hf_z3950_other         , BER_CLASS_UNI, BER_UNI_TAG_EXTERNAL, BER_FLAGS_NOOWNTAG, dissect_z3950_EXTERNAL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_idAuthentication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_idAuthentication_choice, hf_index, ett_z3950_T_idAuthentication,
                                 NULL);

  return offset;
}



static int
dissect_z3950_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t InfoCategory_sequence[] = {
  { &hf_z3950_categoryTypeId, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_OBJECT_IDENTIFIER },
  { &hf_z3950_categoryValue , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_InfoCategory(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InfoCategory_sequence, hf_index, ett_z3950_InfoCategory);

  return offset;
}


static const value_string z3950_T_information_vals[] = {
  {   2, "characterInfo" },
  {   3, "binaryInfo" },
  {   4, "externallyDefinedInfo" },
  {   5, "oid" },
  { 0, NULL }
};

static const ber_choice_t T_information_choice[] = {
  {   2, &hf_z3950_characterInfo , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  {   3, &hf_z3950_binaryInfo    , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_OCTET_STRING },
  {   4, &hf_z3950_externallyDefinedInfo, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_z3950_EXTERNAL },
  {   5, &hf_z3950_oid           , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_z3950_OBJECT_IDENTIFIER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_information(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_information_choice, hf_index, ett_z3950_T_information,
                                 NULL);

  return offset;
}


static const ber_sequence_t T__untag_item_sequence[] = {
  { &hf_z3950_category      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InfoCategory },
  { &hf_z3950_information   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_T_information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T__untag_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T__untag_item_sequence, hf_index, ett_z3950_T__untag_item);

  return offset;
}


static const ber_sequence_t OtherInformation_U_sequence_of[1] = {
  { &hf_z3950_otherInformation_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_T__untag_item },
};

static int
dissect_z3950_OtherInformation_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      OtherInformation_U_sequence_of, hf_index, ett_z3950_OtherInformation_U);

  return offset;
}



static int
dissect_z3950_OtherInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 201, TRUE, dissect_z3950_OtherInformation_U);

  return offset;
}


static const ber_sequence_t InitializeRequest_sequence[] = {
  { &hf_z3950_referenceId   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_ReferenceId },
  { &hf_z3950_protocolVersion, BER_CLASS_CON, 3, BER_FLAGS_NOOWNTAG, dissect_z3950_ProtocolVersion },
  { &hf_z3950_options       , BER_CLASS_CON, 4, BER_FLAGS_NOOWNTAG, dissect_z3950_Options },
  { &hf_z3950_preferredMessageSize, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_exceptionalRecordSize, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_idAuthentication, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_z3950_T_idAuthentication },
  { &hf_z3950_implementationId, BER_CLASS_CON, 110, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_implementationName, BER_CLASS_CON, 111, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_implementationVersion, BER_CLASS_CON, 112, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_userInformationField, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL, dissect_z3950_EXTERNAL },
  { &hf_z3950_otherInfo     , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_InitializeRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InitializeRequest_sequence, hf_index, ett_z3950_InitializeRequest);

  return offset;
}



static int
dissect_z3950_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t InitializeResponse_sequence[] = {
  { &hf_z3950_referenceId   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_ReferenceId },
  { &hf_z3950_protocolVersion, BER_CLASS_CON, 3, BER_FLAGS_NOOWNTAG, dissect_z3950_ProtocolVersion },
  { &hf_z3950_options       , BER_CLASS_CON, 4, BER_FLAGS_NOOWNTAG, dissect_z3950_Options },
  { &hf_z3950_preferredMessageSize, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_exceptionalRecordSize, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_result        , BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_implementationId, BER_CLASS_CON, 110, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_implementationName, BER_CLASS_CON, 111, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_implementationVersion, BER_CLASS_CON, 112, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_userInformationField, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL, dissect_z3950_EXTERNAL },
  { &hf_z3950_otherInfo     , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_InitializeResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InitializeResponse_sequence, hf_index, ett_z3950_InitializeResponse);

  return offset;
}



static int
dissect_z3950_DatabaseName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 105, TRUE, dissect_z3950_InternationalString);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_DatabaseName_sequence_of[1] = {
  { &hf_z3950_databaseNames_item, BER_CLASS_CON, 105, BER_FLAGS_NOOWNTAG, dissect_z3950_DatabaseName },
};

static int
dissect_z3950_SEQUENCE_OF_DatabaseName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_DatabaseName_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_DatabaseName);

  return offset;
}



static int
dissect_z3950_ElementSetName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 103, TRUE, dissect_z3950_InternationalString);

  return offset;
}


static const ber_sequence_t T_databaseSpecific_item_sequence[] = {
  { &hf_z3950_dbName        , BER_CLASS_CON, 105, BER_FLAGS_NOOWNTAG, dissect_z3950_DatabaseName },
  { &hf_z3950_esn           , BER_CLASS_CON, 103, BER_FLAGS_NOOWNTAG, dissect_z3950_ElementSetName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_databaseSpecific_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_databaseSpecific_item_sequence, hf_index, ett_z3950_T_databaseSpecific_item);

  return offset;
}


static const ber_sequence_t T_databaseSpecific_sequence_of[1] = {
  { &hf_z3950_databaseSpecific_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_T_databaseSpecific_item },
};

static int
dissect_z3950_T_databaseSpecific(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_databaseSpecific_sequence_of, hf_index, ett_z3950_T_databaseSpecific);

  return offset;
}


static const value_string z3950_ElementSetNames_vals[] = {
  {   0, "genericElementSetName" },
  {   1, "databaseSpecific" },
  { 0, NULL }
};

static const ber_choice_t ElementSetNames_choice[] = {
  {   0, &hf_z3950_genericElementSetName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  {   1, &hf_z3950_databaseSpecific, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_T_databaseSpecific },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ElementSetNames(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ElementSetNames_choice, hf_index, ett_z3950_ElementSetNames,
                                 NULL);

  return offset;
}



static int
dissect_z3950_T_type_0(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 139 "./asn1/z3950/z3950.cnf"
/*XXX Not implemented yet */



  return offset;
}



static int
dissect_z3950_AttributeSetId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 152 "./asn1/z3950/z3950.cnf"
  tvbuff_t *oid_tvb=NULL;


  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, &oid_tvb);

#line 156 "./asn1/z3950/z3950.cnf"
  if (oid_tvb) {
    guint len = tvb_reported_length_remaining(oid_tvb, 0);
    gchar *oid_str = oid_encoded2string(wmem_packet_scope(),
                                        tvb_get_ptr(oid_tvb, 0, len), len);
    gint attribute_set_idx = Z3950_ATSET_UNKNOWN;
    z3950_atinfo_t *atinfo_data;
    packet_info *pinfo = actx->pinfo;

    if (g_strcmp0(oid_str, Z3950_ATSET_BIB1_OID) == 0) {
      attribute_set_idx = Z3950_ATSET_BIB1;
    }
    if ((atinfo_data = (z3950_atinfo_t *)p_get_proto_data(pinfo->pool, pinfo, proto_z3950, Z3950_ATINFO_KEY)) == NULL) {

      atinfo_data = wmem_new0(pinfo->pool, z3950_atinfo_t);
      atinfo_data->atsetidx = attribute_set_idx;
      p_add_proto_data(pinfo->pool, pinfo,
                       proto_z3950, Z3950_ATINFO_KEY, atinfo_data);
    }
    else {
      atinfo_data->atsetidx = attribute_set_idx;
    }
  }


  return offset;
}



static int
dissect_z3950_T_attributeElement_attributeType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 180 "./asn1/z3950/z3950.cnf"
  gint att_type=0;
  packet_info *pinfo = actx->pinfo;
  z3950_atinfo_t *atinfo_data;

  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &att_type);

#line 185 "./asn1/z3950/z3950.cnf"
  atinfo_data = (z3950_atinfo_t *)p_get_proto_data(pinfo->pool, pinfo, proto_z3950, Z3950_ATINFO_KEY);
  if (atinfo_data && atinfo_data->atsetidx == Z3950_ATSET_BIB1) {
    proto_item_append_text(actx->created_item, " (%s)",
      val_to_str(att_type, z3950_bib1_att_types, "Unknown bib-1 attributeType %d"));
    atinfo_data->attype = att_type;
  }

  return offset;
}



static int
dissect_z3950_T_attributeValue_numeric(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 192 "./asn1/z3950/z3950.cnf"
  gint att_value=0;
  packet_info *pinfo = actx->pinfo;
  z3950_atinfo_t *atinfo_data;
  const value_string *att_value_string = NULL;

  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &att_value);

#line 198 "./asn1/z3950/z3950.cnf"
  atinfo_data = (z3950_atinfo_t *)p_get_proto_data(pinfo->pool, pinfo, proto_z3950, Z3950_ATINFO_KEY);
  if (atinfo_data && atinfo_data->atsetidx == Z3950_ATSET_BIB1) {
    switch (atinfo_data->attype) {
    case Z3950_BIB1_AT_USE:
      att_value_string = z3950_bib1_at_use;
      break;
    case Z3950_BIB1_AT_RELATION:
      att_value_string = z3950_bib1_at_relation;
      break;
    case Z3950_BIB1_AT_POSITION:
      att_value_string = z3950_bib1_at_position;
      break;
    case Z3950_BIB1_AT_STRUCTURE:
      att_value_string = z3950_bib1_at_structure;
      break;
    case Z3950_BIB1_AT_TRUNCATION:
      att_value_string = z3950_bib1_at_truncation;
      break;
    case Z3950_BIB1_AT_COMPLETENESS:
      att_value_string = z3950_bib1_at_completeness;
      break;
    default:
      att_value_string = NULL;
    }
    if (att_value_string) {
      proto_item_append_text(actx->created_item, " (%s)",
        val_to_str(att_value, att_value_string, "Unknown bib-1 attributeValue %d"));
    }
  }

  return offset;
}


static const value_string z3950_StringOrNumeric_vals[] = {
  {   1, "string" },
  {   2, "numeric" },
  { 0, NULL }
};

static const ber_choice_t StringOrNumeric_choice[] = {
  {   1, &hf_z3950_string        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  {   2, &hf_z3950_numeric       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_StringOrNumeric(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 StringOrNumeric_choice, hf_index, ett_z3950_StringOrNumeric,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_StringOrNumeric_sequence_of[1] = {
  { &hf_z3950_attributeValue_complex_list_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_StringOrNumeric },
};

static int
dissect_z3950_SEQUENCE_OF_StringOrNumeric(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_StringOrNumeric_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_StringOrNumeric);

  return offset;
}


static const ber_sequence_t T_semanticAction_sequence_of[1] = {
  { &hf_z3950_semanticAction_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_z3950_INTEGER },
};

static int
dissect_z3950_T_semanticAction(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_semanticAction_sequence_of, hf_index, ett_z3950_T_semanticAction);

  return offset;
}


static const ber_sequence_t T_attributeValue_complex_sequence[] = {
  { &hf_z3950_attributeValue_complex_list, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_StringOrNumeric },
  { &hf_z3950_semanticAction, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_semanticAction },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_attributeValue_complex(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_attributeValue_complex_sequence, hf_index, ett_z3950_T_attributeValue_complex);

  return offset;
}


static const value_string z3950_T_attributeValue_vals[] = {
  { 121, "numeric" },
  { 224, "complex" },
  { 0, NULL }
};

static const ber_choice_t T_attributeValue_choice[] = {
  { 121, &hf_z3950_attributeValue_numeric, BER_CLASS_CON, 121, BER_FLAGS_IMPLTAG, dissect_z3950_T_attributeValue_numeric },
  { 224, &hf_z3950_attributeValue_complex, BER_CLASS_CON, 224, BER_FLAGS_IMPLTAG, dissect_z3950_T_attributeValue_complex },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_attributeValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_attributeValue_choice, hf_index, ett_z3950_T_attributeValue,
                                 NULL);

  return offset;
}


static const ber_sequence_t AttributeElement_sequence[] = {
  { &hf_z3950_attributeSet  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_AttributeSetId },
  { &hf_z3950_attributeElement_attributeType, BER_CLASS_CON, 120, BER_FLAGS_IMPLTAG, dissect_z3950_T_attributeElement_attributeType },
  { &hf_z3950_attributeValue, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_T_attributeValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_AttributeElement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeElement_sequence, hf_index, ett_z3950_AttributeElement);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AttributeElement_sequence_of[1] = {
  { &hf_z3950_attributeList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_AttributeElement },
};

static int
dissect_z3950_SEQUENCE_OF_AttributeElement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_AttributeElement_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_AttributeElement);

  return offset;
}



static int
dissect_z3950_AttributeList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 44, TRUE, dissect_z3950_SEQUENCE_OF_AttributeElement);

  return offset;
}



static int
dissect_z3950_T_general(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 147 "./asn1/z3950/z3950.cnf"
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
              hf_index, BER_CLASS_CON, 2, TRUE,
              dissect_z3950_printable_OCTET_STRING);



  return offset;
}



static int
dissect_z3950_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t Unit_sequence[] = {
  { &hf_z3950_unitSystem    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_z3950_InternationalString },
  { &hf_z3950_unitType      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_z3950_StringOrNumeric },
  { &hf_z3950_unit          , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_z3950_StringOrNumeric },
  { &hf_z3950_scaleFactor   , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_Unit(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Unit_sequence, hf_index, ett_z3950_Unit);

  return offset;
}


static const ber_sequence_t IntUnit_sequence[] = {
  { &hf_z3950_value         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_unitUsed      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_Unit },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_IntUnit(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IntUnit_sequence, hf_index, ett_z3950_IntUnit);

  return offset;
}


static const value_string z3950_Term_vals[] = {
  {  45, "general" },
  { 215, "numeric" },
  { 216, "characterString" },
  { 217, "oid" },
  { 218, "dateTime" },
  { 219, "external" },
  { 220, "integerAndUnit" },
  { 221, "null" },
  { 0, NULL }
};

static const ber_choice_t Term_choice[] = {
  {  45, &hf_z3950_general       , BER_CLASS_CON, 45, BER_FLAGS_IMPLTAG, dissect_z3950_T_general },
  { 215, &hf_z3950_numeric       , BER_CLASS_CON, 215, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { 216, &hf_z3950_characterString, BER_CLASS_CON, 216, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { 217, &hf_z3950_oid           , BER_CLASS_CON, 217, BER_FLAGS_IMPLTAG, dissect_z3950_OBJECT_IDENTIFIER },
  { 218, &hf_z3950_dateTime      , BER_CLASS_CON, 218, BER_FLAGS_IMPLTAG, dissect_z3950_GeneralizedTime },
  { 219, &hf_z3950_external      , BER_CLASS_CON, 219, BER_FLAGS_IMPLTAG, dissect_z3950_EXTERNAL },
  { 220, &hf_z3950_integerAndUnit, BER_CLASS_CON, 220, BER_FLAGS_IMPLTAG, dissect_z3950_IntUnit },
  { 221, &hf_z3950_null          , BER_CLASS_CON, 221, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_Term(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Term_choice, hf_index, ett_z3950_Term,
                                 NULL);

  return offset;
}


static const ber_sequence_t AttributesPlusTerm_U_sequence[] = {
  { &hf_z3950_attributes    , BER_CLASS_CON, 44, BER_FLAGS_NOOWNTAG, dissect_z3950_AttributeList },
  { &hf_z3950_term          , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_Term },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_AttributesPlusTerm_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributesPlusTerm_U_sequence, hf_index, ett_z3950_AttributesPlusTerm_U);

  return offset;
}



static int
dissect_z3950_AttributesPlusTerm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 102, TRUE, dissect_z3950_AttributesPlusTerm_U);

  return offset;
}



static int
dissect_z3950_ResultSetId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 31, TRUE, dissect_z3950_InternationalString);

  return offset;
}


static const ber_sequence_t ResultSetPlusAttributes_U_sequence[] = {
  { &hf_z3950_resultSet     , BER_CLASS_CON, 31, BER_FLAGS_NOOWNTAG, dissect_z3950_ResultSetId },
  { &hf_z3950_attributes    , BER_CLASS_CON, 44, BER_FLAGS_NOOWNTAG, dissect_z3950_AttributeList },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ResultSetPlusAttributes_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ResultSetPlusAttributes_U_sequence, hf_index, ett_z3950_ResultSetPlusAttributes_U);

  return offset;
}



static int
dissect_z3950_ResultSetPlusAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 214, TRUE, dissect_z3950_ResultSetPlusAttributes_U);

  return offset;
}


static const value_string z3950_Operand_vals[] = {
  { 102, "attrTerm" },
  {  31, "resultSet" },
  { 214, "resultAttr" },
  { 0, NULL }
};

static const ber_choice_t Operand_choice[] = {
  { 102, &hf_z3950_attrTerm      , BER_CLASS_CON, 102, BER_FLAGS_NOOWNTAG, dissect_z3950_AttributesPlusTerm },
  {  31, &hf_z3950_resultSet     , BER_CLASS_CON, 31, BER_FLAGS_NOOWNTAG, dissect_z3950_ResultSetId },
  { 214, &hf_z3950_resultAttr    , BER_CLASS_CON, 214, BER_FLAGS_NOOWNTAG, dissect_z3950_ResultSetPlusAttributes },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_Operand(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Operand_choice, hf_index, ett_z3950_Operand,
                                 NULL);

  return offset;
}


static const value_string z3950_T_relationType_vals[] = {
  {   1, "lessThan" },
  {   2, "lessThanOrEqual" },
  {   3, "equal" },
  {   4, "greaterThanOrEqual" },
  {   5, "greaterThan" },
  {   6, "notEqual" },
  { 0, NULL }
};


static int
dissect_z3950_T_relationType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string z3950_KnownProximityUnit_vals[] = {
  {   1, "character" },
  {   2, "word" },
  {   3, "sentence" },
  {   4, "paragraph" },
  {   5, "section" },
  {   6, "chapter" },
  {   7, "document" },
  {   8, "element" },
  {   9, "subelement" },
  {  10, "elementType" },
  {  11, "byte" },
  { 0, NULL }
};


static int
dissect_z3950_KnownProximityUnit(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string z3950_T_proximityUnitCode_vals[] = {
  {   1, "known" },
  {   2, "private" },
  { 0, NULL }
};

static const ber_choice_t T_proximityUnitCode_choice[] = {
  {   1, &hf_z3950_known         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_KnownProximityUnit },
  {   2, &hf_z3950_private       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_proximityUnitCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_proximityUnitCode_choice, hf_index, ett_z3950_T_proximityUnitCode,
                                 NULL);

  return offset;
}


static const ber_sequence_t ProximityOperator_sequence[] = {
  { &hf_z3950_exclusion     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_distance      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_ordered       , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_relationType  , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_z3950_T_relationType },
  { &hf_z3950_proximityUnitCode, BER_CLASS_CON, 5, 0, dissect_z3950_T_proximityUnitCode },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ProximityOperator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProximityOperator_sequence, hf_index, ett_z3950_ProximityOperator);

  return offset;
}


static const value_string z3950_Operator_U_vals[] = {
  {   0, "and" },
  {   1, "or" },
  {   2, "and-not" },
  {   3, "prox" },
  { 0, NULL }
};

static const ber_choice_t Operator_U_choice[] = {
  {   0, &hf_z3950_and           , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   1, &hf_z3950_or            , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   2, &hf_z3950_and_not       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   3, &hf_z3950_prox          , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_ProximityOperator },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_Operator_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Operator_U_choice, hf_index, ett_z3950_Operator_U,
                                 NULL);

  return offset;
}



static int
dissect_z3950_Operator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 46, FALSE, dissect_z3950_Operator_U);

  return offset;
}


static const ber_sequence_t T_rpnRpnOp_sequence[] = {
  { &hf_z3950_rpn1          , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_RPNStructure },
  { &hf_z3950_rpn2          , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_RPNStructure },
  { &hf_z3950_operatorRpnOp , BER_CLASS_CON, 46, BER_FLAGS_NOOWNTAG, dissect_z3950_Operator },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_rpnRpnOp(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_rpnRpnOp_sequence, hf_index, ett_z3950_T_rpnRpnOp);

  return offset;
}


static const value_string z3950_RPNStructure_vals[] = {
  {   0, "op" },
  {   1, "rpnRpnOp" },
  { 0, NULL }
};

static const ber_choice_t RPNStructure_choice[] = {
  {   0, &hf_z3950_operandRpnOp  , BER_CLASS_CON, 0, 0, dissect_z3950_Operand },
  {   1, &hf_z3950_rpnRpnOp      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_T_rpnRpnOp },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_RPNStructure(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RPNStructure_choice, hf_index, ett_z3950_RPNStructure,
                                 NULL);

  return offset;
}


static const ber_sequence_t RPNQuery_sequence[] = {
  { &hf_z3950_attributeSet  , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_z3950_AttributeSetId },
  { &hf_z3950_rpn           , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_RPNStructure },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_RPNQuery(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RPNQuery_sequence, hf_index, ett_z3950_RPNQuery);

  return offset;
}


static const value_string z3950_Query_vals[] = {
  {   0, "type-0" },
  {   1, "type-1" },
  {   2, "type-2" },
  { 100, "type-100" },
  { 101, "type-101" },
  { 102, "type-102" },
  { 0, NULL }
};

static const ber_choice_t Query_choice[] = {
  {   0, &hf_z3950_type_0        , BER_CLASS_CON, 0, 0, dissect_z3950_T_type_0 },
  {   1, &hf_z3950_type_1        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_RPNQuery },
  {   2, &hf_z3950_type_2        , BER_CLASS_CON, 2, 0, dissect_z3950_OCTET_STRING },
  { 100, &hf_z3950_type_100      , BER_CLASS_CON, 100, 0, dissect_z3950_OCTET_STRING },
  { 101, &hf_z3950_type_101      , BER_CLASS_CON, 101, BER_FLAGS_IMPLTAG, dissect_z3950_RPNQuery },
  { 102, &hf_z3950_type_102      , BER_CLASS_CON, 102, 0, dissect_z3950_OCTET_STRING },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_Query(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Query_choice, hf_index, ett_z3950_Query,
                                 NULL);

  return offset;
}


static const ber_sequence_t SearchRequest_sequence[] = {
  { &hf_z3950_referenceId   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_ReferenceId },
  { &hf_z3950_smallSetUpperBound, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_largeSetLowerBound, BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_mediumSetPresentNumber, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_replaceIndicator, BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_resultSetName , BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_databaseNames , BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_DatabaseName },
  { &hf_z3950_smallSetElementSetNames, BER_CLASS_CON, 100, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_z3950_ElementSetNames },
  { &hf_z3950_mediumSetElementSetNames, BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_z3950_ElementSetNames },
  { &hf_z3950_preferredRecordSyntax, BER_CLASS_CON, 104, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_OBJECT_IDENTIFIER },
  { &hf_z3950_query         , BER_CLASS_CON, 21, BER_FLAGS_NOTCHKTAG, dissect_z3950_Query },
  { &hf_z3950_additionalSearchInfo, BER_CLASS_CON, 203, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_OtherInformation },
  { &hf_z3950_otherInfo     , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_SearchRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SearchRequest_sequence, hf_index, ett_z3950_SearchRequest);

  return offset;
}


static const value_string z3950_T_search_resultSetStatus_vals[] = {
  {   1, "subset" },
  {   2, "interim" },
  {   3, "none" },
  { 0, NULL }
};


static int
dissect_z3950_T_search_resultSetStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string z3950_PresentStatus_U_vals[] = {
  {   0, "success" },
  {   1, "partial-1" },
  {   2, "partial-2" },
  {   3, "partial-3" },
  {   4, "partial-4" },
  {   5, "failure" },
  { 0, NULL }
};


static int
dissect_z3950_PresentStatus_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_z3950_PresentStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 27, TRUE, dissect_z3950_PresentStatus_U);

  return offset;
}



static int
dissect_z3950_T_diagnosticSetId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 228 "./asn1/z3950/z3950.cnf"
  tvbuff_t *oid_tvb=NULL;


  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, &oid_tvb);

#line 232 "./asn1/z3950/z3950.cnf"
  if (oid_tvb) {
    guint len = tvb_reported_length_remaining(oid_tvb, 0);
    gchar *oid_str = oid_encoded2string(wmem_packet_scope(),
                                        tvb_get_ptr(oid_tvb, 0, len), len);
    gint diagset_idx = Z3950_DIAGSET_UNKNOWN;
    z3950_diaginfo_t *diaginfo_data;
    packet_info *pinfo = actx->pinfo;

    if (g_strcmp0(oid_str, Z3950_DIAGSET_BIB1_OID) == 0) {
      diagset_idx = Z3950_DIAGSET_BIB1;
    }
    if ((diaginfo_data = (z3950_diaginfo_t *)p_get_proto_data(pinfo->pool, pinfo, proto_z3950, Z3950_DIAGSET_KEY)) == NULL) {

      diaginfo_data = wmem_new0(pinfo->pool, z3950_diaginfo_t);
      diaginfo_data->diagsetidx = diagset_idx;
      p_add_proto_data(pinfo->pool, pinfo,
                       proto_z3950, Z3950_DIAGSET_KEY, diaginfo_data);
    }
    else {
      diaginfo_data->diagsetidx = diagset_idx;
    }
  }


  return offset;
}



static int
dissect_z3950_T_condition(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 256 "./asn1/z3950/z3950.cnf"
  gint diag_condition=0;
  packet_info *pinfo = actx->pinfo;
  z3950_diaginfo_t *diaginfo_data;

  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &diag_condition);

#line 261 "./asn1/z3950/z3950.cnf"
  diaginfo_data = (z3950_diaginfo_t *)p_get_proto_data(pinfo->pool, pinfo, proto_z3950, Z3950_DIAGSET_KEY);
  if (diaginfo_data && diaginfo_data->diagsetidx == Z3950_DIAGSET_BIB1) {
    proto_item_append_text(actx->created_item, " (%s)",
      val_to_str(diag_condition, z3950_bib1_diagconditions, "Unknown bib-1 diagnostic %d"));
    diaginfo_data->diagcondition = diag_condition;
  }

  return offset;
}


static const value_string z3950_T_addinfo_vals[] = {
  {   0, "v2Addinfo" },
  {   1, "v3Addinfo" },
  { 0, NULL }
};

static const ber_choice_t T_addinfo_choice[] = {
  {   0, &hf_z3950_v2Addinfo     , BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_z3950_VisibleString },
  {   1, &hf_z3950_v3Addinfo     , BER_CLASS_UNI, BER_UNI_TAG_GeneralString, BER_FLAGS_NOOWNTAG, dissect_z3950_InternationalString },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_addinfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_addinfo_choice, hf_index, ett_z3950_T_addinfo,
                                 NULL);

  return offset;
}


static const ber_sequence_t DefaultDiagFormat_sequence[] = {
  { &hf_z3950_diagnosticSetId, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_z3950_T_diagnosticSetId },
  { &hf_z3950_condition     , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_z3950_T_condition },
  { &hf_z3950_addinfo       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_T_addinfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_DefaultDiagFormat(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DefaultDiagFormat_sequence, hf_index, ett_z3950_DefaultDiagFormat);

  return offset;
}


static const value_string z3950_DiagRec_vals[] = {
  {   0, "defaultFormat" },
  {   1, "externallyDefined" },
  { 0, NULL }
};

static const ber_choice_t DiagRec_choice[] = {
  {   0, &hf_z3950_defaultFormat , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_DefaultDiagFormat },
  {   1, &hf_z3950_externallyDefined, BER_CLASS_UNI, BER_UNI_TAG_EXTERNAL, BER_FLAGS_NOOWNTAG, dissect_z3950_EXTERNAL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_DiagRec(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DiagRec_choice, hf_index, ett_z3950_DiagRec,
                                 NULL);

  return offset;
}


static const value_string z3950_FragmentSyntax_vals[] = {
  {   0, "externallyTagged" },
  {   1, "notExternallyTagged" },
  { 0, NULL }
};

static const ber_choice_t FragmentSyntax_choice[] = {
  {   0, &hf_z3950_externallyTagged, BER_CLASS_UNI, BER_UNI_TAG_EXTERNAL, BER_FLAGS_NOOWNTAG, dissect_z3950_EXTERNAL },
  {   1, &hf_z3950_notExternallyTagged, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_z3950_OCTET_STRING },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_FragmentSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 FragmentSyntax_choice, hf_index, ett_z3950_FragmentSyntax,
                                 NULL);

  return offset;
}


static const value_string z3950_T_record_vals[] = {
  {   1, "retrievalRecord" },
  {   2, "surrogateDiagnostic" },
  {   3, "startingFragment" },
  {   4, "intermediateFragment" },
  {   5, "finalFragment" },
  { 0, NULL }
};

static const ber_choice_t T_record_choice[] = {
  {   1, &hf_z3950_retrievalRecord, BER_CLASS_CON, 1, 0, dissect_z3950_EXTERNAL },
  {   2, &hf_z3950_surrogateDiagnostic, BER_CLASS_CON, 2, 0, dissect_z3950_DiagRec },
  {   3, &hf_z3950_startingFragment, BER_CLASS_CON, 3, 0, dissect_z3950_FragmentSyntax },
  {   4, &hf_z3950_intermediateFragment, BER_CLASS_CON, 4, 0, dissect_z3950_FragmentSyntax },
  {   5, &hf_z3950_finalFragment , BER_CLASS_CON, 5, 0, dissect_z3950_FragmentSyntax },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_record(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_record_choice, hf_index, ett_z3950_T_record,
                                 NULL);

  return offset;
}


static const ber_sequence_t NamePlusRecord_sequence[] = {
  { &hf_z3950_namePlusRecord_name, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_DatabaseName },
  { &hf_z3950_record        , BER_CLASS_CON, 1, 0, dissect_z3950_T_record },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_NamePlusRecord(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NamePlusRecord_sequence, hf_index, ett_z3950_NamePlusRecord);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_NamePlusRecord_sequence_of[1] = {
  { &hf_z3950_segmentRecords_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_NamePlusRecord },
};

static int
dissect_z3950_SEQUENCE_OF_NamePlusRecord(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_NamePlusRecord_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_NamePlusRecord);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_DiagRec_sequence_of[1] = {
  { &hf_z3950_multipleNonSurDiagnostics_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_DiagRec },
};

static int
dissect_z3950_SEQUENCE_OF_DiagRec(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_DiagRec_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_DiagRec);

  return offset;
}


static const value_string z3950_Records_vals[] = {
  {  28, "responseRecords" },
  { 130, "nonSurrogateDiagnostic" },
  { 205, "multipleNonSurDiagnostics" },
  { 0, NULL }
};

static const ber_choice_t Records_choice[] = {
  {  28, &hf_z3950_responseRecords, BER_CLASS_CON, 28, BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_NamePlusRecord },
  { 130, &hf_z3950_nonSurrogateDiagnostic, BER_CLASS_CON, 130, BER_FLAGS_IMPLTAG, dissect_z3950_DefaultDiagFormat },
  { 205, &hf_z3950_multipleNonSurDiagnostics, BER_CLASS_CON, 205, BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_DiagRec },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_Records(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Records_choice, hf_index, ett_z3950_Records,
                                 NULL);

  return offset;
}


static const ber_sequence_t SearchResponse_sequence[] = {
  { &hf_z3950_referenceId   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_ReferenceId },
  { &hf_z3950_resultCount   , BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_numberOfRecordsReturned, BER_CLASS_CON, 24, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_nextResultSetPosition, BER_CLASS_CON, 25, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_searchStatus  , BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_search_resultSetStatus, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_search_resultSetStatus },
  { &hf_z3950_presentStatus , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_PresentStatus },
  { &hf_z3950_records       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_Records },
  { &hf_z3950_additionalSearchInfo, BER_CLASS_CON, 203, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_OtherInformation },
  { &hf_z3950_otherInfo     , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_SearchResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SearchResponse_sequence, hf_index, ett_z3950_SearchResponse);

  return offset;
}


static const ber_sequence_t Range_sequence[] = {
  { &hf_z3950_startingPosition, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_numberOfRecords, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_Range(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Range_sequence, hf_index, ett_z3950_Range);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Range_sequence_of[1] = {
  { &hf_z3950_additionalRanges_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_Range },
};

static int
dissect_z3950_SEQUENCE_OF_Range(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Range_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_Range);

  return offset;
}


static const value_string z3950_T_specification_elementSpec_vals[] = {
  {   1, "elementSetName" },
  {   2, "externalEspec" },
  { 0, NULL }
};

static const ber_choice_t T_specification_elementSpec_choice[] = {
  {   1, &hf_z3950_elementSetName, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  {   2, &hf_z3950_externalEspec , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_EXTERNAL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_specification_elementSpec(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_specification_elementSpec_choice, hf_index, ett_z3950_T_specification_elementSpec,
                                 NULL);

  return offset;
}


static const ber_sequence_t Specification_sequence[] = {
  { &hf_z3950_schema        , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_OBJECT_IDENTIFIER },
  { &hf_z3950_specification_elementSpec, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_z3950_T_specification_elementSpec },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_Specification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Specification_sequence, hf_index, ett_z3950_Specification);

  return offset;
}


static const ber_sequence_t T_dbSpecific_item_sequence[] = {
  { &hf_z3950_db            , BER_CLASS_CON, 1, 0, dissect_z3950_DatabaseName },
  { &hf_z3950_spec          , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_Specification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_dbSpecific_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_dbSpecific_item_sequence, hf_index, ett_z3950_T_dbSpecific_item);

  return offset;
}


static const ber_sequence_t T_dbSpecific_sequence_of[1] = {
  { &hf_z3950_dbSpecific_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_T_dbSpecific_item },
};

static int
dissect_z3950_T_dbSpecific(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_dbSpecific_sequence_of, hf_index, ett_z3950_T_dbSpecific);

  return offset;
}


static const ber_sequence_t T_compSpec_recordSyntax_sequence_of[1] = {
  { &hf_z3950_compSpec_recordSyntax_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_z3950_OBJECT_IDENTIFIER },
};

static int
dissect_z3950_T_compSpec_recordSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_compSpec_recordSyntax_sequence_of, hf_index, ett_z3950_T_compSpec_recordSyntax);

  return offset;
}


static const ber_sequence_t CompSpec_sequence[] = {
  { &hf_z3950_selectAlternativeSyntax, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_compSpec_generic, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_Specification },
  { &hf_z3950_dbSpecific    , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_dbSpecific },
  { &hf_z3950_compSpec_recordSyntax, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_compSpec_recordSyntax },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_CompSpec(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CompSpec_sequence, hf_index, ett_z3950_CompSpec);

  return offset;
}


static const value_string z3950_T_recordComposition_vals[] = {
  {  19, "simple" },
  { 209, "complex" },
  { 0, NULL }
};

static const ber_choice_t T_recordComposition_choice[] = {
  {  19, &hf_z3950_simple        , BER_CLASS_CON, 19, 0, dissect_z3950_ElementSetNames },
  { 209, &hf_z3950_recordComposition_complex, BER_CLASS_CON, 209, BER_FLAGS_IMPLTAG, dissect_z3950_CompSpec },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_recordComposition(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_recordComposition_choice, hf_index, ett_z3950_T_recordComposition,
                                 NULL);

  return offset;
}


static const ber_sequence_t PresentRequest_sequence[] = {
  { &hf_z3950_referenceId   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_ReferenceId },
  { &hf_z3950_resultSetId   , BER_CLASS_CON, 31, BER_FLAGS_NOOWNTAG, dissect_z3950_ResultSetId },
  { &hf_z3950_resultSetStartPoint, BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_numberOfRecordsRequested, BER_CLASS_CON, 29, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_additionalRanges, BER_CLASS_CON, 212, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_Range },
  { &hf_z3950_recordComposition, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_T_recordComposition },
  { &hf_z3950_preferredRecordSyntax, BER_CLASS_CON, 104, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_OBJECT_IDENTIFIER },
  { &hf_z3950_maxSegmentCount, BER_CLASS_CON, 204, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_maxRecordSize , BER_CLASS_CON, 206, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_maxSegmentSize, BER_CLASS_CON, 207, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_otherInfo     , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_PresentRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PresentRequest_sequence, hf_index, ett_z3950_PresentRequest);

  return offset;
}


static const ber_sequence_t PresentResponse_sequence[] = {
  { &hf_z3950_referenceId   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_ReferenceId },
  { &hf_z3950_numberOfRecordsReturned, BER_CLASS_CON, 24, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_nextResultSetPosition, BER_CLASS_CON, 25, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_presentStatus , BER_CLASS_CON, 27, BER_FLAGS_NOOWNTAG, dissect_z3950_PresentStatus },
  { &hf_z3950_records       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_Records },
  { &hf_z3950_otherInfo     , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_PresentResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PresentResponse_sequence, hf_index, ett_z3950_PresentResponse);

  return offset;
}


static const value_string z3950_T_deleteFunction_vals[] = {
  {   0, "list" },
  {   1, "all" },
  { 0, NULL }
};


static int
dissect_z3950_T_deleteFunction(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ResultSetId_sequence_of[1] = {
  { &hf_z3950_resultSetList_item, BER_CLASS_CON, 31, BER_FLAGS_NOOWNTAG, dissect_z3950_ResultSetId },
};

static int
dissect_z3950_SEQUENCE_OF_ResultSetId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ResultSetId_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_ResultSetId);

  return offset;
}


static const ber_sequence_t DeleteResultSetRequest_sequence[] = {
  { &hf_z3950_referenceId   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_ReferenceId },
  { &hf_z3950_deleteFunction, BER_CLASS_CON, 32, BER_FLAGS_IMPLTAG, dissect_z3950_T_deleteFunction },
  { &hf_z3950_resultSetList , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_SEQUENCE_OF_ResultSetId },
  { &hf_z3950_otherInfo     , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_DeleteResultSetRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeleteResultSetRequest_sequence, hf_index, ett_z3950_DeleteResultSetRequest);

  return offset;
}


static const value_string z3950_DeleteSetStatus_U_vals[] = {
  {   0, "success" },
  {   1, "resultSetDidNotExist" },
  {   2, "previouslyDeletedByTarget" },
  {   3, "systemProblemAtTarget" },
  {   4, "accessNotAllowed" },
  {   5, "resourceControlAtOrigin" },
  {   6, "resourceControlAtTarget" },
  {   7, "bulkDeleteNotSupported" },
  {   8, "notAllRsltSetsDeletedOnBulkDlte" },
  {   9, "notAllRequestedResultSetsDeleted" },
  {  10, "resultSetInUse" },
  { 0, NULL }
};


static int
dissect_z3950_DeleteSetStatus_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_z3950_DeleteSetStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 33, TRUE, dissect_z3950_DeleteSetStatus_U);

  return offset;
}


static const ber_sequence_t ListStatuses_item_sequence[] = {
  { &hf_z3950_listStatuses_id, BER_CLASS_CON, 31, BER_FLAGS_NOOWNTAG, dissect_z3950_ResultSetId },
  { &hf_z3950_status        , BER_CLASS_CON, 33, BER_FLAGS_NOOWNTAG, dissect_z3950_DeleteSetStatus },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ListStatuses_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ListStatuses_item_sequence, hf_index, ett_z3950_ListStatuses_item);

  return offset;
}


static const ber_sequence_t ListStatuses_sequence_of[1] = {
  { &hf_z3950_ListStatuses_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_ListStatuses_item },
};

static int
dissect_z3950_ListStatuses(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      ListStatuses_sequence_of, hf_index, ett_z3950_ListStatuses);

  return offset;
}


static const ber_sequence_t DeleteResultSetResponse_sequence[] = {
  { &hf_z3950_referenceId   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_ReferenceId },
  { &hf_z3950_deleteOperationStatus, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_DeleteSetStatus },
  { &hf_z3950_deleteListStatuses, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_ListStatuses },
  { &hf_z3950_numberNotDeleted, BER_CLASS_CON, 34, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_bulkStatuses  , BER_CLASS_CON, 35, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_ListStatuses },
  { &hf_z3950_deleteMessage , BER_CLASS_CON, 36, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_otherInfo     , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_DeleteResultSetResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeleteResultSetResponse_sequence, hf_index, ett_z3950_DeleteResultSetResponse);

  return offset;
}


static const value_string z3950_T_securityChallenge_vals[] = {
  {  37, "simpleForm" },
  {   0, "externallyDefined" },
  { 0, NULL }
};

static const ber_choice_t T_securityChallenge_choice[] = {
  {  37, &hf_z3950_simpleForm    , BER_CLASS_CON, 37, BER_FLAGS_IMPLTAG, dissect_z3950_OCTET_STRING },
  {   0, &hf_z3950_externallyDefined, BER_CLASS_CON, 0, 0, dissect_z3950_EXTERNAL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_securityChallenge(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_securityChallenge_choice, hf_index, ett_z3950_T_securityChallenge,
                                 NULL);

  return offset;
}


static const ber_sequence_t AccessControlRequest_sequence[] = {
  { &hf_z3950_referenceId   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_ReferenceId },
  { &hf_z3950_securityChallenge, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_T_securityChallenge },
  { &hf_z3950_otherInfo     , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_AccessControlRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AccessControlRequest_sequence, hf_index, ett_z3950_AccessControlRequest);

  return offset;
}


static const value_string z3950_T_securityChallengeResponse_vals[] = {
  {  38, "simpleForm" },
  {   0, "externallyDefined" },
  { 0, NULL }
};

static const ber_choice_t T_securityChallengeResponse_choice[] = {
  {  38, &hf_z3950_simpleForm    , BER_CLASS_CON, 38, BER_FLAGS_IMPLTAG, dissect_z3950_OCTET_STRING },
  {   0, &hf_z3950_externallyDefined, BER_CLASS_CON, 0, 0, dissect_z3950_EXTERNAL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_securityChallengeResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_securityChallengeResponse_choice, hf_index, ett_z3950_T_securityChallengeResponse,
                                 NULL);

  return offset;
}


static const ber_sequence_t AccessControlResponse_sequence[] = {
  { &hf_z3950_referenceId   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_ReferenceId },
  { &hf_z3950_securityChallengeResponse, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_T_securityChallengeResponse },
  { &hf_z3950_diagnostic    , BER_CLASS_CON, 223, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_z3950_DiagRec },
  { &hf_z3950_otherInfo     , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_AccessControlResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AccessControlResponse_sequence, hf_index, ett_z3950_AccessControlResponse);

  return offset;
}



static int
dissect_z3950_ResourceReport(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_external_type(implicit_tag, tree, tvb, offset, actx, hf_index, NULL);

  return offset;
}


static const value_string z3950_T_partialResultsAvailable_vals[] = {
  {   1, "subset" },
  {   2, "interim" },
  {   3, "none" },
  { 0, NULL }
};


static int
dissect_z3950_T_partialResultsAvailable(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ResourceControlRequest_sequence[] = {
  { &hf_z3950_referenceId   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_ReferenceId },
  { &hf_z3950_suspendedFlag , BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_resourceReport, BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL, dissect_z3950_ResourceReport },
  { &hf_z3950_partialResultsAvailable, BER_CLASS_CON, 41, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_partialResultsAvailable },
  { &hf_z3950_resourceControlRequest_responseRequired, BER_CLASS_CON, 42, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_triggeredRequestFlag, BER_CLASS_CON, 43, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_otherInfo     , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ResourceControlRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ResourceControlRequest_sequence, hf_index, ett_z3950_ResourceControlRequest);

  return offset;
}


static const ber_sequence_t ResourceControlResponse_sequence[] = {
  { &hf_z3950_referenceId   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_ReferenceId },
  { &hf_z3950_continueFlag  , BER_CLASS_CON, 44, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_resultSetWanted, BER_CLASS_CON, 45, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_otherInfo     , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ResourceControlResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ResourceControlResponse_sequence, hf_index, ett_z3950_ResourceControlResponse);

  return offset;
}


static const value_string z3950_T_requestedAction_vals[] = {
  {   1, "resourceReport" },
  {   2, "resourceControl" },
  {   3, "cancel" },
  { 0, NULL }
};


static int
dissect_z3950_T_requestedAction(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_z3950_ResourceReportId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t TriggerResourceControlRequest_sequence[] = {
  { &hf_z3950_referenceId   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_ReferenceId },
  { &hf_z3950_requestedAction, BER_CLASS_CON, 46, BER_FLAGS_IMPLTAG, dissect_z3950_T_requestedAction },
  { &hf_z3950_prefResourceReportFormat, BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_ResourceReportId },
  { &hf_z3950_resultSetWanted, BER_CLASS_CON, 48, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_otherInfo     , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_TriggerResourceControlRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TriggerResourceControlRequest_sequence, hf_index, ett_z3950_TriggerResourceControlRequest);

  return offset;
}


static const ber_sequence_t ResourceReportRequest_sequence[] = {
  { &hf_z3950_referenceId   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_ReferenceId },
  { &hf_z3950_opId          , BER_CLASS_CON, 210, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_ReferenceId },
  { &hf_z3950_prefResourceReportFormat, BER_CLASS_CON, 49, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_ResourceReportId },
  { &hf_z3950_otherInfo     , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ResourceReportRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ResourceReportRequest_sequence, hf_index, ett_z3950_ResourceReportRequest);

  return offset;
}


static const value_string z3950_T_resourceReportStatus_vals[] = {
  {   0, "success" },
  {   1, "partial" },
  {   2, "failure-1" },
  {   3, "failure-2" },
  {   4, "failure-3" },
  {   5, "failure-4" },
  {   6, "failure-5" },
  {   7, "failure-6" },
  { 0, NULL }
};


static int
dissect_z3950_T_resourceReportStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ResourceReportResponse_sequence[] = {
  { &hf_z3950_referenceId   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_ReferenceId },
  { &hf_z3950_resourceReportStatus, BER_CLASS_CON, 50, BER_FLAGS_IMPLTAG, dissect_z3950_T_resourceReportStatus },
  { &hf_z3950_resourceReport, BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL, dissect_z3950_ResourceReport },
  { &hf_z3950_otherInfo     , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ResourceReportResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ResourceReportResponse_sequence, hf_index, ett_z3950_ResourceReportResponse);

  return offset;
}


static const ber_sequence_t ScanRequest_sequence[] = {
  { &hf_z3950_referenceId   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_ReferenceId },
  { &hf_z3950_databaseNames , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_DatabaseName },
  { &hf_z3950_attributeSet  , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_AttributeSetId },
  { &hf_z3950_termListAndStartPoint, BER_CLASS_CON, 102, BER_FLAGS_NOOWNTAG, dissect_z3950_AttributesPlusTerm },
  { &hf_z3950_stepSize      , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_numberOfTermsRequested, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_preferredPositionInResponse, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_otherInfo     , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ScanRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ScanRequest_sequence, hf_index, ett_z3950_ScanRequest);

  return offset;
}


static const value_string z3950_T_scanStatus_vals[] = {
  {   0, "success" },
  {   1, "partial-1" },
  {   2, "partial-2" },
  {   3, "partial-3" },
  {   4, "partial-4" },
  {   5, "partial-5" },
  {   6, "failure" },
  { 0, NULL }
};


static int
dissect_z3950_T_scanStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AttributesPlusTerm_sequence_of[1] = {
  { &hf_z3950_alternativeTerm_item, BER_CLASS_CON, 102, BER_FLAGS_NOOWNTAG, dissect_z3950_AttributesPlusTerm },
};

static int
dissect_z3950_SEQUENCE_OF_AttributesPlusTerm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_AttributesPlusTerm_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_AttributesPlusTerm);

  return offset;
}


static const ber_sequence_t T_byDatabase_item_sequence[] = {
  { &hf_z3950_db            , BER_CLASS_CON, 105, BER_FLAGS_NOOWNTAG, dissect_z3950_DatabaseName },
  { &hf_z3950_num           , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_otherDbInfo   , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_byDatabase_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_byDatabase_item_sequence, hf_index, ett_z3950_T_byDatabase_item);

  return offset;
}


static const ber_sequence_t T_byDatabase_sequence_of[1] = {
  { &hf_z3950_byDatabase_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_T_byDatabase_item },
};

static int
dissect_z3950_T_byDatabase(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_byDatabase_sequence_of, hf_index, ett_z3950_T_byDatabase);

  return offset;
}


static const value_string z3950_T_occurrences_vals[] = {
  {   2, "global" },
  {   3, "byDatabase" },
  { 0, NULL }
};

static const ber_choice_t T_occurrences_choice[] = {
  {   2, &hf_z3950_global        , BER_CLASS_CON, 2, 0, dissect_z3950_INTEGER },
  {   3, &hf_z3950_byDatabase    , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_T_byDatabase },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_occurrences(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_occurrences_choice, hf_index, ett_z3950_T_occurrences,
                                 NULL);

  return offset;
}


static const ber_sequence_t OccurrenceByAttributes_item_sequence[] = {
  { &hf_z3950_attributes    , BER_CLASS_CON, 1, 0, dissect_z3950_AttributeList },
  { &hf_z3950_occurrences   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_T_occurrences },
  { &hf_z3950_otherOccurInfo, BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_OccurrenceByAttributes_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OccurrenceByAttributes_item_sequence, hf_index, ett_z3950_OccurrenceByAttributes_item);

  return offset;
}


static const ber_sequence_t OccurrenceByAttributes_sequence_of[1] = {
  { &hf_z3950_OccurrenceByAttributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_OccurrenceByAttributes_item },
};

static int
dissect_z3950_OccurrenceByAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      OccurrenceByAttributes_sequence_of, hf_index, ett_z3950_OccurrenceByAttributes);

  return offset;
}


static const ber_sequence_t TermInfo_sequence[] = {
  { &hf_z3950_term          , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_Term },
  { &hf_z3950_displayTerm   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_suggestedAttributes, BER_CLASS_CON, 44, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_AttributeList },
  { &hf_z3950_alternativeTerm, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_AttributesPlusTerm },
  { &hf_z3950_globalOccurrences, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_byAttributes  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_OccurrenceByAttributes },
  { &hf_z3950_otherTermInfo , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_TermInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TermInfo_sequence, hf_index, ett_z3950_TermInfo);

  return offset;
}


static const value_string z3950_Entry_vals[] = {
  {   1, "termInfo" },
  {   2, "surrogateDiagnostic" },
  { 0, NULL }
};

static const ber_choice_t Entry_choice[] = {
  {   1, &hf_z3950_termInfo      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_TermInfo },
  {   2, &hf_z3950_surrogateDiagnostic, BER_CLASS_CON, 2, 0, dissect_z3950_DiagRec },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_Entry(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Entry_choice, hf_index, ett_z3950_Entry,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Entry_sequence_of[1] = {
  { &hf_z3950_listEntries_entries_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_Entry },
};

static int
dissect_z3950_SEQUENCE_OF_Entry(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Entry_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_Entry);

  return offset;
}


static const ber_sequence_t ListEntries_sequence[] = {
  { &hf_z3950_listEntries_entries, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_Entry },
  { &hf_z3950_nonsurrogateDiagnostics, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_DiagRec },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ListEntries(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ListEntries_sequence, hf_index, ett_z3950_ListEntries);

  return offset;
}


static const ber_sequence_t ScanResponse_sequence[] = {
  { &hf_z3950_referenceId   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_ReferenceId },
  { &hf_z3950_stepSize      , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_scanStatus    , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_z3950_T_scanStatus },
  { &hf_z3950_numberOfEntriesReturned, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_positionOfTerm, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_scanResponse_entries, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_ListEntries },
  { &hf_z3950_attributeSet  , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_AttributeSetId },
  { &hf_z3950_otherInfo     , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ScanResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ScanResponse_sequence, hf_index, ett_z3950_ScanResponse);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_InternationalString_sequence_of[1] = {
  { &hf_z3950_inputResultSetNames_item, BER_CLASS_UNI, BER_UNI_TAG_GeneralString, BER_FLAGS_NOOWNTAG, dissect_z3950_InternationalString },
};

static int
dissect_z3950_SEQUENCE_OF_InternationalString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_InternationalString_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_InternationalString);

  return offset;
}


static const ber_sequence_t T_sortAttributes_sequence[] = {
  { &hf_z3950_sortAttributes_id, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_z3950_AttributeSetId },
  { &hf_z3950_sortAttributes_list, BER_CLASS_CON, 44, BER_FLAGS_NOOWNTAG, dissect_z3950_AttributeList },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_sortAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_sortAttributes_sequence, hf_index, ett_z3950_T_sortAttributes);

  return offset;
}


static const value_string z3950_SortKey_vals[] = {
  {   0, "sortfield" },
  {   1, "elementSpec" },
  {   2, "sortAttributes" },
  { 0, NULL }
};

static const ber_choice_t SortKey_choice[] = {
  {   0, &hf_z3950_sortfield     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  {   1, &hf_z3950_sortKey_elementSpec, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_Specification },
  {   2, &hf_z3950_sortAttributes, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_T_sortAttributes },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_SortKey(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SortKey_choice, hf_index, ett_z3950_SortKey,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_datbaseSpecific_item_sequence[] = {
  { &hf_z3950_databaseName  , BER_CLASS_CON, 105, BER_FLAGS_NOOWNTAG, dissect_z3950_DatabaseName },
  { &hf_z3950_dbSort        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_SortKey },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_datbaseSpecific_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_datbaseSpecific_item_sequence, hf_index, ett_z3950_T_datbaseSpecific_item);

  return offset;
}


static const ber_sequence_t T_datbaseSpecific_sequence_of[1] = {
  { &hf_z3950_datbaseSpecific_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_T_datbaseSpecific_item },
};

static int
dissect_z3950_T_datbaseSpecific(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_datbaseSpecific_sequence_of, hf_index, ett_z3950_T_datbaseSpecific);

  return offset;
}


static const value_string z3950_SortElement_vals[] = {
  {   1, "generic" },
  {   2, "datbaseSpecific" },
  { 0, NULL }
};

static const ber_choice_t SortElement_choice[] = {
  {   1, &hf_z3950_sortElement_generic, BER_CLASS_CON, 1, 0, dissect_z3950_SortKey },
  {   2, &hf_z3950_datbaseSpecific, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_T_datbaseSpecific },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_SortElement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SortElement_choice, hf_index, ett_z3950_SortElement,
                                 NULL);

  return offset;
}


static const value_string z3950_T_sortRelation_vals[] = {
  {   0, "ascending" },
  {   1, "descending" },
  {   3, "ascendingByFrequency" },
  {   4, "descendingByfrequency" },
  { 0, NULL }
};


static int
dissect_z3950_T_sortRelation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string z3950_T_caseSensitivity_vals[] = {
  {   0, "caseSensitive" },
  {   1, "caseInsensitive" },
  { 0, NULL }
};


static int
dissect_z3950_T_caseSensitivity(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string z3950_T_missingValueAction_vals[] = {
  {   1, "abort" },
  {   2, "null" },
  {   3, "missingValueData" },
  { 0, NULL }
};

static const ber_choice_t T_missingValueAction_choice[] = {
  {   1, &hf_z3950_abort         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   2, &hf_z3950_null          , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   3, &hf_z3950_missingValueData, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_OCTET_STRING },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_missingValueAction(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_missingValueAction_choice, hf_index, ett_z3950_T_missingValueAction,
                                 NULL);

  return offset;
}


static const ber_sequence_t SortKeySpec_sequence[] = {
  { &hf_z3950_sortElement   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_SortElement },
  { &hf_z3950_sortRelation  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_T_sortRelation },
  { &hf_z3950_caseSensitivity, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_T_caseSensitivity },
  { &hf_z3950_missingValueAction, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_z3950_T_missingValueAction },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_SortKeySpec(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SortKeySpec_sequence, hf_index, ett_z3950_SortKeySpec);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_SortKeySpec_sequence_of[1] = {
  { &hf_z3950_sortSequence_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_SortKeySpec },
};

static int
dissect_z3950_SEQUENCE_OF_SortKeySpec(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_SortKeySpec_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_SortKeySpec);

  return offset;
}


static const ber_sequence_t SortRequest_sequence[] = {
  { &hf_z3950_referenceId   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_ReferenceId },
  { &hf_z3950_inputResultSetNames, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_InternationalString },
  { &hf_z3950_sortedResultSetName, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_sortSequence  , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_SortKeySpec },
  { &hf_z3950_otherInfo     , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_SortRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SortRequest_sequence, hf_index, ett_z3950_SortRequest);

  return offset;
}


static const value_string z3950_T_sortStatus_vals[] = {
  {   0, "success" },
  {   1, "partial-1" },
  {   2, "failure" },
  { 0, NULL }
};


static int
dissect_z3950_T_sortStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string z3950_T_sort_resultSetStatus_vals[] = {
  {   1, "empty" },
  {   2, "interim" },
  {   3, "unchanged" },
  {   4, "none" },
  { 0, NULL }
};


static int
dissect_z3950_T_sort_resultSetStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SortResponse_sequence[] = {
  { &hf_z3950_referenceId   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_ReferenceId },
  { &hf_z3950_sortStatus    , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_T_sortStatus },
  { &hf_z3950_sort_resultSetStatus, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_sort_resultSetStatus },
  { &hf_z3950_diagnostics   , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_DiagRec },
  { &hf_z3950_otherInfo     , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_SortResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SortResponse_sequence, hf_index, ett_z3950_SortResponse);

  return offset;
}


static const ber_sequence_t Segment_sequence[] = {
  { &hf_z3950_referenceId   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_ReferenceId },
  { &hf_z3950_numberOfRecordsReturned, BER_CLASS_CON, 24, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_segmentRecords, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_NamePlusRecord },
  { &hf_z3950_otherInfo     , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_Segment(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Segment_sequence, hf_index, ett_z3950_Segment);

  return offset;
}


static const value_string z3950_T_function_vals[] = {
  {   1, "create" },
  {   2, "delete" },
  {   3, "modify" },
  { 0, NULL }
};


static int
dissect_z3950_T_function(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string z3950_T_allowableFunctions_item_vals[] = {
  {   1, "delete" },
  {   2, "modifyContents" },
  {   3, "modifyPermissions" },
  {   4, "present" },
  {   5, "invoke" },
  { 0, NULL }
};


static int
dissect_z3950_T_allowableFunctions_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T_allowableFunctions_sequence_of[1] = {
  { &hf_z3950_allowableFunctions_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_z3950_T_allowableFunctions_item },
};

static int
dissect_z3950_T_allowableFunctions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_allowableFunctions_sequence_of, hf_index, ett_z3950_T_allowableFunctions);

  return offset;
}


static const ber_sequence_t Permissions_item_sequence[] = {
  { &hf_z3950_userId        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_allowableFunctions, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_T_allowableFunctions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_Permissions_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Permissions_item_sequence, hf_index, ett_z3950_Permissions_item);

  return offset;
}


static const ber_sequence_t Permissions_sequence_of[1] = {
  { &hf_z3950_Permissions_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_Permissions_item },
};

static int
dissect_z3950_Permissions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Permissions_sequence_of, hf_index, ett_z3950_Permissions);

  return offset;
}


static const value_string z3950_T_waitAction_vals[] = {
  {   1, "wait" },
  {   2, "waitIfPossible" },
  {   3, "dontWait" },
  {   4, "dontReturnPackage" },
  { 0, NULL }
};


static int
dissect_z3950_T_waitAction(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ExtendedServicesRequest_sequence[] = {
  { &hf_z3950_referenceId   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_ReferenceId },
  { &hf_z3950_function      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_T_function },
  { &hf_z3950_packageType   , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_z3950_OBJECT_IDENTIFIER },
  { &hf_z3950_packageName   , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_userId        , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_retentionTime , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_IntUnit },
  { &hf_z3950_permissions   , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_Permissions },
  { &hf_z3950_extendedServicesRequest_description, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_taskSpecificParameters, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_EXTERNAL },
  { &hf_z3950_waitAction    , BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_z3950_T_waitAction },
  { &hf_z3950_elements      , BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_ElementSetName },
  { &hf_z3950_otherInfo     , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ExtendedServicesRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExtendedServicesRequest_sequence, hf_index, ett_z3950_ExtendedServicesRequest);

  return offset;
}


static const value_string z3950_T_operationStatus_vals[] = {
  {   1, "done" },
  {   2, "accepted" },
  {   3, "failure" },
  { 0, NULL }
};


static int
dissect_z3950_T_operationStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ExtendedServicesResponse_sequence[] = {
  { &hf_z3950_referenceId   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_ReferenceId },
  { &hf_z3950_operationStatus, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_T_operationStatus },
  { &hf_z3950_diagnostics   , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_DiagRec },
  { &hf_z3950_taskPackage   , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_EXTERNAL },
  { &hf_z3950_otherInfo     , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ExtendedServicesResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExtendedServicesResponse_sequence, hf_index, ett_z3950_ExtendedServicesResponse);

  return offset;
}


static const value_string z3950_CloseReason_U_vals[] = {
  {   0, "finished" },
  {   1, "shutdown" },
  {   2, "systemProblem" },
  {   3, "costLimit" },
  {   4, "resources" },
  {   5, "securityViolation" },
  {   6, "protocolError" },
  {   7, "lackOfActivity" },
  {   8, "peerAbort" },
  {   9, "unspecified" },
  { 0, NULL }
};


static int
dissect_z3950_CloseReason_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_z3950_CloseReason(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 211, TRUE, dissect_z3950_CloseReason_U);

  return offset;
}


static const ber_sequence_t Close_sequence[] = {
  { &hf_z3950_referenceId   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_ReferenceId },
  { &hf_z3950_closeReason   , BER_CLASS_CON, 211, BER_FLAGS_NOOWNTAG, dissect_z3950_CloseReason },
  { &hf_z3950_diagnosticInformation, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_resourceReportFormat, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_ResourceReportId },
  { &hf_z3950_resourceReport, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_z3950_ResourceReport },
  { &hf_z3950_otherInfo     , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_Close(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Close_sequence, hf_index, ett_z3950_Close);

  return offset;
}


static const value_string z3950_PDU_vals[] = {
  {  20, "initRequest" },
  {  21, "initResponse" },
  {  22, "searchRequest" },
  {  23, "searchResponse" },
  {  24, "presentRequest" },
  {  25, "presentResponse" },
  {  26, "deleteResultSetRequest" },
  {  27, "deleteResultSetResponse" },
  {  28, "accessControlRequest" },
  {  29, "accessControlResponse" },
  {  30, "resourceControlRequest" },
  {  31, "resourceControlResponse" },
  {  32, "triggerResourceControlRequest" },
  {  33, "resourceReportRequest" },
  {  34, "resourceReportResponse" },
  {  35, "scanRequest" },
  {  36, "scanResponse" },
  {  43, "sortRequest" },
  {  44, "sortResponse" },
  {  45, "segmentRequest" },
  {  46, "extendedServicesRequest" },
  {  47, "extendedServicesResponse" },
  {  48, "close" },
  { 0, NULL }
};

static const ber_choice_t PDU_choice[] = {
  {  20, &hf_z3950_initRequest   , BER_CLASS_CON, 20, BER_FLAGS_IMPLTAG, dissect_z3950_InitializeRequest },
  {  21, &hf_z3950_initResponse  , BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_z3950_InitializeResponse },
  {  22, &hf_z3950_searchRequest , BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_z3950_SearchRequest },
  {  23, &hf_z3950_searchResponse, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_z3950_SearchResponse },
  {  24, &hf_z3950_presentRequest, BER_CLASS_CON, 24, BER_FLAGS_IMPLTAG, dissect_z3950_PresentRequest },
  {  25, &hf_z3950_presentResponse, BER_CLASS_CON, 25, BER_FLAGS_IMPLTAG, dissect_z3950_PresentResponse },
  {  26, &hf_z3950_deleteResultSetRequest, BER_CLASS_CON, 26, BER_FLAGS_IMPLTAG, dissect_z3950_DeleteResultSetRequest },
  {  27, &hf_z3950_deleteResultSetResponse, BER_CLASS_CON, 27, BER_FLAGS_IMPLTAG, dissect_z3950_DeleteResultSetResponse },
  {  28, &hf_z3950_accessControlRequest, BER_CLASS_CON, 28, BER_FLAGS_IMPLTAG, dissect_z3950_AccessControlRequest },
  {  29, &hf_z3950_accessControlResponse, BER_CLASS_CON, 29, BER_FLAGS_IMPLTAG, dissect_z3950_AccessControlResponse },
  {  30, &hf_z3950_resourceControlRequest, BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_z3950_ResourceControlRequest },
  {  31, &hf_z3950_resourceControlResponse, BER_CLASS_CON, 31, BER_FLAGS_IMPLTAG, dissect_z3950_ResourceControlResponse },
  {  32, &hf_z3950_triggerResourceControlRequest, BER_CLASS_CON, 32, BER_FLAGS_IMPLTAG, dissect_z3950_TriggerResourceControlRequest },
  {  33, &hf_z3950_resourceReportRequest, BER_CLASS_CON, 33, BER_FLAGS_IMPLTAG, dissect_z3950_ResourceReportRequest },
  {  34, &hf_z3950_resourceReportResponse, BER_CLASS_CON, 34, BER_FLAGS_IMPLTAG, dissect_z3950_ResourceReportResponse },
  {  35, &hf_z3950_scanRequest   , BER_CLASS_CON, 35, BER_FLAGS_IMPLTAG, dissect_z3950_ScanRequest },
  {  36, &hf_z3950_scanResponse  , BER_CLASS_CON, 36, BER_FLAGS_IMPLTAG, dissect_z3950_ScanResponse },
  {  43, &hf_z3950_sortRequest   , BER_CLASS_CON, 43, BER_FLAGS_IMPLTAG, dissect_z3950_SortRequest },
  {  44, &hf_z3950_sortResponse  , BER_CLASS_CON, 44, BER_FLAGS_IMPLTAG, dissect_z3950_SortResponse },
  {  45, &hf_z3950_segmentRequest, BER_CLASS_CON, 45, BER_FLAGS_IMPLTAG, dissect_z3950_Segment },
  {  46, &hf_z3950_extendedServicesRequest, BER_CLASS_CON, 46, BER_FLAGS_IMPLTAG, dissect_z3950_ExtendedServicesRequest },
  {  47, &hf_z3950_extendedServicesResponse, BER_CLASS_CON, 47, BER_FLAGS_IMPLTAG, dissect_z3950_ExtendedServicesResponse },
  {  48, &hf_z3950_close         , BER_CLASS_CON, 48, BER_FLAGS_IMPLTAG, dissect_z3950_Close },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_PDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 127 "./asn1/z3950/z3950.cnf"
  gint choice;

  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PDU_choice, hf_index, ett_z3950_PDU,
                                 &choice);

#line 130 "./asn1/z3950/z3950.cnf"
  if (choice >= 0) {
    packet_info *pinfo = actx->pinfo;
    gint32 tag = PDU_choice[choice].tag;

    col_set_str(pinfo->cinfo, COL_INFO,
      val_to_str_const(tag, z3950_PDU_vals, "Unknown Z39.50 PDU"));
  }


  return offset;
}



static int
dissect_z3950_DBName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 2, TRUE, dissect_z3950_VisibleString);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_DBName_sequence_of[1] = {
  { &hf_z3950_dblist_item   , BER_CLASS_CON, 2, BER_FLAGS_NOOWNTAG, dissect_z3950_DBName },
};

static int
dissect_z3950_SEQUENCE_OF_DBName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_DBName_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_DBName);

  return offset;
}


static const ber_sequence_t OCLC_UserInformation_sequence[] = {
  { &hf_z3950_motd          , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_VisibleString },
  { &hf_z3950_dblist        , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_SEQUENCE_OF_DBName },
  { &hf_z3950_failReason    , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_oCLC_UserInformation_text, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_VisibleString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_OCLC_UserInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OCLC_UserInformation_sequence, hf_index, ett_z3950_OCLC_UserInformation);

  return offset;
}



static int
dissect_z3950_SutrsRecord(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_z3950_InternationalString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t Volume_sequence[] = {
  { &hf_z3950_enumeration   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_chronology    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_enumAndChron  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_Volume(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Volume_sequence, hf_index, ett_z3950_Volume);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Volume_sequence_of[1] = {
  { &hf_z3950_volumes_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_Volume },
};

static int
dissect_z3950_SEQUENCE_OF_Volume(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Volume_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_Volume);

  return offset;
}


static const ber_sequence_t CircRecord_sequence[] = {
  { &hf_z3950_availableNow  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_availablityDate, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_availableThru , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_circRecord_restrictions, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_itemId        , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_renewable     , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_onHold        , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_enumAndChron  , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_midspine      , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_temporaryLocation, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_CircRecord(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CircRecord_sequence, hf_index, ett_z3950_CircRecord);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_CircRecord_sequence_of[1] = {
  { &hf_z3950_circulationData_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_CircRecord },
};

static int
dissect_z3950_SEQUENCE_OF_CircRecord(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_CircRecord_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_CircRecord);

  return offset;
}


static const ber_sequence_t HoldingsAndCircData_sequence[] = {
  { &hf_z3950_typeOfRecord  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_encodingLevel , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_format        , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_receiptAcqStatus, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_generalRetention, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_completeness  , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_dateOfReport  , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_nucCode       , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_localLocation , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_shelvingLocation, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_callNumber    , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_shelvingData  , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_copyNumber    , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_publicNote    , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_reproductionNote, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_termsUseRepro , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_enumAndChron  , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_volumes       , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_Volume },
  { &hf_z3950_circulationData, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_CircRecord },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_HoldingsAndCircData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   HoldingsAndCircData_sequence, hf_index, ett_z3950_HoldingsAndCircData);

  return offset;
}


static const value_string z3950_HoldingsRecord_vals[] = {
  {   1, "marcHoldingsRecord" },
  {   2, "holdingsAndCirc" },
  { 0, NULL }
};

static const ber_choice_t HoldingsRecord_choice[] = {
  {   1, &hf_z3950_marcHoldingsRecord, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_EXTERNAL },
  {   2, &hf_z3950_holdingsAndCirc, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_HoldingsAndCircData },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_HoldingsRecord(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 HoldingsRecord_choice, hf_index, ett_z3950_HoldingsRecord,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_HoldingsRecord_sequence_of[1] = {
  { &hf_z3950_holdingsData_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_HoldingsRecord },
};

static int
dissect_z3950_SEQUENCE_OF_HoldingsRecord(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_HoldingsRecord_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_HoldingsRecord);

  return offset;
}


static const ber_sequence_t OPACRecord_sequence[] = {
  { &hf_z3950_bibliographicRecord, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_EXTERNAL },
  { &hf_z3950_holdingsData  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_HoldingsRecord },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_OPACRecord(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OPACRecord_sequence, hf_index, ett_z3950_OPACRecord);

  return offset;
}


static const value_string z3950_T_tooManyWhat_vals[] = {
  {   1, "argumentWords" },
  {   2, "truncatedWords" },
  {   3, "booleanOperators" },
  {   4, "incompleteSubfields" },
  {   5, "characters" },
  {   6, "recordsRetrieved" },
  {   7, "dataBasesSpecified" },
  {   8, "resultSetsCreated" },
  {   9, "indexTermsProcessed" },
  { 0, NULL }
};


static int
dissect_z3950_T_tooManyWhat(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T_tooMany_sequence[] = {
  { &hf_z3950_tooManyWhat   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_T_tooManyWhat },
  { &hf_z3950_max           , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_tooMany(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_tooMany_sequence, hf_index, ett_z3950_T_tooMany);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Specification_sequence_of[1] = {
  { &hf_z3950_goodOnes_item , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_Specification },
};

static int
dissect_z3950_SEQUENCE_OF_Specification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Specification_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_Specification);

  return offset;
}


static const ber_sequence_t T_badSpec_sequence[] = {
  { &hf_z3950_spec          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_Specification },
  { &hf_z3950_db            , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_DatabaseName },
  { &hf_z3950_goodOnes      , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_Specification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_badSpec(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_badSpec_sequence, hf_index, ett_z3950_T_badSpec);

  return offset;
}


static const value_string z3950_T_reasonCode_vals[] = {
  {   0, "doesNotExist" },
  {   1, "existsButUnavail" },
  {   2, "locked" },
  {   3, "accessDenied" },
  { 0, NULL }
};


static int
dissect_z3950_T_reasonCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T_why_sequence[] = {
  { &hf_z3950_reasonCode    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_reasonCode },
  { &hf_z3950_message       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_why(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_why_sequence, hf_index, ett_z3950_T_why);

  return offset;
}


static const ber_sequence_t T_dbUnavail_sequence[] = {
  { &hf_z3950_db            , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_DatabaseName },
  { &hf_z3950_why           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_T_why },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_dbUnavail(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_dbUnavail_sequence, hf_index, ett_z3950_T_dbUnavail);

  return offset;
}


static const value_string z3950_T_unSupOp_vals[] = {
  {   0, "and" },
  {   1, "or" },
  {   2, "and-not" },
  {   3, "prox" },
  { 0, NULL }
};


static int
dissect_z3950_T_unSupOp(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T_attribute_sequence[] = {
  { &hf_z3950_id            , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_OBJECT_IDENTIFIER },
  { &hf_z3950_type          , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_value         , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_term          , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_z3950_Term },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_attribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_attribute_sequence, hf_index, ett_z3950_T_attribute);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AttributeList_sequence_of[1] = {
  { &hf_z3950_recommendedAlternatives_item, BER_CLASS_CON, 44, BER_FLAGS_NOOWNTAG, dissect_z3950_AttributeList },
};

static int
dissect_z3950_SEQUENCE_OF_AttributeList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_AttributeList_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_AttributeList);

  return offset;
}


static const ber_sequence_t T_attCombo_sequence[] = {
  { &hf_z3950_unsupportedCombination, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_AttributeList },
  { &hf_z3950_recommendedAlternatives, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_AttributeList },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_attCombo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_attCombo_sequence, hf_index, ett_z3950_T_attCombo);

  return offset;
}


static const value_string z3950_T_problem_vals[] = {
  {   1, "codedValue" },
  {   2, "unparsable" },
  {   3, "tooShort" },
  {   4, "type" },
  { 0, NULL }
};


static int
dissect_z3950_T_problem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T_diagFormat_term_sequence[] = {
  { &hf_z3950_problem       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_problem },
  { &hf_z3950_term          , BER_CLASS_CON, 2, BER_FLAGS_NOTCHKTAG, dissect_z3950_Term },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_diagFormat_term(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_diagFormat_term_sequence, hf_index, ett_z3950_T_diagFormat_term);

  return offset;
}


static const value_string z3950_T_diagFormat_proximity_vals[] = {
  {   1, "resultSets" },
  {   2, "badSet" },
  {   3, "relation" },
  {   4, "unit" },
  {   5, "distance" },
  {   6, "attributes" },
  {   7, "ordered" },
  {   8, "exclusion" },
  { 0, NULL }
};

static const ber_choice_t T_diagFormat_proximity_choice[] = {
  {   1, &hf_z3950_resultSets    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   2, &hf_z3950_badSet        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  {   3, &hf_z3950_relation      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  {   4, &hf_z3950_diagFormat_proximity_unit, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  {   5, &hf_z3950_distance      , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  {   6, &hf_z3950_attributes    , BER_CLASS_CON, 6, 0, dissect_z3950_AttributeList },
  {   7, &hf_z3950_diagFormat_proximity_ordered, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   8, &hf_z3950_diagFormat_proximity_exclusion, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_diagFormat_proximity(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_diagFormat_proximity_choice, hf_index, ett_z3950_T_diagFormat_proximity,
                                 NULL);

  return offset;
}


static const value_string z3950_T_posInResponse_vals[] = {
  {   1, "mustBeOne" },
  {   2, "mustBePositive" },
  {   3, "mustBeNonNegative" },
  {   4, "other" },
  { 0, NULL }
};


static int
dissect_z3950_T_posInResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string z3950_T_scan_vals[] = {
  {   0, "nonZeroStepSize" },
  {   1, "specifiedStepSize" },
  {   3, "termList1" },
  {   4, "termList2" },
  {   5, "posInResponse" },
  {   6, "resources" },
  {   7, "endOfList" },
  { 0, NULL }
};

static const ber_choice_t T_scan_choice[] = {
  {   0, &hf_z3950_nonZeroStepSize, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   1, &hf_z3950_specifiedStepSize, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   3, &hf_z3950_termList1     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   4, &hf_z3950_termList2     , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_AttributeList },
  {   5, &hf_z3950_posInResponse , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_z3950_T_posInResponse },
  {   6, &hf_z3950_resources     , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   7, &hf_z3950_endOfList     , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_scan(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_scan_choice, hf_index, ett_z3950_T_scan,
                                 NULL);

  return offset;
}


static const value_string z3950_T_key_vals[] = {
  {   1, "tooMany" },
  {   2, "duplicate" },
  { 0, NULL }
};


static int
dissect_z3950_T_key(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string z3950_T_illegal_vals[] = {
  {   1, "relation" },
  {   2, "case" },
  {   3, "action" },
  {   4, "sort" },
  { 0, NULL }
};


static int
dissect_z3950_T_illegal(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string z3950_T_sort_vals[] = {
  {   0, "sequence" },
  {   1, "noRsName" },
  {   2, "tooMany" },
  {   3, "incompatible" },
  {   4, "generic" },
  {   5, "dbSpecific" },
  {   6, "sortElement" },
  {   7, "key" },
  {   8, "action" },
  {   9, "illegal" },
  {  10, "inputTooLarge" },
  {  11, "aggregateTooLarge" },
  { 0, NULL }
};

static const ber_choice_t T_sort_choice[] = {
  {   0, &hf_z3950_sequence      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   1, &hf_z3950_noRsName      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   2, &hf_z3950_diagFormat_sort_tooMany, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  {   3, &hf_z3950_incompatible  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   4, &hf_z3950_generic       , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   5, &hf_z3950_diagFormat_sort_dbSpecific, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   6, &hf_z3950_sortElement   , BER_CLASS_CON, 6, 0, dissect_z3950_SortElement },
  {   7, &hf_z3950_key           , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_z3950_T_key },
  {   8, &hf_z3950_action        , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   9, &hf_z3950_illegal       , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_z3950_T_illegal },
  {  10, &hf_z3950_inputTooLarge , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_InternationalString },
  {  11, &hf_z3950_aggregateTooLarge, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_sort(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_sort_choice, hf_index, ett_z3950_T_sort,
                                 NULL);

  return offset;
}


static const value_string z3950_T_segmentation_vals[] = {
  {   0, "segmentCount" },
  {   1, "segmentSize" },
  { 0, NULL }
};

static const ber_choice_t T_segmentation_choice[] = {
  {   0, &hf_z3950_segmentCount  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   1, &hf_z3950_segmentSize   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_segmentation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_segmentation_choice, hf_index, ett_z3950_T_segmentation,
                                 NULL);

  return offset;
}


static const value_string z3950_T_req_vals[] = {
  {   1, "nameInUse" },
  {   2, "noSuchName" },
  {   3, "quota" },
  {   4, "type" },
  { 0, NULL }
};


static int
dissect_z3950_T_req(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string z3950_T_permission_vals[] = {
  {   1, "id" },
  {   2, "modifyDelete" },
  { 0, NULL }
};


static int
dissect_z3950_T_permission(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string z3950_T_immediate_vals[] = {
  {   1, "failed" },
  {   2, "service" },
  {   3, "parameters" },
  { 0, NULL }
};


static int
dissect_z3950_T_immediate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string z3950_T_extServices_vals[] = {
  {   1, "req" },
  {   2, "permission" },
  {   3, "immediate" },
  { 0, NULL }
};

static const ber_choice_t T_extServices_choice[] = {
  {   1, &hf_z3950_req           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_T_req },
  {   2, &hf_z3950_permission    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_T_permission },
  {   3, &hf_z3950_immediate     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_T_immediate },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_extServices(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_extServices_choice, hf_index, ett_z3950_T_extServices,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_diagFormat_accessCtrl_oid_sequence_of[1] = {
  { &hf_z3950_diagFormat_accessCtrl_oid_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_z3950_OBJECT_IDENTIFIER },
};

static int
dissect_z3950_T_diagFormat_accessCtrl_oid(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_diagFormat_accessCtrl_oid_sequence_of, hf_index, ett_z3950_T_diagFormat_accessCtrl_oid);

  return offset;
}


static const ber_sequence_t T_alternative_sequence_of[1] = {
  { &hf_z3950_alternative_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_z3950_OBJECT_IDENTIFIER },
};

static int
dissect_z3950_T_alternative(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_alternative_sequence_of, hf_index, ett_z3950_T_alternative);

  return offset;
}


static const value_string z3950_T_accessCtrl_vals[] = {
  {   1, "noUser" },
  {   2, "refused" },
  {   3, "simple" },
  {   4, "oid" },
  {   5, "alternative" },
  {   6, "pwdInv" },
  {   7, "pwdExp" },
  { 0, NULL }
};

static const ber_choice_t T_accessCtrl_choice[] = {
  {   1, &hf_z3950_noUser        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   2, &hf_z3950_refused       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   3, &hf_z3950_diagFormat_accessCtrl_simple, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   4, &hf_z3950_diagFormat_accessCtrl_oid, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_z3950_T_diagFormat_accessCtrl_oid },
  {   5, &hf_z3950_alternative   , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_z3950_T_alternative },
  {   6, &hf_z3950_pwdInv        , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   7, &hf_z3950_pwdExp        , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_accessCtrl(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_accessCtrl_choice, hf_index, ett_z3950_T_accessCtrl,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_suggestedAlternatives_sequence_of[1] = {
  { &hf_z3950_suggestedAlternatives_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_z3950_OBJECT_IDENTIFIER },
};

static int
dissect_z3950_T_suggestedAlternatives(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_suggestedAlternatives_sequence_of, hf_index, ett_z3950_T_suggestedAlternatives);

  return offset;
}


static const ber_sequence_t T_diagFormat_recordSyntax_sequence[] = {
  { &hf_z3950_unsupportedSyntax, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_OBJECT_IDENTIFIER },
  { &hf_z3950_suggestedAlternatives, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_suggestedAlternatives },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_diagFormat_recordSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_diagFormat_recordSyntax_sequence, hf_index, ett_z3950_T_diagFormat_recordSyntax);

  return offset;
}


static const value_string z3950_DiagFormat_vals[] = {
  { 1000, "tooMany" },
  { 1001, "badSpec" },
  { 1002, "dbUnavail" },
  { 1003, "unSupOp" },
  { 1004, "attribute" },
  { 1005, "attCombo" },
  { 1006, "term" },
  { 1007, "proximity" },
  { 1008, "scan" },
  { 1009, "sort" },
  { 1010, "segmentation" },
  { 1011, "extServices" },
  { 1012, "accessCtrl" },
  { 1013, "recordSyntax" },
  { 0, NULL }
};

static const ber_choice_t DiagFormat_choice[] = {
  { 1000, &hf_z3950_tooMany       , BER_CLASS_CON, 1000, BER_FLAGS_IMPLTAG, dissect_z3950_T_tooMany },
  { 1001, &hf_z3950_badSpec       , BER_CLASS_CON, 1001, BER_FLAGS_IMPLTAG, dissect_z3950_T_badSpec },
  { 1002, &hf_z3950_dbUnavail     , BER_CLASS_CON, 1002, BER_FLAGS_IMPLTAG, dissect_z3950_T_dbUnavail },
  { 1003, &hf_z3950_unSupOp       , BER_CLASS_CON, 1003, BER_FLAGS_IMPLTAG, dissect_z3950_T_unSupOp },
  { 1004, &hf_z3950_attribute     , BER_CLASS_CON, 1004, BER_FLAGS_IMPLTAG, dissect_z3950_T_attribute },
  { 1005, &hf_z3950_attCombo      , BER_CLASS_CON, 1005, BER_FLAGS_IMPLTAG, dissect_z3950_T_attCombo },
  { 1006, &hf_z3950_diagFormat_term, BER_CLASS_CON, 1006, BER_FLAGS_IMPLTAG, dissect_z3950_T_diagFormat_term },
  { 1007, &hf_z3950_diagFormat_proximity, BER_CLASS_CON, 1007, 0, dissect_z3950_T_diagFormat_proximity },
  { 1008, &hf_z3950_scan          , BER_CLASS_CON, 1008, 0, dissect_z3950_T_scan },
  { 1009, &hf_z3950_sort          , BER_CLASS_CON, 1009, 0, dissect_z3950_T_sort },
  { 1010, &hf_z3950_segmentation  , BER_CLASS_CON, 1010, 0, dissect_z3950_T_segmentation },
  { 1011, &hf_z3950_extServices   , BER_CLASS_CON, 1011, 0, dissect_z3950_T_extServices },
  { 1012, &hf_z3950_accessCtrl    , BER_CLASS_CON, 1012, 0, dissect_z3950_T_accessCtrl },
  { 1013, &hf_z3950_diagFormat_recordSyntax, BER_CLASS_CON, 1013, BER_FLAGS_IMPLTAG, dissect_z3950_T_diagFormat_recordSyntax },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_DiagFormat(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DiagFormat_choice, hf_index, ett_z3950_DiagFormat,
                                 NULL);

  return offset;
}


static const value_string z3950_T_diagnosticFormat_item_diagnostic_vals[] = {
  {   1, "defaultDiagRec" },
  {   2, "explicitDiagnostic" },
  { 0, NULL }
};

static const ber_choice_t T_diagnosticFormat_item_diagnostic_choice[] = {
  {   1, &hf_z3950_defaultDiagRec, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_DefaultDiagFormat },
  {   2, &hf_z3950_explicitDiagnostic, BER_CLASS_CON, 2, 0, dissect_z3950_DiagFormat },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_diagnosticFormat_item_diagnostic(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_diagnosticFormat_item_diagnostic_choice, hf_index, ett_z3950_T_diagnosticFormat_item_diagnostic,
                                 NULL);

  return offset;
}


static const ber_sequence_t DiagnosticFormat_item_sequence[] = {
  { &hf_z3950_diagnosticFormat_item_diagnostic, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_z3950_T_diagnosticFormat_item_diagnostic },
  { &hf_z3950_message       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_DiagnosticFormat_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DiagnosticFormat_item_sequence, hf_index, ett_z3950_DiagnosticFormat_item);

  return offset;
}


static const ber_sequence_t DiagnosticFormat_sequence_of[1] = {
  { &hf_z3950_DiagnosticFormat_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_DiagnosticFormat_item },
};

static int
dissect_z3950_DiagnosticFormat(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      DiagnosticFormat_sequence_of, hf_index, ett_z3950_DiagnosticFormat);

  return offset;
}



static int
dissect_z3950_LanguageCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_z3950_InternationalString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t CommonInfo_sequence[] = {
  { &hf_z3950_dateAdded     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_GeneralizedTime },
  { &hf_z3950_dateChanged   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_GeneralizedTime },
  { &hf_z3950_expiry        , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_GeneralizedTime },
  { &hf_z3950_humanString_Language, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_LanguageCode },
  { &hf_z3950_otherInfo     , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_CommonInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CommonInfo_sequence, hf_index, ett_z3950_CommonInfo);

  return offset;
}


static const ber_sequence_t HumanString_item_sequence[] = {
  { &hf_z3950_language      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_LanguageCode },
  { &hf_z3950_text          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_HumanString_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   HumanString_item_sequence, hf_index, ett_z3950_HumanString_item);

  return offset;
}


static const ber_sequence_t HumanString_sequence_of[1] = {
  { &hf_z3950_HumanString_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_HumanString_item },
};

static int
dissect_z3950_HumanString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      HumanString_sequence_of, hf_index, ett_z3950_HumanString);

  return offset;
}


static const value_string z3950_T_bodyType_vals[] = {
  {   1, "ianaType" },
  {   2, "z3950type" },
  {   3, "otherType" },
  { 0, NULL }
};

static const ber_choice_t T_bodyType_choice[] = {
  {   1, &hf_z3950_ianaType      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  {   2, &hf_z3950_z3950type     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  {   3, &hf_z3950_otherType     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_bodyType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_bodyType_choice, hf_index, ett_z3950_T_bodyType,
                                 NULL);

  return offset;
}


static const ber_sequence_t IconObject_item_sequence[] = {
  { &hf_z3950_bodyType      , BER_CLASS_CON, 1, 0, dissect_z3950_T_bodyType },
  { &hf_z3950_content       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_IconObject_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IconObject_item_sequence, hf_index, ett_z3950_IconObject_item);

  return offset;
}


static const ber_sequence_t IconObject_sequence_of[1] = {
  { &hf_z3950_IconObject_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_IconObject_item },
};

static int
dissect_z3950_IconObject(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      IconObject_sequence_of, hf_index, ett_z3950_IconObject);

  return offset;
}


static const ber_sequence_t ContactInfo_sequence[] = {
  { &hf_z3950_name          , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_description   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_address       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_email         , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_phone         , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ContactInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ContactInfo_sequence, hf_index, ett_z3950_ContactInfo);

  return offset;
}


static const ber_sequence_t DatabaseList_sequence_of[1] = {
  { &hf_z3950_DatabaseList_item, BER_CLASS_CON, 105, BER_FLAGS_NOOWNTAG, dissect_z3950_DatabaseName },
};

static int
dissect_z3950_DatabaseList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      DatabaseList_sequence_of, hf_index, ett_z3950_DatabaseList);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_DatabaseList_sequence_of[1] = {
  { &hf_z3950_dbCombinations_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_DatabaseList },
};

static int
dissect_z3950_SEQUENCE_OF_DatabaseList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_DatabaseList_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_DatabaseList);

  return offset;
}


static const ber_sequence_t T_internetAddress_sequence[] = {
  { &hf_z3950_hostAddress   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_port          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_internetAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_internetAddress_sequence, hf_index, ett_z3950_T_internetAddress);

  return offset;
}


static const ber_sequence_t T_osiPresentationAddress_sequence[] = {
  { &hf_z3950_pSel          , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_sSel          , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_tSel          , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_nSap          , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_osiPresentationAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_osiPresentationAddress_sequence, hf_index, ett_z3950_T_osiPresentationAddress);

  return offset;
}


static const ber_sequence_t T_networkAddress_other_sequence[] = {
  { &hf_z3950_networkAddress_other_type, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_networkAddress_other_address, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_networkAddress_other(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_networkAddress_other_sequence, hf_index, ett_z3950_T_networkAddress_other);

  return offset;
}


static const value_string z3950_NetworkAddress_vals[] = {
  {   0, "internetAddress" },
  {   1, "osiPresentationAddress" },
  {   2, "other" },
  { 0, NULL }
};

static const ber_choice_t NetworkAddress_choice[] = {
  {   0, &hf_z3950_internetAddress, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_T_internetAddress },
  {   1, &hf_z3950_osiPresentationAddress, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_T_osiPresentationAddress },
  {   2, &hf_z3950_networkAddress_other, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_T_networkAddress_other },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_NetworkAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 NetworkAddress_choice, hf_index, ett_z3950_NetworkAddress,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_NetworkAddress_sequence_of[1] = {
  { &hf_z3950_addresses_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_NetworkAddress },
};

static int
dissect_z3950_SEQUENCE_OF_NetworkAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_NetworkAddress_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_NetworkAddress);

  return offset;
}


static const ber_sequence_t T_privateCapabilities_operators_item_sequence[] = {
  { &hf_z3950_operator      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_description   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_privateCapabilities_operators_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_privateCapabilities_operators_item_sequence, hf_index, ett_z3950_T_privateCapabilities_operators_item);

  return offset;
}


static const ber_sequence_t T_privateCapabilities_operators_sequence_of[1] = {
  { &hf_z3950_privateCapabilities_operators_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_T_privateCapabilities_operators_item },
};

static int
dissect_z3950_T_privateCapabilities_operators(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_privateCapabilities_operators_sequence_of, hf_index, ett_z3950_T_privateCapabilities_operators);

  return offset;
}


static const ber_sequence_t SearchKey_sequence[] = {
  { &hf_z3950_searchKey     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_description   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_SearchKey(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SearchKey_sequence, hf_index, ett_z3950_SearchKey);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_SearchKey_sequence_of[1] = {
  { &hf_z3950_searchKeys_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_SearchKey },
};

static int
dissect_z3950_SEQUENCE_OF_SearchKey(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_SearchKey_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_SearchKey);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_HumanString_sequence_of[1] = {
  { &hf_z3950_keywords_item , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_HumanString },
};

static int
dissect_z3950_SEQUENCE_OF_HumanString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_HumanString_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_HumanString);

  return offset;
}


static const ber_sequence_t PrivateCapabilities_sequence[] = {
  { &hf_z3950_privateCapabilities_operators, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_privateCapabilities_operators },
  { &hf_z3950_searchKeys    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_SearchKey },
  { &hf_z3950_privateCapabilities_description, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_HumanString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_PrivateCapabilities(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PrivateCapabilities_sequence, hf_index, ett_z3950_PrivateCapabilities);

  return offset;
}


static const ber_sequence_t T_operators_sequence_of[1] = {
  { &hf_z3950_operators_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_z3950_INTEGER },
};

static int
dissect_z3950_T_operators(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_operators_sequence_of, hf_index, ett_z3950_T_operators);

  return offset;
}


static const ber_sequence_t T_proximitySupport_unitsSupported_item_private_sequence[] = {
  { &hf_z3950_proximitySupport_unitsSupported_item_private_unit, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_description   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_z3950_HumanString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_proximitySupport_unitsSupported_item_private(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_proximitySupport_unitsSupported_item_private_sequence, hf_index, ett_z3950_T_proximitySupport_unitsSupported_item_private);

  return offset;
}


static const value_string z3950_T_unitsSupported_item_vals[] = {
  {   1, "known" },
  {   2, "private" },
  { 0, NULL }
};

static const ber_choice_t T_unitsSupported_item_choice[] = {
  {   1, &hf_z3950_proximitySupport_unitsSupported_item_known, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  {   2, &hf_z3950_proximitySupport_unitsSupported_item_private, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_T_proximitySupport_unitsSupported_item_private },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_unitsSupported_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_unitsSupported_item_choice, hf_index, ett_z3950_T_unitsSupported_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_unitsSupported_sequence_of[1] = {
  { &hf_z3950_unitsSupported_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_T_unitsSupported_item },
};

static int
dissect_z3950_T_unitsSupported(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_unitsSupported_sequence_of, hf_index, ett_z3950_T_unitsSupported);

  return offset;
}


static const ber_sequence_t ProximitySupport_sequence[] = {
  { &hf_z3950_anySupport    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_unitsSupported, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_unitsSupported },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ProximitySupport(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProximitySupport_sequence, hf_index, ett_z3950_ProximitySupport);

  return offset;
}


static const ber_sequence_t RpnCapabilities_sequence[] = {
  { &hf_z3950_operators     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_operators },
  { &hf_z3950_resultSetAsOperandSupported, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_restrictionOperandSupported, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_proximity     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_ProximitySupport },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_RpnCapabilities(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RpnCapabilities_sequence, hf_index, ett_z3950_RpnCapabilities);

  return offset;
}


static const ber_sequence_t Iso8777Capabilities_sequence[] = {
  { &hf_z3950_searchKeys    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_SearchKey },
  { &hf_z3950_restrictions  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_Iso8777Capabilities(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Iso8777Capabilities_sequence, hf_index, ett_z3950_Iso8777Capabilities);

  return offset;
}


static const value_string z3950_QueryTypeDetails_vals[] = {
  {   0, "private" },
  {   1, "rpn" },
  {   2, "iso8777" },
  { 100, "z39-58" },
  { 101, "erpn" },
  { 102, "rankedList" },
  { 0, NULL }
};

static const ber_choice_t QueryTypeDetails_choice[] = {
  {   0, &hf_z3950_queryTypeDetails_private, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_PrivateCapabilities },
  {   1, &hf_z3950_queryTypeDetails_rpn, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_RpnCapabilities },
  {   2, &hf_z3950_iso8777       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_Iso8777Capabilities },
  { 100, &hf_z3950_z39_58        , BER_CLASS_CON, 100, BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { 101, &hf_z3950_erpn          , BER_CLASS_CON, 101, BER_FLAGS_IMPLTAG, dissect_z3950_RpnCapabilities },
  { 102, &hf_z3950_rankedList    , BER_CLASS_CON, 102, BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_QueryTypeDetails(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 QueryTypeDetails_choice, hf_index, ett_z3950_QueryTypeDetails,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_QueryTypeDetails_sequence_of[1] = {
  { &hf_z3950_queryTypesSupported_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_QueryTypeDetails },
};

static int
dissect_z3950_SEQUENCE_OF_QueryTypeDetails(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_QueryTypeDetails_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_QueryTypeDetails);

  return offset;
}


static const ber_sequence_t T_diagnosticsSets_sequence_of[1] = {
  { &hf_z3950_diagnosticsSets_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_z3950_OBJECT_IDENTIFIER },
};

static int
dissect_z3950_T_diagnosticsSets(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_diagnosticsSets_sequence_of, hf_index, ett_z3950_T_diagnosticsSets);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AttributeSetId_sequence_of[1] = {
  { &hf_z3950_attributeSetIds_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_z3950_AttributeSetId },
};

static int
dissect_z3950_SEQUENCE_OF_AttributeSetId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_AttributeSetId_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_AttributeSetId);

  return offset;
}


static const ber_sequence_t T_schemas_sequence_of[1] = {
  { &hf_z3950_schemas_item  , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_z3950_OBJECT_IDENTIFIER },
};

static int
dissect_z3950_T_schemas(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_schemas_sequence_of, hf_index, ett_z3950_T_schemas);

  return offset;
}


static const ber_sequence_t T_recordSyntaxes_sequence_of[1] = {
  { &hf_z3950_recordSyntaxes_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_z3950_OBJECT_IDENTIFIER },
};

static int
dissect_z3950_T_recordSyntaxes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_recordSyntaxes_sequence_of, hf_index, ett_z3950_T_recordSyntaxes);

  return offset;
}


static const ber_sequence_t T_resourceChallenges_sequence_of[1] = {
  { &hf_z3950_resourceChallenges_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_z3950_OBJECT_IDENTIFIER },
};

static int
dissect_z3950_T_resourceChallenges(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_resourceChallenges_sequence_of, hf_index, ett_z3950_T_resourceChallenges);

  return offset;
}


static const value_string z3950_T_accessType_vals[] = {
  {   0, "any" },
  {   1, "search" },
  {   2, "present" },
  {   3, "specific-elements" },
  {   4, "extended-services" },
  {   5, "by-database" },
  { 0, NULL }
};


static int
dissect_z3950_T_accessType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T_accessChallenges_sequence_of[1] = {
  { &hf_z3950_accessChallenges_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_z3950_OBJECT_IDENTIFIER },
};

static int
dissect_z3950_T_accessChallenges(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_accessChallenges_sequence_of, hf_index, ett_z3950_T_accessChallenges);

  return offset;
}


static const ber_sequence_t AccessRestrictions_item_sequence[] = {
  { &hf_z3950_accessType    , BER_CLASS_CON, 0, 0, dissect_z3950_T_accessType },
  { &hf_z3950_accessText    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_accessChallenges, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_accessChallenges },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_AccessRestrictions_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AccessRestrictions_item_sequence, hf_index, ett_z3950_AccessRestrictions_item);

  return offset;
}


static const ber_sequence_t AccessRestrictions_sequence_of[1] = {
  { &hf_z3950_AccessRestrictions_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_AccessRestrictions_item },
};

static int
dissect_z3950_AccessRestrictions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      AccessRestrictions_sequence_of, hf_index, ett_z3950_AccessRestrictions);

  return offset;
}


static const ber_sequence_t Charge_sequence[] = {
  { &hf_z3950_cost          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_IntUnit },
  { &hf_z3950_perWhat       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_Unit },
  { &hf_z3950_charge_text   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_Charge(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Charge_sequence, hf_index, ett_z3950_Charge);

  return offset;
}


static const ber_sequence_t T_otherCharges_item_sequence[] = {
  { &hf_z3950_forWhat       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_charge        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_Charge },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_otherCharges_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_otherCharges_item_sequence, hf_index, ett_z3950_T_otherCharges_item);

  return offset;
}


static const ber_sequence_t T_otherCharges_sequence_of[1] = {
  { &hf_z3950_otherCharges_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_T_otherCharges_item },
};

static int
dissect_z3950_T_otherCharges(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_otherCharges_sequence_of, hf_index, ett_z3950_T_otherCharges);

  return offset;
}


static const ber_sequence_t Costs_sequence[] = {
  { &hf_z3950_connectCharge , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_Charge },
  { &hf_z3950_connectTime   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_Charge },
  { &hf_z3950_displayCharge , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_Charge },
  { &hf_z3950_searchCharge  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_Charge },
  { &hf_z3950_subscriptCharge, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_Charge },
  { &hf_z3950_otherCharges  , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_otherCharges },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_Costs(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Costs_sequence, hf_index, ett_z3950_Costs);

  return offset;
}


static const ber_sequence_t T_variantSets_sequence_of[1] = {
  { &hf_z3950_variantSets_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_z3950_OBJECT_IDENTIFIER },
};

static int
dissect_z3950_T_variantSets(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_variantSets_sequence_of, hf_index, ett_z3950_T_variantSets);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ElementSetName_sequence_of[1] = {
  { &hf_z3950_elementSetNames_item, BER_CLASS_CON, 103, BER_FLAGS_NOOWNTAG, dissect_z3950_ElementSetName },
};

static int
dissect_z3950_SEQUENCE_OF_ElementSetName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ElementSetName_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_ElementSetName);

  return offset;
}


static const ber_sequence_t AccessInfo_sequence[] = {
  { &hf_z3950_queryTypesSupported, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_QueryTypeDetails },
  { &hf_z3950_diagnosticsSets, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_diagnosticsSets },
  { &hf_z3950_attributeSetIds, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_AttributeSetId },
  { &hf_z3950_schemas       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_schemas },
  { &hf_z3950_recordSyntaxes, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_recordSyntaxes },
  { &hf_z3950_resourceChallenges, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_resourceChallenges },
  { &hf_z3950_restrictedAccess, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_AccessRestrictions },
  { &hf_z3950_costInfo      , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_Costs },
  { &hf_z3950_variantSets   , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_variantSets },
  { &hf_z3950_elementSetNames, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_ElementSetName },
  { &hf_z3950_unitSystems   , BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_InternationalString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_AccessInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AccessInfo_sequence, hf_index, ett_z3950_AccessInfo);

  return offset;
}


static const ber_sequence_t TargetInfo_sequence[] = {
  { &hf_z3950_commonInfo    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_CommonInfo },
  { &hf_z3950_name          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_recent_news   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_icon          , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_IconObject },
  { &hf_z3950_namedResultSets, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_multipleDBsearch, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_maxResultSets , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_maxResultSize , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_maxTerms      , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_timeoutInterval, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_IntUnit },
  { &hf_z3950_welcomeMessage, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_contactInfo   , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_ContactInfo },
  { &hf_z3950_description   , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_nicknames     , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_InternationalString },
  { &hf_z3950_usage_restrictions, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_paymentAddr   , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_hours         , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_dbCombinations, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_DatabaseList },
  { &hf_z3950_addresses     , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_NetworkAddress },
  { &hf_z3950_languages     , BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_InternationalString },
  { &hf_z3950_commonAccessInfo, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_AccessInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_TargetInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TargetInfo_sequence, hf_index, ett_z3950_TargetInfo);

  return offset;
}


static const value_string z3950_T_recordCount_vals[] = {
  {   0, "actualNumber" },
  {   1, "approxNumber" },
  { 0, NULL }
};

static const ber_choice_t T_recordCount_choice[] = {
  {   0, &hf_z3950_actualNumber  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  {   1, &hf_z3950_approxNumber  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_recordCount(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_recordCount_choice, hf_index, ett_z3950_T_recordCount,
                                 NULL);

  return offset;
}


static const ber_sequence_t DatabaseInfo_sequence[] = {
  { &hf_z3950_commonInfo    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_CommonInfo },
  { &hf_z3950_databaseInfo_name, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_DatabaseName },
  { &hf_z3950_explainDatabase, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  { &hf_z3950_databaseInfo_nicknames, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_DatabaseName },
  { &hf_z3950_icon          , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_IconObject },
  { &hf_z3950_user_fee      , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_available     , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_titleString   , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_keywords      , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_HumanString },
  { &hf_z3950_description   , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_associatedDbs , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_DatabaseList },
  { &hf_z3950_subDbs        , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_DatabaseList },
  { &hf_z3950_disclaimers   , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_news          , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_recordCount   , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL, dissect_z3950_T_recordCount },
  { &hf_z3950_defaultOrder  , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_avRecordSize  , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_maxRecordSize , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_hours         , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_bestTime      , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_lastUpdate    , BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_GeneralizedTime },
  { &hf_z3950_updateInterval, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_IntUnit },
  { &hf_z3950_coverage      , BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_proprietary   , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_copyrightText , BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_copyrightNotice, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_producerContactInfo, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_ContactInfo },
  { &hf_z3950_supplierContactInfo, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_ContactInfo },
  { &hf_z3950_submissionContactInfo, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_ContactInfo },
  { &hf_z3950_accessInfo    , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_AccessInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_DatabaseInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DatabaseInfo_sequence, hf_index, ett_z3950_DatabaseInfo);

  return offset;
}


static const ber_sequence_t T_tagTypeMapping_item_sequence[] = {
  { &hf_z3950_tagType       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_tagSet        , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_OBJECT_IDENTIFIER },
  { &hf_z3950_defaultTagType, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_tagTypeMapping_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_tagTypeMapping_item_sequence, hf_index, ett_z3950_T_tagTypeMapping_item);

  return offset;
}


static const ber_sequence_t T_tagTypeMapping_sequence_of[1] = {
  { &hf_z3950_tagTypeMapping_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_T_tagTypeMapping_item },
};

static int
dissect_z3950_T_tagTypeMapping(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_tagTypeMapping_sequence_of, hf_index, ett_z3950_T_tagTypeMapping);

  return offset;
}


static const ber_sequence_t Path_item_sequence[] = {
  { &hf_z3950_tagType       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_tagValue      , BER_CLASS_CON, 2, BER_FLAGS_NOTCHKTAG, dissect_z3950_StringOrNumeric },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_Path_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Path_item_sequence, hf_index, ett_z3950_Path_item);

  return offset;
}


static const ber_sequence_t Path_sequence_of[1] = {
  { &hf_z3950_Path_item     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_Path_item },
};

static int
dissect_z3950_Path(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Path_sequence_of, hf_index, ett_z3950_Path);

  return offset;
}


static const value_string z3950_PrimitiveDataType_vals[] = {
  {   0, "octetString" },
  {   1, "numeric" },
  {   2, "date" },
  {   3, "external" },
  {   4, "string" },
  {   5, "trueOrFalse" },
  {   6, "oid" },
  {   7, "intUnit" },
  {   8, "empty" },
  { 100, "noneOfTheAbove" },
  { 0, NULL }
};


static int
dissect_z3950_PrimitiveDataType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ElementInfo_sequence_of[1] = {
  { &hf_z3950_recordStructure_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_ElementInfo },
};

static int
dissect_z3950_SEQUENCE_OF_ElementInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ElementInfo_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_ElementInfo);

  return offset;
}


static const value_string z3950_ElementDataType_vals[] = {
  {   0, "primitive" },
  {   1, "structured" },
  { 0, NULL }
};

static const ber_choice_t ElementDataType_choice[] = {
  {   0, &hf_z3950_primitive     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_PrimitiveDataType },
  {   1, &hf_z3950_structured    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_ElementInfo },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ElementDataType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ElementDataType_choice, hf_index, ett_z3950_ElementDataType,
                                 NULL);

  return offset;
}


static const ber_sequence_t ElementInfo_sequence[] = {
  { &hf_z3950_elementName   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_elementTagPath, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_Path },
  { &hf_z3950_elementInfo_dataType, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_z3950_ElementDataType },
  { &hf_z3950_required      , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_repeatable    , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_description   , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ElementInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ElementInfo_sequence, hf_index, ett_z3950_ElementInfo);

  return offset;
}


static const ber_sequence_t SchemaInfo_sequence[] = {
  { &hf_z3950_commonInfo    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_CommonInfo },
  { &hf_z3950_schema        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_OBJECT_IDENTIFIER },
  { &hf_z3950_name          , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_description   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_tagTypeMapping, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_tagTypeMapping },
  { &hf_z3950_recordStructure, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_ElementInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_SchemaInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SchemaInfo_sequence, hf_index, ett_z3950_SchemaInfo);

  return offset;
}


static const ber_sequence_t T_tagSetInfo_elements_item_sequence[] = {
  { &hf_z3950_elementname   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_nicknames     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_InternationalString },
  { &hf_z3950_elementTag    , BER_CLASS_CON, 3, BER_FLAGS_NOTCHKTAG, dissect_z3950_StringOrNumeric },
  { &hf_z3950_description   , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_dataType      , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_z3950_PrimitiveDataType },
  { &hf_z3950_otherTagInfo  , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_tagSetInfo_elements_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_tagSetInfo_elements_item_sequence, hf_index, ett_z3950_T_tagSetInfo_elements_item);

  return offset;
}


static const ber_sequence_t T_tagSetInfo_elements_sequence_of[1] = {
  { &hf_z3950_tagSetInfo_elements_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_T_tagSetInfo_elements_item },
};

static int
dissect_z3950_T_tagSetInfo_elements(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_tagSetInfo_elements_sequence_of, hf_index, ett_z3950_T_tagSetInfo_elements);

  return offset;
}


static const ber_sequence_t TagSetInfo_sequence[] = {
  { &hf_z3950_commonInfo    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_CommonInfo },
  { &hf_z3950_tagSet        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_OBJECT_IDENTIFIER },
  { &hf_z3950_name          , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_description   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_tagSetInfo_elements, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_tagSetInfo_elements },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_TagSetInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TagSetInfo_sequence, hf_index, ett_z3950_TagSetInfo);

  return offset;
}


static const ber_sequence_t T_transferSyntaxes_sequence_of[1] = {
  { &hf_z3950_transferSyntaxes_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_z3950_OBJECT_IDENTIFIER },
};

static int
dissect_z3950_T_transferSyntaxes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_transferSyntaxes_sequence_of, hf_index, ett_z3950_T_transferSyntaxes);

  return offset;
}


static const ber_sequence_t RecordSyntaxInfo_sequence[] = {
  { &hf_z3950_commonInfo    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_CommonInfo },
  { &hf_z3950_recordSyntax  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_OBJECT_IDENTIFIER },
  { &hf_z3950_name          , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_transferSyntaxes, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_transferSyntaxes },
  { &hf_z3950_description   , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_asn1Module    , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_abstractStructure, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_ElementInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_RecordSyntaxInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RecordSyntaxInfo_sequence, hf_index, ett_z3950_RecordSyntaxInfo);

  return offset;
}


static const ber_sequence_t AttributeDescription_sequence[] = {
  { &hf_z3950_name          , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_description   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_attributeDescription_attributeValue, BER_CLASS_CON, 2, BER_FLAGS_NOTCHKTAG, dissect_z3950_StringOrNumeric },
  { &hf_z3950_equivalentAttributes, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_StringOrNumeric },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_AttributeDescription(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeDescription_sequence, hf_index, ett_z3950_AttributeDescription);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AttributeDescription_sequence_of[1] = {
  { &hf_z3950_attributeValues_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_AttributeDescription },
};

static int
dissect_z3950_SEQUENCE_OF_AttributeDescription(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_AttributeDescription_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_AttributeDescription);

  return offset;
}


static const ber_sequence_t AttributeType_sequence[] = {
  { &hf_z3950_name          , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_description   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_attributeType , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_attributeValues, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_AttributeDescription },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_AttributeType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeType_sequence, hf_index, ett_z3950_AttributeType);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AttributeType_sequence_of[1] = {
  { &hf_z3950_attributeSetInfo_attributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_AttributeType },
};

static int
dissect_z3950_SEQUENCE_OF_AttributeType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_AttributeType_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_AttributeType);

  return offset;
}


static const ber_sequence_t AttributeSetInfo_sequence[] = {
  { &hf_z3950_commonInfo    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_CommonInfo },
  { &hf_z3950_attributeSet  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_AttributeSetId },
  { &hf_z3950_name          , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_attributeSetInfo_attributes, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_AttributeType },
  { &hf_z3950_description   , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_AttributeSetInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeSetInfo_sequence, hf_index, ett_z3950_AttributeSetInfo);

  return offset;
}


static const value_string z3950_T_searchCost_vals[] = {
  {   0, "optimized" },
  {   1, "normal" },
  {   2, "expensive" },
  {   3, "filter" },
  { 0, NULL }
};


static int
dissect_z3950_T_searchCost(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T_termLists_item_sequence[] = {
  { &hf_z3950_name          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_title         , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_searchCost    , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_searchCost },
  { &hf_z3950_scanable      , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_broader       , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_InternationalString },
  { &hf_z3950_narrower      , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_InternationalString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_termLists_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_termLists_item_sequence, hf_index, ett_z3950_T_termLists_item);

  return offset;
}


static const ber_sequence_t T_termLists_sequence_of[1] = {
  { &hf_z3950_termLists_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_T_termLists_item },
};

static int
dissect_z3950_T_termLists(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_termLists_sequence_of, hf_index, ett_z3950_T_termLists);

  return offset;
}


static const ber_sequence_t TermListInfo_sequence[] = {
  { &hf_z3950_commonInfo    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_CommonInfo },
  { &hf_z3950_databaseName  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_DatabaseName },
  { &hf_z3950_termLists     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_T_termLists },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_TermListInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TermListInfo_sequence, hf_index, ett_z3950_TermListInfo);

  return offset;
}


static const value_string z3950_T_extendedServicesInfo_waitAction_vals[] = {
  {   1, "waitSupported" },
  {   2, "waitAlways" },
  {   3, "waitNotSupported" },
  {   4, "depends" },
  {   5, "notSaying" },
  { 0, NULL }
};


static int
dissect_z3950_T_extendedServicesInfo_waitAction(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ExtendedServicesInfo_sequence[] = {
  { &hf_z3950_commonInfo    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_CommonInfo },
  { &hf_z3950_extendedServicesInfo_type, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_OBJECT_IDENTIFIER },
  { &hf_z3950_name          , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_privateType   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_restrictionsApply, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_feeApply      , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_available     , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_retentionSupported, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_extendedServicesInfo_waitAction, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_z3950_T_extendedServicesInfo_waitAction },
  { &hf_z3950_description   , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_specificExplain, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_EXTERNAL },
  { &hf_z3950_esASN         , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ExtendedServicesInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExtendedServicesInfo_sequence, hf_index, ett_z3950_ExtendedServicesInfo);

  return offset;
}


static const ber_sequence_t OmittedAttributeInterpretation_sequence[] = {
  { &hf_z3950_defaultValue  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_z3950_StringOrNumeric },
  { &hf_z3950_defaultDescription, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_OmittedAttributeInterpretation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OmittedAttributeInterpretation_sequence, hf_index, ett_z3950_OmittedAttributeInterpretation);

  return offset;
}


static const ber_sequence_t AttributeValue_sequence[] = {
  { &hf_z3950_attributeValue_value, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_z3950_StringOrNumeric },
  { &hf_z3950_description   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_subAttributes , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_StringOrNumeric },
  { &hf_z3950_superAttributes, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_StringOrNumeric },
  { &hf_z3950_partialSupport, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_AttributeValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeValue_sequence, hf_index, ett_z3950_AttributeValue);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AttributeValue_sequence_of[1] = {
  { &hf_z3950_attributeTypeDetails_attributeValues_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_AttributeValue },
};

static int
dissect_z3950_SEQUENCE_OF_AttributeValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_AttributeValue_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_AttributeValue);

  return offset;
}


static const ber_sequence_t AttributeTypeDetails_sequence[] = {
  { &hf_z3950_attributeType , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_defaultIfOmitted, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_OmittedAttributeInterpretation },
  { &hf_z3950_attributeTypeDetails_attributeValues, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_AttributeValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_AttributeTypeDetails(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeTypeDetails_sequence, hf_index, ett_z3950_AttributeTypeDetails);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AttributeTypeDetails_sequence_of[1] = {
  { &hf_z3950_attributesByType_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_AttributeTypeDetails },
};

static int
dissect_z3950_SEQUENCE_OF_AttributeTypeDetails(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_AttributeTypeDetails_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_AttributeTypeDetails);

  return offset;
}


static const ber_sequence_t AttributeSetDetails_sequence[] = {
  { &hf_z3950_attributeSet  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_AttributeSetId },
  { &hf_z3950_attributesByType, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_AttributeTypeDetails },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_AttributeSetDetails(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeSetDetails_sequence, hf_index, ett_z3950_AttributeSetDetails);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AttributeSetDetails_sequence_of[1] = {
  { &hf_z3950_attributesBySet_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_AttributeSetDetails },
};

static int
dissect_z3950_SEQUENCE_OF_AttributeSetDetails(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_AttributeSetDetails_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_AttributeSetDetails);

  return offset;
}


static const value_string z3950_T_attributeOccurrence_attributeValues_vals[] = {
  {   3, "any-or-none" },
  {   4, "specific" },
  { 0, NULL }
};

static const ber_choice_t T_attributeOccurrence_attributeValues_choice[] = {
  {   3, &hf_z3950_any_or_none   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   4, &hf_z3950_specific      , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_StringOrNumeric },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_attributeOccurrence_attributeValues(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_attributeOccurrence_attributeValues_choice, hf_index, ett_z3950_T_attributeOccurrence_attributeValues,
                                 NULL);

  return offset;
}


static const ber_sequence_t AttributeOccurrence_sequence[] = {
  { &hf_z3950_attributeSet  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_AttributeSetId },
  { &hf_z3950_attributeType , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_mustBeSupplied, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  { &hf_z3950_attributeOccurrence_attributeValues, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_T_attributeOccurrence_attributeValues },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_AttributeOccurrence(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeOccurrence_sequence, hf_index, ett_z3950_AttributeOccurrence);

  return offset;
}


static const ber_sequence_t AttributeCombination_sequence_of[1] = {
  { &hf_z3950_AttributeCombination_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_AttributeOccurrence },
};

static int
dissect_z3950_AttributeCombination(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      AttributeCombination_sequence_of, hf_index, ett_z3950_AttributeCombination);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AttributeCombination_sequence_of[1] = {
  { &hf_z3950_legalCombinations_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_AttributeCombination },
};

static int
dissect_z3950_SEQUENCE_OF_AttributeCombination(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_AttributeCombination_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_AttributeCombination);

  return offset;
}


static const ber_sequence_t AttributeCombinations_sequence[] = {
  { &hf_z3950_defaultAttributeSet, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_AttributeSetId },
  { &hf_z3950_legalCombinations, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_AttributeCombination },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_AttributeCombinations(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeCombinations_sequence, hf_index, ett_z3950_AttributeCombinations);

  return offset;
}


static const ber_sequence_t AttributeDetails_sequence[] = {
  { &hf_z3950_commonInfo    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_CommonInfo },
  { &hf_z3950_databaseName  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_DatabaseName },
  { &hf_z3950_attributesBySet, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_AttributeSetDetails },
  { &hf_z3950_attributeCombinations, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_AttributeCombinations },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_AttributeDetails(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeDetails_sequence, hf_index, ett_z3950_AttributeDetails);

  return offset;
}


static const ber_sequence_t T_scanInfo_sequence[] = {
  { &hf_z3950_maxStepSize   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_collatingSequence, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_increasing    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_scanInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_scanInfo_sequence, hf_index, ett_z3950_T_scanInfo);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Term_sequence_of[1] = {
  { &hf_z3950_sampleTerms_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_Term },
};

static int
dissect_z3950_SEQUENCE_OF_Term(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Term_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_Term);

  return offset;
}


static const ber_sequence_t TermListDetails_sequence[] = {
  { &hf_z3950_commonInfo    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_CommonInfo },
  { &hf_z3950_termListName  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_description   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_termListDetails_attributes, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_AttributeCombinations },
  { &hf_z3950_scanInfo      , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_scanInfo },
  { &hf_z3950_estNumberTerms, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_sampleTerms   , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_Term },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_TermListDetails(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TermListDetails_sequence, hf_index, ett_z3950_TermListDetails);

  return offset;
}


static const ber_sequence_t RecordTag_sequence[] = {
  { &hf_z3950_qualifier     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_z3950_StringOrNumeric },
  { &hf_z3950_tagValue      , BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_z3950_StringOrNumeric },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_RecordTag(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RecordTag_sequence, hf_index, ett_z3950_RecordTag);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Path_sequence_of[1] = {
  { &hf_z3950_schemaTags_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_Path },
};

static int
dissect_z3950_SEQUENCE_OF_Path(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Path_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_Path);

  return offset;
}


static const ber_sequence_t PerElementDetails_sequence[] = {
  { &hf_z3950_name          , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_recordTag     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_RecordTag },
  { &hf_z3950_schemaTags    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_Path },
  { &hf_z3950_maxSize       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_minSize       , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_avgSize       , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_fixedSize     , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_repeatable    , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_required      , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_description   , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_contents      , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_billingInfo   , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_restrictions  , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_alternateNames, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_InternationalString },
  { &hf_z3950_genericNames  , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_InternationalString },
  { &hf_z3950_searchAccess  , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_AttributeCombinations },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_PerElementDetails(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PerElementDetails_sequence, hf_index, ett_z3950_PerElementDetails);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_PerElementDetails_sequence_of[1] = {
  { &hf_z3950_detailsPerElement_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_PerElementDetails },
};

static int
dissect_z3950_SEQUENCE_OF_PerElementDetails(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_PerElementDetails_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_PerElementDetails);

  return offset;
}


static const ber_sequence_t ElementSetDetails_sequence[] = {
  { &hf_z3950_commonInfo    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_CommonInfo },
  { &hf_z3950_databaseName  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_DatabaseName },
  { &hf_z3950_elementSetDetails_elementSetName, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_ElementSetName },
  { &hf_z3950_recordSyntax  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_OBJECT_IDENTIFIER },
  { &hf_z3950_schema        , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_z3950_OBJECT_IDENTIFIER },
  { &hf_z3950_description   , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_detailsPerElement, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_PerElementDetails },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ElementSetDetails(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ElementSetDetails_sequence, hf_index, ett_z3950_ElementSetDetails);

  return offset;
}


static const ber_sequence_t RetrievalRecordDetails_sequence[] = {
  { &hf_z3950_commonInfo    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_CommonInfo },
  { &hf_z3950_databaseName  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_DatabaseName },
  { &hf_z3950_schema        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_OBJECT_IDENTIFIER },
  { &hf_z3950_recordSyntax  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_OBJECT_IDENTIFIER },
  { &hf_z3950_description   , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_detailsPerElement, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_PerElementDetails },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_RetrievalRecordDetails(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RetrievalRecordDetails_sequence, hf_index, ett_z3950_RetrievalRecordDetails);

  return offset;
}


static const value_string z3950_T_sortType_vals[] = {
  {   0, "character" },
  {   1, "numeric" },
  {   2, "structured" },
  { 0, NULL }
};

static const ber_choice_t T_sortType_choice[] = {
  {   0, &hf_z3950_character     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   1, &hf_z3950_sortKeyDetails_sortType_numeric, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   2, &hf_z3950_sortKeyDetails_sortType_structured, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_sortType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_sortType_choice, hf_index, ett_z3950_T_sortType,
                                 NULL);

  return offset;
}


static const value_string z3950_T_sortKeyDetails_caseSensitivity_vals[] = {
  {   0, "always" },
  {   1, "never" },
  {   2, "default-yes" },
  {   3, "default-no" },
  { 0, NULL }
};


static int
dissect_z3950_T_sortKeyDetails_caseSensitivity(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SortKeyDetails_sequence[] = {
  { &hf_z3950_description   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_elementSpecifications, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_Specification },
  { &hf_z3950_attributeSpecifications, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_AttributeCombinations },
  { &hf_z3950_sortType      , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_z3950_T_sortType },
  { &hf_z3950_sortKeyDetails_caseSensitivity, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_sortKeyDetails_caseSensitivity },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_SortKeyDetails(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SortKeyDetails_sequence, hf_index, ett_z3950_SortKeyDetails);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_SortKeyDetails_sequence_of[1] = {
  { &hf_z3950_sortKeys_item , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_SortKeyDetails },
};

static int
dissect_z3950_SEQUENCE_OF_SortKeyDetails(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_SortKeyDetails_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_SortKeyDetails);

  return offset;
}


static const ber_sequence_t SortDetails_sequence[] = {
  { &hf_z3950_commonInfo    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_CommonInfo },
  { &hf_z3950_databaseName  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_DatabaseName },
  { &hf_z3950_sortKeys      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_SortKeyDetails },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_SortDetails(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SortDetails_sequence, hf_index, ett_z3950_SortDetails);

  return offset;
}


static const value_string z3950_T_processingContext_vals[] = {
  {   0, "access" },
  {   1, "search" },
  {   2, "retrieval" },
  {   3, "record-presentation" },
  {   4, "record-handling" },
  { 0, NULL }
};


static int
dissect_z3950_T_processingContext(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ProcessingInformation_sequence[] = {
  { &hf_z3950_commonInfo    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_CommonInfo },
  { &hf_z3950_databaseName  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_DatabaseName },
  { &hf_z3950_processingContext, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_T_processingContext },
  { &hf_z3950_name          , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_oid           , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_z3950_OBJECT_IDENTIFIER },
  { &hf_z3950_description   , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_instructions  , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_EXTERNAL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ProcessingInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProcessingInformation_sequence, hf_index, ett_z3950_ProcessingInformation);

  return offset;
}


static const value_string z3950_ValueDescription_vals[] = {
  {   0, "integer" },
  {   1, "string" },
  {   2, "octets" },
  {   3, "oid" },
  {   4, "unit" },
  {   5, "valueAndUnit" },
  { 0, NULL }
};

static const ber_choice_t ValueDescription_choice[] = {
  {   0, &hf_z3950_integer       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_z3950_INTEGER },
  {   1, &hf_z3950_string        , BER_CLASS_UNI, BER_UNI_TAG_GeneralString, BER_FLAGS_NOOWNTAG, dissect_z3950_InternationalString },
  {   2, &hf_z3950_octets        , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_z3950_OCTET_STRING },
  {   3, &hf_z3950_oid           , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_z3950_OBJECT_IDENTIFIER },
  {   4, &hf_z3950_valueDescription_unit, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_Unit },
  {   5, &hf_z3950_valueAndUnit  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_IntUnit },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ValueDescription(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ValueDescription_choice, hf_index, ett_z3950_ValueDescription,
                                 NULL);

  return offset;
}


static const ber_sequence_t ValueRange_sequence[] = {
  { &hf_z3950_lower         , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_z3950_ValueDescription },
  { &hf_z3950_upper         , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_z3950_ValueDescription },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ValueRange(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ValueRange_sequence, hf_index, ett_z3950_ValueRange);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ValueDescription_sequence_of[1] = {
  { &hf_z3950_enumerated_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_ValueDescription },
};

static int
dissect_z3950_SEQUENCE_OF_ValueDescription(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ValueDescription_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_ValueDescription);

  return offset;
}


static const value_string z3950_ValueSet_vals[] = {
  {   0, "range" },
  {   1, "enumerated" },
  { 0, NULL }
};

static const ber_choice_t ValueSet_choice[] = {
  {   0, &hf_z3950_range         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_ValueRange },
  {   1, &hf_z3950_enumerated    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_ValueDescription },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ValueSet(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ValueSet_choice, hf_index, ett_z3950_ValueSet,
                                 NULL);

  return offset;
}


static const ber_sequence_t VariantValue_sequence[] = {
  { &hf_z3950_dataType      , BER_CLASS_CON, 0, 0, dissect_z3950_PrimitiveDataType },
  { &hf_z3950_values        , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_z3950_ValueSet },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_VariantValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   VariantValue_sequence, hf_index, ett_z3950_VariantValue);

  return offset;
}


static const ber_sequence_t VariantType_sequence[] = {
  { &hf_z3950_name          , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_description   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_variantType   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_variantValue  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_VariantValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_VariantType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   VariantType_sequence, hf_index, ett_z3950_VariantType);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_VariantType_sequence_of[1] = {
  { &hf_z3950_variantTypes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_VariantType },
};

static int
dissect_z3950_SEQUENCE_OF_VariantType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_VariantType_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_VariantType);

  return offset;
}


static const ber_sequence_t VariantClass_sequence[] = {
  { &hf_z3950_name          , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_description   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_variantClass  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_variantTypes  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_VariantType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_VariantClass(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   VariantClass_sequence, hf_index, ett_z3950_VariantClass);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_VariantClass_sequence_of[1] = {
  { &hf_z3950_variantSetInfo_variants_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_VariantClass },
};

static int
dissect_z3950_SEQUENCE_OF_VariantClass(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_VariantClass_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_VariantClass);

  return offset;
}


static const ber_sequence_t VariantSetInfo_sequence[] = {
  { &hf_z3950_commonInfo    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_CommonInfo },
  { &hf_z3950_variantSet    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_OBJECT_IDENTIFIER },
  { &hf_z3950_name          , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_variantSetInfo_variants, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_VariantClass },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_VariantSetInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   VariantSetInfo_sequence, hf_index, ett_z3950_VariantSetInfo);

  return offset;
}


static const ber_sequence_t Units_sequence[] = {
  { &hf_z3950_name          , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_description   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_unit          , BER_CLASS_CON, 2, BER_FLAGS_NOTCHKTAG, dissect_z3950_StringOrNumeric },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_Units(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Units_sequence, hf_index, ett_z3950_Units);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Units_sequence_of[1] = {
  { &hf_z3950_unitType_units_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_Units },
};

static int
dissect_z3950_SEQUENCE_OF_Units(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Units_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_Units);

  return offset;
}


static const ber_sequence_t UnitType_sequence[] = {
  { &hf_z3950_name          , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_description   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_unitType      , BER_CLASS_CON, 2, BER_FLAGS_NOTCHKTAG, dissect_z3950_StringOrNumeric },
  { &hf_z3950_unitType_units, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_Units },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_UnitType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UnitType_sequence, hf_index, ett_z3950_UnitType);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_UnitType_sequence_of[1] = {
  { &hf_z3950_unitInfo_units_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_UnitType },
};

static int
dissect_z3950_SEQUENCE_OF_UnitType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_UnitType_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_UnitType);

  return offset;
}


static const ber_sequence_t UnitInfo_sequence[] = {
  { &hf_z3950_commonInfo    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_CommonInfo },
  { &hf_z3950_unitSystem    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_description   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_unitInfo_units, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_UnitType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_UnitInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UnitInfo_sequence, hf_index, ett_z3950_UnitInfo);

  return offset;
}


static const ber_sequence_t CategoryInfo_sequence[] = {
  { &hf_z3950_categoryInfo_category, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_originalCategory, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_description   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_HumanString },
  { &hf_z3950_asn1Module    , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_CategoryInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CategoryInfo_sequence, hf_index, ett_z3950_CategoryInfo);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_CategoryInfo_sequence_of[1] = {
  { &hf_z3950_categories_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_CategoryInfo },
};

static int
dissect_z3950_SEQUENCE_OF_CategoryInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_CategoryInfo_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_CategoryInfo);

  return offset;
}


static const ber_sequence_t CategoryList_sequence[] = {
  { &hf_z3950_commonInfo    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_CommonInfo },
  { &hf_z3950_categories    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_CategoryInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_CategoryList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CategoryList_sequence, hf_index, ett_z3950_CategoryList);

  return offset;
}


static const value_string z3950_Explain_Record_vals[] = {
  {   0, "targetInfo" },
  {   1, "databaseInfo" },
  {   2, "schemaInfo" },
  {   3, "tagSetInfo" },
  {   4, "recordSyntaxInfo" },
  {   5, "attributeSetInfo" },
  {   6, "termListInfo" },
  {   7, "extendedServicesInfo" },
  {   8, "attributeDetails" },
  {   9, "termListDetails" },
  {  10, "elementSetDetails" },
  {  11, "retrievalRecordDetails" },
  {  12, "sortDetails" },
  {  13, "processing" },
  {  14, "variants" },
  {  15, "units" },
  { 100, "categoryList" },
  { 0, NULL }
};

static const ber_choice_t Explain_Record_choice[] = {
  {   0, &hf_z3950_targetInfo    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_z3950_TargetInfo },
  {   1, &hf_z3950_databaseInfo  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_DatabaseInfo },
  {   2, &hf_z3950_schemaInfo    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_SchemaInfo },
  {   3, &hf_z3950_tagSetInfo    , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_TagSetInfo },
  {   4, &hf_z3950_recordSyntaxInfo, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_z3950_RecordSyntaxInfo },
  {   5, &hf_z3950_attributeSetInfo, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_z3950_AttributeSetInfo },
  {   6, &hf_z3950_termListInfo  , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_z3950_TermListInfo },
  {   7, &hf_z3950_extendedServicesInfo, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_z3950_ExtendedServicesInfo },
  {   8, &hf_z3950_attributeDetails, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_z3950_AttributeDetails },
  {   9, &hf_z3950_termListDetails, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_z3950_TermListDetails },
  {  10, &hf_z3950_elementSetDetails, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_z3950_ElementSetDetails },
  {  11, &hf_z3950_retrievalRecordDetails, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_z3950_RetrievalRecordDetails },
  {  12, &hf_z3950_sortDetails   , BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_z3950_SortDetails },
  {  13, &hf_z3950_processing    , BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_z3950_ProcessingInformation },
  {  14, &hf_z3950_variants      , BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_z3950_VariantSetInfo },
  {  15, &hf_z3950_units         , BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_z3950_UnitInfo },
  { 100, &hf_z3950_categoryList  , BER_CLASS_CON, 100, BER_FLAGS_IMPLTAG, dissect_z3950_CategoryList },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_Explain_Record(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Explain_Record_choice, hf_index, ett_z3950_Explain_Record,
                                 NULL);

  return offset;
}


static const ber_sequence_t FormatSpec_sequence[] = {
  { &hf_z3950_formatSpec_type, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_size          , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_bestPosn      , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_FormatSpec(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FormatSpec_sequence, hf_index, ett_z3950_FormatSpec);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_FormatSpec_sequence_of[1] = {
  { &hf_z3950_briefBib_format_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_FormatSpec },
};

static int
dissect_z3950_SEQUENCE_OF_FormatSpec(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_FormatSpec_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_FormatSpec);

  return offset;
}


static const ber_sequence_t BriefBib_sequence[] = {
  { &hf_z3950_briefBib_title, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_author        , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_callNumber    , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_recordType    , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_bibliographicLevel, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_briefBib_format, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_FormatSpec },
  { &hf_z3950_publicationPlace, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_publicationDate, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_targetSystemKey, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_satisfyingElement, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_rank          , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_documentId    , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_abstract      , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_otherInfo     , BER_CLASS_CON, 201, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_z3950_OtherInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_BriefBib(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BriefBib_sequence, hf_index, ett_z3950_BriefBib);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_TaggedElement_sequence_of[1] = {
  { &hf_z3950_subtree_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_TaggedElement },
};

static int
dissect_z3950_SEQUENCE_OF_TaggedElement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_TaggedElement_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_TaggedElement);

  return offset;
}


static const value_string z3950_ElementData_vals[] = {
  {   0, "octets" },
  {   1, "numeric" },
  {   2, "date" },
  {   3, "ext" },
  {   4, "string" },
  {   5, "trueOrFalse" },
  {   6, "oid" },
  {   7, "intUnit" },
  {   8, "elementNotThere" },
  {   9, "elementEmpty" },
  {  10, "noDataRequested" },
  {  11, "diagnostic" },
  {  12, "subtree" },
  { 0, NULL }
};

static const ber_choice_t ElementData_choice[] = {
  {   0, &hf_z3950_octets        , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_z3950_OCTET_STRING },
  {   1, &hf_z3950_numeric       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_z3950_INTEGER },
  {   2, &hf_z3950_date          , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_z3950_GeneralizedTime },
  {   3, &hf_z3950_ext           , BER_CLASS_UNI, BER_UNI_TAG_EXTERNAL, BER_FLAGS_NOOWNTAG, dissect_z3950_EXTERNAL },
  {   4, &hf_z3950_string        , BER_CLASS_UNI, BER_UNI_TAG_GeneralString, BER_FLAGS_NOOWNTAG, dissect_z3950_InternationalString },
  {   5, &hf_z3950_trueOrFalse   , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_z3950_BOOLEAN },
  {   6, &hf_z3950_oid           , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_z3950_OBJECT_IDENTIFIER },
  {   7, &hf_z3950_intUnit       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_IntUnit },
  {   8, &hf_z3950_elementNotThere, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   9, &hf_z3950_elementEmpty  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {  10, &hf_z3950_noDataRequested, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {  11, &hf_z3950_elementData_diagnostic, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_z3950_EXTERNAL },
  {  12, &hf_z3950_subtree       , BER_CLASS_CON, 6, 0, dissect_z3950_SEQUENCE_OF_TaggedElement },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ElementData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ElementData_choice, hf_index, ett_z3950_ElementData,
                                 NULL);

  return offset;
}


static const ber_sequence_t Order_sequence[] = {
  { &hf_z3950_ascending     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_order         , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_Order(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Order_sequence, hf_index, ett_z3950_Order);

  return offset;
}


static const value_string z3950_T_usage_type_vals[] = {
  {   1, "redistributable" },
  {   2, "restricted" },
  {   3, "licensePointer" },
  { 0, NULL }
};


static int
dissect_z3950_T_usage_type(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t Usage_sequence[] = {
  { &hf_z3950_usage_type    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_T_usage_type },
  { &hf_z3950_restriction   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_Usage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Usage_sequence, hf_index, ett_z3950_Usage);

  return offset;
}


static const ber_sequence_t HitVector_sequence[] = {
  { &hf_z3950_satisfier     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_z3950_Term },
  { &hf_z3950_offsetIntoElement, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_IntUnit },
  { &hf_z3950_length        , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_IntUnit },
  { &hf_z3950_hitRank       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_targetToken   , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_HitVector(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   HitVector_sequence, hf_index, ett_z3950_HitVector);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_HitVector_sequence_of[1] = {
  { &hf_z3950_hits_item     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_HitVector },
};

static int
dissect_z3950_SEQUENCE_OF_HitVector(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_HitVector_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_HitVector);

  return offset;
}


static const value_string z3950_T_variant_triples_item_value_vals[] = {
  {   0, "integer" },
  {   1, "string" },
  {   2, "octetString" },
  {   3, "oid" },
  {   4, "boolean" },
  {   5, "null" },
  {   6, "unit" },
  {   7, "valueAndUnit" },
  { 0, NULL }
};

static const ber_choice_t T_variant_triples_item_value_choice[] = {
  {   0, &hf_z3950_integer       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_z3950_INTEGER },
  {   1, &hf_z3950_string        , BER_CLASS_UNI, BER_UNI_TAG_GeneralString, BER_FLAGS_NOOWNTAG, dissect_z3950_InternationalString },
  {   2, &hf_z3950_octetString   , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_z3950_OCTET_STRING },
  {   3, &hf_z3950_oid           , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_z3950_OBJECT_IDENTIFIER },
  {   4, &hf_z3950_boolean       , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_z3950_BOOLEAN },
  {   5, &hf_z3950_null          , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_z3950_NULL },
  {   6, &hf_z3950_variant_triples_item_value_unit, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_Unit },
  {   7, &hf_z3950_valueAndUnit  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_IntUnit },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_variant_triples_item_value(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_variant_triples_item_value_choice, hf_index, ett_z3950_T_variant_triples_item_value,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_triples_item_sequence[] = {
  { &hf_z3950_variantSetId  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_OBJECT_IDENTIFIER },
  { &hf_z3950_class         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_type          , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_variant_triples_item_value, BER_CLASS_CON, 3, 0, dissect_z3950_T_variant_triples_item_value },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_triples_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_triples_item_sequence, hf_index, ett_z3950_T_triples_item);

  return offset;
}


static const ber_sequence_t T_triples_sequence_of[1] = {
  { &hf_z3950_triples_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_T_triples_item },
};

static int
dissect_z3950_T_triples(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_triples_sequence_of, hf_index, ett_z3950_T_triples);

  return offset;
}


static const ber_sequence_t Variant_sequence[] = {
  { &hf_z3950_globalVariantSetId, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_OBJECT_IDENTIFIER },
  { &hf_z3950_triples       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_T_triples },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_Variant(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Variant_sequence, hf_index, ett_z3950_Variant);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Variant_sequence_of[1] = {
  { &hf_z3950_supportedVariants_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_Variant },
};

static int
dissect_z3950_SEQUENCE_OF_Variant(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Variant_sequence_of, hf_index, ett_z3950_SEQUENCE_OF_Variant);

  return offset;
}


static const ber_sequence_t TagPath_item_sequence[] = {
  { &hf_z3950_tagType       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_tagValue      , BER_CLASS_CON, 2, BER_FLAGS_NOTCHKTAG, dissect_z3950_StringOrNumeric },
  { &hf_z3950_tagOccurrence , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_TagPath_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TagPath_item_sequence, hf_index, ett_z3950_TagPath_item);

  return offset;
}


static const ber_sequence_t TagPath_sequence_of[1] = {
  { &hf_z3950_TagPath_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_TagPath_item },
};

static int
dissect_z3950_TagPath(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      TagPath_sequence_of, hf_index, ett_z3950_TagPath);

  return offset;
}


static const ber_sequence_t ElementMetaData_sequence[] = {
  { &hf_z3950_seriesOrder   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_Order },
  { &hf_z3950_usageRight    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_Usage },
  { &hf_z3950_hits          , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_HitVector },
  { &hf_z3950_displayName   , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_supportedVariants, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_Variant },
  { &hf_z3950_message       , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_elementDescriptor, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_OCTET_STRING },
  { &hf_z3950_surrogateFor  , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_TagPath },
  { &hf_z3950_surrogateElement, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_TagPath },
  { &hf_z3950_other         , BER_CLASS_CON, 99, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_EXTERNAL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ElementMetaData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ElementMetaData_sequence, hf_index, ett_z3950_ElementMetaData);

  return offset;
}


static const ber_sequence_t TaggedElement_sequence[] = {
  { &hf_z3950_tagType       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_tagValue      , BER_CLASS_CON, 2, BER_FLAGS_NOTCHKTAG, dissect_z3950_StringOrNumeric },
  { &hf_z3950_tagOccurrence , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_taggedElement_content, BER_CLASS_CON, 4, BER_FLAGS_NOTCHKTAG, dissect_z3950_ElementData },
  { &hf_z3950_metaData      , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_ElementMetaData },
  { &hf_z3950_appliedVariant, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_Variant },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_TaggedElement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TaggedElement_sequence, hf_index, ett_z3950_TaggedElement);

  return offset;
}


static const ber_sequence_t GenericRecord_sequence_of[1] = {
  { &hf_z3950_GenericRecord_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_TaggedElement },
};

static int
dissect_z3950_GenericRecord(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      GenericRecord_sequence_of, hf_index, ett_z3950_GenericRecord);

  return offset;
}


static const value_string z3950_T_taskStatus_vals[] = {
  {   0, "pending" },
  {   1, "active" },
  {   2, "complete" },
  {   3, "aborted" },
  { 0, NULL }
};


static int
dissect_z3950_T_taskStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t TaskPackage_sequence[] = {
  { &hf_z3950_packageType   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_OBJECT_IDENTIFIER },
  { &hf_z3950_packageName   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_userId        , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_retentionTime , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_IntUnit },
  { &hf_z3950_permissions   , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_Permissions },
  { &hf_z3950_taskPackage_description, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_targetReference, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_OCTET_STRING },
  { &hf_z3950_creationDateTime, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_GeneralizedTime },
  { &hf_z3950_taskStatus    , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_z3950_T_taskStatus },
  { &hf_z3950_packageDiagnostics, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_DiagRec },
  { &hf_z3950_taskSpecificParameters, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_z3950_EXTERNAL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_TaskPackage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TaskPackage_sequence, hf_index, ett_z3950_TaskPackage);

  return offset;
}


static const value_string z3950_T_promptId_enummeratedPrompt_type_vals[] = {
  {   0, "groupId" },
  {   1, "userId" },
  {   2, "password" },
  {   3, "newPassword" },
  {   4, "copyright" },
  {   5, "sessionId" },
  { 0, NULL }
};


static int
dissect_z3950_T_promptId_enummeratedPrompt_type(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T_enummeratedPrompt_sequence[] = {
  { &hf_z3950_promptId_enummeratedPrompt_type, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_T_promptId_enummeratedPrompt_type },
  { &hf_z3950_suggestedString, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_enummeratedPrompt(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_enummeratedPrompt_sequence, hf_index, ett_z3950_T_enummeratedPrompt);

  return offset;
}


static const value_string z3950_PromptId_vals[] = {
  {   1, "enummeratedPrompt" },
  {   2, "nonEnumeratedPrompt" },
  { 0, NULL }
};

static const ber_choice_t PromptId_choice[] = {
  {   1, &hf_z3950_enummeratedPrompt, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_T_enummeratedPrompt },
  {   2, &hf_z3950_nonEnumeratedPrompt, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_PromptId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PromptId_choice, hf_index, ett_z3950_PromptId,
                                 NULL);

  return offset;
}


static const ber_sequence_t Encryption_sequence[] = {
  { &hf_z3950_cryptType     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_OCTET_STRING },
  { &hf_z3950_credential    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_OCTET_STRING },
  { &hf_z3950_data          , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_Encryption(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Encryption_sequence, hf_index, ett_z3950_Encryption);

  return offset;
}


static const value_string z3950_T_promptInfo_vals[] = {
  {   1, "character" },
  {   2, "encrypted" },
  { 0, NULL }
};

static const ber_choice_t T_promptInfo_choice[] = {
  {   1, &hf_z3950_challenge_item_promptInfo_character, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  {   2, &hf_z3950_encrypted     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_Encryption },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_promptInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_promptInfo_choice, hf_index, ett_z3950_T_promptInfo,
                                 NULL);

  return offset;
}


static const value_string z3950_T_challenge_item_dataType_vals[] = {
  {   1, "integer" },
  {   2, "date" },
  {   3, "float" },
  {   4, "alphaNumeric" },
  {   5, "url-urn" },
  {   6, "boolean" },
  { 0, NULL }
};


static int
dissect_z3950_T_challenge_item_dataType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t Challenge_item_sequence[] = {
  { &hf_z3950_promptId      , BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_z3950_PromptId },
  { &hf_z3950_defaultResponse, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_promptInfo    , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_z3950_T_promptInfo },
  { &hf_z3950_regExpr       , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_responseRequired, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  { &hf_z3950_allowedValues , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_InternationalString },
  { &hf_z3950_shouldSave    , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  { &hf_z3950_challenge_item_dataType, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_T_challenge_item_dataType },
  { &hf_z3950_challenge_item_diagnostic, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_EXTERNAL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_Challenge_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Challenge_item_sequence, hf_index, ett_z3950_Challenge_item);

  return offset;
}


static const ber_sequence_t Challenge_sequence_of[1] = {
  { &hf_z3950_Challenge_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_Challenge_item },
};

static int
dissect_z3950_Challenge(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Challenge_sequence_of, hf_index, ett_z3950_Challenge);

  return offset;
}


static const value_string z3950_T_promptResponse_vals[] = {
  {   1, "string" },
  {   2, "accept" },
  {   3, "acknowledge" },
  {   4, "diagnostic" },
  {   5, "encrypted" },
  { 0, NULL }
};

static const ber_choice_t T_promptResponse_choice[] = {
  {   1, &hf_z3950_string        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  {   2, &hf_z3950_accept        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  {   3, &hf_z3950_acknowledge   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   4, &hf_z3950_diagnostic    , BER_CLASS_CON, 4, 0, dissect_z3950_DiagRec },
  {   5, &hf_z3950_encrypted     , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_z3950_Encryption },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_promptResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_promptResponse_choice, hf_index, ett_z3950_T_promptResponse,
                                 NULL);

  return offset;
}


static const ber_sequence_t Response_item_sequence[] = {
  { &hf_z3950_promptId      , BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_z3950_PromptId },
  { &hf_z3950_promptResponse, BER_CLASS_CON, 2, 0, dissect_z3950_T_promptResponse },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_Response_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Response_item_sequence, hf_index, ett_z3950_Response_item);

  return offset;
}


static const ber_sequence_t Response_sequence_of[1] = {
  { &hf_z3950_Response_item , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_Response_item },
};

static int
dissect_z3950_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Response_sequence_of, hf_index, ett_z3950_Response);

  return offset;
}


static const value_string z3950_PromptObject_vals[] = {
  {   1, "challenge" },
  {   2, "response" },
  { 0, NULL }
};

static const ber_choice_t PromptObject_choice[] = {
  {   1, &hf_z3950_challenge     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_Challenge },
  {   2, &hf_z3950_response      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_Response },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_PromptObject(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PromptObject_choice, hf_index, ett_z3950_PromptObject,
                                 NULL);

  return offset;
}


static const ber_sequence_t DRNType_sequence[] = {
  { &hf_z3950_dRNType_userId, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_OCTET_STRING },
  { &hf_z3950_salt          , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_OCTET_STRING },
  { &hf_z3950_randomNumber  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_z3950_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_DRNType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DRNType_sequence, hf_index, ett_z3950_DRNType);

  return offset;
}


static const value_string z3950_DES_RN_Object_vals[] = {
  {   1, "challenge" },
  {   2, "response" },
  { 0, NULL }
};

static const ber_choice_t DES_RN_Object_choice[] = {
  {   1, &hf_z3950_dES_RN_Object_challenge, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_DRNType },
  {   2, &hf_z3950_rES_RN_Object_response, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_DRNType },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_DES_RN_Object(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DES_RN_Object_choice, hf_index, ett_z3950_DES_RN_Object,
                                 NULL);

  return offset;
}


static const ber_sequence_t KRBRequest_sequence[] = {
  { &hf_z3950_service       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_instance      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_realm         , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_KRBRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KRBRequest_sequence, hf_index, ett_z3950_KRBRequest);

  return offset;
}


static const ber_sequence_t KRBResponse_sequence[] = {
  { &hf_z3950_userid        , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_ticket        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_KRBResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KRBResponse_sequence, hf_index, ett_z3950_KRBResponse);

  return offset;
}


static const value_string z3950_KRBObject_vals[] = {
  {   1, "challenge" },
  {   2, "response" },
  { 0, NULL }
};

static const ber_choice_t KRBObject_choice[] = {
  {   1, &hf_z3950_kRBObject_challenge, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_KRBRequest },
  {   2, &hf_z3950_kRBObject_response, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_KRBResponse },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_KRBObject(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 KRBObject_choice, hf_index, ett_z3950_KRBObject,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_queryExpression_term_sequence[] = {
  { &hf_z3950_queryTerm     , BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_z3950_Term },
  { &hf_z3950_termComment   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_queryExpression_term(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_queryExpression_term_sequence, hf_index, ett_z3950_T_queryExpression_term);

  return offset;
}


static const value_string z3950_QueryExpression_vals[] = {
  {   1, "term" },
  {   2, "query" },
  { 0, NULL }
};

static const ber_choice_t QueryExpression_choice[] = {
  {   1, &hf_z3950_queryExpression_term, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_T_queryExpression_term },
  {   2, &hf_z3950_query         , BER_CLASS_CON, 2, 0, dissect_z3950_Query },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_QueryExpression(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 QueryExpression_choice, hf_index, ett_z3950_QueryExpression,
                                 NULL);

  return offset;
}


static const value_string z3950_T_databases_vals[] = {
  {   1, "all" },
  {   2, "list" },
  { 0, NULL }
};

static const ber_choice_t T_databases_choice[] = {
  {   1, &hf_z3950_all           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_z3950_NULL },
  {   2, &hf_z3950_list          , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_SEQUENCE_OF_DatabaseName },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_T_databases(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_databases_choice, hf_index, ett_z3950_T_databases,
                                 NULL);

  return offset;
}


static const ber_sequence_t ResultsByDB_item_sequence[] = {
  { &hf_z3950_databases     , BER_CLASS_CON, 1, 0, dissect_z3950_T_databases },
  { &hf_z3950_count         , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_resultSetName , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_ResultsByDB_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ResultsByDB_item_sequence, hf_index, ett_z3950_ResultsByDB_item);

  return offset;
}


static const ber_sequence_t ResultsByDB_sequence_of[1] = {
  { &hf_z3950_ResultsByDB_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_ResultsByDB_item },
};

static int
dissect_z3950_ResultsByDB(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      ResultsByDB_sequence_of, hf_index, ett_z3950_ResultsByDB);

  return offset;
}


static const ber_sequence_t SearchInfoReport_item_sequence[] = {
  { &hf_z3950_subqueryId    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_InternationalString },
  { &hf_z3950_fullQuery     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_z3950_BOOLEAN },
  { &hf_z3950_subqueryExpression, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_z3950_QueryExpression },
  { &hf_z3950_subqueryInterpretation, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_z3950_QueryExpression },
  { &hf_z3950_subqueryRecommendation, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_z3950_QueryExpression },
  { &hf_z3950_subqueryCount , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_INTEGER },
  { &hf_z3950_subqueryWeight, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_IntUnit },
  { &hf_z3950_resultsByDB   , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_z3950_ResultsByDB },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_z3950_SearchInfoReport_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SearchInfoReport_item_sequence, hf_index, ett_z3950_SearchInfoReport_item);

  return offset;
}


static const ber_sequence_t SearchInfoReport_sequence_of[1] = {
  { &hf_z3950_SearchInfoReport_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_z3950_SearchInfoReport_item },
};

static int
dissect_z3950_SearchInfoReport(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SearchInfoReport_sequence_of, hf_index, ett_z3950_SearchInfoReport);

  return offset;
}

/*--- PDUs ---*/

static int dissect_OCLC_UserInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_z3950_OCLC_UserInformation(FALSE, tvb, offset, &asn1_ctx, tree, hf_z3950_OCLC_UserInformation_PDU);
  return offset;
}
static int dissect_SutrsRecord_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_z3950_SutrsRecord(FALSE, tvb, offset, &asn1_ctx, tree, hf_z3950_SutrsRecord_PDU);
  return offset;
}
static int dissect_OPACRecord_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_z3950_OPACRecord(FALSE, tvb, offset, &asn1_ctx, tree, hf_z3950_OPACRecord_PDU);
  return offset;
}
static int dissect_DiagnosticFormat_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_z3950_DiagnosticFormat(FALSE, tvb, offset, &asn1_ctx, tree, hf_z3950_DiagnosticFormat_PDU);
  return offset;
}
static int dissect_Explain_Record_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_z3950_Explain_Record(FALSE, tvb, offset, &asn1_ctx, tree, hf_z3950_Explain_Record_PDU);
  return offset;
}
static int dissect_BriefBib_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_z3950_BriefBib(FALSE, tvb, offset, &asn1_ctx, tree, hf_z3950_BriefBib_PDU);
  return offset;
}
static int dissect_GenericRecord_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_z3950_GenericRecord(FALSE, tvb, offset, &asn1_ctx, tree, hf_z3950_GenericRecord_PDU);
  return offset;
}
static int dissect_TaskPackage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_z3950_TaskPackage(FALSE, tvb, offset, &asn1_ctx, tree, hf_z3950_TaskPackage_PDU);
  return offset;
}
static int dissect_PromptObject_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_z3950_PromptObject(FALSE, tvb, offset, &asn1_ctx, tree, hf_z3950_PromptObject_PDU);
  return offset;
}
static int dissect_DES_RN_Object_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_z3950_DES_RN_Object(FALSE, tvb, offset, &asn1_ctx, tree, hf_z3950_DES_RN_Object_PDU);
  return offset;
}
static int dissect_KRBObject_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_z3950_KRBObject(FALSE, tvb, offset, &asn1_ctx, tree, hf_z3950_KRBObject_PDU);
  return offset;
}
static int dissect_SearchInfoReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_z3950_SearchInfoReport(FALSE, tvb, offset, &asn1_ctx, tree, hf_z3950_SearchInfoReport_PDU);
  return offset;
}


/*--- End of included file: packet-z3950-fn.c ---*/
#line 921 "./asn1/z3950/packet-z3950-template.c"

static int
dissect_z3950(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item      *z3950_item = NULL;
    proto_tree      *z3950_tree = NULL;
    int                     offset = 0;
    asn1_ctx_t asn1_ctx;
    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);


    /* make entry in the Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);

    /* create the z3950 protocol tree */
    z3950_item = proto_tree_add_item(tree, proto_z3950, tvb, 0, -1, FALSE);
    z3950_tree = proto_item_add_subtree(z3950_item, ett_z3950);

    return dissect_z3950_PDU(FALSE, tvb, offset, &asn1_ctx, z3950_tree, -1);
}

static guint
get_z3950_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    guint plen;
    guint ber_offset;
    TRY {
        /* Skip past identifier */
        ber_offset = get_ber_identifier(tvb, offset, NULL, NULL, NULL);
	ber_offset = get_ber_length(tvb, ber_offset, &plen, NULL);
        plen += (ber_offset - offset);
    }
    CATCH(ReportedBoundsError) {
	plen = 0;
    }
    ENDTRY;

    return plen;
}

static int
dissect_z3950_segment(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{

    /* Min length of 8 assumes 3 for identifer and 5 for length. */
    tcp_dissect_pdus(tvb, pinfo, tree, z3950_desegment, 8, get_z3950_pdu_len, dissect_z3950, data);
    return tvb_captured_length(tvb);
}

/*--- proto_register_z3950 -------------------------------------------*/
void proto_register_z3950(void) {

    /* List of fields */
    static hf_register_info hf[] = {


/*--- Included file: packet-z3950-hfarr.c ---*/
#line 1 "./asn1/z3950/packet-z3950-hfarr.c"
    { &hf_z3950_OCLC_UserInformation_PDU,
      { "OCLC-UserInformation", "z3950.OCLC_UserInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_SutrsRecord_PDU,
      { "SutrsRecord", "z3950.SutrsRecord",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_OPACRecord_PDU,
      { "OPACRecord", "z3950.OPACRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_DiagnosticFormat_PDU,
      { "DiagnosticFormat", "z3950.DiagnosticFormat",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_Explain_Record_PDU,
      { "Explain-Record", "z3950.Explain_Record",
        FT_UINT32, BASE_DEC, VALS(z3950_Explain_Record_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_BriefBib_PDU,
      { "BriefBib", "z3950.BriefBib_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_GenericRecord_PDU,
      { "GenericRecord", "z3950.GenericRecord",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_TaskPackage_PDU,
      { "TaskPackage", "z3950.TaskPackage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_PromptObject_PDU,
      { "PromptObject", "z3950.PromptObject",
        FT_UINT32, BASE_DEC, VALS(z3950_PromptObject_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_DES_RN_Object_PDU,
      { "DES-RN-Object", "z3950.DES_RN_Object",
        FT_UINT32, BASE_DEC, VALS(z3950_DES_RN_Object_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_KRBObject_PDU,
      { "KRBObject", "z3950.KRBObject",
        FT_UINT32, BASE_DEC, VALS(z3950_KRBObject_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_SearchInfoReport_PDU,
      { "SearchInfoReport", "z3950.SearchInfoReport",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_initRequest,
      { "initRequest", "z3950.initRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitializeRequest", HFILL }},
    { &hf_z3950_initResponse,
      { "initResponse", "z3950.initResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitializeResponse", HFILL }},
    { &hf_z3950_searchRequest,
      { "searchRequest", "z3950.searchRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_searchResponse,
      { "searchResponse", "z3950.searchResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_presentRequest,
      { "presentRequest", "z3950.presentRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_presentResponse,
      { "presentResponse", "z3950.presentResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_deleteResultSetRequest,
      { "deleteResultSetRequest", "z3950.deleteResultSetRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_deleteResultSetResponse,
      { "deleteResultSetResponse", "z3950.deleteResultSetResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_accessControlRequest,
      { "accessControlRequest", "z3950.accessControlRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_accessControlResponse,
      { "accessControlResponse", "z3950.accessControlResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_resourceControlRequest,
      { "resourceControlRequest", "z3950.resourceControlRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_resourceControlResponse,
      { "resourceControlResponse", "z3950.resourceControlResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_triggerResourceControlRequest,
      { "triggerResourceControlRequest", "z3950.triggerResourceControlRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_resourceReportRequest,
      { "resourceReportRequest", "z3950.resourceReportRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_resourceReportResponse,
      { "resourceReportResponse", "z3950.resourceReportResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_scanRequest,
      { "scanRequest", "z3950.scanRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_scanResponse,
      { "scanResponse", "z3950.scanResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_sortRequest,
      { "sortRequest", "z3950.sortRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_sortResponse,
      { "sortResponse", "z3950.sortResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_segmentRequest,
      { "segmentRequest", "z3950.segmentRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Segment", HFILL }},
    { &hf_z3950_extendedServicesRequest,
      { "extendedServicesRequest", "z3950.extendedServicesRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_extendedServicesResponse,
      { "extendedServicesResponse", "z3950.extendedServicesResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_close,
      { "close", "z3950.close_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_referenceId,
      { "referenceId", "z3950.referenceId",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_protocolVersion,
      { "protocolVersion", "z3950.protocolVersion",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_options,
      { "options", "z3950.options",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_preferredMessageSize,
      { "preferredMessageSize", "z3950.preferredMessageSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_exceptionalRecordSize,
      { "exceptionalRecordSize", "z3950.exceptionalRecordSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_idAuthentication,
      { "idAuthentication", "z3950.idAuthentication",
        FT_UINT32, BASE_DEC, VALS(z3950_T_idAuthentication_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_open,
      { "open", "z3950.open",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_z3950_idPass,
      { "idPass", "z3950.idPass_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_groupId,
      { "groupId", "z3950.groupId",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_userId,
      { "userId", "z3950.userId",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_password,
      { "password", "z3950.password",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_anonymous,
      { "anonymous", "z3950.anonymous_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_other,
      { "other", "z3950.other_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_z3950_implementationId,
      { "implementationId", "z3950.implementationId",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_implementationName,
      { "implementationName", "z3950.implementationName",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_implementationVersion,
      { "implementationVersion", "z3950.implementationVersion",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_userInformationField,
      { "userInformationField", "z3950.userInformationField_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_z3950_otherInfo,
      { "otherInfo", "z3950.otherInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "OtherInformation", HFILL }},
    { &hf_z3950_result,
      { "result", "z3950.result",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_smallSetUpperBound,
      { "smallSetUpperBound", "z3950.smallSetUpperBound",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_largeSetLowerBound,
      { "largeSetLowerBound", "z3950.largeSetLowerBound",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_mediumSetPresentNumber,
      { "mediumSetPresentNumber", "z3950.mediumSetPresentNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_replaceIndicator,
      { "replaceIndicator", "z3950.replaceIndicator",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_resultSetName,
      { "resultSetName", "z3950.resultSetName",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_databaseNames,
      { "databaseNames", "z3950.databaseNames",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_DatabaseName", HFILL }},
    { &hf_z3950_databaseNames_item,
      { "DatabaseName", "z3950.DatabaseName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_smallSetElementSetNames,
      { "smallSetElementSetNames", "z3950.smallSetElementSetNames",
        FT_UINT32, BASE_DEC, VALS(z3950_ElementSetNames_vals), 0,
        "ElementSetNames", HFILL }},
    { &hf_z3950_mediumSetElementSetNames,
      { "mediumSetElementSetNames", "z3950.mediumSetElementSetNames",
        FT_UINT32, BASE_DEC, VALS(z3950_ElementSetNames_vals), 0,
        "ElementSetNames", HFILL }},
    { &hf_z3950_preferredRecordSyntax,
      { "preferredRecordSyntax", "z3950.preferredRecordSyntax",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_z3950_query,
      { "query", "z3950.query",
        FT_UINT32, BASE_DEC, VALS(z3950_Query_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_additionalSearchInfo,
      { "additionalSearchInfo", "z3950.additionalSearchInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "OtherInformation", HFILL }},
    { &hf_z3950_type_0,
      { "type-0", "z3950.type_0_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_type_1,
      { "type-1", "z3950.type_1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RPNQuery", HFILL }},
    { &hf_z3950_type_2,
      { "type-2", "z3950.type_2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_z3950_type_100,
      { "type-100", "z3950.type_100",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_z3950_type_101,
      { "type-101", "z3950.type_101_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RPNQuery", HFILL }},
    { &hf_z3950_type_102,
      { "type-102", "z3950.type_102",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_z3950_attributeSet,
      { "attributeSet", "z3950.attributeSet",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeSetId", HFILL }},
    { &hf_z3950_rpn,
      { "rpn", "z3950.rpn",
        FT_UINT32, BASE_DEC, VALS(z3950_RPNStructure_vals), 0,
        "RPNStructure", HFILL }},
    { &hf_z3950_operandRpnOp,
      { "op", "z3950.op",
        FT_UINT32, BASE_DEC, VALS(z3950_Operand_vals), 0,
        "Operand", HFILL }},
    { &hf_z3950_rpnRpnOp,
      { "rpnRpnOp", "z3950.rpnRpnOp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_rpn1,
      { "rpn1", "z3950.rpn1",
        FT_UINT32, BASE_DEC, VALS(z3950_RPNStructure_vals), 0,
        "RPNStructure", HFILL }},
    { &hf_z3950_rpn2,
      { "rpn2", "z3950.rpn2",
        FT_UINT32, BASE_DEC, VALS(z3950_RPNStructure_vals), 0,
        "RPNStructure", HFILL }},
    { &hf_z3950_operatorRpnOp,
      { "op", "z3950.op",
        FT_UINT32, BASE_DEC, VALS(z3950_Operator_U_vals), 0,
        "Operator", HFILL }},
    { &hf_z3950_attrTerm,
      { "attrTerm", "z3950.attrTerm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributesPlusTerm", HFILL }},
    { &hf_z3950_resultSet,
      { "resultSet", "z3950.resultSet",
        FT_STRING, BASE_NONE, NULL, 0,
        "ResultSetId", HFILL }},
    { &hf_z3950_resultAttr,
      { "resultAttr", "z3950.resultAttr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResultSetPlusAttributes", HFILL }},
    { &hf_z3950_attributes,
      { "attributes", "z3950.attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AttributeList", HFILL }},
    { &hf_z3950_term,
      { "term", "z3950.term",
        FT_UINT32, BASE_DEC, VALS(z3950_Term_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_attributeList_item,
      { "AttributeElement", "z3950.AttributeElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_general,
      { "general", "z3950.general",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_numeric,
      { "numeric", "z3950.numeric",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_characterString,
      { "characterString", "z3950.characterString",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_oid,
      { "oid", "z3950.oid",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_z3950_dateTime,
      { "dateTime", "z3950.dateTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_z3950_external,
      { "external", "z3950.external_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_integerAndUnit,
      { "integerAndUnit", "z3950.integerAndUnit_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IntUnit", HFILL }},
    { &hf_z3950_null,
      { "null", "z3950.null_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_and,
      { "and", "z3950.and_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_or,
      { "or", "z3950.or_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_and_not,
      { "and-not", "z3950.and_not_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_prox,
      { "prox", "z3950.prox_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProximityOperator", HFILL }},
    { &hf_z3950_attributeElement_attributeType,
      { "attributeType", "z3950.attributeType",
        FT_INT32, BASE_DEC, NULL, 0,
        "T_attributeElement_attributeType", HFILL }},
    { &hf_z3950_attributeValue,
      { "attributeValue", "z3950.attributeValue",
        FT_UINT32, BASE_DEC, VALS(z3950_T_attributeValue_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_attributeValue_numeric,
      { "numeric", "z3950.numeric",
        FT_INT32, BASE_DEC, NULL, 0,
        "T_attributeValue_numeric", HFILL }},
    { &hf_z3950_attributeValue_complex,
      { "complex", "z3950.complex_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_attributeValue_complex", HFILL }},
    { &hf_z3950_attributeValue_complex_list,
      { "list", "z3950.list",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_StringOrNumeric", HFILL }},
    { &hf_z3950_attributeValue_complex_list_item,
      { "StringOrNumeric", "z3950.StringOrNumeric",
        FT_UINT32, BASE_DEC, VALS(z3950_StringOrNumeric_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_semanticAction,
      { "semanticAction", "z3950.semanticAction",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_semanticAction_item,
      { "semanticAction item", "z3950.semanticAction_item",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_exclusion,
      { "exclusion", "z3950.exclusion",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_distance,
      { "distance", "z3950.distance",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_ordered,
      { "ordered", "z3950.ordered",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_relationType,
      { "relationType", "z3950.relationType",
        FT_INT32, BASE_DEC, VALS(z3950_T_relationType_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_proximityUnitCode,
      { "proximityUnitCode", "z3950.proximityUnitCode",
        FT_UINT32, BASE_DEC, VALS(z3950_T_proximityUnitCode_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_known,
      { "known", "z3950.known",
        FT_INT32, BASE_DEC, VALS(z3950_KnownProximityUnit_vals), 0,
        "KnownProximityUnit", HFILL }},
    { &hf_z3950_private,
      { "private", "z3950.private",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_resultCount,
      { "resultCount", "z3950.resultCount",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_numberOfRecordsReturned,
      { "numberOfRecordsReturned", "z3950.numberOfRecordsReturned",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_nextResultSetPosition,
      { "nextResultSetPosition", "z3950.nextResultSetPosition",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_searchStatus,
      { "searchStatus", "z3950.searchStatus",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_search_resultSetStatus,
      { "resultSetStatus", "z3950.resultSetStatus",
        FT_INT32, BASE_DEC, VALS(z3950_T_search_resultSetStatus_vals), 0,
        "T_search_resultSetStatus", HFILL }},
    { &hf_z3950_presentStatus,
      { "presentStatus", "z3950.presentStatus",
        FT_INT32, BASE_DEC, VALS(z3950_PresentStatus_U_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_records,
      { "records", "z3950.records",
        FT_UINT32, BASE_DEC, VALS(z3950_Records_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_resultSetId,
      { "resultSetId", "z3950.resultSetId",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_resultSetStartPoint,
      { "resultSetStartPoint", "z3950.resultSetStartPoint",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_numberOfRecordsRequested,
      { "numberOfRecordsRequested", "z3950.numberOfRecordsRequested",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_additionalRanges,
      { "additionalRanges", "z3950.additionalRanges",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Range", HFILL }},
    { &hf_z3950_additionalRanges_item,
      { "Range", "z3950.Range_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_recordComposition,
      { "recordComposition", "z3950.recordComposition",
        FT_UINT32, BASE_DEC, VALS(z3950_T_recordComposition_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_simple,
      { "simple", "z3950.simple",
        FT_UINT32, BASE_DEC, VALS(z3950_ElementSetNames_vals), 0,
        "ElementSetNames", HFILL }},
    { &hf_z3950_recordComposition_complex,
      { "complex", "z3950.complex_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompSpec", HFILL }},
    { &hf_z3950_maxSegmentCount,
      { "maxSegmentCount", "z3950.maxSegmentCount",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_maxRecordSize,
      { "maxRecordSize", "z3950.maxRecordSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_maxSegmentSize,
      { "maxSegmentSize", "z3950.maxSegmentSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_segmentRecords,
      { "segmentRecords", "z3950.segmentRecords",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_NamePlusRecord", HFILL }},
    { &hf_z3950_segmentRecords_item,
      { "NamePlusRecord", "z3950.NamePlusRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_responseRecords,
      { "responseRecords", "z3950.responseRecords",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_NamePlusRecord", HFILL }},
    { &hf_z3950_responseRecords_item,
      { "NamePlusRecord", "z3950.NamePlusRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_nonSurrogateDiagnostic,
      { "nonSurrogateDiagnostic", "z3950.nonSurrogateDiagnostic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefaultDiagFormat", HFILL }},
    { &hf_z3950_multipleNonSurDiagnostics,
      { "multipleNonSurDiagnostics", "z3950.multipleNonSurDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_DiagRec", HFILL }},
    { &hf_z3950_multipleNonSurDiagnostics_item,
      { "DiagRec", "z3950.DiagRec",
        FT_UINT32, BASE_DEC, VALS(z3950_DiagRec_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_namePlusRecord_name,
      { "name", "z3950.name",
        FT_STRING, BASE_NONE, NULL, 0,
        "DatabaseName", HFILL }},
    { &hf_z3950_record,
      { "record", "z3950.record",
        FT_UINT32, BASE_DEC, VALS(z3950_T_record_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_retrievalRecord,
      { "retrievalRecord", "z3950.retrievalRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_z3950_surrogateDiagnostic,
      { "surrogateDiagnostic", "z3950.surrogateDiagnostic",
        FT_UINT32, BASE_DEC, VALS(z3950_DiagRec_vals), 0,
        "DiagRec", HFILL }},
    { &hf_z3950_startingFragment,
      { "startingFragment", "z3950.startingFragment",
        FT_UINT32, BASE_DEC, VALS(z3950_FragmentSyntax_vals), 0,
        "FragmentSyntax", HFILL }},
    { &hf_z3950_intermediateFragment,
      { "intermediateFragment", "z3950.intermediateFragment",
        FT_UINT32, BASE_DEC, VALS(z3950_FragmentSyntax_vals), 0,
        "FragmentSyntax", HFILL }},
    { &hf_z3950_finalFragment,
      { "finalFragment", "z3950.finalFragment",
        FT_UINT32, BASE_DEC, VALS(z3950_FragmentSyntax_vals), 0,
        "FragmentSyntax", HFILL }},
    { &hf_z3950_externallyTagged,
      { "externallyTagged", "z3950.externallyTagged_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_z3950_notExternallyTagged,
      { "notExternallyTagged", "z3950.notExternallyTagged",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_z3950_defaultFormat,
      { "defaultFormat", "z3950.defaultFormat_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefaultDiagFormat", HFILL }},
    { &hf_z3950_externallyDefined,
      { "externallyDefined", "z3950.externallyDefined_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_z3950_diagnosticSetId,
      { "diagnosticSetId", "z3950.diagnosticSetId",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_condition,
      { "condition", "z3950.condition",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_addinfo,
      { "addinfo", "z3950.addinfo",
        FT_UINT32, BASE_DEC, VALS(z3950_T_addinfo_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_v2Addinfo,
      { "v2Addinfo", "z3950.v2Addinfo",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_z3950_v3Addinfo,
      { "v3Addinfo", "z3950.v3Addinfo",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_startingPosition,
      { "startingPosition", "z3950.startingPosition",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_numberOfRecords,
      { "numberOfRecords", "z3950.numberOfRecords",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_genericElementSetName,
      { "genericElementSetName", "z3950.genericElementSetName",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_databaseSpecific,
      { "databaseSpecific", "z3950.databaseSpecific",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_databaseSpecific_item,
      { "databaseSpecific item", "z3950.databaseSpecific_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_dbName,
      { "dbName", "z3950.dbName",
        FT_STRING, BASE_NONE, NULL, 0,
        "DatabaseName", HFILL }},
    { &hf_z3950_esn,
      { "esn", "z3950.esn",
        FT_STRING, BASE_NONE, NULL, 0,
        "ElementSetName", HFILL }},
    { &hf_z3950_selectAlternativeSyntax,
      { "selectAlternativeSyntax", "z3950.selectAlternativeSyntax",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_compSpec_generic,
      { "generic", "z3950.generic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Specification", HFILL }},
    { &hf_z3950_dbSpecific,
      { "dbSpecific", "z3950.dbSpecific",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_dbSpecific_item,
      { "dbSpecific item", "z3950.dbSpecific_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_db,
      { "db", "z3950.db",
        FT_STRING, BASE_NONE, NULL, 0,
        "DatabaseName", HFILL }},
    { &hf_z3950_spec,
      { "spec", "z3950.spec_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Specification", HFILL }},
    { &hf_z3950_compSpec_recordSyntax,
      { "recordSyntax", "z3950.recordSyntax",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_compSpec_recordSyntax", HFILL }},
    { &hf_z3950_compSpec_recordSyntax_item,
      { "recordSyntax item", "z3950.recordSyntax_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_z3950_schema,
      { "schema", "z3950.schema",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_z3950_specification_elementSpec,
      { "elementSpec", "z3950.elementSpec",
        FT_UINT32, BASE_DEC, VALS(z3950_T_specification_elementSpec_vals), 0,
        "T_specification_elementSpec", HFILL }},
    { &hf_z3950_elementSetName,
      { "elementSetName", "z3950.elementSetName",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_externalEspec,
      { "externalEspec", "z3950.externalEspec_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_z3950_deleteFunction,
      { "deleteFunction", "z3950.deleteFunction",
        FT_INT32, BASE_DEC, VALS(z3950_T_deleteFunction_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_resultSetList,
      { "resultSetList", "z3950.resultSetList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ResultSetId", HFILL }},
    { &hf_z3950_resultSetList_item,
      { "ResultSetId", "z3950.ResultSetId",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_deleteOperationStatus,
      { "deleteOperationStatus", "z3950.deleteOperationStatus",
        FT_INT32, BASE_DEC, VALS(z3950_DeleteSetStatus_U_vals), 0,
        "DeleteSetStatus", HFILL }},
    { &hf_z3950_deleteListStatuses,
      { "deleteListStatuses", "z3950.deleteListStatuses",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ListStatuses", HFILL }},
    { &hf_z3950_numberNotDeleted,
      { "numberNotDeleted", "z3950.numberNotDeleted",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_bulkStatuses,
      { "bulkStatuses", "z3950.bulkStatuses",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ListStatuses", HFILL }},
    { &hf_z3950_deleteMessage,
      { "deleteMessage", "z3950.deleteMessage",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_ListStatuses_item,
      { "ListStatuses item", "z3950.ListStatuses_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_listStatuses_id,
      { "id", "z3950.id",
        FT_STRING, BASE_NONE, NULL, 0,
        "ResultSetId", HFILL }},
    { &hf_z3950_status,
      { "status", "z3950.status",
        FT_INT32, BASE_DEC, VALS(z3950_DeleteSetStatus_U_vals), 0,
        "DeleteSetStatus", HFILL }},
    { &hf_z3950_securityChallenge,
      { "securityChallenge", "z3950.securityChallenge",
        FT_UINT32, BASE_DEC, VALS(z3950_T_securityChallenge_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_simpleForm,
      { "simpleForm", "z3950.simpleForm",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_z3950_securityChallengeResponse,
      { "securityChallengeResponse", "z3950.securityChallengeResponse",
        FT_UINT32, BASE_DEC, VALS(z3950_T_securityChallengeResponse_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_diagnostic,
      { "diagnostic", "z3950.diagnostic",
        FT_UINT32, BASE_DEC, VALS(z3950_DiagRec_vals), 0,
        "DiagRec", HFILL }},
    { &hf_z3950_suspendedFlag,
      { "suspendedFlag", "z3950.suspendedFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_resourceReport,
      { "resourceReport", "z3950.resourceReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_partialResultsAvailable,
      { "partialResultsAvailable", "z3950.partialResultsAvailable",
        FT_INT32, BASE_DEC, VALS(z3950_T_partialResultsAvailable_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_resourceControlRequest_responseRequired,
      { "responseRequired", "z3950.responseRequired",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_triggeredRequestFlag,
      { "triggeredRequestFlag", "z3950.triggeredRequestFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_continueFlag,
      { "continueFlag", "z3950.continueFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_resultSetWanted,
      { "resultSetWanted", "z3950.resultSetWanted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_requestedAction,
      { "requestedAction", "z3950.requestedAction",
        FT_INT32, BASE_DEC, VALS(z3950_T_requestedAction_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_prefResourceReportFormat,
      { "prefResourceReportFormat", "z3950.prefResourceReportFormat",
        FT_OID, BASE_NONE, NULL, 0,
        "ResourceReportId", HFILL }},
    { &hf_z3950_opId,
      { "opId", "z3950.opId",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ReferenceId", HFILL }},
    { &hf_z3950_resourceReportStatus,
      { "resourceReportStatus", "z3950.resourceReportStatus",
        FT_INT32, BASE_DEC, VALS(z3950_T_resourceReportStatus_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_termListAndStartPoint,
      { "termListAndStartPoint", "z3950.termListAndStartPoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributesPlusTerm", HFILL }},
    { &hf_z3950_stepSize,
      { "stepSize", "z3950.stepSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_numberOfTermsRequested,
      { "numberOfTermsRequested", "z3950.numberOfTermsRequested",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_preferredPositionInResponse,
      { "preferredPositionInResponse", "z3950.preferredPositionInResponse",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_scanStatus,
      { "scanStatus", "z3950.scanStatus",
        FT_INT32, BASE_DEC, VALS(z3950_T_scanStatus_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_numberOfEntriesReturned,
      { "numberOfEntriesReturned", "z3950.numberOfEntriesReturned",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_positionOfTerm,
      { "positionOfTerm", "z3950.positionOfTerm",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_scanResponse_entries,
      { "entries", "z3950.entries_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ListEntries", HFILL }},
    { &hf_z3950_listEntries_entries,
      { "entries", "z3950.entries",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Entry", HFILL }},
    { &hf_z3950_listEntries_entries_item,
      { "Entry", "z3950.Entry",
        FT_UINT32, BASE_DEC, VALS(z3950_Entry_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_nonsurrogateDiagnostics,
      { "nonsurrogateDiagnostics", "z3950.nonsurrogateDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_DiagRec", HFILL }},
    { &hf_z3950_nonsurrogateDiagnostics_item,
      { "DiagRec", "z3950.DiagRec",
        FT_UINT32, BASE_DEC, VALS(z3950_DiagRec_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_termInfo,
      { "termInfo", "z3950.termInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_displayTerm,
      { "displayTerm", "z3950.displayTerm",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_suggestedAttributes,
      { "suggestedAttributes", "z3950.suggestedAttributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AttributeList", HFILL }},
    { &hf_z3950_alternativeTerm,
      { "alternativeTerm", "z3950.alternativeTerm",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AttributesPlusTerm", HFILL }},
    { &hf_z3950_alternativeTerm_item,
      { "AttributesPlusTerm", "z3950.AttributesPlusTerm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_globalOccurrences,
      { "globalOccurrences", "z3950.globalOccurrences",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_byAttributes,
      { "byAttributes", "z3950.byAttributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "OccurrenceByAttributes", HFILL }},
    { &hf_z3950_otherTermInfo,
      { "otherTermInfo", "z3950.otherTermInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "OtherInformation", HFILL }},
    { &hf_z3950_OccurrenceByAttributes_item,
      { "OccurrenceByAttributes item", "z3950.OccurrenceByAttributes_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_occurrences,
      { "occurrences", "z3950.occurrences",
        FT_UINT32, BASE_DEC, VALS(z3950_T_occurrences_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_global,
      { "global", "z3950.global",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_byDatabase,
      { "byDatabase", "z3950.byDatabase",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_byDatabase_item,
      { "byDatabase item", "z3950.byDatabase_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_num,
      { "num", "z3950.num",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_otherDbInfo,
      { "otherDbInfo", "z3950.otherDbInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "OtherInformation", HFILL }},
    { &hf_z3950_otherOccurInfo,
      { "otherOccurInfo", "z3950.otherOccurInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "OtherInformation", HFILL }},
    { &hf_z3950_inputResultSetNames,
      { "inputResultSetNames", "z3950.inputResultSetNames",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_InternationalString", HFILL }},
    { &hf_z3950_inputResultSetNames_item,
      { "InternationalString", "z3950.InternationalString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_sortedResultSetName,
      { "sortedResultSetName", "z3950.sortedResultSetName",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_sortSequence,
      { "sortSequence", "z3950.sortSequence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_SortKeySpec", HFILL }},
    { &hf_z3950_sortSequence_item,
      { "SortKeySpec", "z3950.SortKeySpec_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_sortStatus,
      { "sortStatus", "z3950.sortStatus",
        FT_INT32, BASE_DEC, VALS(z3950_T_sortStatus_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_sort_resultSetStatus,
      { "resultSetStatus", "z3950.resultSetStatus",
        FT_INT32, BASE_DEC, VALS(z3950_T_sort_resultSetStatus_vals), 0,
        "T_sort_resultSetStatus", HFILL }},
    { &hf_z3950_diagnostics,
      { "diagnostics", "z3950.diagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_DiagRec", HFILL }},
    { &hf_z3950_diagnostics_item,
      { "DiagRec", "z3950.DiagRec",
        FT_UINT32, BASE_DEC, VALS(z3950_DiagRec_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_sortElement,
      { "sortElement", "z3950.sortElement",
        FT_UINT32, BASE_DEC, VALS(z3950_SortElement_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_sortRelation,
      { "sortRelation", "z3950.sortRelation",
        FT_INT32, BASE_DEC, VALS(z3950_T_sortRelation_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_caseSensitivity,
      { "caseSensitivity", "z3950.caseSensitivity",
        FT_INT32, BASE_DEC, VALS(z3950_T_caseSensitivity_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_missingValueAction,
      { "missingValueAction", "z3950.missingValueAction",
        FT_UINT32, BASE_DEC, VALS(z3950_T_missingValueAction_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_abort,
      { "abort", "z3950.abort_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_missingValueData,
      { "missingValueData", "z3950.missingValueData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_z3950_sortElement_generic,
      { "generic", "z3950.generic",
        FT_UINT32, BASE_DEC, VALS(z3950_SortKey_vals), 0,
        "SortKey", HFILL }},
    { &hf_z3950_datbaseSpecific,
      { "datbaseSpecific", "z3950.datbaseSpecific",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_datbaseSpecific_item,
      { "datbaseSpecific item", "z3950.datbaseSpecific_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_databaseName,
      { "databaseName", "z3950.databaseName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_dbSort,
      { "dbSort", "z3950.dbSort",
        FT_UINT32, BASE_DEC, VALS(z3950_SortKey_vals), 0,
        "SortKey", HFILL }},
    { &hf_z3950_sortfield,
      { "sortfield", "z3950.sortfield",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_sortKey_elementSpec,
      { "elementSpec", "z3950.elementSpec_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Specification", HFILL }},
    { &hf_z3950_sortAttributes,
      { "sortAttributes", "z3950.sortAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_sortAttributes_id,
      { "id", "z3950.id",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeSetId", HFILL }},
    { &hf_z3950_sortAttributes_list,
      { "list", "z3950.list",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AttributeList", HFILL }},
    { &hf_z3950_function,
      { "function", "z3950.function",
        FT_INT32, BASE_DEC, VALS(z3950_T_function_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_packageType,
      { "packageType", "z3950.packageType",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_z3950_packageName,
      { "packageName", "z3950.packageName",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_retentionTime,
      { "retentionTime", "z3950.retentionTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IntUnit", HFILL }},
    { &hf_z3950_permissions,
      { "permissions", "z3950.permissions",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_extendedServicesRequest_description,
      { "description", "z3950.description",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_taskSpecificParameters,
      { "taskSpecificParameters", "z3950.taskSpecificParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_z3950_waitAction,
      { "waitAction", "z3950.waitAction",
        FT_INT32, BASE_DEC, VALS(z3950_T_waitAction_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_elements,
      { "elements", "z3950.elements",
        FT_STRING, BASE_NONE, NULL, 0,
        "ElementSetName", HFILL }},
    { &hf_z3950_operationStatus,
      { "operationStatus", "z3950.operationStatus",
        FT_INT32, BASE_DEC, VALS(z3950_T_operationStatus_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_taskPackage,
      { "taskPackage", "z3950.taskPackage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_z3950_Permissions_item,
      { "Permissions item", "z3950.Permissions_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_allowableFunctions,
      { "allowableFunctions", "z3950.allowableFunctions",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_allowableFunctions_item,
      { "allowableFunctions item", "z3950.allowableFunctions_item",
        FT_INT32, BASE_DEC, VALS(z3950_T_allowableFunctions_item_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_closeReason,
      { "closeReason", "z3950.closeReason",
        FT_INT32, BASE_DEC, VALS(z3950_CloseReason_U_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_diagnosticInformation,
      { "diagnosticInformation", "z3950.diagnosticInformation",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_resourceReportFormat,
      { "resourceReportFormat", "z3950.resourceReportFormat",
        FT_OID, BASE_NONE, NULL, 0,
        "ResourceReportId", HFILL }},
    { &hf_z3950_otherInformation_item,
      { "_untag item", "z3950._untag_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_category,
      { "category", "z3950.category_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InfoCategory", HFILL }},
    { &hf_z3950_information,
      { "information", "z3950.information",
        FT_UINT32, BASE_DEC, VALS(z3950_T_information_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_characterInfo,
      { "characterInfo", "z3950.characterInfo",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_binaryInfo,
      { "binaryInfo", "z3950.binaryInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_z3950_externallyDefinedInfo,
      { "externallyDefinedInfo", "z3950.externallyDefinedInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_z3950_categoryTypeId,
      { "categoryTypeId", "z3950.categoryTypeId",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_z3950_categoryValue,
      { "categoryValue", "z3950.categoryValue",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_value,
      { "value", "z3950.value",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_unitUsed,
      { "unitUsed", "z3950.unitUsed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Unit", HFILL }},
    { &hf_z3950_unitSystem,
      { "unitSystem", "z3950.unitSystem",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_unitType,
      { "unitType", "z3950.unitType",
        FT_UINT32, BASE_DEC, VALS(z3950_StringOrNumeric_vals), 0,
        "StringOrNumeric", HFILL }},
    { &hf_z3950_unit,
      { "unit", "z3950.unit",
        FT_UINT32, BASE_DEC, VALS(z3950_StringOrNumeric_vals), 0,
        "StringOrNumeric", HFILL }},
    { &hf_z3950_scaleFactor,
      { "scaleFactor", "z3950.scaleFactor",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_string,
      { "string", "z3950.string",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_motd,
      { "motd", "z3950.motd",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_z3950_dblist,
      { "dblist", "z3950.dblist",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_DBName", HFILL }},
    { &hf_z3950_dblist_item,
      { "DBName", "z3950.DBName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_failReason,
      { "failReason", "z3950.failReason",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_oCLC_UserInformation_text,
      { "text", "z3950.text",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_z3950_bibliographicRecord,
      { "bibliographicRecord", "z3950.bibliographicRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_z3950_holdingsData,
      { "holdingsData", "z3950.holdingsData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_HoldingsRecord", HFILL }},
    { &hf_z3950_holdingsData_item,
      { "HoldingsRecord", "z3950.HoldingsRecord",
        FT_UINT32, BASE_DEC, VALS(z3950_HoldingsRecord_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_marcHoldingsRecord,
      { "marcHoldingsRecord", "z3950.marcHoldingsRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_z3950_holdingsAndCirc,
      { "holdingsAndCirc", "z3950.holdingsAndCirc_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "HoldingsAndCircData", HFILL }},
    { &hf_z3950_typeOfRecord,
      { "typeOfRecord", "z3950.typeOfRecord",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_encodingLevel,
      { "encodingLevel", "z3950.encodingLevel",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_format,
      { "format", "z3950.format",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_receiptAcqStatus,
      { "receiptAcqStatus", "z3950.receiptAcqStatus",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_generalRetention,
      { "generalRetention", "z3950.generalRetention",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_completeness,
      { "completeness", "z3950.completeness",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_dateOfReport,
      { "dateOfReport", "z3950.dateOfReport",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_nucCode,
      { "nucCode", "z3950.nucCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_localLocation,
      { "localLocation", "z3950.localLocation",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_shelvingLocation,
      { "shelvingLocation", "z3950.shelvingLocation",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_callNumber,
      { "callNumber", "z3950.callNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_shelvingData,
      { "shelvingData", "z3950.shelvingData",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_copyNumber,
      { "copyNumber", "z3950.copyNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_publicNote,
      { "publicNote", "z3950.publicNote",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_reproductionNote,
      { "reproductionNote", "z3950.reproductionNote",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_termsUseRepro,
      { "termsUseRepro", "z3950.termsUseRepro",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_enumAndChron,
      { "enumAndChron", "z3950.enumAndChron",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_volumes,
      { "volumes", "z3950.volumes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Volume", HFILL }},
    { &hf_z3950_volumes_item,
      { "Volume", "z3950.Volume_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_circulationData,
      { "circulationData", "z3950.circulationData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_CircRecord", HFILL }},
    { &hf_z3950_circulationData_item,
      { "CircRecord", "z3950.CircRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_enumeration,
      { "enumeration", "z3950.enumeration",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_chronology,
      { "chronology", "z3950.chronology",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_availableNow,
      { "availableNow", "z3950.availableNow",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_availablityDate,
      { "availablityDate", "z3950.availablityDate",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_availableThru,
      { "availableThru", "z3950.availableThru",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_circRecord_restrictions,
      { "restrictions", "z3950.restrictions",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_itemId,
      { "itemId", "z3950.itemId",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_renewable,
      { "renewable", "z3950.renewable",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_onHold,
      { "onHold", "z3950.onHold",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_midspine,
      { "midspine", "z3950.midspine",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_temporaryLocation,
      { "temporaryLocation", "z3950.temporaryLocation",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_DiagnosticFormat_item,
      { "DiagnosticFormat item", "z3950.DiagnosticFormat_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_diagnosticFormat_item_diagnostic,
      { "diagnostic", "z3950.diagnostic",
        FT_UINT32, BASE_DEC, VALS(z3950_T_diagnosticFormat_item_diagnostic_vals), 0,
        "T_diagnosticFormat_item_diagnostic", HFILL }},
    { &hf_z3950_defaultDiagRec,
      { "defaultDiagRec", "z3950.defaultDiagRec_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefaultDiagFormat", HFILL }},
    { &hf_z3950_explicitDiagnostic,
      { "explicitDiagnostic", "z3950.explicitDiagnostic",
        FT_UINT32, BASE_DEC, VALS(z3950_DiagFormat_vals), 0,
        "DiagFormat", HFILL }},
    { &hf_z3950_message,
      { "message", "z3950.message",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_tooMany,
      { "tooMany", "z3950.tooMany_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_tooManyWhat,
      { "tooManyWhat", "z3950.tooManyWhat",
        FT_INT32, BASE_DEC, VALS(z3950_T_tooManyWhat_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_max,
      { "max", "z3950.max",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_badSpec,
      { "badSpec", "z3950.badSpec_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_goodOnes,
      { "goodOnes", "z3950.goodOnes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Specification", HFILL }},
    { &hf_z3950_goodOnes_item,
      { "Specification", "z3950.Specification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_dbUnavail,
      { "dbUnavail", "z3950.dbUnavail_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_why,
      { "why", "z3950.why_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_reasonCode,
      { "reasonCode", "z3950.reasonCode",
        FT_INT32, BASE_DEC, VALS(z3950_T_reasonCode_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_unSupOp,
      { "unSupOp", "z3950.unSupOp",
        FT_INT32, BASE_DEC, VALS(z3950_T_unSupOp_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_attribute,
      { "attribute", "z3950.attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_id,
      { "id", "z3950.id",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_z3950_type,
      { "type", "z3950.type",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_attCombo,
      { "attCombo", "z3950.attCombo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_unsupportedCombination,
      { "unsupportedCombination", "z3950.unsupportedCombination",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AttributeList", HFILL }},
    { &hf_z3950_recommendedAlternatives,
      { "recommendedAlternatives", "z3950.recommendedAlternatives",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AttributeList", HFILL }},
    { &hf_z3950_recommendedAlternatives_item,
      { "AttributeList", "z3950.AttributeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_diagFormat_term,
      { "term", "z3950.term_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_diagFormat_term", HFILL }},
    { &hf_z3950_problem,
      { "problem", "z3950.problem",
        FT_INT32, BASE_DEC, VALS(z3950_T_problem_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_diagFormat_proximity,
      { "proximity", "z3950.proximity",
        FT_UINT32, BASE_DEC, VALS(z3950_T_diagFormat_proximity_vals), 0,
        "T_diagFormat_proximity", HFILL }},
    { &hf_z3950_resultSets,
      { "resultSets", "z3950.resultSets_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_badSet,
      { "badSet", "z3950.badSet",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_relation,
      { "relation", "z3950.relation",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_diagFormat_proximity_unit,
      { "unit", "z3950.unit",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_diagFormat_proximity_ordered,
      { "ordered", "z3950.ordered_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_diagFormat_proximity_exclusion,
      { "exclusion", "z3950.exclusion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_scan,
      { "scan", "z3950.scan",
        FT_UINT32, BASE_DEC, VALS(z3950_T_scan_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_nonZeroStepSize,
      { "nonZeroStepSize", "z3950.nonZeroStepSize_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_specifiedStepSize,
      { "specifiedStepSize", "z3950.specifiedStepSize_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_termList1,
      { "termList1", "z3950.termList1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_termList2,
      { "termList2", "z3950.termList2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AttributeList", HFILL }},
    { &hf_z3950_termList2_item,
      { "AttributeList", "z3950.AttributeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_posInResponse,
      { "posInResponse", "z3950.posInResponse",
        FT_INT32, BASE_DEC, VALS(z3950_T_posInResponse_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_resources,
      { "resources", "z3950.resources_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_endOfList,
      { "endOfList", "z3950.endOfList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_sort,
      { "sort", "z3950.sort",
        FT_UINT32, BASE_DEC, VALS(z3950_T_sort_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_sequence,
      { "sequence", "z3950.sequence_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_noRsName,
      { "noRsName", "z3950.noRsName_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_diagFormat_sort_tooMany,
      { "tooMany", "z3950.tooMany",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_incompatible,
      { "incompatible", "z3950.incompatible_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_generic,
      { "generic", "z3950.generic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_diagFormat_sort_dbSpecific,
      { "dbSpecific", "z3950.dbSpecific_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_key,
      { "key", "z3950.key",
        FT_INT32, BASE_DEC, VALS(z3950_T_key_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_action,
      { "action", "z3950.action_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_illegal,
      { "illegal", "z3950.illegal",
        FT_INT32, BASE_DEC, VALS(z3950_T_illegal_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_inputTooLarge,
      { "inputTooLarge", "z3950.inputTooLarge",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_InternationalString", HFILL }},
    { &hf_z3950_inputTooLarge_item,
      { "InternationalString", "z3950.InternationalString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_aggregateTooLarge,
      { "aggregateTooLarge", "z3950.aggregateTooLarge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_segmentation,
      { "segmentation", "z3950.segmentation",
        FT_UINT32, BASE_DEC, VALS(z3950_T_segmentation_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_segmentCount,
      { "segmentCount", "z3950.segmentCount_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_segmentSize,
      { "segmentSize", "z3950.segmentSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_extServices,
      { "extServices", "z3950.extServices",
        FT_UINT32, BASE_DEC, VALS(z3950_T_extServices_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_req,
      { "req", "z3950.req",
        FT_INT32, BASE_DEC, VALS(z3950_T_req_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_permission,
      { "permission", "z3950.permission",
        FT_INT32, BASE_DEC, VALS(z3950_T_permission_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_immediate,
      { "immediate", "z3950.immediate",
        FT_INT32, BASE_DEC, VALS(z3950_T_immediate_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_accessCtrl,
      { "accessCtrl", "z3950.accessCtrl",
        FT_UINT32, BASE_DEC, VALS(z3950_T_accessCtrl_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_noUser,
      { "noUser", "z3950.noUser_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_refused,
      { "refused", "z3950.refused_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_diagFormat_accessCtrl_simple,
      { "simple", "z3950.simple_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_diagFormat_accessCtrl_oid,
      { "oid", "z3950.oid",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_diagFormat_accessCtrl_oid", HFILL }},
    { &hf_z3950_diagFormat_accessCtrl_oid_item,
      { "oid item", "z3950.oid_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_z3950_alternative,
      { "alternative", "z3950.alternative",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_alternative_item,
      { "alternative item", "z3950.alternative_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_z3950_pwdInv,
      { "pwdInv", "z3950.pwdInv_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_pwdExp,
      { "pwdExp", "z3950.pwdExp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_diagFormat_recordSyntax,
      { "recordSyntax", "z3950.recordSyntax_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_diagFormat_recordSyntax", HFILL }},
    { &hf_z3950_unsupportedSyntax,
      { "unsupportedSyntax", "z3950.unsupportedSyntax",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_z3950_suggestedAlternatives,
      { "suggestedAlternatives", "z3950.suggestedAlternatives",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_suggestedAlternatives_item,
      { "suggestedAlternatives item", "z3950.suggestedAlternatives_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_z3950_targetInfo,
      { "targetInfo", "z3950.targetInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_databaseInfo,
      { "databaseInfo", "z3950.databaseInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_schemaInfo,
      { "schemaInfo", "z3950.schemaInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_tagSetInfo,
      { "tagSetInfo", "z3950.tagSetInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_recordSyntaxInfo,
      { "recordSyntaxInfo", "z3950.recordSyntaxInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_attributeSetInfo,
      { "attributeSetInfo", "z3950.attributeSetInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_termListInfo,
      { "termListInfo", "z3950.termListInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_extendedServicesInfo,
      { "extendedServicesInfo", "z3950.extendedServicesInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_attributeDetails,
      { "attributeDetails", "z3950.attributeDetails_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_termListDetails,
      { "termListDetails", "z3950.termListDetails_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_elementSetDetails,
      { "elementSetDetails", "z3950.elementSetDetails_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_retrievalRecordDetails,
      { "retrievalRecordDetails", "z3950.retrievalRecordDetails_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_sortDetails,
      { "sortDetails", "z3950.sortDetails_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_processing,
      { "processing", "z3950.processing_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProcessingInformation", HFILL }},
    { &hf_z3950_variants,
      { "variants", "z3950.variants_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "VariantSetInfo", HFILL }},
    { &hf_z3950_units,
      { "units", "z3950.units_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnitInfo", HFILL }},
    { &hf_z3950_categoryList,
      { "categoryList", "z3950.categoryList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_commonInfo,
      { "commonInfo", "z3950.commonInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_name,
      { "name", "z3950.name",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_recent_news,
      { "recent-news", "z3950.recent_news",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_icon,
      { "icon", "z3950.icon",
        FT_UINT32, BASE_DEC, NULL, 0,
        "IconObject", HFILL }},
    { &hf_z3950_namedResultSets,
      { "namedResultSets", "z3950.namedResultSets",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_multipleDBsearch,
      { "multipleDBsearch", "z3950.multipleDBsearch",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_maxResultSets,
      { "maxResultSets", "z3950.maxResultSets",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_maxResultSize,
      { "maxResultSize", "z3950.maxResultSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_maxTerms,
      { "maxTerms", "z3950.maxTerms",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_timeoutInterval,
      { "timeoutInterval", "z3950.timeoutInterval_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IntUnit", HFILL }},
    { &hf_z3950_welcomeMessage,
      { "welcomeMessage", "z3950.welcomeMessage",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_contactInfo,
      { "contactInfo", "z3950.contactInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_description,
      { "description", "z3950.description",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_nicknames,
      { "nicknames", "z3950.nicknames",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_InternationalString", HFILL }},
    { &hf_z3950_nicknames_item,
      { "InternationalString", "z3950.InternationalString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_usage_restrictions,
      { "usage-restrictions", "z3950.usage_restrictions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_paymentAddr,
      { "paymentAddr", "z3950.paymentAddr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_hours,
      { "hours", "z3950.hours",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_dbCombinations,
      { "dbCombinations", "z3950.dbCombinations",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_DatabaseList", HFILL }},
    { &hf_z3950_dbCombinations_item,
      { "DatabaseList", "z3950.DatabaseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_addresses,
      { "addresses", "z3950.addresses",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_NetworkAddress", HFILL }},
    { &hf_z3950_addresses_item,
      { "NetworkAddress", "z3950.NetworkAddress",
        FT_UINT32, BASE_DEC, VALS(z3950_NetworkAddress_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_languages,
      { "languages", "z3950.languages",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_InternationalString", HFILL }},
    { &hf_z3950_languages_item,
      { "InternationalString", "z3950.InternationalString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_commonAccessInfo,
      { "commonAccessInfo", "z3950.commonAccessInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AccessInfo", HFILL }},
    { &hf_z3950_databaseInfo_name,
      { "name", "z3950.name",
        FT_STRING, BASE_NONE, NULL, 0,
        "DatabaseName", HFILL }},
    { &hf_z3950_explainDatabase,
      { "explainDatabase", "z3950.explainDatabase_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_databaseInfo_nicknames,
      { "nicknames", "z3950.nicknames",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_DatabaseName", HFILL }},
    { &hf_z3950_databaseInfo_nicknames_item,
      { "DatabaseName", "z3950.DatabaseName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_user_fee,
      { "user-fee", "z3950.user_fee",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_available,
      { "available", "z3950.available",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_titleString,
      { "titleString", "z3950.titleString",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_keywords,
      { "keywords", "z3950.keywords",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_HumanString", HFILL }},
    { &hf_z3950_keywords_item,
      { "HumanString", "z3950.HumanString",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_associatedDbs,
      { "associatedDbs", "z3950.associatedDbs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DatabaseList", HFILL }},
    { &hf_z3950_subDbs,
      { "subDbs", "z3950.subDbs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DatabaseList", HFILL }},
    { &hf_z3950_disclaimers,
      { "disclaimers", "z3950.disclaimers",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_news,
      { "news", "z3950.news",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_recordCount,
      { "recordCount", "z3950.recordCount",
        FT_UINT32, BASE_DEC, VALS(z3950_T_recordCount_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_actualNumber,
      { "actualNumber", "z3950.actualNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_approxNumber,
      { "approxNumber", "z3950.approxNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_defaultOrder,
      { "defaultOrder", "z3950.defaultOrder",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_avRecordSize,
      { "avRecordSize", "z3950.avRecordSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_bestTime,
      { "bestTime", "z3950.bestTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_lastUpdate,
      { "lastUpdate", "z3950.lastUpdate",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_z3950_updateInterval,
      { "updateInterval", "z3950.updateInterval_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IntUnit", HFILL }},
    { &hf_z3950_coverage,
      { "coverage", "z3950.coverage",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_proprietary,
      { "proprietary", "z3950.proprietary",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_copyrightText,
      { "copyrightText", "z3950.copyrightText",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_copyrightNotice,
      { "copyrightNotice", "z3950.copyrightNotice",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_producerContactInfo,
      { "producerContactInfo", "z3950.producerContactInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContactInfo", HFILL }},
    { &hf_z3950_supplierContactInfo,
      { "supplierContactInfo", "z3950.supplierContactInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContactInfo", HFILL }},
    { &hf_z3950_submissionContactInfo,
      { "submissionContactInfo", "z3950.submissionContactInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContactInfo", HFILL }},
    { &hf_z3950_accessInfo,
      { "accessInfo", "z3950.accessInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_tagTypeMapping,
      { "tagTypeMapping", "z3950.tagTypeMapping",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_tagTypeMapping_item,
      { "tagTypeMapping item", "z3950.tagTypeMapping_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_tagType,
      { "tagType", "z3950.tagType",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_tagSet,
      { "tagSet", "z3950.tagSet",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_z3950_defaultTagType,
      { "defaultTagType", "z3950.defaultTagType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_recordStructure,
      { "recordStructure", "z3950.recordStructure",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ElementInfo", HFILL }},
    { &hf_z3950_recordStructure_item,
      { "ElementInfo", "z3950.ElementInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_elementName,
      { "elementName", "z3950.elementName",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_elementTagPath,
      { "elementTagPath", "z3950.elementTagPath",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Path", HFILL }},
    { &hf_z3950_elementInfo_dataType,
      { "dataType", "z3950.dataType",
        FT_UINT32, BASE_DEC, VALS(z3950_ElementDataType_vals), 0,
        "ElementDataType", HFILL }},
    { &hf_z3950_required,
      { "required", "z3950.required",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_repeatable,
      { "repeatable", "z3950.repeatable",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_Path_item,
      { "Path item", "z3950.Path_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_tagValue,
      { "tagValue", "z3950.tagValue",
        FT_UINT32, BASE_DEC, VALS(z3950_StringOrNumeric_vals), 0,
        "StringOrNumeric", HFILL }},
    { &hf_z3950_primitive,
      { "primitive", "z3950.primitive",
        FT_INT32, BASE_DEC, VALS(z3950_PrimitiveDataType_vals), 0,
        "PrimitiveDataType", HFILL }},
    { &hf_z3950_structured,
      { "structured", "z3950.structured",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ElementInfo", HFILL }},
    { &hf_z3950_structured_item,
      { "ElementInfo", "z3950.ElementInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_tagSetInfo_elements,
      { "elements", "z3950.elements",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_tagSetInfo_elements", HFILL }},
    { &hf_z3950_tagSetInfo_elements_item,
      { "elements item", "z3950.elements_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_tagSetInfo_elements_item", HFILL }},
    { &hf_z3950_elementname,
      { "elementname", "z3950.elementname",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_elementTag,
      { "elementTag", "z3950.elementTag",
        FT_UINT32, BASE_DEC, VALS(z3950_StringOrNumeric_vals), 0,
        "StringOrNumeric", HFILL }},
    { &hf_z3950_dataType,
      { "dataType", "z3950.dataType",
        FT_INT32, BASE_DEC, VALS(z3950_PrimitiveDataType_vals), 0,
        "PrimitiveDataType", HFILL }},
    { &hf_z3950_otherTagInfo,
      { "otherTagInfo", "z3950.otherTagInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "OtherInformation", HFILL }},
    { &hf_z3950_recordSyntax,
      { "recordSyntax", "z3950.recordSyntax",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_z3950_transferSyntaxes,
      { "transferSyntaxes", "z3950.transferSyntaxes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_transferSyntaxes_item,
      { "transferSyntaxes item", "z3950.transferSyntaxes_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_z3950_asn1Module,
      { "asn1Module", "z3950.asn1Module",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_abstractStructure,
      { "abstractStructure", "z3950.abstractStructure",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ElementInfo", HFILL }},
    { &hf_z3950_abstractStructure_item,
      { "ElementInfo", "z3950.ElementInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_attributeSetInfo_attributes,
      { "attributes", "z3950.attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AttributeType", HFILL }},
    { &hf_z3950_attributeSetInfo_attributes_item,
      { "AttributeType", "z3950.AttributeType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_attributeType,
      { "attributeType", "z3950.attributeType",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_attributeValues,
      { "attributeValues", "z3950.attributeValues",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AttributeDescription", HFILL }},
    { &hf_z3950_attributeValues_item,
      { "AttributeDescription", "z3950.AttributeDescription_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_attributeDescription_attributeValue,
      { "attributeValue", "z3950.attributeValue",
        FT_UINT32, BASE_DEC, VALS(z3950_StringOrNumeric_vals), 0,
        "StringOrNumeric", HFILL }},
    { &hf_z3950_equivalentAttributes,
      { "equivalentAttributes", "z3950.equivalentAttributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_StringOrNumeric", HFILL }},
    { &hf_z3950_equivalentAttributes_item,
      { "StringOrNumeric", "z3950.StringOrNumeric",
        FT_UINT32, BASE_DEC, VALS(z3950_StringOrNumeric_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_termLists,
      { "termLists", "z3950.termLists",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_termLists_item,
      { "termLists item", "z3950.termLists_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_title,
      { "title", "z3950.title",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_searchCost,
      { "searchCost", "z3950.searchCost",
        FT_INT32, BASE_DEC, VALS(z3950_T_searchCost_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_scanable,
      { "scanable", "z3950.scanable",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_broader,
      { "broader", "z3950.broader",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_InternationalString", HFILL }},
    { &hf_z3950_broader_item,
      { "InternationalString", "z3950.InternationalString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_narrower,
      { "narrower", "z3950.narrower",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_InternationalString", HFILL }},
    { &hf_z3950_narrower_item,
      { "InternationalString", "z3950.InternationalString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_extendedServicesInfo_type,
      { "type", "z3950.type",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_z3950_privateType,
      { "privateType", "z3950.privateType",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_restrictionsApply,
      { "restrictionsApply", "z3950.restrictionsApply",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_feeApply,
      { "feeApply", "z3950.feeApply",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_retentionSupported,
      { "retentionSupported", "z3950.retentionSupported",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_extendedServicesInfo_waitAction,
      { "waitAction", "z3950.waitAction",
        FT_INT32, BASE_DEC, VALS(z3950_T_extendedServicesInfo_waitAction_vals), 0,
        "T_extendedServicesInfo_waitAction", HFILL }},
    { &hf_z3950_specificExplain,
      { "specificExplain", "z3950.specificExplain_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_z3950_esASN,
      { "esASN", "z3950.esASN",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_attributesBySet,
      { "attributesBySet", "z3950.attributesBySet",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AttributeSetDetails", HFILL }},
    { &hf_z3950_attributesBySet_item,
      { "AttributeSetDetails", "z3950.AttributeSetDetails_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_attributeCombinations,
      { "attributeCombinations", "z3950.attributeCombinations_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_attributesByType,
      { "attributesByType", "z3950.attributesByType",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AttributeTypeDetails", HFILL }},
    { &hf_z3950_attributesByType_item,
      { "AttributeTypeDetails", "z3950.AttributeTypeDetails_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_defaultIfOmitted,
      { "defaultIfOmitted", "z3950.defaultIfOmitted_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "OmittedAttributeInterpretation", HFILL }},
    { &hf_z3950_attributeTypeDetails_attributeValues,
      { "attributeValues", "z3950.attributeValues",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AttributeValue", HFILL }},
    { &hf_z3950_attributeTypeDetails_attributeValues_item,
      { "AttributeValue", "z3950.AttributeValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_defaultValue,
      { "defaultValue", "z3950.defaultValue",
        FT_UINT32, BASE_DEC, VALS(z3950_StringOrNumeric_vals), 0,
        "StringOrNumeric", HFILL }},
    { &hf_z3950_defaultDescription,
      { "defaultDescription", "z3950.defaultDescription",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_attributeValue_value,
      { "value", "z3950.value",
        FT_UINT32, BASE_DEC, VALS(z3950_StringOrNumeric_vals), 0,
        "StringOrNumeric", HFILL }},
    { &hf_z3950_subAttributes,
      { "subAttributes", "z3950.subAttributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_StringOrNumeric", HFILL }},
    { &hf_z3950_subAttributes_item,
      { "StringOrNumeric", "z3950.StringOrNumeric",
        FT_UINT32, BASE_DEC, VALS(z3950_StringOrNumeric_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_superAttributes,
      { "superAttributes", "z3950.superAttributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_StringOrNumeric", HFILL }},
    { &hf_z3950_superAttributes_item,
      { "StringOrNumeric", "z3950.StringOrNumeric",
        FT_UINT32, BASE_DEC, VALS(z3950_StringOrNumeric_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_partialSupport,
      { "partialSupport", "z3950.partialSupport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_termListName,
      { "termListName", "z3950.termListName",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_termListDetails_attributes,
      { "attributes", "z3950.attributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeCombinations", HFILL }},
    { &hf_z3950_scanInfo,
      { "scanInfo", "z3950.scanInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_maxStepSize,
      { "maxStepSize", "z3950.maxStepSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_collatingSequence,
      { "collatingSequence", "z3950.collatingSequence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_increasing,
      { "increasing", "z3950.increasing",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_estNumberTerms,
      { "estNumberTerms", "z3950.estNumberTerms",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_sampleTerms,
      { "sampleTerms", "z3950.sampleTerms",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Term", HFILL }},
    { &hf_z3950_sampleTerms_item,
      { "Term", "z3950.Term",
        FT_UINT32, BASE_DEC, VALS(z3950_Term_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_elementSetDetails_elementSetName,
      { "elementSetName", "z3950.elementSetName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_detailsPerElement,
      { "detailsPerElement", "z3950.detailsPerElement",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_PerElementDetails", HFILL }},
    { &hf_z3950_detailsPerElement_item,
      { "PerElementDetails", "z3950.PerElementDetails_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_recordTag,
      { "recordTag", "z3950.recordTag_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_schemaTags,
      { "schemaTags", "z3950.schemaTags",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Path", HFILL }},
    { &hf_z3950_schemaTags_item,
      { "Path", "z3950.Path",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_maxSize,
      { "maxSize", "z3950.maxSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_minSize,
      { "minSize", "z3950.minSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_avgSize,
      { "avgSize", "z3950.avgSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_fixedSize,
      { "fixedSize", "z3950.fixedSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_contents,
      { "contents", "z3950.contents",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_billingInfo,
      { "billingInfo", "z3950.billingInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_restrictions,
      { "restrictions", "z3950.restrictions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_alternateNames,
      { "alternateNames", "z3950.alternateNames",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_InternationalString", HFILL }},
    { &hf_z3950_alternateNames_item,
      { "InternationalString", "z3950.InternationalString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_genericNames,
      { "genericNames", "z3950.genericNames",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_InternationalString", HFILL }},
    { &hf_z3950_genericNames_item,
      { "InternationalString", "z3950.InternationalString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_searchAccess,
      { "searchAccess", "z3950.searchAccess_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeCombinations", HFILL }},
    { &hf_z3950_qualifier,
      { "qualifier", "z3950.qualifier",
        FT_UINT32, BASE_DEC, VALS(z3950_StringOrNumeric_vals), 0,
        "StringOrNumeric", HFILL }},
    { &hf_z3950_sortKeys,
      { "sortKeys", "z3950.sortKeys",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_SortKeyDetails", HFILL }},
    { &hf_z3950_sortKeys_item,
      { "SortKeyDetails", "z3950.SortKeyDetails_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_elementSpecifications,
      { "elementSpecifications", "z3950.elementSpecifications",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Specification", HFILL }},
    { &hf_z3950_elementSpecifications_item,
      { "Specification", "z3950.Specification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_attributeSpecifications,
      { "attributeSpecifications", "z3950.attributeSpecifications_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeCombinations", HFILL }},
    { &hf_z3950_sortType,
      { "sortType", "z3950.sortType",
        FT_UINT32, BASE_DEC, VALS(z3950_T_sortType_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_character,
      { "character", "z3950.character_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_sortKeyDetails_sortType_numeric,
      { "numeric", "z3950.numeric_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_sortKeyDetails_sortType_structured,
      { "structured", "z3950.structured",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_sortKeyDetails_caseSensitivity,
      { "caseSensitivity", "z3950.caseSensitivity",
        FT_INT32, BASE_DEC, VALS(z3950_T_sortKeyDetails_caseSensitivity_vals), 0,
        "T_sortKeyDetails_caseSensitivity", HFILL }},
    { &hf_z3950_processingContext,
      { "processingContext", "z3950.processingContext",
        FT_INT32, BASE_DEC, VALS(z3950_T_processingContext_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_instructions,
      { "instructions", "z3950.instructions_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_z3950_variantSet,
      { "variantSet", "z3950.variantSet",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_z3950_variantSetInfo_variants,
      { "variants", "z3950.variants",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_VariantClass", HFILL }},
    { &hf_z3950_variantSetInfo_variants_item,
      { "VariantClass", "z3950.VariantClass_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_variantClass,
      { "variantClass", "z3950.variantClass",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_variantTypes,
      { "variantTypes", "z3950.variantTypes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_VariantType", HFILL }},
    { &hf_z3950_variantTypes_item,
      { "VariantType", "z3950.VariantType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_variantType,
      { "variantType", "z3950.variantType",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_variantValue,
      { "variantValue", "z3950.variantValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_values,
      { "values", "z3950.values",
        FT_UINT32, BASE_DEC, VALS(z3950_ValueSet_vals), 0,
        "ValueSet", HFILL }},
    { &hf_z3950_range,
      { "range", "z3950.range_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ValueRange", HFILL }},
    { &hf_z3950_enumerated,
      { "enumerated", "z3950.enumerated",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ValueDescription", HFILL }},
    { &hf_z3950_enumerated_item,
      { "ValueDescription", "z3950.ValueDescription",
        FT_UINT32, BASE_DEC, VALS(z3950_ValueDescription_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_lower,
      { "lower", "z3950.lower",
        FT_UINT32, BASE_DEC, VALS(z3950_ValueDescription_vals), 0,
        "ValueDescription", HFILL }},
    { &hf_z3950_upper,
      { "upper", "z3950.upper",
        FT_UINT32, BASE_DEC, VALS(z3950_ValueDescription_vals), 0,
        "ValueDescription", HFILL }},
    { &hf_z3950_integer,
      { "integer", "z3950.integer",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_octets,
      { "octets", "z3950.octets",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_z3950_valueDescription_unit,
      { "unit", "z3950.unit_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_valueAndUnit,
      { "valueAndUnit", "z3950.valueAndUnit_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IntUnit", HFILL }},
    { &hf_z3950_unitInfo_units,
      { "units", "z3950.units",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_UnitType", HFILL }},
    { &hf_z3950_unitInfo_units_item,
      { "UnitType", "z3950.UnitType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_unitType_units,
      { "units", "z3950.units",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Units", HFILL }},
    { &hf_z3950_unitType_units_item,
      { "Units", "z3950.Units_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_categories,
      { "categories", "z3950.categories",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_CategoryInfo", HFILL }},
    { &hf_z3950_categories_item,
      { "CategoryInfo", "z3950.CategoryInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_categoryInfo_category,
      { "category", "z3950.category",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_originalCategory,
      { "originalCategory", "z3950.originalCategory",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_dateAdded,
      { "dateAdded", "z3950.dateAdded",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_z3950_dateChanged,
      { "dateChanged", "z3950.dateChanged",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_z3950_expiry,
      { "expiry", "z3950.expiry",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_z3950_humanString_Language,
      { "humanString-Language", "z3950.humanString_Language",
        FT_STRING, BASE_NONE, NULL, 0,
        "LanguageCode", HFILL }},
    { &hf_z3950_HumanString_item,
      { "HumanString item", "z3950.HumanString_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_language,
      { "language", "z3950.language",
        FT_STRING, BASE_NONE, NULL, 0,
        "LanguageCode", HFILL }},
    { &hf_z3950_text,
      { "text", "z3950.text",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_IconObject_item,
      { "IconObject item", "z3950.IconObject_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_bodyType,
      { "bodyType", "z3950.bodyType",
        FT_UINT32, BASE_DEC, VALS(z3950_T_bodyType_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_ianaType,
      { "ianaType", "z3950.ianaType",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_z3950type,
      { "z3950type", "z3950.z3950type",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_otherType,
      { "otherType", "z3950.otherType",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_content,
      { "content", "z3950.content",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_z3950_address,
      { "address", "z3950.address",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_email,
      { "email", "z3950.email",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_phone,
      { "phone", "z3950.phone",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_internetAddress,
      { "internetAddress", "z3950.internetAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_hostAddress,
      { "hostAddress", "z3950.hostAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_port,
      { "port", "z3950.port",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_osiPresentationAddress,
      { "osiPresentationAddress", "z3950.osiPresentationAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_pSel,
      { "pSel", "z3950.pSel",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_sSel,
      { "sSel", "z3950.sSel",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_tSel,
      { "tSel", "z3950.tSel",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_nSap,
      { "nSap", "z3950.nSap",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_networkAddress_other,
      { "other", "z3950.other_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_networkAddress_other", HFILL }},
    { &hf_z3950_networkAddress_other_type,
      { "type", "z3950.type",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_networkAddress_other_address,
      { "address", "z3950.address",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_queryTypesSupported,
      { "queryTypesSupported", "z3950.queryTypesSupported",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_QueryTypeDetails", HFILL }},
    { &hf_z3950_queryTypesSupported_item,
      { "QueryTypeDetails", "z3950.QueryTypeDetails",
        FT_UINT32, BASE_DEC, VALS(z3950_QueryTypeDetails_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_diagnosticsSets,
      { "diagnosticsSets", "z3950.diagnosticsSets",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_diagnosticsSets_item,
      { "diagnosticsSets item", "z3950.diagnosticsSets_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_z3950_attributeSetIds,
      { "attributeSetIds", "z3950.attributeSetIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AttributeSetId", HFILL }},
    { &hf_z3950_attributeSetIds_item,
      { "AttributeSetId", "z3950.AttributeSetId",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_schemas,
      { "schemas", "z3950.schemas",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_schemas_item,
      { "schemas item", "z3950.schemas_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_z3950_recordSyntaxes,
      { "recordSyntaxes", "z3950.recordSyntaxes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_recordSyntaxes_item,
      { "recordSyntaxes item", "z3950.recordSyntaxes_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_z3950_resourceChallenges,
      { "resourceChallenges", "z3950.resourceChallenges",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_resourceChallenges_item,
      { "resourceChallenges item", "z3950.resourceChallenges_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_z3950_restrictedAccess,
      { "restrictedAccess", "z3950.restrictedAccess",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AccessRestrictions", HFILL }},
    { &hf_z3950_costInfo,
      { "costInfo", "z3950.costInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Costs", HFILL }},
    { &hf_z3950_variantSets,
      { "variantSets", "z3950.variantSets",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_variantSets_item,
      { "variantSets item", "z3950.variantSets_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_z3950_elementSetNames,
      { "elementSetNames", "z3950.elementSetNames",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ElementSetName", HFILL }},
    { &hf_z3950_elementSetNames_item,
      { "ElementSetName", "z3950.ElementSetName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_unitSystems,
      { "unitSystems", "z3950.unitSystems",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_InternationalString", HFILL }},
    { &hf_z3950_unitSystems_item,
      { "InternationalString", "z3950.InternationalString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_queryTypeDetails_private,
      { "private", "z3950.private_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrivateCapabilities", HFILL }},
    { &hf_z3950_queryTypeDetails_rpn,
      { "rpn", "z3950.rpn_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RpnCapabilities", HFILL }},
    { &hf_z3950_iso8777,
      { "iso8777", "z3950.iso8777_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Iso8777Capabilities", HFILL }},
    { &hf_z3950_z39_58,
      { "z39-58", "z3950.z39_58",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_erpn,
      { "erpn", "z3950.erpn_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RpnCapabilities", HFILL }},
    { &hf_z3950_rankedList,
      { "rankedList", "z3950.rankedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_privateCapabilities_operators,
      { "operators", "z3950.operators",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_privateCapabilities_operators", HFILL }},
    { &hf_z3950_privateCapabilities_operators_item,
      { "operators item", "z3950.operators_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_privateCapabilities_operators_item", HFILL }},
    { &hf_z3950_operator,
      { "operator", "z3950.operator",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_searchKeys,
      { "searchKeys", "z3950.searchKeys",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_SearchKey", HFILL }},
    { &hf_z3950_searchKeys_item,
      { "SearchKey", "z3950.SearchKey_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_privateCapabilities_description,
      { "description", "z3950.description",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_HumanString", HFILL }},
    { &hf_z3950_privateCapabilities_description_item,
      { "HumanString", "z3950.HumanString",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_operators,
      { "operators", "z3950.operators",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_operators_item,
      { "operators item", "z3950.operators_item",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_resultSetAsOperandSupported,
      { "resultSetAsOperandSupported", "z3950.resultSetAsOperandSupported",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_restrictionOperandSupported,
      { "restrictionOperandSupported", "z3950.restrictionOperandSupported",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_proximity,
      { "proximity", "z3950.proximity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProximitySupport", HFILL }},
    { &hf_z3950_anySupport,
      { "anySupport", "z3950.anySupport",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_unitsSupported,
      { "unitsSupported", "z3950.unitsSupported",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_unitsSupported_item,
      { "unitsSupported item", "z3950.unitsSupported_item",
        FT_UINT32, BASE_DEC, VALS(z3950_T_unitsSupported_item_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_proximitySupport_unitsSupported_item_known,
      { "known", "z3950.known",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_proximitySupport_unitsSupported_item_private,
      { "private", "z3950.private_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_proximitySupport_unitsSupported_item_private", HFILL }},
    { &hf_z3950_proximitySupport_unitsSupported_item_private_unit,
      { "unit", "z3950.unit",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_searchKey,
      { "searchKey", "z3950.searchKey",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_AccessRestrictions_item,
      { "AccessRestrictions item", "z3950.AccessRestrictions_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_accessType,
      { "accessType", "z3950.accessType",
        FT_INT32, BASE_DEC, VALS(z3950_T_accessType_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_accessText,
      { "accessText", "z3950.accessText",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_accessChallenges,
      { "accessChallenges", "z3950.accessChallenges",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_accessChallenges_item,
      { "accessChallenges item", "z3950.accessChallenges_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_z3950_connectCharge,
      { "connectCharge", "z3950.connectCharge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Charge", HFILL }},
    { &hf_z3950_connectTime,
      { "connectTime", "z3950.connectTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Charge", HFILL }},
    { &hf_z3950_displayCharge,
      { "displayCharge", "z3950.displayCharge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Charge", HFILL }},
    { &hf_z3950_searchCharge,
      { "searchCharge", "z3950.searchCharge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Charge", HFILL }},
    { &hf_z3950_subscriptCharge,
      { "subscriptCharge", "z3950.subscriptCharge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Charge", HFILL }},
    { &hf_z3950_otherCharges,
      { "otherCharges", "z3950.otherCharges",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_otherCharges_item,
      { "otherCharges item", "z3950.otherCharges_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_forWhat,
      { "forWhat", "z3950.forWhat",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_charge,
      { "charge", "z3950.charge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_cost,
      { "cost", "z3950.cost_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IntUnit", HFILL }},
    { &hf_z3950_perWhat,
      { "perWhat", "z3950.perWhat_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Unit", HFILL }},
    { &hf_z3950_charge_text,
      { "text", "z3950.text",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HumanString", HFILL }},
    { &hf_z3950_DatabaseList_item,
      { "DatabaseName", "z3950.DatabaseName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_defaultAttributeSet,
      { "defaultAttributeSet", "z3950.defaultAttributeSet",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeSetId", HFILL }},
    { &hf_z3950_legalCombinations,
      { "legalCombinations", "z3950.legalCombinations",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AttributeCombination", HFILL }},
    { &hf_z3950_legalCombinations_item,
      { "AttributeCombination", "z3950.AttributeCombination",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_AttributeCombination_item,
      { "AttributeOccurrence", "z3950.AttributeOccurrence_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_mustBeSupplied,
      { "mustBeSupplied", "z3950.mustBeSupplied_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_attributeOccurrence_attributeValues,
      { "attributeValues", "z3950.attributeValues",
        FT_UINT32, BASE_DEC, VALS(z3950_T_attributeOccurrence_attributeValues_vals), 0,
        "T_attributeOccurrence_attributeValues", HFILL }},
    { &hf_z3950_any_or_none,
      { "any-or-none", "z3950.any_or_none_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_specific,
      { "specific", "z3950.specific",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_StringOrNumeric", HFILL }},
    { &hf_z3950_specific_item,
      { "StringOrNumeric", "z3950.StringOrNumeric",
        FT_UINT32, BASE_DEC, VALS(z3950_StringOrNumeric_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_briefBib_title,
      { "title", "z3950.title",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_author,
      { "author", "z3950.author",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_recordType,
      { "recordType", "z3950.recordType",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_bibliographicLevel,
      { "bibliographicLevel", "z3950.bibliographicLevel",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_briefBib_format,
      { "format", "z3950.format",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_FormatSpec", HFILL }},
    { &hf_z3950_briefBib_format_item,
      { "FormatSpec", "z3950.FormatSpec_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_publicationPlace,
      { "publicationPlace", "z3950.publicationPlace",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_publicationDate,
      { "publicationDate", "z3950.publicationDate",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_targetSystemKey,
      { "targetSystemKey", "z3950.targetSystemKey",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_satisfyingElement,
      { "satisfyingElement", "z3950.satisfyingElement",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_rank,
      { "rank", "z3950.rank",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_documentId,
      { "documentId", "z3950.documentId",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_abstract,
      { "abstract", "z3950.abstract",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_formatSpec_type,
      { "type", "z3950.type",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_size,
      { "size", "z3950.size",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_bestPosn,
      { "bestPosn", "z3950.bestPosn",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_GenericRecord_item,
      { "TaggedElement", "z3950.TaggedElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_tagOccurrence,
      { "tagOccurrence", "z3950.tagOccurrence",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_taggedElement_content,
      { "content", "z3950.content",
        FT_UINT32, BASE_DEC, VALS(z3950_ElementData_vals), 0,
        "ElementData", HFILL }},
    { &hf_z3950_metaData,
      { "metaData", "z3950.metaData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ElementMetaData", HFILL }},
    { &hf_z3950_appliedVariant,
      { "appliedVariant", "z3950.appliedVariant_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Variant", HFILL }},
    { &hf_z3950_date,
      { "date", "z3950.date",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_z3950_ext,
      { "ext", "z3950.ext_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_z3950_trueOrFalse,
      { "trueOrFalse", "z3950.trueOrFalse",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_intUnit,
      { "intUnit", "z3950.intUnit_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_elementNotThere,
      { "elementNotThere", "z3950.elementNotThere_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_elementEmpty,
      { "elementEmpty", "z3950.elementEmpty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_noDataRequested,
      { "noDataRequested", "z3950.noDataRequested_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_elementData_diagnostic,
      { "diagnostic", "z3950.diagnostic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_z3950_subtree,
      { "subtree", "z3950.subtree",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_TaggedElement", HFILL }},
    { &hf_z3950_subtree_item,
      { "TaggedElement", "z3950.TaggedElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_seriesOrder,
      { "seriesOrder", "z3950.seriesOrder_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Order", HFILL }},
    { &hf_z3950_usageRight,
      { "usageRight", "z3950.usageRight_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Usage", HFILL }},
    { &hf_z3950_hits,
      { "hits", "z3950.hits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_HitVector", HFILL }},
    { &hf_z3950_hits_item,
      { "HitVector", "z3950.HitVector_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_displayName,
      { "displayName", "z3950.displayName",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_supportedVariants,
      { "supportedVariants", "z3950.supportedVariants",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Variant", HFILL }},
    { &hf_z3950_supportedVariants_item,
      { "Variant", "z3950.Variant_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_elementDescriptor,
      { "elementDescriptor", "z3950.elementDescriptor",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_z3950_surrogateFor,
      { "surrogateFor", "z3950.surrogateFor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TagPath", HFILL }},
    { &hf_z3950_surrogateElement,
      { "surrogateElement", "z3950.surrogateElement",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TagPath", HFILL }},
    { &hf_z3950_TagPath_item,
      { "TagPath item", "z3950.TagPath_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_ascending,
      { "ascending", "z3950.ascending",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_order,
      { "order", "z3950.order",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_usage_type,
      { "type", "z3950.type",
        FT_INT32, BASE_DEC, VALS(z3950_T_usage_type_vals), 0,
        "T_usage_type", HFILL }},
    { &hf_z3950_restriction,
      { "restriction", "z3950.restriction",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_satisfier,
      { "satisfier", "z3950.satisfier",
        FT_UINT32, BASE_DEC, VALS(z3950_Term_vals), 0,
        "Term", HFILL }},
    { &hf_z3950_offsetIntoElement,
      { "offsetIntoElement", "z3950.offsetIntoElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IntUnit", HFILL }},
    { &hf_z3950_length,
      { "length", "z3950.length_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IntUnit", HFILL }},
    { &hf_z3950_hitRank,
      { "hitRank", "z3950.hitRank",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_targetToken,
      { "targetToken", "z3950.targetToken",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_z3950_globalVariantSetId,
      { "globalVariantSetId", "z3950.globalVariantSetId",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_z3950_triples,
      { "triples", "z3950.triples",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_triples_item,
      { "triples item", "z3950.triples_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_variantSetId,
      { "variantSetId", "z3950.variantSetId",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_z3950_class,
      { "class", "z3950.class",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_variant_triples_item_value,
      { "value", "z3950.value",
        FT_UINT32, BASE_DEC, VALS(z3950_T_variant_triples_item_value_vals), 0,
        "T_variant_triples_item_value", HFILL }},
    { &hf_z3950_octetString,
      { "octetString", "z3950.octetString",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_z3950_boolean,
      { "boolean", "z3950.boolean",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_variant_triples_item_value_unit,
      { "unit", "z3950.unit_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_taskPackage_description,
      { "description", "z3950.description",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_targetReference,
      { "targetReference", "z3950.targetReference",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_z3950_creationDateTime,
      { "creationDateTime", "z3950.creationDateTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_z3950_taskStatus,
      { "taskStatus", "z3950.taskStatus",
        FT_INT32, BASE_DEC, VALS(z3950_T_taskStatus_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_packageDiagnostics,
      { "packageDiagnostics", "z3950.packageDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_DiagRec", HFILL }},
    { &hf_z3950_packageDiagnostics_item,
      { "DiagRec", "z3950.DiagRec",
        FT_UINT32, BASE_DEC, VALS(z3950_DiagRec_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_challenge,
      { "challenge", "z3950.challenge",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_response,
      { "response", "z3950.response",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_Challenge_item,
      { "Challenge item", "z3950.Challenge_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_promptId,
      { "promptId", "z3950.promptId",
        FT_UINT32, BASE_DEC, VALS(z3950_PromptId_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_defaultResponse,
      { "defaultResponse", "z3950.defaultResponse",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_promptInfo,
      { "promptInfo", "z3950.promptInfo",
        FT_UINT32, BASE_DEC, VALS(z3950_T_promptInfo_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_challenge_item_promptInfo_character,
      { "character", "z3950.character",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_encrypted,
      { "encrypted", "z3950.encrypted_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Encryption", HFILL }},
    { &hf_z3950_regExpr,
      { "regExpr", "z3950.regExpr",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_responseRequired,
      { "responseRequired", "z3950.responseRequired_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_allowedValues,
      { "allowedValues", "z3950.allowedValues",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_InternationalString", HFILL }},
    { &hf_z3950_allowedValues_item,
      { "InternationalString", "z3950.InternationalString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_shouldSave,
      { "shouldSave", "z3950.shouldSave_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_challenge_item_dataType,
      { "dataType", "z3950.dataType",
        FT_INT32, BASE_DEC, VALS(z3950_T_challenge_item_dataType_vals), 0,
        "T_challenge_item_dataType", HFILL }},
    { &hf_z3950_challenge_item_diagnostic,
      { "diagnostic", "z3950.diagnostic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_z3950_Response_item,
      { "Response item", "z3950.Response_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_promptResponse,
      { "promptResponse", "z3950.promptResponse",
        FT_UINT32, BASE_DEC, VALS(z3950_T_promptResponse_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_accept,
      { "accept", "z3950.accept",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_acknowledge,
      { "acknowledge", "z3950.acknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_enummeratedPrompt,
      { "enummeratedPrompt", "z3950.enummeratedPrompt_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_promptId_enummeratedPrompt_type,
      { "type", "z3950.type",
        FT_INT32, BASE_DEC, VALS(z3950_T_promptId_enummeratedPrompt_type_vals), 0,
        "T_promptId_enummeratedPrompt_type", HFILL }},
    { &hf_z3950_suggestedString,
      { "suggestedString", "z3950.suggestedString",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_nonEnumeratedPrompt,
      { "nonEnumeratedPrompt", "z3950.nonEnumeratedPrompt",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_cryptType,
      { "cryptType", "z3950.cryptType",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_z3950_credential,
      { "credential", "z3950.credential",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_z3950_data,
      { "data", "z3950.data",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_z3950_dES_RN_Object_challenge,
      { "challenge", "z3950.challenge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DRNType", HFILL }},
    { &hf_z3950_rES_RN_Object_response,
      { "response", "z3950.response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DRNType", HFILL }},
    { &hf_z3950_dRNType_userId,
      { "userId", "z3950.userId",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_z3950_salt,
      { "salt", "z3950.salt",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_z3950_randomNumber,
      { "randomNumber", "z3950.randomNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_z3950_kRBObject_challenge,
      { "challenge", "z3950.challenge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "KRBRequest", HFILL }},
    { &hf_z3950_kRBObject_response,
      { "response", "z3950.response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "KRBResponse", HFILL }},
    { &hf_z3950_service,
      { "service", "z3950.service",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_instance,
      { "instance", "z3950.instance",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_realm,
      { "realm", "z3950.realm",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_userid,
      { "userid", "z3950.userid",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_ticket,
      { "ticket", "z3950.ticket",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_z3950_SearchInfoReport_item,
      { "SearchInfoReport item", "z3950.SearchInfoReport_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_subqueryId,
      { "subqueryId", "z3950.subqueryId",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_fullQuery,
      { "fullQuery", "z3950.fullQuery",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_z3950_subqueryExpression,
      { "subqueryExpression", "z3950.subqueryExpression",
        FT_UINT32, BASE_DEC, VALS(z3950_QueryExpression_vals), 0,
        "QueryExpression", HFILL }},
    { &hf_z3950_subqueryInterpretation,
      { "subqueryInterpretation", "z3950.subqueryInterpretation",
        FT_UINT32, BASE_DEC, VALS(z3950_QueryExpression_vals), 0,
        "QueryExpression", HFILL }},
    { &hf_z3950_subqueryRecommendation,
      { "subqueryRecommendation", "z3950.subqueryRecommendation",
        FT_UINT32, BASE_DEC, VALS(z3950_QueryExpression_vals), 0,
        "QueryExpression", HFILL }},
    { &hf_z3950_subqueryCount,
      { "subqueryCount", "z3950.subqueryCount",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_subqueryWeight,
      { "subqueryWeight", "z3950.subqueryWeight_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IntUnit", HFILL }},
    { &hf_z3950_resultsByDB,
      { "resultsByDB", "z3950.resultsByDB",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_ResultsByDB_item,
      { "ResultsByDB item", "z3950.ResultsByDB_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_databases,
      { "databases", "z3950.databases",
        FT_UINT32, BASE_DEC, VALS(z3950_T_databases_vals), 0,
        NULL, HFILL }},
    { &hf_z3950_all,
      { "all", "z3950.all_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_list,
      { "list", "z3950.list",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_DatabaseName", HFILL }},
    { &hf_z3950_list_item,
      { "DatabaseName", "z3950.DatabaseName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_count,
      { "count", "z3950.count",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_z3950_queryExpression_term,
      { "term", "z3950.term_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_queryExpression_term", HFILL }},
    { &hf_z3950_queryTerm,
      { "queryTerm", "z3950.queryTerm",
        FT_UINT32, BASE_DEC, VALS(z3950_Term_vals), 0,
        "Term", HFILL }},
    { &hf_z3950_termComment,
      { "termComment", "z3950.termComment",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalString", HFILL }},
    { &hf_z3950_ProtocolVersion_U_version_1,
      { "version-1", "z3950.ProtocolVersion.U.version.1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_z3950_ProtocolVersion_U_version_2,
      { "version-2", "z3950.ProtocolVersion.U.version.2",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_z3950_ProtocolVersion_U_version_3,
      { "version-3", "z3950.ProtocolVersion.U.version.3",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_z3950_Options_U_search,
      { "search", "z3950.Options.U.search",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_z3950_Options_U_present,
      { "present", "z3950.Options.U.present",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_z3950_Options_U_delSet,
      { "delSet", "z3950.Options.U.delSet",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_z3950_Options_U_resourceReport,
      { "resourceReport", "z3950.Options.U.resourceReport",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_z3950_Options_U_triggerResourceCtrl,
      { "triggerResourceCtrl", "z3950.Options.U.triggerResourceCtrl",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_z3950_Options_U_resourceCtrl,
      { "resourceCtrl", "z3950.Options.U.resourceCtrl",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_z3950_Options_U_accessCtrl,
      { "accessCtrl", "z3950.Options.U.accessCtrl",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_z3950_Options_U_scan,
      { "scan", "z3950.Options.U.scan",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_z3950_Options_U_sort,
      { "sort", "z3950.Options.U.sort",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_z3950_Options_U_spare_bit9,
      { "spare_bit9", "z3950.Options.U.spare.bit9",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_z3950_Options_U_extendedServices,
      { "extendedServices", "z3950.Options.U.extendedServices",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_z3950_Options_U_level_1Segmentation,
      { "level-1Segmentation", "z3950.Options.U.level.1Segmentation",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_z3950_Options_U_level_2Segmentation,
      { "level-2Segmentation", "z3950.Options.U.level.2Segmentation",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_z3950_Options_U_concurrentOperations,
      { "concurrentOperations", "z3950.Options.U.concurrentOperations",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_z3950_Options_U_namedResultSets,
      { "namedResultSets", "z3950.Options.U.namedResultSets",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},

/*--- End of included file: packet-z3950-hfarr.c ---*/
#line 977 "./asn1/z3950/packet-z3950-template.c"

    { &hf_z3950_referenceId_printable,
        { "referenceId", "z3950.referenceId.printable",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_z3950_general_printable,
        { "general", "z3950.general.printable",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/* MARC hf definitions */
    { &hf_marc_record,
        { "MARC record", "marc",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_record_terminator,
        { "MARC record terminator", "marc.terminator",
        FT_CHAR, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_leader,
        { "MARC leader", "marc.leader",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_leader_length,
        { "MARC leader length", "marc.leader.length",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_leader_status,
        { "MARC leader status", "marc.leader.status",
        FT_CHAR, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_leader_type,
        { "MARC leader type", "marc.leader.type",
        FT_CHAR, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_leader_biblevel,
        { "MARC leader biblevel", "marc.leader.biblevel",
        FT_CHAR, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_leader_control,
        { "MARC leader control", "marc.leader.control",
        FT_CHAR, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_leader_encoding,
        { "MARC leader encoding", "marc.leader.encoding",
        FT_CHAR, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_leader_indicator_count,
        { "MARC leader indicator count", "marc.leader.indicator_count",
        FT_CHAR, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_leader_subfield_count,
        { "MARC leader subfield count", "marc.leader.subfield_count",
        FT_CHAR, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_leader_data_offset,
        { "MARC leader data offset", "marc.leader.data_offset",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_leader_encoding_level,
        { "MARC leader encoding level", "marc.leader.encoding_level",
        FT_CHAR, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_leader_descriptive_cataloging,
        { "MARC leader descriptive cataloging", "marc.leader.descriptive_cataloging",
        FT_CHAR, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_leader_multipart_level,
        { "MARC leader multipart level", "marc.leader.multipart_level",
        FT_CHAR, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_leader_length_of_field_length,
        { "MARC leader length-of-field length", "marc.leader.length_of_field_length",
        FT_CHAR, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_leader_starting_character_position_length,
        { "MARC leader starting-character-position length", "marc.leader.starting_character_position_length",
        FT_CHAR, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_leader_implementation_defined_length,
        { "MARC leader implementation-defined length", "marc.leader.implementation_defined_length",
        FT_CHAR, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_directory,
        { "MARC directory", "marc.directory",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_directory_entry,
        { "MARC directory entry", "marc.directory.entry",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_directory_entry_tag,
        { "tag", "marc.directory.entry.tag",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_directory_entry_length,
        { "length", "marc.directory.entry.length",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_directory_entry_starting_position,
        { "starting position", "marc.directory.entry.starting_position",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_directory_terminator,
        { "MARC directory terminator", "marc.directory.terminator",
        FT_CHAR, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_fields,
        { "MARC data fields", "marc.fields",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_field,
        { "MARC field", "marc.field",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_field_control,
        { "Control field", "marc.field.control",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_field_terminator,
        { "MARC field terminator", "marc.field.terminator",
        FT_CHAR, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_field_indicator1,
        { "MARC field indicator1", "marc.field.indicator1",
        FT_CHAR, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_field_indicator2,
        { "MARC field indicator2", "marc.field.indicator2",
        FT_CHAR, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_field_subfield_indicator,
        { "MARC field subfield indicator", "marc.field.subfield.indicator",
        FT_CHAR, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_field_subfield_tag,
        { "MARC field subfield tag", "marc.field.subfield.tag",
        FT_CHAR, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_marc_field_subfield,
        { "MARC Subfield", "marc.field.subfield",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    };

    /* List of subtrees */
    static gint *ett[] = {
		  &ett_z3950,
/* MARC etts */
                  &ett_marc_record,
                  &ett_marc_leader,
                  &ett_marc_directory,
                  &ett_marc_directory_entry,
                  &ett_marc_fields,
                  &ett_marc_field,

/*--- Included file: packet-z3950-ettarr.c ---*/
#line 1 "./asn1/z3950/packet-z3950-ettarr.c"
    &ett_z3950_PDU,
    &ett_z3950_InitializeRequest,
    &ett_z3950_T_idAuthentication,
    &ett_z3950_T_idPass,
    &ett_z3950_InitializeResponse,
    &ett_z3950_ProtocolVersion_U,
    &ett_z3950_Options_U,
    &ett_z3950_SearchRequest,
    &ett_z3950_SEQUENCE_OF_DatabaseName,
    &ett_z3950_Query,
    &ett_z3950_RPNQuery,
    &ett_z3950_RPNStructure,
    &ett_z3950_T_rpnRpnOp,
    &ett_z3950_Operand,
    &ett_z3950_AttributesPlusTerm_U,
    &ett_z3950_ResultSetPlusAttributes_U,
    &ett_z3950_SEQUENCE_OF_AttributeElement,
    &ett_z3950_Term,
    &ett_z3950_Operator_U,
    &ett_z3950_AttributeElement,
    &ett_z3950_T_attributeValue,
    &ett_z3950_T_attributeValue_complex,
    &ett_z3950_SEQUENCE_OF_StringOrNumeric,
    &ett_z3950_T_semanticAction,
    &ett_z3950_ProximityOperator,
    &ett_z3950_T_proximityUnitCode,
    &ett_z3950_SearchResponse,
    &ett_z3950_PresentRequest,
    &ett_z3950_SEQUENCE_OF_Range,
    &ett_z3950_T_recordComposition,
    &ett_z3950_Segment,
    &ett_z3950_SEQUENCE_OF_NamePlusRecord,
    &ett_z3950_PresentResponse,
    &ett_z3950_Records,
    &ett_z3950_SEQUENCE_OF_DiagRec,
    &ett_z3950_NamePlusRecord,
    &ett_z3950_T_record,
    &ett_z3950_FragmentSyntax,
    &ett_z3950_DiagRec,
    &ett_z3950_DefaultDiagFormat,
    &ett_z3950_T_addinfo,
    &ett_z3950_Range,
    &ett_z3950_ElementSetNames,
    &ett_z3950_T_databaseSpecific,
    &ett_z3950_T_databaseSpecific_item,
    &ett_z3950_CompSpec,
    &ett_z3950_T_dbSpecific,
    &ett_z3950_T_dbSpecific_item,
    &ett_z3950_T_compSpec_recordSyntax,
    &ett_z3950_Specification,
    &ett_z3950_T_specification_elementSpec,
    &ett_z3950_DeleteResultSetRequest,
    &ett_z3950_SEQUENCE_OF_ResultSetId,
    &ett_z3950_DeleteResultSetResponse,
    &ett_z3950_ListStatuses,
    &ett_z3950_ListStatuses_item,
    &ett_z3950_AccessControlRequest,
    &ett_z3950_T_securityChallenge,
    &ett_z3950_AccessControlResponse,
    &ett_z3950_T_securityChallengeResponse,
    &ett_z3950_ResourceControlRequest,
    &ett_z3950_ResourceControlResponse,
    &ett_z3950_TriggerResourceControlRequest,
    &ett_z3950_ResourceReportRequest,
    &ett_z3950_ResourceReportResponse,
    &ett_z3950_ScanRequest,
    &ett_z3950_ScanResponse,
    &ett_z3950_ListEntries,
    &ett_z3950_SEQUENCE_OF_Entry,
    &ett_z3950_Entry,
    &ett_z3950_TermInfo,
    &ett_z3950_SEQUENCE_OF_AttributesPlusTerm,
    &ett_z3950_OccurrenceByAttributes,
    &ett_z3950_OccurrenceByAttributes_item,
    &ett_z3950_T_occurrences,
    &ett_z3950_T_byDatabase,
    &ett_z3950_T_byDatabase_item,
    &ett_z3950_SortRequest,
    &ett_z3950_SEQUENCE_OF_InternationalString,
    &ett_z3950_SEQUENCE_OF_SortKeySpec,
    &ett_z3950_SortResponse,
    &ett_z3950_SortKeySpec,
    &ett_z3950_T_missingValueAction,
    &ett_z3950_SortElement,
    &ett_z3950_T_datbaseSpecific,
    &ett_z3950_T_datbaseSpecific_item,
    &ett_z3950_SortKey,
    &ett_z3950_T_sortAttributes,
    &ett_z3950_ExtendedServicesRequest,
    &ett_z3950_ExtendedServicesResponse,
    &ett_z3950_Permissions,
    &ett_z3950_Permissions_item,
    &ett_z3950_T_allowableFunctions,
    &ett_z3950_Close,
    &ett_z3950_OtherInformation_U,
    &ett_z3950_T__untag_item,
    &ett_z3950_T_information,
    &ett_z3950_InfoCategory,
    &ett_z3950_IntUnit,
    &ett_z3950_Unit,
    &ett_z3950_StringOrNumeric,
    &ett_z3950_OCLC_UserInformation,
    &ett_z3950_SEQUENCE_OF_DBName,
    &ett_z3950_OPACRecord,
    &ett_z3950_SEQUENCE_OF_HoldingsRecord,
    &ett_z3950_HoldingsRecord,
    &ett_z3950_HoldingsAndCircData,
    &ett_z3950_SEQUENCE_OF_Volume,
    &ett_z3950_SEQUENCE_OF_CircRecord,
    &ett_z3950_Volume,
    &ett_z3950_CircRecord,
    &ett_z3950_DiagnosticFormat,
    &ett_z3950_DiagnosticFormat_item,
    &ett_z3950_T_diagnosticFormat_item_diagnostic,
    &ett_z3950_DiagFormat,
    &ett_z3950_T_tooMany,
    &ett_z3950_T_badSpec,
    &ett_z3950_SEQUENCE_OF_Specification,
    &ett_z3950_T_dbUnavail,
    &ett_z3950_T_why,
    &ett_z3950_T_attribute,
    &ett_z3950_T_attCombo,
    &ett_z3950_SEQUENCE_OF_AttributeList,
    &ett_z3950_T_diagFormat_term,
    &ett_z3950_T_diagFormat_proximity,
    &ett_z3950_T_scan,
    &ett_z3950_T_sort,
    &ett_z3950_T_segmentation,
    &ett_z3950_T_extServices,
    &ett_z3950_T_accessCtrl,
    &ett_z3950_T_diagFormat_accessCtrl_oid,
    &ett_z3950_T_alternative,
    &ett_z3950_T_diagFormat_recordSyntax,
    &ett_z3950_T_suggestedAlternatives,
    &ett_z3950_Explain_Record,
    &ett_z3950_TargetInfo,
    &ett_z3950_SEQUENCE_OF_DatabaseList,
    &ett_z3950_SEQUENCE_OF_NetworkAddress,
    &ett_z3950_DatabaseInfo,
    &ett_z3950_SEQUENCE_OF_HumanString,
    &ett_z3950_T_recordCount,
    &ett_z3950_SchemaInfo,
    &ett_z3950_T_tagTypeMapping,
    &ett_z3950_T_tagTypeMapping_item,
    &ett_z3950_SEQUENCE_OF_ElementInfo,
    &ett_z3950_ElementInfo,
    &ett_z3950_Path,
    &ett_z3950_Path_item,
    &ett_z3950_ElementDataType,
    &ett_z3950_TagSetInfo,
    &ett_z3950_T_tagSetInfo_elements,
    &ett_z3950_T_tagSetInfo_elements_item,
    &ett_z3950_RecordSyntaxInfo,
    &ett_z3950_T_transferSyntaxes,
    &ett_z3950_AttributeSetInfo,
    &ett_z3950_SEQUENCE_OF_AttributeType,
    &ett_z3950_AttributeType,
    &ett_z3950_SEQUENCE_OF_AttributeDescription,
    &ett_z3950_AttributeDescription,
    &ett_z3950_TermListInfo,
    &ett_z3950_T_termLists,
    &ett_z3950_T_termLists_item,
    &ett_z3950_ExtendedServicesInfo,
    &ett_z3950_AttributeDetails,
    &ett_z3950_SEQUENCE_OF_AttributeSetDetails,
    &ett_z3950_AttributeSetDetails,
    &ett_z3950_SEQUENCE_OF_AttributeTypeDetails,
    &ett_z3950_AttributeTypeDetails,
    &ett_z3950_SEQUENCE_OF_AttributeValue,
    &ett_z3950_OmittedAttributeInterpretation,
    &ett_z3950_AttributeValue,
    &ett_z3950_TermListDetails,
    &ett_z3950_T_scanInfo,
    &ett_z3950_SEQUENCE_OF_Term,
    &ett_z3950_ElementSetDetails,
    &ett_z3950_SEQUENCE_OF_PerElementDetails,
    &ett_z3950_RetrievalRecordDetails,
    &ett_z3950_PerElementDetails,
    &ett_z3950_SEQUENCE_OF_Path,
    &ett_z3950_RecordTag,
    &ett_z3950_SortDetails,
    &ett_z3950_SEQUENCE_OF_SortKeyDetails,
    &ett_z3950_SortKeyDetails,
    &ett_z3950_T_sortType,
    &ett_z3950_ProcessingInformation,
    &ett_z3950_VariantSetInfo,
    &ett_z3950_SEQUENCE_OF_VariantClass,
    &ett_z3950_VariantClass,
    &ett_z3950_SEQUENCE_OF_VariantType,
    &ett_z3950_VariantType,
    &ett_z3950_VariantValue,
    &ett_z3950_ValueSet,
    &ett_z3950_SEQUENCE_OF_ValueDescription,
    &ett_z3950_ValueRange,
    &ett_z3950_ValueDescription,
    &ett_z3950_UnitInfo,
    &ett_z3950_SEQUENCE_OF_UnitType,
    &ett_z3950_UnitType,
    &ett_z3950_SEQUENCE_OF_Units,
    &ett_z3950_Units,
    &ett_z3950_CategoryList,
    &ett_z3950_SEQUENCE_OF_CategoryInfo,
    &ett_z3950_CategoryInfo,
    &ett_z3950_CommonInfo,
    &ett_z3950_HumanString,
    &ett_z3950_HumanString_item,
    &ett_z3950_IconObject,
    &ett_z3950_IconObject_item,
    &ett_z3950_T_bodyType,
    &ett_z3950_ContactInfo,
    &ett_z3950_NetworkAddress,
    &ett_z3950_T_internetAddress,
    &ett_z3950_T_osiPresentationAddress,
    &ett_z3950_T_networkAddress_other,
    &ett_z3950_AccessInfo,
    &ett_z3950_SEQUENCE_OF_QueryTypeDetails,
    &ett_z3950_T_diagnosticsSets,
    &ett_z3950_SEQUENCE_OF_AttributeSetId,
    &ett_z3950_T_schemas,
    &ett_z3950_T_recordSyntaxes,
    &ett_z3950_T_resourceChallenges,
    &ett_z3950_T_variantSets,
    &ett_z3950_SEQUENCE_OF_ElementSetName,
    &ett_z3950_QueryTypeDetails,
    &ett_z3950_PrivateCapabilities,
    &ett_z3950_T_privateCapabilities_operators,
    &ett_z3950_T_privateCapabilities_operators_item,
    &ett_z3950_SEQUENCE_OF_SearchKey,
    &ett_z3950_RpnCapabilities,
    &ett_z3950_T_operators,
    &ett_z3950_Iso8777Capabilities,
    &ett_z3950_ProximitySupport,
    &ett_z3950_T_unitsSupported,
    &ett_z3950_T_unitsSupported_item,
    &ett_z3950_T_proximitySupport_unitsSupported_item_private,
    &ett_z3950_SearchKey,
    &ett_z3950_AccessRestrictions,
    &ett_z3950_AccessRestrictions_item,
    &ett_z3950_T_accessChallenges,
    &ett_z3950_Costs,
    &ett_z3950_T_otherCharges,
    &ett_z3950_T_otherCharges_item,
    &ett_z3950_Charge,
    &ett_z3950_DatabaseList,
    &ett_z3950_AttributeCombinations,
    &ett_z3950_SEQUENCE_OF_AttributeCombination,
    &ett_z3950_AttributeCombination,
    &ett_z3950_AttributeOccurrence,
    &ett_z3950_T_attributeOccurrence_attributeValues,
    &ett_z3950_BriefBib,
    &ett_z3950_SEQUENCE_OF_FormatSpec,
    &ett_z3950_FormatSpec,
    &ett_z3950_GenericRecord,
    &ett_z3950_TaggedElement,
    &ett_z3950_ElementData,
    &ett_z3950_SEQUENCE_OF_TaggedElement,
    &ett_z3950_ElementMetaData,
    &ett_z3950_SEQUENCE_OF_HitVector,
    &ett_z3950_SEQUENCE_OF_Variant,
    &ett_z3950_TagPath,
    &ett_z3950_TagPath_item,
    &ett_z3950_Order,
    &ett_z3950_Usage,
    &ett_z3950_HitVector,
    &ett_z3950_Variant,
    &ett_z3950_T_triples,
    &ett_z3950_T_triples_item,
    &ett_z3950_T_variant_triples_item_value,
    &ett_z3950_TaskPackage,
    &ett_z3950_PromptObject,
    &ett_z3950_Challenge,
    &ett_z3950_Challenge_item,
    &ett_z3950_T_promptInfo,
    &ett_z3950_Response,
    &ett_z3950_Response_item,
    &ett_z3950_T_promptResponse,
    &ett_z3950_PromptId,
    &ett_z3950_T_enummeratedPrompt,
    &ett_z3950_Encryption,
    &ett_z3950_DES_RN_Object,
    &ett_z3950_DRNType,
    &ett_z3950_KRBObject,
    &ett_z3950_KRBRequest,
    &ett_z3950_KRBResponse,
    &ett_z3950_SearchInfoReport,
    &ett_z3950_SearchInfoReport_item,
    &ett_z3950_ResultsByDB,
    &ett_z3950_ResultsByDB_item,
    &ett_z3950_T_databases,
    &ett_z3950_QueryExpression,
    &ett_z3950_T_queryExpression_term,

/*--- End of included file: packet-z3950-ettarr.c ---*/
#line 1134 "./asn1/z3950/packet-z3950-template.c"
    };

    module_t *z3950_module;

/* Expert info */
    static ei_register_info ei[] = {
/* Z39.50 expert info */

/* MARC expert info */
        { &ei_marc_invalid_length, { "marc.invalid_length", PI_MALFORMED, PI_ERROR,
                                     "MARC record too short", EXPFILL }},
        { &ei_marc_invalid_value, { "marc.invalid_value", PI_MALFORMED, PI_ERROR,
                                     "MARC field has invalid value", EXPFILL }},
        { &ei_marc_invalid_record_length, { "marc.invalid_record_length", PI_MALFORMED, PI_ERROR,
                                     "MARC length field has invalid value", EXPFILL }},
    };

    expert_module_t* expert_z3950;


    /* Register protocol */
    proto_z3950 = proto_register_protocol(PNAME, PSNAME, PFNAME);
    /* Register fields and subtrees */
    proto_register_field_array(proto_z3950, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_z3950 = expert_register_protocol(proto_z3950);
    expert_register_field_array(expert_z3950, ei, array_length(ei));

    /* Register preferences */
    z3950_module = prefs_register_protocol(proto_z3950, NULL);
    prefs_register_bool_preference(z3950_module, "desegment_buffers",
                                   "Reassemble Z39.50 buffers spanning multiple TCP segments",
                                   "Whether the Z39.50 dissector should reassemble TDS buffers spanning multiple TCP segments. "
                                   "To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                   &z3950_desegment);

    /* Allow dissector to be found by name. */
    z3950_handle = register_dissector(PSNAME, dissect_z3950_segment,
					      proto_z3950);

}

/*--- proto_reg_handoff_z3950 ---------------------------------------*/
void
proto_reg_handoff_z3950(void)
{

    dissector_add_uint_with_preference("tcp.port",
	global_z3950_port, z3950_handle);


/*--- Included file: packet-z3950-dis-tab.c ---*/
#line 1 "./asn1/z3950/packet-z3950-dis-tab.c"
  register_ber_oid_dissector("1.2.840.10003.5.100", dissect_Explain_Record_PDU, proto_z3950, "Explain-record");
  register_ber_oid_dissector("1.2.840.10003.5.101", dissect_SutrsRecord_PDU, proto_z3950, "Sutrs-record");
  register_ber_oid_dissector("1.2.840.10003.5.102", dissect_OPACRecord_PDU, proto_z3950, "OPAC-record");
  register_ber_oid_dissector("1.2.840.10003.5.103", dissect_BriefBib_PDU, proto_z3950, "Summary-record");
  register_ber_oid_dissector("1.2.840.10003.5.105", dissect_GenericRecord_PDU, proto_z3950, "GRS-1-record");
  register_ber_oid_dissector("1.2.840.10003.5.106", dissect_TaskPackage_PDU, proto_z3950, "ESTaskPackage");
  register_ber_oid_dissector("1.2.840.10003.4.2", dissect_DiagnosticFormat_PDU, proto_z3950, "diag-1");
  register_ber_oid_dissector("1.2.840.10003.8.1", dissect_PromptObject_PDU, proto_z3950, "Prompt-1");
  register_ber_oid_dissector("1.2.840.10003.8.2", dissect_DES_RN_Object_PDU, proto_z3950, "DES-1");
  register_ber_oid_dissector("1.2.840.10003.8.3", dissect_KRBObject_PDU, proto_z3950, "KRB-1");
  register_ber_oid_dissector("1.2.840.10003.10.1", dissect_SearchInfoReport_PDU, proto_z3950, "SearchResult-1");
  register_ber_oid_dissector("1.2.840.10003.10.1000.17.1", dissect_OCLC_UserInformation_PDU, proto_z3950, "OCLC-UserInfo-1");


/*--- End of included file: packet-z3950-dis-tab.c ---*/
#line 1185 "./asn1/z3950/packet-z3950-template.c"

    register_ber_oid_dissector(Z3950_RECORDSYNTAX_MARC21_OID, dissect_marc_record, proto_z3950, "MARC21");

    oid_add_from_string("Z39.50", "1.2.840.10003");
    oid_add_from_string("Z39.50-APDU", "1.2.840.10003.2");
    oid_add_from_string("Z39.50-attributeSet", "1.2.840.10003.3");
    oid_add_from_string("Z39.50-diagnostic", "1.2.840.10003.4");
    oid_add_from_string("Z39.50-recordSyntax", "1.2.840.10003.5");
    oid_add_from_string("Z39.50-resourceReport", "1.2.840.10003.7");
    oid_add_from_string("Z39.50-accessControl", "1.2.840.10003.8");
    oid_add_from_string("Z39.50-extendedService", "1.2.840.10003.9");
    oid_add_from_string("Z39.50-userinfoFormat", "1.2.840.10003.10");
    oid_add_from_string("Z39.50-elementSpec", "1.2.840.10003.11");
    oid_add_from_string("Z39.50-variantSet", "1.2.840.10003.12");
    oid_add_from_string("Z39.50-schema", "1.2.840.10003.13");
    oid_add_from_string("Z39.50-tagSet", "1.2.840.10003.14");
    oid_add_from_string("Z39.50-negotiation", "1.2.840.10003.15");
    oid_add_from_string("Z39.50-query", "1.2.840.10003.16");
    /* MARC Record Syntaxes */
    oid_add_from_string("UNIMARC","1.2.840.10003.5.1");
    oid_add_from_string("INTERMARC","1.2.840.10003.5.2");
    oid_add_from_string("CCF","1.2.840.10003.5.3");
    oid_add_from_string("MARC21 (formerly USMARC)",Z3950_RECORDSYNTAX_MARC21_OID);
    oid_add_from_string("UKMARC","1.2.840.10003.5.11");
    oid_add_from_string("NORMARC","1.2.840.10003.5.12");
    oid_add_from_string("Librismarc","1.2.840.10003.5.13");
    oid_add_from_string("danMARC2","1.2.840.10003.5.14");
    oid_add_from_string("Finmarc","1.2.840.10003.5.15");
    oid_add_from_string("MAB","1.2.840.10003.5.16");
    oid_add_from_string("Canmarc","1.2.840.10003.5.17");
    oid_add_from_string("SBN","1.2.840.10003.5.18");
    oid_add_from_string("Picamarc","1.2.840.10003.5.19");
    oid_add_from_string("Ausmarc","1.2.840.10003.5.20");
    oid_add_from_string("Ibermarc","1.2.840.10003.5.21");
    oid_add_from_string("Catmarc","1.2.840.10003.5.22");
    oid_add_from_string("Malmarc","1.2.840.10003.5.23");
    oid_add_from_string("JPmarc","1.2.840.10003.5.24");
    oid_add_from_string("SWEMarc","1.2.840.10003.5.25");
    oid_add_from_string("SIGLEmarc","1.2.840.10003.5.26");
    oid_add_from_string("ISDS/ISSNmarc","1.2.840.10003.5.27");
    oid_add_from_string("RUSMarc","1.2.840.10003.5.28");
    oid_add_from_string("Hunmarc","1.2.840.10003.5.29");
    oid_add_from_string("NACSIS-CATP","1.2.840.10003.5.30");
    oid_add_from_string("FINMARC2000","1.2.840.10003.5.31");
    oid_add_from_string("MARC21-fin","1.2.840.10003.5.32");
    oid_add_from_string("COMARC","1.2.840.10003.5.33");
    /* Non-MARC record syntaxes */
    oid_add_from_string("Explain","1.2.840.10003.5.100");
    oid_add_from_string("Explain with ZSQL","1.2.840.10003.5.100.1");
    oid_add_from_string("SUTRS","1.2.840.10003.5.101");
    oid_add_from_string("OPAC","1.2.840.10003.5.102");
    oid_add_from_string("Summary","1.2.840.10003.5.103");
    oid_add_from_string("GRS-0","1.2.840.10003.5.104");
    oid_add_from_string("GRS-1","1.2.840.10003.5.105");
    oid_add_from_string("ESTaskPackage","1.2.840.10003.5.106");
    oid_add_from_string("fragment","1.2.840.10003.5.108");
    /* Attribute sets */
    oid_add_from_string("bib-1",Z3950_ATSET_BIB1_OID);
    oid_add_from_string("exp-1","1.2.840.10003.3.2");
    oid_add_from_string("ext-1","1.2.840.10003.3.3");
    oid_add_from_string("ccl-1","1.2.840.10003.3.4");
    oid_add_from_string("gils","1.2.840.10003.3.5");
    oid_add_from_string("stas","1.2.840.10003.3.6");
    oid_add_from_string("collections-1","1.2.840.10003.3.7");
    oid_add_from_string("cimi-1","1.2.840.10003.3.8");
    oid_add_from_string("geo-1","1.2.840.10003.3.9");
    oid_add_from_string("ZBIG","1.2.840.10003.3.10");
    oid_add_from_string("util","1.2.840.10003.3.11");
    oid_add_from_string("xd-1","1.2.840.10003.3.12");
    oid_add_from_string("Zthes","1.2.840.10003.3.13");
    oid_add_from_string("Fin-1","1.2.840.10003.3.14");
    oid_add_from_string("Dan-1","1.2.840.10003.3.15");
    oid_add_from_string("Holdings","1.2.840.10003.3.16");
    oid_add_from_string("MARC","1.2.840.10003.3.17");
    oid_add_from_string("bib-2","1.2.840.10003.3.18");
    oid_add_from_string("ZeeRex","1.2.840.10003.3.19");
    /* Diagnostic sets */
    oid_add_from_string("bib-1-diagnostics",Z3950_DIAGSET_BIB1_OID);

}

/* MARC routines */

static int
dissect_marc_record(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
    proto_item *record_item, *leader_item,
               *directory_item,
               *fields_item,
               *item;
    proto_tree *marc_tree, *leader_tree,
               *directory_tree,
               *fields_tree;
    marc_directory_entry *marc_directory;
    guint len = tvb_reported_length(tvb);
    const guint8 *marc_value_str;
    guint record_length = 0,
          data_offset = 0,
          length_of_field_size,
          starting_character_position_size,
          directory_entry_len,
          directory_entry_count,
          dir_index,
          offset = 0;
    guint32 marc_value_char;

    record_item = proto_tree_add_item(tree, hf_marc_record,
                           tvb, 0, len, ENC_NA);
    marc_tree =  proto_item_add_subtree(record_item, ett_marc_record);
    if (len < MARC_LEADER_LENGTH) {
        expert_add_info_format(pinfo, record_item,
            &ei_marc_invalid_record_length,
            "MARC record length %d is shorter than leader", len);
    }
    leader_item = proto_tree_add_item(marc_tree, hf_marc_leader, tvb, 0,
                           MARC_LEADER_LENGTH, ENC_NA);
    leader_tree = proto_item_add_subtree(leader_item, ett_marc_leader);

    marc_value_str = NULL;
    item = proto_tree_add_item_ret_string(leader_tree,
                      hf_marc_leader_length, tvb, offset, 5, ENC_ASCII|ENC_NA,
                      wmem_packet_scope(),&marc_value_str);
    offset += 5;

    if (marc_value_str) {
        if (isdigit_string(marc_value_str)) {
            record_length = (guint)strtoul(marc_value_str, NULL, 10);
        }
        else {
            expert_add_info_format(pinfo, item,
                &ei_marc_invalid_value,
                "MARC length field '%s' contains invalid characters",
                marc_value_str );
        }
        if (record_length != len) {
            expert_add_info_format(pinfo, item,
                &ei_marc_invalid_length,
                "MARC length field value %d does not match reported length %d",
                record_length, len);
        }
    }

    proto_tree_add_item(leader_tree, hf_marc_leader_status, tvb, offset, 1, ENC_ASCII);
    offset += 1;
    proto_tree_add_item(leader_tree, hf_marc_leader_type, tvb, offset, 1, ENC_ASCII);
    offset += 1;
    proto_tree_add_item(leader_tree, hf_marc_leader_biblevel, tvb, offset, 1, ENC_ASCII);
    offset += 1;
    proto_tree_add_item(leader_tree, hf_marc_leader_control, tvb, offset, 1, ENC_ASCII);
    offset += 1;
    proto_tree_add_item(leader_tree, hf_marc_leader_encoding, tvb, offset, 1, ENC_ASCII);
    offset += 1;
    marc_value_char = MARC_CHAR_UNINITIALIZED;
    item = proto_tree_add_item_ret_uint(leader_tree, hf_marc_leader_indicator_count,
               tvb, offset, 1, ENC_ASCII, &marc_value_char);
    offset += 1;
    if (marc_value_char != MARC_CHAR_UNINITIALIZED) {
        if (!marc_isdigit(marc_value_char)) {
            expert_add_info_format(pinfo, item, &ei_marc_invalid_value,
                "Indicator count '%c' is invalid", marc_value_char);
        }
        else {
            if (marc_char_to_int(marc_value_char) != 2) {
                expert_add_info_format(pinfo, item, &ei_marc_invalid_length,
                    "MARC21 requires indicator count equal 2, not %d",
                    marc_char_to_int(marc_value_char));
            }
        }
    }

    marc_value_char = MARC_CHAR_UNINITIALIZED;
    item = proto_tree_add_item_ret_uint(leader_tree, hf_marc_leader_subfield_count,
            tvb, offset, 1, ENC_ASCII, &marc_value_char);
    offset += 1;
    if (marc_value_char != MARC_CHAR_UNINITIALIZED) {
        if (!marc_isdigit(marc_value_char)) {
            expert_add_info_format(pinfo, item, &ei_marc_invalid_value,
                "Subfield count '%c' is invalid", marc_value_char);
        }
        else {
            if (marc_char_to_int(marc_value_char) != 2) {
                expert_add_info_format(pinfo, item, &ei_marc_invalid_length,
                    "MARC21 requires subfield count equal 2, not %d",
                    marc_char_to_int(marc_value_char));
            }
        }
    }

    item = proto_tree_add_item_ret_string(leader_tree, hf_marc_leader_data_offset,
               tvb, offset, 5, ENC_ASCII|ENC_NA,
               wmem_packet_scope(),&marc_value_str);
    offset += 5;
    if (marc_value_str) {
        if (isdigit_string(marc_value_str)) {
            data_offset = (guint)strtoul(marc_value_str, NULL, 10);
        }
        else {
            expert_add_info_format(pinfo, item,
                &ei_marc_invalid_value,
                "MARC data offset field '%s' contains invalid characters",
                marc_value_str );
        }
        if (data_offset < MARC_LEADER_LENGTH ||
            data_offset > record_length) {
            expert_add_info_format(pinfo, item,
                &ei_marc_invalid_length,
                "MARC data offset %d does not lie within record (length %d)",
                data_offset, len);
        }
    }
    proto_tree_add_item(leader_tree, hf_marc_leader_encoding_level, tvb, offset, 1, ENC_ASCII);
    offset += 1;
    proto_tree_add_item(leader_tree, hf_marc_leader_descriptive_cataloging, tvb, offset, 1, ENC_ASCII);
    offset += 1;
    proto_tree_add_item(leader_tree, hf_marc_leader_multipart_level, tvb, offset, 1, ENC_ASCII);
    offset += 1;
    marc_value_char = MARC_CHAR_UNINITIALIZED;
    item = proto_tree_add_item_ret_uint(leader_tree, hf_marc_leader_length_of_field_length,
            tvb, offset, 1, ENC_ASCII, &marc_value_char);
    offset += 1;
    length_of_field_size = 4;
    if (marc_value_char != MARC_CHAR_UNINITIALIZED) {
        if (!marc_isdigit(marc_value_char)) {
            expert_add_info_format(pinfo, item, &ei_marc_invalid_value,
                "Length-of field-length '%c' is invalid", marc_value_char);
        }
        else {
            if (marc_char_to_int(marc_value_char) != 4) {
                expert_add_info_format(pinfo, item, &ei_marc_invalid_length,
                    "MARC21 requires length-of-field equal 4, not %d",
                    marc_char_to_int(marc_value_char));
            }
        }
    }

    marc_value_char = MARC_CHAR_UNINITIALIZED;
    item = proto_tree_add_item_ret_uint(leader_tree, hf_marc_leader_starting_character_position_length,
            tvb, offset, 1, ENC_ASCII, &marc_value_char);
    offset += 1;
    starting_character_position_size = 5;
    if (marc_value_char != MARC_CHAR_UNINITIALIZED) {
        if (!marc_isdigit(marc_value_char)) {
            expert_add_info_format(pinfo, item, &ei_marc_invalid_value,
                "Starting-character-position length '%c' is invalid", marc_value_char);
        }
        else {
            if (marc_char_to_int(marc_value_char) != 5) {
                expert_add_info_format(pinfo, item, &ei_marc_invalid_length,
                    "MARC21 requires starting-character-position equal 5, not %d",
                    marc_char_to_int(marc_value_char));
            }
        }
    }

    proto_tree_add_item(leader_tree, hf_marc_leader_implementation_defined_length, tvb, offset, 1, ENC_ASCII);
    offset += 1;

    /* One position is defined as unused-must-be-zero.
     * Don't bother displaying or checking it. */
    offset += 1;

    /* Process the directory */

    directory_entry_len = 3 + length_of_field_size
                            + starting_character_position_size;
    directory_entry_count = ((data_offset - 1) - MARC_LEADER_LENGTH) / directory_entry_len;

    marc_directory = (marc_directory_entry *)wmem_alloc0(wmem_packet_scope(),
                                 directory_entry_count * sizeof(marc_directory_entry));

    directory_item = proto_tree_add_item(marc_tree, hf_marc_directory,
                         tvb, offset, data_offset - offset, ENC_NA);
    directory_tree = proto_item_add_subtree(directory_item, ett_marc_directory);

    dir_index = 0;
    /* Minus one for the terminator character */
    while (offset < (data_offset - 1)) {
        guint32 tag_value = 0,
                length_value = 0,
                starting_char_value = 0;
        proto_item *length_item;
        proto_item *directory_entry_item;
        proto_tree *directory_entry_tree;

        directory_entry_item = proto_tree_add_item(directory_tree, hf_marc_directory_entry,
                                   tvb, offset, directory_entry_len, ENC_NA);
        directory_entry_tree = proto_item_add_subtree(directory_entry_item, ett_marc_directory_entry);

        marc_value_str = NULL;
        item = proto_tree_add_item_ret_string(directory_entry_tree, hf_marc_directory_entry_tag,
                   tvb, offset, 3, ENC_ASCII,
                   wmem_packet_scope(), &marc_value_str);
        offset += 3;
        if (marc_value_str) {
            if (isdigit_string(marc_value_str)) {
                tag_value = (guint)strtoul(marc_value_str, NULL, 10);
            }
            else {
                expert_add_info_format(pinfo, item,
                    &ei_marc_invalid_value,
                    "MARC directory tag value %d ('%s') contains invalid characters",
                    dir_index, marc_value_str );
            }
        }
        marc_value_str = NULL;
        length_item = proto_tree_add_item_ret_string(directory_entry_tree,
            hf_marc_directory_entry_length,
            tvb, offset, length_of_field_size, ENC_ASCII,
            wmem_packet_scope(), &marc_value_str);
        offset += length_of_field_size;
        if (marc_value_str) {
            if (isdigit_string(marc_value_str)) {
                length_value = (guint)strtoul(marc_value_str, NULL, 10);
            }
            else {
                expert_add_info_format(pinfo, length_item,
                    &ei_marc_invalid_value,
                    "MARC directory length value %d ('%s') contains invalid characters",
                    dir_index, marc_value_str );
            }
        }
        marc_value_str = NULL;
        item = proto_tree_add_item_ret_string(directory_entry_tree, hf_marc_directory_entry_starting_position,
            tvb, offset, starting_character_position_size, ENC_ASCII,
            wmem_packet_scope(), &marc_value_str);
        offset += starting_character_position_size;
        if (marc_value_str) {
            if (isdigit_string(marc_value_str)) {
                starting_char_value = (guint)strtoul(marc_value_str, NULL, 10);
            }
            else {
                expert_add_info_format(pinfo, item,
                    &ei_marc_invalid_value,
                    "MARC directory entry %d starting char value '%s' contains invalid characters",
                    dir_index, marc_value_str );
            }
        }

        if (starting_char_value >= (record_length - data_offset)) {
            expert_add_info_format(pinfo, item,
                &ei_marc_invalid_value,
                "MARC directory entry %d starting char value %d is outside record size %d",
                dir_index, starting_char_value, (record_length - data_offset));
        }
        if ((starting_char_value + length_value) >= (record_length - data_offset)) {
            expert_add_info_format(pinfo, length_item,
                &ei_marc_invalid_value,
                "MARC directory entry %d length value %d goes outside record size %d",
                dir_index, length_value, (record_length - data_offset));
        }
        marc_directory[dir_index].tag = tag_value;
        marc_directory[dir_index].length = length_value;
        marc_directory[dir_index].starting_character = starting_char_value;
        dir_index++;
    }
    proto_tree_add_item(directory_tree, hf_marc_directory_terminator,
        tvb, offset, 1, ENC_ASCII);
    offset += 1;

    fields_item = proto_tree_add_item(marc_tree, hf_marc_fields,
                         tvb, offset, record_length - offset, ENC_NA);
    fields_tree = proto_item_add_subtree(fields_item, ett_marc_fields);

    for (dir_index = 0; dir_index < directory_entry_count; dir_index++) {
        const gchar *tag_str;
        proto_item *field_item;
        proto_tree *field_tree;

        field_item = proto_tree_add_item(fields_tree, hf_marc_field,
                         tvb, offset, marc_directory[dir_index].length, ENC_NA);
        field_tree = proto_item_add_subtree(field_item, ett_marc_field);

        tag_str = try_val_to_str(marc_directory[dir_index].tag, marc_tag_names);
        if (tag_str) {
            proto_item_append_text(field_item," Tag %03d (%s)",
                marc_directory[dir_index].tag, tag_str);
        }
        else {
            proto_item_append_text(field_item," Tag %03d",
                marc_directory[dir_index].tag);
        }

        if (marc_directory[dir_index].tag < 10) {
            proto_tree_add_item(field_tree, hf_marc_field_control,
                    tvb, offset, marc_directory[dir_index].length - 1, ENC_ASCII|ENC_NA);
            offset += marc_directory[dir_index].length - 1;
            proto_tree_add_item(field_tree, hf_marc_field_terminator,
                    tvb, offset, 1, ENC_ASCII);
            offset += 1;
        }
        else {
            guint next_offset = offset + marc_directory[dir_index].length - 1;
            proto_tree_add_item(field_tree, hf_marc_field_indicator1,
                    tvb, offset, 1, ENC_ASCII);
            offset += 1;
            proto_tree_add_item(field_tree, hf_marc_field_indicator2,
                    tvb, offset, 1, ENC_ASCII);
            offset += 1;
            do {
                gint next_subfield;
                proto_tree_add_item(field_tree, hf_marc_field_subfield_indicator,
                        tvb, offset, 1, ENC_ASCII);
                offset += 1;
                proto_tree_add_item(field_tree, hf_marc_field_subfield_tag,
                        tvb, offset, 1, ENC_ASCII);
                offset += 1;
                next_subfield = tvb_find_guint8(tvb, offset, next_offset - offset,
                                                MARC_SUBFIELD_INDICATOR);
                if (next_subfield >= 0) {
                    proto_tree_add_item(field_tree, hf_marc_field_subfield,
                            tvb, offset, next_subfield - offset, ENC_ASCII|ENC_NA);
                    offset += (next_subfield - offset);
                }
                else {
                    proto_tree_add_item(field_tree, hf_marc_field_subfield,
                            tvb, offset, next_offset - offset, ENC_ASCII|ENC_NA);
                    offset = next_offset;
                }
            } while (offset < next_offset);
            proto_tree_add_item(field_tree, hf_marc_field_terminator,
                    tvb, offset, 1, ENC_ASCII);
            offset += 1;
        }

    }
    proto_tree_add_item(marc_tree, hf_marc_record_terminator,
            tvb, offset, 1, ENC_ASCII);
    offset += 1;

    if (offset != len) {
        expert_add_info_format(pinfo, record_item,
            &ei_marc_invalid_record_length,
            "MARC record component length %d does not match record length %d",
            offset, len);
    }

    return len;
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
