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
 * MARC21: https://www.loc.gov/marc/bibliographic/
 * Z39.50 Maintenance Agency: https://www.loc.gov/z3950/agency/
 * Z39.50 2003 standard: https://www.loc.gov/z3950/agency/Z39-50-2003.pdf
 * Z39.50 1995 ASN.1: https://www.loc.gov/z3950/agency/asn1.html
 * Registered Z39.50 Object Identifiers:
 *   https://www.loc.gov/z3950/agency/defns/oids.html
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
    int      atsetidx;
    int      attype;
} z3950_atinfo_t;

typedef struct z3950_diaginfo_t {
    int      diagsetidx;
    int      diagcondition;
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
    uint32_t tag;
    uint32_t length;
    uint32_t starting_character;
} marc_directory_entry;

static dissector_handle_t z3950_handle;

void proto_reg_handoff_z3950(void);
void proto_register_z3950(void);

/* Initialize the protocol and registered fields */
static int proto_z3950;
static int global_z3950_port = Z3950_PORT;
static bool z3950_desegment = true;

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
    { 1037, "Serial Item and Contribution Identifier (SICI)" },
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
    { 1111, "DC-RightsManagement" },
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
    { 1048, "ES: Cannot create task package -- exceeds maximum permissible size" },
    { 1049, "ES: Cannot return task package -- exceeds maximum permissible size" },
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
    { 1070, "User not authorized to receive record(s) in requested syntax" },
    { 1071, "preferredRecordSyntax not supplied" },
    { 1072, "Query term includes characters that do not translate into the target character set" },
    { 1073, "Database records do not contain data associated with access point" },
    { 1074, "Proxy failure" },
    { 0, NULL}
};

#include "packet-z3950-hf.c"

static int hf_z3950_referenceId_printable;
static int hf_z3950_general_printable;

/* Initialize the subtree pointers */
static int ett_z3950;

#include "packet-z3950-ett.c"

/* MARC variables and forwards */

static int dissect_marc_record(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_);

/* MARC fields */
static int hf_marc_record;
static int hf_marc_record_terminator;
static int hf_marc_leader;
static int hf_marc_leader_length;
static int hf_marc_leader_status;
static int hf_marc_leader_type;
static int hf_marc_leader_biblevel;
static int hf_marc_leader_control;
static int hf_marc_leader_encoding;
static int hf_marc_leader_indicator_count;
static int hf_marc_leader_subfield_count;
static int hf_marc_leader_data_offset;
static int hf_marc_leader_encoding_level;
static int hf_marc_leader_descriptive_cataloging;
static int hf_marc_leader_multipart_level;
static int hf_marc_leader_length_of_field_length;
static int hf_marc_leader_starting_character_position_length;
static int hf_marc_leader_implementation_defined_length;
static int hf_marc_directory;
static int hf_marc_directory_entry;
static int hf_marc_directory_entry_tag;
static int hf_marc_directory_entry_length;
static int hf_marc_directory_entry_starting_position;
static int hf_marc_directory_terminator;
static int hf_marc_fields;
static int hf_marc_field;
static int hf_marc_field_control;
static int hf_marc_field_terminator;
static int hf_marc_field_indicator1;
static int hf_marc_field_indicator2;
static int hf_marc_field_subfield_indicator;
static int hf_marc_field_subfield_tag;
static int hf_marc_field_subfield;

/* MARC subtree pointers */
static int ett_marc_record;
static int ett_marc_leader;
static int ett_marc_directory;
static int ett_marc_directory_entry;
static int ett_marc_fields;
static int ett_marc_field;

/* MARC expert fields */
static expert_field ei_marc_invalid_length;
static expert_field ei_marc_invalid_value;
static expert_field ei_marc_invalid_record_length;

/* MARC value strings */

static const value_string marc_tag_names[] = {
    { 1, "Control Number" },
    { 3, "Control Number Identifier" },
    { 5, "Date and Time of Latest Transaction" },
    { 6, "Fixed-length Data Elements - Additional Material Characteristics" },
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
    { 987, "Local LoC Conversation History" },
    { 991, "Local LoC Location Information" },
    { 992, "Local LoC Location Information" },
    { 0, NULL}
};

static int
dissect_z3950_printable_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    tvbuff_t *next_tvb = NULL;
    int hf_alternate = 0;
    unsigned old_offset = offset;

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

#include "packet-z3950-fn.c"

static int
dissect_z3950(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item      *z3950_item = NULL;
    proto_tree      *z3950_tree = NULL;
    int                     offset = 0;
    asn1_ctx_t asn1_ctx;
    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);


    /* make entry in the Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);

    /* create the z3950 protocol tree */
    z3950_item = proto_tree_add_item(tree, proto_z3950, tvb, 0, -1, ENC_NA);
    z3950_tree = proto_item_add_subtree(z3950_item, ett_z3950);

    return dissect_z3950_PDU(false, tvb, offset, &asn1_ctx, z3950_tree, -1);
}

static unsigned
get_z3950_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    unsigned plen;
    unsigned ber_offset;
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

    /* Min length of 8 assumes 3 for identifier and 5 for length. */
    tcp_dissect_pdus(tvb, pinfo, tree, z3950_desegment, 8, get_z3950_pdu_len, dissect_z3950, data);
    return tvb_captured_length(tvb);
}

/*--- proto_register_z3950 -------------------------------------------*/
void proto_register_z3950(void) {

    /* List of fields */
    static hf_register_info hf[] = {

#include "packet-z3950-hfarr.c"

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
    static int *ett[] = {
		  &ett_z3950,
/* MARC etts */
                  &ett_marc_record,
                  &ett_marc_leader,
                  &ett_marc_directory,
                  &ett_marc_directory_entry,
                  &ett_marc_fields,
                  &ett_marc_field,
#include "packet-z3950-ettarr.c"
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

#include "packet-z3950-dis-tab.c"

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
    unsigned len = tvb_reported_length(tvb);
    const uint8_t *marc_value_str;
    unsigned record_length = 0,
          data_offset = 0,
          length_of_field_size,
          starting_character_position_size,
          directory_entry_len,
          directory_entry_count,
          dir_index,
          offset = 0;
    uint32_t marc_value_char;

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
                      pinfo->pool,&marc_value_str);
    offset += 5;

    if (marc_value_str) {
        if (isdigit_string(marc_value_str)) {
            record_length = (unsigned)strtoul(marc_value_str, NULL, 10);
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
               pinfo->pool,&marc_value_str);
    offset += 5;
    if (marc_value_str) {
        if (isdigit_string(marc_value_str)) {
            data_offset = (unsigned)strtoul(marc_value_str, NULL, 10);
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

    marc_directory = (marc_directory_entry *)wmem_alloc0(pinfo->pool,
                                 directory_entry_count * sizeof(marc_directory_entry));

    directory_item = proto_tree_add_item(marc_tree, hf_marc_directory,
                         tvb, offset, data_offset - offset, ENC_NA);
    directory_tree = proto_item_add_subtree(directory_item, ett_marc_directory);

    dir_index = 0;
    /* Minus one for the terminator character */
    while (offset < (data_offset - 1)) {
        uint32_t tag_value = 0,
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
                   pinfo->pool, &marc_value_str);
        offset += 3;
        if (marc_value_str) {
            if (isdigit_string(marc_value_str)) {
                tag_value = (unsigned)strtoul(marc_value_str, NULL, 10);
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
            pinfo->pool, &marc_value_str);
        offset += length_of_field_size;
        if (marc_value_str) {
            if (isdigit_string(marc_value_str)) {
                length_value = (unsigned)strtoul(marc_value_str, NULL, 10);
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
            pinfo->pool, &marc_value_str);
        offset += starting_character_position_size;
        if (marc_value_str) {
            if (isdigit_string(marc_value_str)) {
                starting_char_value = (unsigned)strtoul(marc_value_str, NULL, 10);
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
        const char *tag_str;
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
                    tvb, offset, marc_directory[dir_index].length - 1, ENC_ASCII);
            offset += marc_directory[dir_index].length - 1;
            proto_tree_add_item(field_tree, hf_marc_field_terminator,
                    tvb, offset, 1, ENC_ASCII);
            offset += 1;
        }
        else {
            unsigned next_offset = offset + marc_directory[dir_index].length - 1;
            proto_tree_add_item(field_tree, hf_marc_field_indicator1,
                    tvb, offset, 1, ENC_ASCII);
            offset += 1;
            proto_tree_add_item(field_tree, hf_marc_field_indicator2,
                    tvb, offset, 1, ENC_ASCII);
            offset += 1;
            do {
                int next_subfield;
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
                            tvb, offset, next_subfield - offset, ENC_ASCII);
                    offset += (next_subfield - offset);
                }
                else {
                    proto_tree_add_item(field_tree, hf_marc_field_subfield,
                            tvb, offset, next_offset - offset, ENC_ASCII);
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
