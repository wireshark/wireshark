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
 * $Id: packet-ncp2222.inc,v 1.42 2002/10/16 23:24:21 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define NCP_PACKET_INIT_COUNT	200
#define PROTO_LENGTH_UNTIL_END -1

static const value_string nds_tags[] = {
        { 0x00000000, "No Such Entry" },
        { 0x00000001, "Local Entry" },
        { 0x00000002, "Remote Entry" },
        { 0x00000003, "Alias Entry" },
        { 0x00000004, "Referral Information" },
        { 0x00000006, "Entry and Referrals" },
	{ 0,	NULL }
};

static const value_string nds_info_type[] = {
        { 0x00000000, "Attribute Names Only / " },
        { 0x00000001, "Attribute Name & Value / " },
        { 0x00000002, "Effective Privileges / " },
        { 0x00000003, "Value Information / " },
        { 0x00000004, "Abbreviated Value / " },
	{ 0,	NULL }
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
	{ 0,	NULL }
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
	{ 0,	NULL }
};

static const value_string nds_protocol_type[] = {
        { 0x00000000, "(IPX Protocol)" },
        { 0x00000001, "(IP Protocol)" },
        { 0x00000002, "(SDLC Protocol)" },
        { 0x00000003, "(TokenRing on Ethernet Protocol)" },
        { 0x00000004, "(OSI Protocol)" },
        { 0x00000005, "(AppleTalk Protocol)" },
        { 0x00000006, "(NetBEUI Protocol)" },
        { 0x00000007, "(Socket Address Protocol)" },
        { 0x00000008, "(UDP Protocol)" },
        { 0x00000009, "(TCP Protocol)" },
        { 0x0000000a, "(UDP v6 Protocol)" },
        { 0x0000000b, "(TCP v6 Protocol)" },
        { 0x0000000c, "(Internal Protocol)" },
        { 0x0000000d, "(URL Protocol)" },
	{ 0,	NULL }
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
        { 0,	NULL }
};

static const value_string name_space_type[] = {
        { 0x00000000, "DOS Name Space" },
        { 0x00000001, "MAC Name Space" },
        { 0x00000002, "NFS Name Space" },
        { 0x00000003, "FTAM Name Space" },
        { 0x00000004, "OS/2, Long Name Space" },
        { 0,	NULL }
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
        { 0,	NULL }
};

static const value_string nds_replica_type[] = {
        { 0x0000, "Master" },
        { 0x0001, "Secondary" },
        { 0x0002, "Read Only" },
        { 0x0003, "Sub Ref" },
        { 0,	NULL }
};

static const value_string class_def_type[] = {
        { 0x0000, "Return Class Name" },
        { 0x0001, "Return Class Name, Flag, and Definition" },
        { 0x0002, "Return Class Name, Flag, Definition, and Super Class" },
        { 0x0003, "Return Class Name, Flag, and ASN.1 identifier" },
        { 0x0004, "Return Class Name, Flag, Definition, Super Class, and ACL" },
        { 0x0005, "Return Class Name, Flag, Creation Timestamp, Modification Timestamp, Definition, and ACL" },
        { 0,	NULL }
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
        { 0xfffffd0a, "(-758) Auxiliary Not Containere" },
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
        { 0xffff0000, "Ok" },
        { 0x0000, "Ok" },
	{ 0,	NULL }
};


static void
process_ptvc_record(ptvcursor_t *ptvc, const ptvc_record *rec,
		int *req_cond_results, gboolean really_decode,
		const ncp_record *ncp_rec);

/* NCP packets come in request/reply pairs. The request packets tell the type
 * of NCP request and give a sequence ID. The response, unfortunately, only
 * identifies itself via the sequence ID; you have to know what type of NCP
 * request the request packet contained in order to successfully parse the NCP
 * response. A global method for doing this does not exist in ethereal yet
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
	conversation_t	*conversation;
	guint8		nw_sequence;
} ncp_req_hash_key;


typedef struct {
	guint32		nw_eid;
} ncp_req_eid_hash_key;

typedef struct {
        const ncp_record	*ncp_rec;
        gboolean		*req_cond_results;
        guint32			req_frame_num;
        guint32                 req_nds_flags;
        guint8                  nds_request_verb;
        guint8                  nds_version;
        char *                  object_name;
} ncp_req_hash_value;

typedef struct {
        char   		        object_name[256];
        char                    *object_class;
} ncp_req_eid_hash_value;

static GHashTable *ncp_req_hash = NULL;
static GHashTable *ncp_req_eid_hash = NULL;
static GMemChunk *ncp_req_eid_hash_keys = NULL;
static GMemChunk *ncp_req_eid_hash_values = NULL;
static GMemChunk *ncp_req_hash_keys = NULL;
static GMemChunk *ncp_req_hash_values = NULL;

/* Hash Functions */
gint
ncp_equal(gconstpointer v, gconstpointer v2)
{
	ncp_req_hash_key	*val1 = (ncp_req_hash_key*)v;
	ncp_req_hash_key	*val2 = (ncp_req_hash_key*)v2;

	if (val1->conversation == val2->conversation &&
	    val1->nw_sequence  == val2->nw_sequence ) {
		return 1;
	}
	return 0;
}

gint
ncp_eid_equal(gconstpointer v, gconstpointer v2)
{
	ncp_req_eid_hash_key	*val1 = (ncp_req_eid_hash_key*)v;
	ncp_req_eid_hash_key	*val2 = (ncp_req_eid_hash_key*)v2;

        if (val1->nw_eid == val2->nw_eid ) {
		return 1;
	}
	return 0;
}

guint
ncp_hash(gconstpointer v)
{
	ncp_req_hash_key	*ncp_key = (ncp_req_hash_key*)v;
	return GPOINTER_TO_UINT(ncp_key->conversation) + ncp_key->nw_sequence;
}

guint
ncp_eid_hash(gconstpointer v)
{
	ncp_req_eid_hash_key	*ncp_eid_key = (ncp_req_eid_hash_key*)v;
	return GPOINTER_TO_UINT(ncp_eid_key->nw_eid);
}

/* Frees memory used by the ncp_req_hash_value's */
static void
ncp_req_hash_cleanup(gpointer key _U_, gpointer value, gpointer user_data _U_)
{
	ncp_req_hash_value	*request_value = (ncp_req_hash_value*) value;

	if (request_value->req_cond_results) {
		g_free(request_value->req_cond_results);
	}
}

/* Frees memory used by the ncp_req_hash_value's */
static void
ncp_req_eid_hash_cleanup(gpointer key _U_, gpointer value, gpointer user_data _U_)
{
	ncp_req_eid_hash_value	*request_eid_value = (ncp_req_eid_hash_value*) value;

	if (request_eid_value->object_class) {
		g_free(request_eid_value->object_name);
	}
}

/* Initializes the hash table and the mem_chunk area each time a new
 * file is loaded or re-loaded in ethereal */
static void
ncp_init_protocol(void)
{
	if (ncp_req_hash) {
		g_hash_table_foreach(ncp_req_hash, ncp_req_hash_cleanup, NULL);
		g_hash_table_destroy(ncp_req_hash);
	}
	if (ncp_req_eid_hash) {
		g_hash_table_foreach(ncp_req_eid_hash, ncp_req_eid_hash_cleanup, NULL);
		g_hash_table_destroy(ncp_req_eid_hash);
	}
	if (ncp_req_hash_keys)
		g_mem_chunk_destroy(ncp_req_hash_keys);
	if (ncp_req_hash_values)
		g_mem_chunk_destroy(ncp_req_hash_values);
	if (ncp_req_eid_hash_keys)
		g_mem_chunk_destroy(ncp_req_eid_hash_keys);
	if (ncp_req_eid_hash_values)
		g_mem_chunk_destroy(ncp_req_eid_hash_values);

	ncp_req_hash = g_hash_table_new(ncp_hash, ncp_equal);
	ncp_req_eid_hash = g_hash_table_new(ncp_eid_hash, ncp_eid_equal);
	ncp_req_hash_keys = g_mem_chunk_new("ncp_req_hash_keys",
			sizeof(ncp_req_hash_key),
			NCP_PACKET_INIT_COUNT * sizeof(ncp_req_hash_key),
			G_ALLOC_ONLY);
	ncp_req_hash_values = g_mem_chunk_new("ncp_req_hash_values",
			sizeof(ncp_req_hash_value),
			NCP_PACKET_INIT_COUNT * sizeof(ncp_req_hash_value),
			G_ALLOC_ONLY);
	ncp_req_eid_hash_keys = g_mem_chunk_new("ncp_req_eid_hash_keys",
			sizeof(ncp_req_eid_hash_key),
			NCP_PACKET_INIT_COUNT * sizeof(ncp_req_eid_hash_key),
			G_ALLOC_ONLY);
	ncp_req_eid_hash_values = g_mem_chunk_new("ncp_req_eid_hash_values",
			sizeof(ncp_req_eid_hash_value),
			NCP_PACKET_INIT_COUNT * sizeof(ncp_req_eid_hash_value),
			G_ALLOC_ONLY);
}

/* After the sequential run, we don't need the ncp_request hash and keys
 * anymore; the lookups have already been done and the vital info
 * saved in the reply-packets' private_data in the frame_data struct. */
static void
ncp_postseq_cleanup(void)
{
	if (ncp_req_hash) {
		/* Destroy the hash, but don't clean up request_condition data. */
		g_hash_table_destroy(ncp_req_hash);
		ncp_req_hash = NULL;
	}
	if (ncp_req_hash_keys) {
		g_mem_chunk_destroy(ncp_req_hash_keys);
		ncp_req_hash_keys = NULL;
	}
	/* Don't free the ncp_req_hash_values, as they're
	 * needed during random-access processing of the proto_tree.*/
	if (ncp_req_eid_hash) {
		/* Destroy the hash, but don't clean up request_condition data. */
		g_hash_table_destroy(ncp_req_eid_hash);
		ncp_req_eid_hash = NULL;
	}
	if (ncp_req_eid_hash_keys) {
		g_mem_chunk_destroy(ncp_req_eid_hash_keys);
		ncp_req_eid_hash_keys = NULL;
	}
}

ncp_req_hash_value*
ncp_hash_insert(conversation_t *conversation, guint8 nw_sequence,
		const ncp_record *ncp_rec)
{
	ncp_req_hash_key		*request_key;
	ncp_req_hash_value		*request_value;

	/* Now remember the request, so we can find it if we later
	   a reply to it. */
	request_key = g_mem_chunk_alloc(ncp_req_hash_keys);
	request_key->conversation = conversation;
	request_key->nw_sequence = nw_sequence;

	request_value = g_mem_chunk_alloc(ncp_req_hash_values);
	request_value->ncp_rec = ncp_rec;
	request_value->req_cond_results = NULL;
        request_value->req_nds_flags = 0;
	request_value->nds_request_verb = 0;
	request_value->nds_version = 0;
	request_value->object_name = NULL;
        
        g_hash_table_insert(ncp_req_hash, request_key, request_value);

	return request_value;
}

ncp_req_eid_hash_value*
ncp_eid_hash_insert(guint32 nw_eid)
{
	ncp_req_eid_hash_key		*request_eid_key;
	ncp_req_eid_hash_value		*request_eid_value;

	/* Now remember the request, so we can find it if we later
	   a reply to it. */
	request_eid_key = g_mem_chunk_alloc(ncp_req_eid_hash_keys);
        request_eid_key->nw_eid = nw_eid;

	request_eid_value = g_mem_chunk_alloc(ncp_req_eid_hash_values);
	strcpy(request_eid_value->object_name, " ");
        request_eid_value->object_class = NULL;
        
        g_hash_table_insert(ncp_req_eid_hash, request_eid_key, request_eid_value);

	return request_eid_value;
}

/* Returns the ncp_rec*, or NULL if not found. */
ncp_req_hash_value*
ncp_hash_lookup(conversation_t *conversation, guint8 nw_sequence)
{
	ncp_req_hash_key		request_key;

	request_key.conversation = conversation;
	request_key.nw_sequence = nw_sequence;

	return g_hash_table_lookup(ncp_req_hash, &request_key);
}

/* Returns the value_rec* for needed EID, or NULL if not found. */
ncp_req_eid_hash_value*
ncp_eid_hash_lookup(conversation_t *conversation _U_, guint32 nw_eid)
{
	ncp_req_eid_hash_key		request_eid_key;

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
guint
get_item_value(proto_item *item)
{
	return fvalue_get_integer(PITEM_FINFO(item)->value);
}


char *
get_item_string(proto_item *item)
{
	return fvalue_get(PITEM_FINFO(item)->value);
}

char *
get_item_name(proto_item *item)
{
	return PITEM_FINFO(item)->hfinfo->name;
}


typedef proto_item* (*padd_func_t)(ptvcursor_t*, const ptvc_record*);

/*
 * XXX - are these just DOS-format dates and times?
 *
 * Should we put code to understand various date and time formats (UNIX,
 * DOS, SMB weird mutant UNIX, NT, Mac, etc. into libethereal, and have
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
	guint	year;
	guint	month;
	guint	day;
} nw_date_t;

typedef struct {
	guint	hour;
	guint	minute;
	guint	second;
} nw_time_t;

typedef struct {
	char *  buffer;
} nw_uni_t;

#define VTYPE_NONE		0	/* no value */
#define VTYPE_UINT8		1
#define VTYPE_UINT16		2
#define VTYPE_UINT32		3
#define VTYPE_STRING		4
#define VTYPE_BITFIELD		5
#define VTYPE_MULTIVALUE_UINT32	6
#define VTYPE_BYTES		7
#define VTYPE_BOOLEAN		8

#define MVTYPE_ATTR_REQUEST		1
#define MVTYPE_ATTR_REPLY		2
#define MVTYPE_ATTR_REQUEST2		3	/* XXX - how does this differ from 1? */
#define MVTYPE_READ_CLASS_REQ		4
#define MVTYPE_READ_REPLICAS		5
#define MVTYPE_MODIFY_ATTR_REQUEST	6
#define MVTYPE_ADDR_REFERRAL_REQUEST	7
#define MVTYPE_ADDR_REFERRAL_REPLY	8
#define MVTYPE_LOC_ADDR_REFERRAL_REPLY	9
#define MVTYPE_PROC_ENTRY_SPECIFIERS	10
#define MVTYPE_PRINT_TIMESTAMP		11
#define MVTYPE_LIST_PARTITIONS		12
#define MVTYPE_CLASS_NAMES		13
#define MVTYPE_MODIFY_CLASS		14

typedef struct {
        guint8          vtype;
        guint32         vvalue;
        char*           vstring;
        char*           vdesc;
        guint32         vlength;
        guint32         voffset;
        guint32         hfname;
        char*           bit1;
        guint32         bit1hfname;
        char*           bit2;
        guint32         bit2hfname;
        char*           bit3;
        guint32         bit3hfname;
        char*           bit4;
        guint32         bit4hfname;
        char*           bit5;
        guint32         bit5hfname;
        char*           bit6;
        guint32         bit6hfname;
        char*           bit7;
        guint32         bit7hfname;
        char*           bit8;
        guint32         bit8hfname;
        char*           bit9;
        guint32         bit9hfname;
        char*           bit10;
        guint32         bit10hfname;
        char*           bit11;
        guint32         bit11hfname;
        char*           bit12;
        guint32         bit12hfname;
        char*           bit13;
        guint32         bit13hfname;
        char*           bit14;
        guint32         bit14hfname;
        char*           bit15;
        guint32         bit15hfname;
        char*           bit16;
        guint32         bit16hfname;
        guint8          mvtype;
        guint32         vflags;
        guint32         nds_version;
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
	nwtime->minute = ((data & 0x07e0) >> 5) + 1;
	nwtime->hour   = ((data & 0xf800) >> 11) + 1;
}

char *
unicode_to_string(char * data, guint32 length)
{
        guint32 i;
	guint16 character;
        int     offset = 0;
        char *  buffer = "";
        
        if (data[1] == 0x00){

        	for (i = 0; i < length; i++) {
        		character = data[offset];
        		buffer[i] = character & 0xff;
        		offset += 2;
                }
        }
        else
        {        
                buffer = data;
        }        
        return buffer;
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
	proto_item	*item;
	nw_date_t	nw_date;
	gint		offset;

	offset = ptvcursor_current_offset(ptvc);

	item = ptvcursor_add(ptvc, *rec->hf_ptr,
		rec->length, rec->endianness);

	uint_to_nwdate(get_item_value(item), &nw_date);
	
	proto_item_set_text(item, get_item_name(item)); 
	proto_item_append_text(item, ": %04u/%02u/%02u",
			nw_date.year, nw_date.month, nw_date.day);
	return item;
}

static proto_item*
padd_time(ptvcursor_t *ptvc, const ptvc_record *rec)
{
	proto_item	*item;
	nw_time_t	nw_time;
	gint		offset;

	offset = ptvcursor_current_offset(ptvc);

	item = ptvcursor_add(ptvc, *rec->hf_ptr,
		rec->length, rec->endianness);

	uint_to_nwtime(get_item_value(item), &nw_time);
	
	proto_item_set_text(item, get_item_name(item)); 
	proto_item_append_text(item, ": %02u:%02u:%02u",
			nw_time.hour, nw_time.minute, nw_time.second);
	return item;
}


/* Convert a string from little-endian unicode to ascii.  At the moment we
   fake it by taking every odd byte.  )-:  The caller must free the
   result returned. */
static proto_item*
padd_uni(ptvcursor_t *ptvc, const ptvc_record *rec)
{
	proto_item      *item;
        nw_uni_t        nw_uni;
        guint            offset;
        
	nw_uni.buffer = "\0";
        offset = ptvcursor_current_offset(ptvc);

	item = ptvcursor_add(ptvc, *rec->hf_ptr,
		rec->length, rec->endianness);

        proto_item_set_text(item, get_item_name(item)); 
	proto_item_append_text(item, " %s",
			nw_uni.buffer);
                                
	return item;
} 

/* Add a value for a ptvc_record, and process the sub-ptvc_record
 * that it points to. */
static void
process_bitfield_sub_ptvc_record(ptvcursor_t *ptvc, const ptvc_record *rec,
		gboolean really_decode)
{
	proto_item		*item;
	proto_tree		*sub_tree;
	const ptvc_record	*sub_rec;
	int			current_offset;
	gint			ett;
	ptvcursor_t		*sub_ptvc;

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
			g_assert(!sub_rec->sub_ptvc_rec);
			ptvcursor_add_no_advance(sub_ptvc, *sub_rec->hf_ptr,
					sub_rec->length, sub_rec->endianness);
			sub_rec++;
		}

		/* Free it. */
		ptvcursor_free(sub_ptvc);
	}
	else {
		ptvcursor_advance(ptvc, rec->length);
	}
}

/* Process a sub-ptvc_record that points to a "struct" ptvc_record. */
static void
process_struct_sub_ptvc_record(ptvcursor_t *ptvc, const ptvc_record *rec,
		int *req_cond_results, gboolean really_decode,
		const ncp_record *ncp_rec)
{
	const ptvc_record	*sub_rec;
	gint			ett;
	proto_tree		*old_tree=NULL, *new_tree;
	proto_item		*item=NULL;
	gint			offset=0;

	/* Create a sub-proto_tree? */
	if (rec->sub_ptvc_rec->descr) {
		ett = *rec->sub_ptvc_rec->ett;
		old_tree = ptvcursor_tree(ptvc);
		offset = ptvcursor_current_offset(ptvc);
		item = proto_tree_add_text(old_tree, ptvcursor_tvbuff(ptvc),
				offset, PROTO_LENGTH_UNTIL_END,
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
		proto_item_set_len(item, ptvcursor_current_offset(ptvc) - offset);
		ptvcursor_set_tree(ptvc, old_tree);
	}
}

/* Run through the table of ptvc_record's and add info to the tree. This
 * is the work-horse of process_ptvc_record(). */
static void
_process_ptvc_record(ptvcursor_t *ptvc, const ptvc_record *rec,
		int *req_cond_results, gboolean really_decode,
		const ncp_record *ncp_rec)
{
	proto_item	*item;
	guint		i, repeat_count;
	padd_func_t	func = NULL;

	if (rec->sub_ptvc_rec) {
		/* Repeat this? */
		if (rec->repeat_index == NO_REPEAT) {
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
						g_assert_not_reached();
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
				g_assert(rec->var_index == NO_VAR);
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
						g_assert_not_reached();
				}
				for (i = 0; i < repeat_count; i++ ) {
					func(ptvc, rec);
				}
			}
			else {
				for (i = 0; i < repeat_count; i++ ) {
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
		int *req_cond_results, gboolean really_decode,
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
	{ 0x01, 0x00, NO_SUBFUNC, "Create Connection Service", NCP_GROUP_CONNECTION,
		NULL, NULL, ncp_0x2_errors, NULL, NO_REQ_COND_SIZE, NULL };

static const ncp_record ncp5555_request =
	{ 0x01, 0x00, NO_SUBFUNC, "Destroy Connection Service", NCP_GROUP_CONNECTION,
		NULL, NULL, ncp_0x2_errors, NULL, NO_REQ_COND_SIZE, NULL };

static const ncp_record ncpbbbb_request =
	{ 0x01, 0x00, NO_SUBFUNC, "Server Broadcast Message", NCP_GROUP_CONNECTION,
		NULL, NULL, ncp_0x2_errors, NULL, NO_REQ_COND_SIZE, NULL };                

static const ncp_record ncplip_echo =
	{ 0x01, 0x00, NO_SUBFUNC, "LIP Echo Packet", NCP_GROUP_CONNECTION,
		NULL, NULL, ncp_0x2_errors, NULL, NO_REQ_COND_SIZE, NULL };

/* Wrapper around proto_tree_free() */
void free_proto_tree(void *tree)
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
       
/*
 * XXX - this routine assumes that "dest_buf" points to a buffer large
 * enough for the string we'll be generating; unfortunately, it usually
 * points to a null constant string, which is unlikely to be large
 * enough for any characters whatsoever (so that this routine will
 * overwrite some arbitrary stuff in memory), and may even be in
 * a read-only portion of the address space (so that this routine
 * will crash).
 *
 * We "#if 0" it out for now, to eliminate crashes.
 */
static void
get_string(tvbuff_t* tvb, guint offset, guint str_length, char *dest_buf)
{
#if 0
        guint32 i;
        guint16 c_char;
        guint32 length_remaining = 0;
        
        length_remaining = tvb_length_remaining(tvb, offset);
        if(str_length > length_remaining)
        {
                strcpy(dest_buf, "String too long to process");
                return;
        }        
        for ( i = 0; i < str_length; i++ )
        {
                c_char = tvb_get_guint8(tvb, offset );
                if (c_char<0x20 || c_char>0x7e)
                {
                        if (c_char != 0x00)
                        { 
                        c_char = 0x2e;
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
                        return;
                }        
        }
dest_buf[i] = '\0';
return;
#endif
}

/*************************************
* Return based on % format in request
* %d = integer in decimal format = 0
* %x = integer in hex format = 1
* %s = string = 2
**************************************/  
int
get_info_type(gchar* check_string)
{
        guint length;
        guint i;
        char char_val;
        
        length =  strlen(check_string);
        
        for (i = 0 ; i < length-1 ; i++ ) {
                char_val = check_string[i+1];
                if (check_string[i] == 0x25 && check_string[i+1] == 0x64) {
                        return 0;
                } 
                if ( check_string[i] == 0x25 && check_string[i+1] == 0x78) {
                        return 1;
                }
        }
        return 2;
}                

static void
process_bitfield(proto_tree *ncp_tree, tvbuff_t *tvb, nds_val *values)
{
        char                    flags_str[512];
        char *                  sep = NULL;
	proto_item		*tinew;
	proto_tree		*flags_tree;
        guint32                 i;
        guint32                 bvalue = 0;

        bvalue = 0x00000001;
        strcpy(flags_str, "");
        sep = "";
        for (i = 0 ; i < (values->vlength*8); i++ ) {
                if (values->vvalue & bvalue) 
                {
                        strcat(flags_str, sep);
                        switch(bvalue){
                                case 0x00000001:
                                        strcat(flags_str, values->bit1);
                                        break;
                                case 0x00000002:        
                                        strcat(flags_str, values->bit2);
                                        break;
                                case 0x00000004:        
                                        strcat(flags_str, values->bit3);
                                        break;
                                case 0x00000008:        
                                        strcat(flags_str, values->bit4);
                                        break;
                                case 0x00000010:        
                                        strcat(flags_str, values->bit5);
                                        break;
                                case 0x00000020:        
                                        strcat(flags_str, values->bit6);
                                        break;
                                case 0x00000040:        
                                        strcat(flags_str, values->bit7);
                                        break;
                                case 0x00000080:        
                                        strcat(flags_str, values->bit8);
                                        break;
                                case 0x00000100:        
                                        strcat(flags_str, values->bit9);
                                        break;
                                case 0x00000200:        
                                        strcat(flags_str, values->bit10);
                                        break;
                                case 0x00000400:        
                                        strcat(flags_str, values->bit11);
                                        break;
                                case 0x00000800:        
                                        strcat(flags_str, values->bit12);
                                        break;
                                case 0x00001000:        
                                        strcat(flags_str, values->bit13);
                                        break;
                                case 0x00002000:        
                                        strcat(flags_str, values->bit14);
                                        break;
                                case 0x00004000:        
                                        strcat(flags_str, values->bit15);
                                        break;
                                case 0x00008000:        
                                        strcat(flags_str, values->bit16);
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
                                case 0x0000008:
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


static void
print_nds_values(proto_tree *vtree, tvbuff_t *tvb, guint32 syntax_type, nds_val *vvalues)
{
        guint32         value1 = 0;
        guint32         value2 = 0;
        guint32         value3 = 0;
        guint32         value4 = 0;
        guint32         value5 = 0;
        guint32         value6 = 0;
        guint32         voffset = 0;
        guint32         icounter;
        guint32         number_of_values = 0;
        guint32         number_of_items = 0;
        guint32         r;
        proto_item      *vitem;
        proto_tree      *nvtree;
        proto_item      *aditem;
        proto_tree      *adtree;
        char            *valuestr = NULL;
        guint16         rtype = 0;
        guint16         rstate = 0;
        guint16         rnum = 0;
        guint16         revent = 0;

        voffset = vvalues->voffset;
        if(tvb_get_guint8(tvb, voffset) == 0x00)
        {
                voffset = voffset+2;
        }                
        
        number_of_values = tvb_get_letohl(tvb, voffset);
        
        vitem = proto_tree_add_uint_format(vtree, hf_nds_uint32value, tvb, voffset,
                4, number_of_values, "Number of Values: %u", number_of_values);
        
        nvtree = proto_item_add_subtree(vitem, ett_nds);
        
        voffset = voffset + 4; 
        
        for (icounter = 1 ; icounter <= number_of_values; icounter++ )
        {                      
                switch(syntax_type)
                {       
                       case 0x00000006:        /* Case Insensitive List */
                       case 0x0000000d:        /* Binary String List */
                       case 0x00000012:        /* Postal Address */
                               voffset += align_4(tvb, voffset);
                               voffset = voffset+4;         
                               number_of_items = tvb_get_letohl(tvb, voffset);
                               voffset = voffset+4;
                               for (r=1; r<=number_of_items; r++)
                               {
                                       value1 = tvb_get_letohl(tvb, voffset);
                                       voffset = voffset + 4;
                                       get_string(tvb, voffset, value1, vvalues->vstring);
                                       proto_tree_add_string(nvtree, hf_value_string, tvb, voffset, 
                                           value1, vvalues->vstring);
                                       voffset = voffset + value1;    
                               }            
                               voffset += align_4(tvb, voffset);
                               break;
                       case 0x00000007:        /* Boolean */
                               value1 = tvb_get_letohl(tvb, voffset); /* length of field */
                               if (value1==0)
                               {
                               vvalues->vstring = "False";
                               }
                               else
                               {
                               vvalues->vstring = "True";
                               }
                               proto_tree_add_string(nvtree, hf_value_string, tvb, voffset, 
                                           value1, vvalues->vstring);
                               voffset=voffset+8;
                               break;
                       case 0x00000009:        /* Binary String */
                       case 0x00000015:        /* Stream */
                               value1 = tvb_get_letohl(tvb, voffset); /* length of field */
                               if(value1 > tvb_length_remaining(tvb, voffset))
                               {
                                        break;
                               }
                               voffset += 4;
                               proto_tree_add_bytes(nvtree, hf_value_bytes, tvb, voffset, value1, tvb_get_ptr(tvb, voffset, value1));
                               voffset += value1;
                               voffset += (value1%2);
                               break;
                       case 0x00000008:        /* Signed Integer */
                       case 0x00000016:        /* Counter */
                       case 0x00000018:        /* Time */
                       case 0x0000001b:        /* Interval */
                               value1 = tvb_get_letohl(tvb, voffset); /* length of field */
                               voffset = voffset+4;
                               value2 = tvb_get_letohl(tvb, voffset); /* Value */
                               proto_tree_add_uint_format(nvtree, hf_nds_uint32value, tvb, voffset,
                                        value1, value2, "Value %d", value2);
                               voffset = voffset+4;
                               break;
                       case 0x0000000b:        /* Fax Number */
                               value1 = tvb_get_letohl(tvb, voffset); /* length of field */
                               voffset = voffset+4;
                               get_string(tvb, voffset, value1, vvalues->vstring);
                               proto_tree_add_string(nvtree, hf_value_string, tvb, voffset, 
                                        value1, vvalues->vstring);
                               voffset = voffset + value1;
                               voffset += align_4(tvb, voffset);
                               value2 = tvb_get_letohl(tvb, voffset); /* Bit Count */
                               voffset=voffset+4;
                               value3 = tvb_get_letohl(tvb, voffset); /* Bit length */
                               voffset = voffset+4;
                               get_string(tvb, voffset, value3, vvalues->vstring);
                               proto_tree_add_string(nvtree, hf_value_string, tvb, voffset, 
                                        value3, vvalues->vstring);
                               voffset = voffset+value3;         
                               voffset += align_4(tvb, voffset);
                               break;
                       case 0x0000000c:        /* Network Address */
                               value1 = tvb_get_letohl(tvb, voffset); /* length of field */
                               voffset = voffset + 4;
                               value2 = tvb_get_letohl(tvb, voffset); /* type of Protocol */
                               valuestr = match_strval(value2, nds_protocol_type);
                               if (valuestr == NULL)
                               { 
                                               valuestr="(Undefined Protocol)";
                               }
                               proto_tree_add_uint_format(nvtree, hf_nds_uint32value, tvb, voffset,
                                   value1, value2, valuestr, value2);
                               voffset = voffset+4;
                               value3 = tvb_get_letohl(tvb, voffset); /* length of address */
                               voffset = voffset+4;
                               switch (value2)
                               { 
                                        case 0x00000000:
                                                proto_tree_add_item(nvtree, hf_nds_net, tvb, voffset, 4, FALSE);
		                                proto_tree_add_item(nvtree, hf_nds_node, tvb, voffset+4, 6, FALSE);
		                                proto_tree_add_item(nvtree, hf_nds_socket, tvb, voffset+10, 2, FALSE);
                                                break;
	        	                        /*proto_tree_add_item(nvtree, hf_nds_port, tvb, voffset, 2, FALSE);
                                                value4 = tvb_get_letohl(tvb, voffset+2);
	                                        proto_tree_add_ipv4(nvtree, hf_add_ref_ip, tvb, voffset+2, 4, value4);
                                                break;*/
                                        case 0x00000008:
	        	                        proto_tree_add_item(nvtree, hf_nds_port, tvb, voffset, 2, FALSE);
                                                value4 = tvb_get_letohl(tvb, voffset+2);
	                                        proto_tree_add_ipv4(nvtree, hf_add_ref_udp, tvb, voffset+2, 4, value4);
                                                break;
                                        case 0x00000009:
		                                proto_tree_add_item(nvtree, hf_nds_port, tvb, voffset, 2, FALSE);
                                                value4 = tvb_get_letohl(tvb, voffset+2);
                                                proto_tree_add_ipv4(nvtree, hf_add_ref_tcp, tvb, voffset+2, 4, value4);
                                                break;
                                        case 0x00000001:
                                        case 0x0000000d:
                                                get_string(tvb, voffset, value3, vvalues->vstring);
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
                               valuestr = match_strval(value2, name_space_type);
                               if (valuestr == NULL)
                               {
                                        valuestr = "Unknown Name Space";
                               }
                               proto_tree_add_string(nvtree, hf_value_string, tvb, voffset, 
                                        4, valuestr);
                               voffset = voffset+4;
                               value3 = tvb_get_letohl(tvb, voffset); /* Length of Volume name */
                               voffset = voffset+4;
                               get_string(tvb, voffset, value3, vvalues->vstring);
                               proto_tree_add_string(nvtree, hf_value_string, tvb, voffset, 
                                        value3, vvalues->vstring);
                               voffset = voffset+value3;
                               voffset += align_4(tvb, voffset);
                               value4 = tvb_get_letohl(tvb, voffset); /* Length of Path name */
                               voffset = voffset+4;
                               get_string(tvb, voffset, value4, vvalues->vstring);
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
                               get_string(tvb, voffset, value2, vvalues->vstring);
                               proto_tree_add_string(nvtree, hf_value_string, tvb, voffset, 
                                        value2, vvalues->vstring);
                               voffset = voffset+value2;
                               voffset += align_4(tvb, voffset);
                               rtype = tvb_get_letohs(tvb, voffset); /* replica type */
                               valuestr = match_strval(rtype, nds_replica_type);
                               if (valuestr == NULL)
                               { 
                                        valuestr="(Unknown Replica Type)";
                               }
                               proto_tree_add_string(nvtree, hf_replica_type, tvb, voffset,
                                        2, valuestr);
                               voffset = voffset+2; 
                               rstate = tvb_get_letohs(tvb, voffset); /* replica state */
                               valuestr = match_strval(rstate, nds_replica_state);
                               if (valuestr == NULL)
                               { 
                                        valuestr="(Unknown Replica State)";
                               }
                               proto_tree_add_string(nvtree, hf_replica_state, tvb, voffset,
                                        2, valuestr);
                               voffset = voffset+2;
                               value3 = tvb_get_letohl(tvb, voffset); /* Replica number */
                               proto_tree_add_uint_format(nvtree, hf_replica_number, tvb, voffset, 
                                        4, value3, "Replica Number %d", value3);
                               voffset = voffset+4;
                               if(vvalues->nds_version == 0xfe)
                               {
                                        voffset += 4;
                               }
                               number_of_items = tvb_get_letohl(tvb, voffset);  /* Number of Addresses */
                               aditem = proto_tree_add_uint_format(vtree, hf_nds_uint32value, tvb, voffset,
                                        4, number_of_items, "Number of Addresses: %u", number_of_items);
        
                               adtree = proto_item_add_subtree(aditem, ett_nds);
                               voffset = voffset+4;
                               for (r=1; r <= number_of_items; r++)
                               {
                                        voffset += align_4(tvb, voffset);
                                        value4 = tvb_get_letohl(tvb, voffset); /* type of Protocol */
                                        valuestr = match_strval(value4, nds_protocol_type);
                                        if (valuestr == NULL)
                                        { 
                                               valuestr="(Undefined Protocol)";
                                        }
                                        proto_tree_add_uint_format(adtree, hf_nds_uint32value, tvb, voffset,
                                                4, value4, valuestr, value4);
                                        voffset = voffset+4;
                                        value5 = tvb_get_letohl(tvb, voffset); /* length of address */
                                        voffset = voffset+4;
                                        switch (value4)
                                        { 
                                                case 0x00000000:
                                                        proto_tree_add_item(adtree, hf_nds_net, tvb, voffset, 4, FALSE);
		                                        proto_tree_add_item(adtree, hf_nds_node, tvb, voffset+4, 6, FALSE);
		                                        proto_tree_add_item(adtree, hf_nds_socket, tvb, voffset+10, 2, FALSE);
                                                        break;
                                                case 0x00000001:
	        	                                proto_tree_add_item(adtree, hf_nds_port, tvb, voffset, 2, FALSE);
                                                        value6 = tvb_get_letohl(tvb, voffset+2);
	                                                proto_tree_add_ipv4(adtree, hf_add_ref_ip, tvb, voffset+2, 4, value6);
                                                        break;
                                                case 0x00000008:
	        	                                proto_tree_add_item(adtree, hf_nds_port, tvb, voffset, 2, FALSE);
                                                        value6 = tvb_get_letohl(tvb, voffset+2);
	                                                proto_tree_add_ipv4(adtree, hf_add_ref_udp, tvb, voffset+2, 4, value6);
                                                        break;
                                                case 0x00000009:
		                                        proto_tree_add_item(adtree, hf_nds_port, tvb, voffset, 2, FALSE);
                                                        value6 = tvb_get_letohl(tvb, voffset+2);
                                                        proto_tree_add_ipv4(adtree, hf_add_ref_tcp, tvb, voffset+2, 4, value6);
                                                        break;
                                                case 0x0000000d:
                                                        get_string(tvb, voffset, value5, vvalues->vstring);
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
                               get_string(tvb, voffset, value2, vvalues->vstring); /* Unicode String */
                               proto_tree_add_string(nvtree, hf_value_string, tvb, voffset, 
                                   value2, vvalues->vstring);
                               voffset = voffset + value2;    
                               voffset += align_4(tvb, voffset);
                               value3 = tvb_get_letohl(tvb, voffset);
                               voffset = voffset + 4;
                               get_string(tvb, voffset, value3, vvalues->vstring); /* Unicode Subject Name */
                               proto_tree_add_string(nvtree, hf_value_string, tvb, voffset, 
                                   value3, vvalues->vstring);
                               voffset = voffset + value3;    
                               voffset += align_4(tvb, voffset);
                               value4 = tvb_get_letohl(tvb, voffset);         /* Privileges */
                               proto_tree_add_uint_format(nvtree, hf_nds_uint32value, tvb, voffset,
                                        4, value4, "Privileges %8x", value4);
                               voffset = voffset+4;
                               voffset += align_4(tvb, voffset);
                               break;
                       case 0x00000013:        /* Time Stamp */
                               value1 = tvb_get_letohl(tvb, voffset);         /* Seconds */
                               proto_tree_add_uint_format(nvtree, hf_nds_uint32value, tvb, voffset,
                                        4, value1, "Lenght of Record: %d", value1);
                               voffset = voffset+4;
                               value2 = tvb_get_letohl(tvb, voffset);
                               proto_tree_add_uint_format(nvtree, hf_nds_uint32value, tvb, voffset,
                                        4, value2, "Seconds: %d", value2);
                               voffset = voffset + 4;
                               rnum = tvb_get_letohs(tvb, voffset); /* replica number */
                               proto_tree_add_uint_format(nvtree, hf_nds_rnum, tvb, voffset,
                                        2, rnum, "Replica Number: %d", rnum);
                               voffset = voffset+2;
                               revent = tvb_get_letohs(tvb, voffset); /* Event */
                               proto_tree_add_uint_format(nvtree, hf_nds_revent, tvb, voffset,
                                        2, revent, "Event: %d", revent);
                               voffset = voffset+14;
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
                               get_string(tvb, voffset, value3, vvalues->vstring);
                               proto_tree_add_string_format(nvtree, hf_value_string, tvb, voffset, 
                                        value3, vvalues->vstring,
                                        "Server Distinguished Name - %s", vvalues->vstring);
                               voffset = voffset+value3;
                               voffset += align_4(tvb, voffset);
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
                               get_string(tvb, voffset, value4, vvalues->vstring);
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
                               get_string(tvb, voffset, value3, vvalues->vstring);
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
                               get_string(tvb, voffset, value1, vvalues->vstring);
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
        nw_uni_t        mval_buf;
        proto_tree      *nestree;
	proto_item      *nesitem;
        proto_tree      *atree;
	proto_item      *aitem;
        char *          vstring="";
              
       	mval_buf.buffer = "";

        switch (vtype)
        {
                case 0: /* No Specifier Type */
                        value1 = tvb_get_letohl(tvb, ioffset);   /* ES Type */
                        proto_tree_add_item(estree, hf_es_value, tvb, ioffset, 
                                4, value1);
                        ioffset = ioffset + 4;
                        break;
                case 1: /* Unicode String */
                        value1 = tvb_get_letohl(tvb, ioffset);   /* Delimeter Set */
                        ioffset = ioffset + 4;        
                        get_string(tvb, ioffset, value1, mval_buf.buffer);
                        values->vstring = mval_buf.buffer;
                        proto_tree_add_string_format(estree, hf_mv_string, tvb, ioffset, 
                                value1, values->vstring, "Delimeter ->%s", values->vstring);
                        ioffset=ioffset + value1;
                        ioffset += align_4(tvb, ioffset);
                        value2 = tvb_get_letohl(tvb, ioffset);
                        ioffset = ioffset + 4;        
                        get_string(tvb, ioffset, value2, mval_buf.buffer);
                        values->vstring = mval_buf.buffer;
                        proto_tree_add_string(estree, hf_mv_string, tvb, ioffset, 
                                value2, values->vstring);
                        values->voffset=ioffset + value2;
                        ioffset = values->voffset;
                        break;
                case 2: /* Based */
                        value1 = tvb_get_letohl(tvb, ioffset);   /* ES Type */
                        vstring = match_strval(value1, es_type);
                        if (vstring == NULL)
                        {
                                vstring = "No ES Type Found";
                        }        
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
                                        value2 = tvb_get_letohl(tvb, ioffset);   /* Delimeter Set */
                                        ioffset = ioffset + 4;        
                                        get_string(tvb, ioffset, value2, mval_buf.buffer);
                                        values->vstring = mval_buf.buffer;
                                        proto_tree_add_string_format(nestree, hf_mv_string, tvb, ioffset, 
                                                value2, values->vstring, "Delimeter ->%s", values->vstring);
                                        ioffset=ioffset + value2;
                                        ioffset += align_4(tvb, ioffset);
                                        value3 = tvb_get_letohl(tvb, ioffset);
                                        ioffset = ioffset + 4;        
                                        get_string(tvb, ioffset, value3, mval_buf.buffer);
                                        values->vstring = mval_buf.buffer;
                                        proto_tree_add_string(nestree, hf_mv_string, tvb, ioffset, 
                                                value3, values->vstring);
                                        values->voffset=ioffset + value3;
                                        ioffset = values->voffset;
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
                                                value3 = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                                                proto_tree_add_item(nestree, hf_es_seconds, tvb, ioffset, 
                                                        4, value3);
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
                                        value4 = tvb_get_letohl(tvb, ioffset);   /* Delimeter Set */
                                        ioffset = ioffset + 4;        
                                        get_string(tvb, ioffset, value4, mval_buf.buffer);
                                        values->vstring = mval_buf.buffer;
                                        proto_tree_add_string(nestree, hf_mv_string, tvb, ioffset, 
                                                value4, values->vstring);
                                        ioffset=ioffset + value4;
                                        ioffset += align_4(tvb, ioffset);
                                        value5 = tvb_get_letohl(tvb, ioffset);   /* RDN */
                                        ioffset = ioffset + 4;        
                                        get_string(tvb, ioffset, value5, mval_buf.buffer);
                                        values->vstring = mval_buf.buffer;
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
                                        proto_tree_add_item(estree, hf_es_value, tvb, ioffset, 
                                                4, value1);
                                        ioffset = ioffset + 4;
                                        break;
                         }
                        value1 = tvb_get_letohl(tvb, ioffset);   /* ES Type */
                        vstring = match_strval(value1, es_type);
                        if (vstring == NULL)
                        {
                                vstring = "No ES Type Found";
                        }        
                        nesitem = proto_tree_add_string_format(estree, hf_es_type, tvb, ioffset, 
                                4, vstring, "Object Name Type - %s", vstring);
                        nestree = proto_item_add_subtree(nesitem, ett_nds);
                        ioffset = ioffset + 4;
                        switch (value1)
                        {
                                case 0: /* No Specifier Type */
                                        value2 = tvb_get_letohl(tvb, ioffset);   /* ES Type */
                                        proto_tree_add_item(estree, hf_es_value, tvb, ioffset, 
                                                4, value2);
                                        ioffset = ioffset + 4;
                                        break;
                                case 1: /* Unicode String */
                                        value2 = tvb_get_letohl(tvb, ioffset);   /* Delimeter Set */
                                        ioffset = ioffset + 4;        
                                        get_string(tvb, ioffset, value2, mval_buf.buffer);
                                        values->vstring = mval_buf.buffer;
                                        proto_tree_add_string_format(estree, hf_mv_string, tvb, ioffset, 
                                                value2, values->vstring, "Delimeter ->%s", values->vstring);
                                        ioffset=ioffset + value2;
                                        ioffset += align_4(tvb, ioffset);
                                        value3 = tvb_get_letohl(tvb, ioffset);
                                        ioffset = ioffset + 4;        
                                        get_string(tvb, ioffset, value3, mval_buf.buffer);
                                        values->vstring = mval_buf.buffer;
                                        proto_tree_add_string(estree, hf_mv_string, tvb, ioffset, 
                                                value3, values->vstring);
                                        values->voffset=ioffset + value3;
                                        ioffset = values->voffset;
                                        break;
                                case 2: /* Based */
                                        break;
                                case 3: /* Hinted */
                                        break;
                                case 4: /* Tuned */
                                        value2 = tvb_get_letohl(tvb, ioffset);   /* Count */
                                        proto_tree_add_item(estree, hf_es_rdn_count, tvb, ioffset, 
                                                4, value2);
                                        ioffset = ioffset + 4;
                                        for (r = 1 ; r <= value2; r++ )
                                        {
                                                value3 = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                                                proto_tree_add_item(estree, hf_es_seconds, tvb, ioffset, 
                                                        4, value3);
                                                ioffset = ioffset + 4;
                                                replica_num = tvb_get_letohs(tvb, ioffset);   /* Replica */
                                                proto_tree_add_item(estree, hf_nds_replica_num, tvb, ioffset, 
                                                        2, replica_num);
                                                ioffset = ioffset + 2;
                                                event_num = tvb_get_letohs(tvb, ioffset);   /* Event */
                                                proto_tree_add_item(estree, hf_nds_event_num, tvb, ioffset, 
                                                        2, event_num);
                                                ioffset = ioffset + 2;
                                        }        
                                        value4 = tvb_get_letohl(tvb, ioffset);   /* Delimeter Set */
                                        ioffset = ioffset + 4;        
                                        get_string(tvb, ioffset, value4, mval_buf.buffer);
                                        values->vstring = mval_buf.buffer;
                                        proto_tree_add_string(estree, hf_mv_string, tvb, ioffset, 
                                                value4, values->vstring);
                                        ioffset=ioffset + value4;
                                        ioffset += align_4(tvb, ioffset);
                                        value5 = tvb_get_letohl(tvb, ioffset);   /* RDN */
                                        ioffset = ioffset + 4;        
                                        get_string(tvb, ioffset, value5, mval_buf.buffer);
                                        values->vstring = mval_buf.buffer;
                                        proto_tree_add_string(estree, hf_rdn_string, tvb, ioffset, 
                                                value5, values->vstring);
                                        ioffset=ioffset + value5;
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
                        break;
                case 3: /* Hinted */
                        number_of_referrals = tvb_get_letohl(tvb, ioffset);
                        
                        for (r = 1 ; r <= number_of_referrals; r++ )
                        {
		                aitem = proto_tree_add_uint_format(estree, hf_referral_record, tvb, 6, 0,
		                r, "NDS Referral Record #%u", r);
                                atree = proto_item_add_subtree(aitem, ett_nds);
                                
                                value1 = tvb_get_letohl(tvb, ioffset);
                                
	                        proto_tree_add_uint_format(atree, hf_referral_addcount, tvb, ioffset, 4,
        	                        value1, "Number of Addresses in Referral - %d", value1);
                                     
                                ioffset = ioffset + 4;
                                for (i = 1 ; i <= value1; i++ ) 
                                {
                                        value2 = tvb_get_letohl(tvb, ioffset);
                                        values->vstring = match_strval(value2, nds_protocol_type);
                                        if (values->vstring == NULL)
                                        { 
                                               values->vstring="(Undefined Protocol)";
                                        }
                                        proto_tree_add_uint_format(atree, hf_nds_uint32value, tvb, ioffset,
                                        4, value2, vstring, value2);
                                        ioffset = ioffset+4;
                                        value3 = tvb_get_letohl(tvb, ioffset);
                                        ioffset = ioffset+4;
                                        switch (value2)
                                        { 
                                                case 0x00000000:
                                                        proto_tree_add_item(atree, hf_nds_net, tvb, ioffset, 4, FALSE);
		                                        proto_tree_add_item(atree, hf_nds_node, tvb, ioffset+4, 6, FALSE);
		                                        proto_tree_add_item(atree, hf_nds_socket, tvb, ioffset+10, 2, FALSE);
                                                        break;
                                                case 0x00000001:
        	        	                        proto_tree_add_item(atree, hf_nds_port, tvb, ioffset, 2, FALSE);
                                                        value4 = tvb_get_letohl(tvb, ioffset+2);
	                                                proto_tree_add_ipv4(atree, hf_add_ref_ip, tvb, ioffset+2, 4, value4);
                                                        break;
                                                case 0x00000008:
		                                        proto_tree_add_item(atree, hf_nds_port, tvb, ioffset, 2, FALSE);
                                                        value4 = tvb_get_letohl(tvb, ioffset+2);
	                                                proto_tree_add_ipv4(atree, hf_add_ref_udp, tvb, ioffset+2, 4, value4);
                                                        break;
                                                case 0x00000009:
		                                        proto_tree_add_item(atree, hf_nds_port, tvb, ioffset, 2, FALSE);
                                                        value4 = tvb_get_letohl(tvb, ioffset+2);
                                        	        proto_tree_add_ipv4(atree, hf_add_ref_tcp, tvb, ioffset+2, 4, value4);
                                                        break;
                                                case 0x0000000d:
                                                        get_string(tvb, ioffset, value3, values->vstring);
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
                        value1 = tvb_get_letohl(tvb, ioffset);   /* ES Type */
                        vstring = match_strval(value1, es_type);
                        if (vstring == NULL)
                        {
                                vstring = "No ES Type Found";
                        }        
                        nesitem = proto_tree_add_string_format(estree, hf_es_type, tvb, ioffset, 
                                4, vstring, "Object Name Type - %s", vstring);
                        nestree = proto_item_add_subtree(nesitem, ett_nds);
                        ioffset = ioffset + 4;
                        switch (value1)
                        {
                                case 0: /* No Specifier Type */
                                        value2 = tvb_get_letohl(tvb, ioffset);   /* ES Type */
                                        proto_tree_add_item(estree, hf_es_value, tvb, ioffset, 
                                                4, value2);
                                        ioffset = ioffset + 4;
                                        break;
                                case 1: /* Unicode String */
                                        value2 = tvb_get_letohl(tvb, ioffset);   /* Delimeter Set */
                                        ioffset = ioffset + 4;        
                                        get_string(tvb, ioffset, value2, mval_buf.buffer);
                                        values->vstring = mval_buf.buffer;
                                        proto_tree_add_string_format(estree, hf_mv_string, tvb, ioffset, 
                                                value2, values->vstring, "Delimeter ->%s", values->vstring);
                                        ioffset=ioffset + value2;
                                        ioffset += align_4(tvb, ioffset);
                                        value3 = tvb_get_letohl(tvb, ioffset);
                                        ioffset = ioffset + 4;        
                                        get_string(tvb, ioffset, value3, mval_buf.buffer);
                                        values->vstring = mval_buf.buffer;
                                        proto_tree_add_string(estree, hf_mv_string, tvb, ioffset, 
                                                value3, values->vstring);
                                        values->voffset=ioffset + value3;
                                        ioffset = values->voffset;
                                        break;
                                case 2: /* Based */
                                        break;
                                case 3: /* Hinted */
                                        break;
                                case 4: /* Tuned */
                                        value2 = tvb_get_letohl(tvb, ioffset);   /* Count */
                                        proto_tree_add_item(estree, hf_es_rdn_count, tvb, ioffset, 
                                                4, value2);
                                        ioffset = ioffset + 4;
                                        for (r = 1 ; r <= value2; r++ )
                                        {
                                                value3 = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                                                proto_tree_add_item(estree, hf_es_seconds, tvb, ioffset, 
                                                        4, value3);
                                                ioffset = ioffset + 4;
                                                replica_num = tvb_get_letohs(tvb, ioffset);   /* Replica */
                                                proto_tree_add_item(estree, hf_nds_replica_num, tvb, ioffset, 
                                                        2, replica_num);
                                                ioffset = ioffset + 2;
                                                event_num = tvb_get_letohs(tvb, ioffset);   /* Event */
                                                proto_tree_add_item(estree, hf_nds_event_num, tvb, ioffset, 
                                                        2, event_num);
                                                ioffset = ioffset + 2;
                                        }        
                                        value4 = tvb_get_letohl(tvb, ioffset);   /* Delimeter Set */
                                        ioffset = ioffset + 4;        
                                        get_string(tvb, ioffset, value4, mval_buf.buffer);
                                        values->vstring = mval_buf.buffer;
                                        proto_tree_add_string(estree, hf_mv_string, tvb, ioffset, 
                                                value4, values->vstring);
                                        ioffset=ioffset + value4;
                                        ioffset += align_4(tvb, ioffset);
                                        value5 = tvb_get_letohl(tvb, ioffset);   /* RDN */
                                        ioffset = ioffset + 4;        
                                        get_string(tvb, ioffset, value5, mval_buf.buffer);
                                        values->vstring = mval_buf.buffer;
                                        proto_tree_add_string(estree, hf_rdn_string, tvb, ioffset, 
                                                value5, values->vstring);
                                        ioffset=ioffset + value5;
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
                        break;
                case 4: /* Tuned */
                        value1 = tvb_get_letohl(tvb, ioffset);   /* Count */
                        proto_tree_add_item(estree, hf_es_rdn_count, tvb, ioffset, 
                                4, value1);
                        ioffset = ioffset + 4;
                        for (r = 1 ; r <= value1; r++ )
                        {
                                value2 = tvb_get_letohl(tvb, ioffset);   /* Seconds */
                                proto_tree_add_item(estree, hf_es_seconds, tvb, ioffset, 
                                        4, value2);
                                ioffset = ioffset + 4;
                                replica_num = tvb_get_letohs(tvb, ioffset);   /* Replica */
                                proto_tree_add_item(estree, hf_nds_replica_num, tvb, ioffset, 
                                        2, replica_num);
                                ioffset = ioffset + 2;
                                event_num = tvb_get_letohs(tvb, ioffset);   /* Event */
                                proto_tree_add_item(estree, hf_nds_event_num, tvb, ioffset, 
                                        2, event_num);
                                ioffset = ioffset + 2;
                        }        
                        value3 = tvb_get_letohl(tvb, ioffset);   /* Delimeter Set */
                        ioffset = ioffset + 4;        
                        get_string(tvb, ioffset, value3, mval_buf.buffer);
                        values->vstring = mval_buf.buffer;
                        proto_tree_add_string(estree, hf_mv_string, tvb, ioffset, 
                                value3, values->vstring);
                        ioffset=ioffset + value3;
                        ioffset += align_4(tvb, ioffset);
                        value4 = tvb_get_letohl(tvb, ioffset);   /* RDN */
                        ioffset = ioffset + 4;        
                        get_string(tvb, ioffset, value4, mval_buf.buffer);
                        values->vstring = mval_buf.buffer;
                        proto_tree_add_string(estree, hf_rdn_string, tvb, ioffset, 
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

static void
process_multivalues(proto_tree *ncp_tree, tvbuff_t *tvb, nds_val *values)
{
        guint32         i;
        guint32         r;
        guint32         ioffset = 0;
        guint32         value1 = 0;
        guint32         value2 = 0;
        guint8          value3 = 0;
        guint32         value4 = 0;
        gint            value5 = 0;
        guint32         value6 = 0;
        guint32         value7 = 0;
        char *          valuestr = "";
        proto_tree      *ntree;
        proto_tree      *atree;
	proto_item      *nitem;
        proto_item      *aitem;
        guint32         number_of_referrals = 0;
        nw_uni_t        mval_buf;
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
               
       	mval_buf.buffer = "";
        if(values->mvtype != MVTYPE_LIST_PARTITIONS)
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
                case MVTYPE_ATTR_REQUEST:	/* Attribute Request */
                        for (i = 1 ; i <= values->vvalue; i++ )
                        {
                                ioffset += align_4(tvb, ioffset);
                                value1 = tvb_get_letohl(tvb, ioffset);
                                ioffset = ioffset + 4;
                                get_string(tvb, ioffset, value1, mval_buf.buffer);
                                values->vstring = mval_buf.buffer;                                
                                proto_tree_add_string(ntree, hf_mv_string, tvb, ioffset, 
                                        value1, values->vstring);
                                ioffset = ioffset + value1;        
                        }
                        break;

                case MVTYPE_ATTR_REPLY:		/* Attribute Reply */
                        switch(values->vflags)
                        {
                                case 0:
                                        for (i = 1 ; i <= values->vvalue; i++ )
                                        {
                                                ioffset += align_4(tvb, ioffset);
                                                value1 = tvb_get_letohl(tvb, ioffset);
                                                ioffset = ioffset + 4;
                                                get_string(tvb, ioffset, value1, mval_buf.buffer);
                                                values->vstring = mval_buf.buffer;                                
                                                proto_tree_add_string(ntree, hf_mv_string, tvb, ioffset, 
                                                        value1, values->vstring);
                                                ioffset = ioffset + value1;        
                                        }
                                        break;
                                case 1:
                                        for (i = 1 ; i <= values->vvalue; i++ )
                                        {
                                                value1 = tvb_get_letohl(tvb, ioffset);
                                                values->vstring = match_strval(value1, nds_syntax);
                                                if (values->vstring == NULL)
                                                {
                                                        values->vstring = "No Syntax Found";
                                                }        
                                                proto_tree_add_string(ntree, hf_nds_syntax, tvb, ioffset, 
                                                4, values->vstring);
                                                ioffset = ioffset + 4;
                                                value2 = tvb_get_letohl(tvb, ioffset);
                                                ioffset = ioffset + 4;        
                                                get_string(tvb, ioffset, value2, mval_buf.buffer);
                                                values->vstring = mval_buf.buffer;
                                                proto_tree_add_string(ntree, hf_mv_string, tvb, ioffset, 
                                                        value2, values->vstring);        
                                                values->voffset=ioffset + value2;
                                                print_nds_values(ntree, tvb, value1, values);        
                                                ioffset = values->voffset;
                                        }
                                        break;                
                                case 2:
                                        for (i = 1 ; i <= values->vvalue; i++ )
                                        {
                                                value1 = tvb_get_letohl(tvb, ioffset);
                                                values->vstring = match_strval(value1, nds_syntax);
                                                if (values->vstring == NULL)
                                                {
                                                        values->vstring = "No Syntax Found";
                                                }        
                                                proto_tree_add_string(ntree, hf_nds_syntax, tvb, ioffset, 
                                                4, values->vstring);
                                                ioffset = ioffset + 4;
                                                value2 = tvb_get_letohl(tvb, ioffset);
                                                ioffset = ioffset + 4;        
                                                get_string(tvb, ioffset, value2, mval_buf.buffer);
                                                values->vstring = mval_buf.buffer;
                                                proto_tree_add_string(ntree, hf_mv_string, tvb, ioffset, 
                                                        value2, values->vstring);
                                                values->voffset=ioffset + value2;
                                                ioffset += value2;
                                                ioffset += align_4(tvb, ioffset);
                                                value3 = tvb_get_letohl(tvb, ioffset);
                                                
                	                        proto_tree_add_uint_format(ntree, hf_nds_uint32value, tvb, ioffset, 4,
                        	                        value1, "Number of Values - %d", value1);
                                                     
                                                ioffset = ioffset + 4;
                                                for (r = 1 ; r <= value3; r++ ) 
                                                {
                                                        ioffset += 4;   /* Length = 4 */
                                                        value4 = tvb_get_letohl(tvb, ioffset);
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
                                                values->vstring = match_strval(value1, nds_syntax);
                                                if (values->vstring == NULL)
                                                {
                                                        values->vstring = "No Syntax Found";
                                                }        
                                                proto_tree_add_string(ntree, hf_nds_syntax, tvb, ioffset, 
                                                4, values->vstring);
                                                ioffset = ioffset + 4;
                                                value2 = tvb_get_letohl(tvb, ioffset);
                                                ioffset = ioffset + 4;        
                                                get_string(tvb, ioffset, value2, mval_buf.buffer);
                                                values->vstring = mval_buf.buffer;
                                                proto_tree_add_string(ntree, hf_mv_string, tvb, ioffset, 
                                                        value2, values->vstring);
                                                ioffset = ioffset + value2;
                                                ioffset += align_4(tvb, ioffset);
                                                value3 = tvb_get_letohl(tvb, ioffset);
                                                
                	                        aitem = proto_tree_add_uint_format(ntree, hf_nds_uint32value, tvb, ioffset, 4,
                        	                        value3, "Number of Values - %d", value3);
        
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
                                                        value4 = tvb_get_letohl(tvb, ioffset);
                                                        proto_tree_add_uint_format(atree, hf_es_seconds, tvb, ioffset,
                                                                4, value4, "Seconds %d", value4);
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
                                                values->vstring = match_strval(value1, nds_syntax);
                                                if (values->vstring == NULL)
                                                {
                                                        values->vstring = "No Syntax Found";
                                                }        
                                                proto_tree_add_string(ntree, hf_nds_syntax, tvb, ioffset, 
                                                4, values->vstring);
                                                ioffset = ioffset + 4;
                                                value2 = tvb_get_letohl(tvb, ioffset);
                                                ioffset = ioffset + 4;        
                                                get_string(tvb, ioffset, value2, mval_buf.buffer);
                                                values->vstring = mval_buf.buffer;
                                                proto_tree_add_string(ntree, hf_mv_string, tvb, ioffset, 
                                                        value2, values->vstring);
                                                ioffset = ioffset + value2;
                                                value3 = tvb_get_letohl(tvb, ioffset);
                                                
                	                        proto_tree_add_uint_format(ntree, hf_nds_uint32value, tvb, ioffset, 4,
                        	                        value3, "Number of Values - %d", value3);
                                                     
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
                                                        value1 = tvb_get_letohl(tvb, ioffset);
                                                        proto_tree_add_uint_format(ntree, hf_es_seconds, tvb, ioffset,
                                                                4, value1, "Seconds %d", value1);
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

                case MVTYPE_ATTR_REQUEST2:	/* Attribute Request */
                        for (i = 1 ; i <= values->vvalue; i++ )
                        {
                                ioffset += align_4(tvb, ioffset);
                                value1 = tvb_get_letohl(tvb, ioffset);
                                proto_tree_add_uint_format(ntree, hf_nds_uint32value, tvb, ioffset,
                                        4, value1, "Value %d", value1);
                                ioffset = ioffset + value1;        
                        }
                        break;

                case MVTYPE_READ_CLASS_REQ:	/* Read Class Request */
                        for (i = 1 ; i <= values->vvalue; i++ )
                        {
                                ioffset += align_4(tvb, ioffset);
                                value1 = tvb_get_letohl(tvb, ioffset);
                                ioffset = ioffset + 4;
                                get_string(tvb, ioffset, value1, mval_buf.buffer);
                                values->vstring = mval_buf.buffer;                                
                                proto_tree_add_string(ntree, hf_nds_base, tvb, ioffset, 
                                        value1, values->vstring);
                                values->mvtype = 1;        
                                ioffset = ioffset + value1;        
                        }
                        break;

                case MVTYPE_READ_REPLICAS:	/* Read Replicas */
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
                                                                temp_values.vstring = match_strval(value1, nds_replica_state);
                                                                if (temp_values.vstring == NULL)
                                                                {
                                                                        temp_values.vstring = "No Replica State Found";
                                                                }        
                                                                proto_tree_add_string(ntree, hf_replica_state, tvb, ioffset, 
                                                                4, temp_values.vstring);
                                                                ioffset = ioffset + 4;
                                                                break;
                                                        case 0x0000008:                 /*p3values.bit4 = "Modification Timestamp"*/
                                                                value1 = tvb_get_letohl(tvb, ioffset);
                                                                proto_tree_add_uint_format(ntree, hf_es_seconds, tvb, ioffset,
                                                                        4, value1, "Seconds %d", value1);
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
                                                                value1 = tvb_get_letohl(tvb, ioffset);
                                                                proto_tree_add_uint_format(ntree, hf_nds_purge, tvb, ioffset,
                                                                        4, value1, "Purge Time %d", value1);
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
                                                                get_string(tvb, ioffset, value1, mval_buf.buffer);
                                                                temp_values.vstring = mval_buf.buffer;                                
                                                                proto_tree_add_string(ntree, hf_nds_name, tvb, ioffset, 
                                                                        value1, temp_values.vstring);
                                                                ioffset = ioffset + value1;        
                                                                break;
                                                        case 0x00000080:                /*p3values.bit8 = "Replica Type & State"*/
                                                                value1 = tvb_get_letohl(tvb, ioffset);
                                                                value2 = value1 & 0x00ff;
                                                                temp_values.vstring = match_strval(value2, nds_replica_type);
                                                                if (temp_values.vstring == NULL)
                                                                {
                                                                        temp_values.vstring = "No Replica Type Found";
                                                                }        
                                                                proto_tree_add_string(ntree, hf_replica_type, tvb, ioffset, 
                                                                4, temp_values.vstring);
                                                                value3 = value1 & 0xff00;
                                                                temp_values.vstring = match_strval(value3, nds_replica_state);
                                                                if (temp_values.vstring == NULL)
                                                                {
                                                                        temp_values.vstring = "No Replica State Found";
                                                                }        
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
                               valuestr = match_strval(value1, nds_kind_of_changes);
                               if (valuestr == NULL)
                               { 
                                               valuestr="(Kind Change Not Found)";
                               }
                               proto_tree_add_uint_format(ntree, hf_nds_uint32value, tvb, ioffset,
                               values->vlength, value1, valuestr, value1);
                               ioffset = ioffset+4;
                               value2 = tvb_get_letohl(tvb, ioffset);
                               ioffset = ioffset + 4;
                               get_string(tvb, ioffset, value2, mval_buf.buffer);   /* Name of Attribute */
                               temp_values.vstring = mval_buf.buffer;                                
                               proto_tree_add_string(ntree, hf_mv_string, tvb, ioffset, 
                                       value2, temp_values.vstring);
                               ioffset = ioffset + value2;
                               ioffset += align_4(tvb, ioffset);
                               if(value1 != 1 && value1 != 6)
                               {
                                       values->voffset = ioffset;
                                       print_nds_values(ntree, tvb, 9, values);        
                                       ioffset = values->voffset;
                               }
                        }
                        break;

                case MVTYPE_ADDR_REFERRAL_REQUEST: /* Address Referral Request */
                        for (i = 0 ; i < values->vvalue; i++ ) 
                        {
        
                               value1 = tvb_get_letohl(tvb, ioffset);
                               valuestr = match_strval(value1, nds_protocol_type);
                               if (valuestr == NULL)
                               { 
                                               valuestr="(Undefined Protocol)";
                               }
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
        	                        value1, "Number of Addresses in Referral - %d", value1);
                                     
                                ioffset = ioffset + 4;
                                for (i = 1 ; i <= value1; i++ ) 
                                {
                                        value2 = tvb_get_letohl(tvb, ioffset);
                                        valuestr = match_strval(value2, nds_protocol_type);
                                        if (valuestr == NULL)
                                        { 
                                               valuestr="(Undefined Protocol)";
                                        }
                                        proto_tree_add_uint_format(atree, hf_nds_uint32value, tvb, ioffset,
                                        values->vlength, value2, valuestr, value2);
                                        ioffset = ioffset+4;
                                        value3 = tvb_get_letohl(tvb, ioffset);
                                        ioffset = ioffset+4;
                                        switch (value2)
                                        { 
                                                case 0x00000000:
                                                        proto_tree_add_item(atree, hf_nds_net, tvb, ioffset, 4, FALSE);
		                                        proto_tree_add_item(atree, hf_nds_node, tvb, ioffset+4, 6, FALSE);
		                                        proto_tree_add_item(atree, hf_nds_socket, tvb, ioffset+10, 2, FALSE);
                                                        break;
                                                case 0x00000001:
        	        	                        proto_tree_add_item(atree, hf_nds_port, tvb, ioffset, 2, FALSE);
                                                        value4 = tvb_get_letohl(tvb, ioffset+2);
	                                                proto_tree_add_ipv4(atree, hf_add_ref_ip, tvb, ioffset+2, 4, value4);
                                                        break;
                                                case 0x00000008:
		                                        proto_tree_add_item(atree, hf_nds_port, tvb, ioffset, 2, FALSE);
                                                        value4 = tvb_get_letohl(tvb, ioffset+2);
	                                                proto_tree_add_ipv4(atree, hf_add_ref_udp, tvb, ioffset+2, 4, value4);
                                                        break;
                                                case 0x00000009:
		                                        proto_tree_add_item(atree, hf_nds_port, tvb, ioffset, 2, FALSE);
                                                        value4 = tvb_get_letohl(tvb, ioffset+2);
                                        	        proto_tree_add_ipv4(atree, hf_add_ref_tcp, tvb, ioffset+2, 4, value4);
                                                        break;
                                                case 0x0000000d:
                                                        get_string(tvb, ioffset, value3, values->vstring);
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
                                valuestr = match_strval(value2, nds_protocol_type);
                                if (valuestr == NULL)
                                { 
                                        valuestr="(Undefined Protocol)";
                                }
                                proto_tree_add_uint_format(atree, hf_nds_uint32value, tvb, ioffset,
                                values->vlength, value2, valuestr, value2);
                                ioffset = ioffset+4;
                                value3 = tvb_get_letohl(tvb, ioffset);
                                ioffset = ioffset+4;
                                
                                switch (value2)
                                { 
                                        case 0x00000000:
                                                proto_tree_add_item(atree, hf_nds_net, tvb, ioffset, 4, FALSE);
		                                proto_tree_add_item(atree, hf_nds_node, tvb, ioffset+4, 6, FALSE);
		                                proto_tree_add_item(atree, hf_nds_socket, tvb, ioffset+10, 2, FALSE);
                                                break;
                                        case 0x00000001:
       	        	                        proto_tree_add_item(atree, hf_nds_port, tvb, ioffset, 2, FALSE);
                                                ioffset=ioffset+2;
                                                value4 = tvb_get_letohl(tvb, ioffset);
                                                proto_tree_add_ipv4(atree, hf_add_ref_ip, tvb, ioffset, 4, value4);
                                                break;
                                        case 0x00000008:
		                                proto_tree_add_item(atree, hf_nds_port, tvb, ioffset, 2, FALSE);
                                                ioffset=ioffset+2;
                                                value4 = tvb_get_letohl(tvb, ioffset);
	                                        proto_tree_add_ipv4(atree, hf_add_ref_udp, tvb, ioffset, 4, value4);
                                                break;
                                        case 0x00000009:
		                                proto_tree_add_item(atree, hf_nds_port, tvb, ioffset, 2, FALSE);
                                                ioffset=ioffset+2;
                                                value4 = tvb_get_letohl(tvb, ioffset);
                                                proto_tree_add_ipv4(atree, hf_add_ref_tcp, tvb, ioffset, 4, value4);
                                                break;
                                        case 0x0000000d:
                                                get_string(tvb, ioffset, value3, values->vstring);
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
                        values->vstring = match_strval(value2, es_type);
                        if (values->vstring == NULL)
                        {
                                values->vstring = "No ES Type Found";
                        }        
                        esitem = proto_tree_add_string_format(ntree, hf_es_type, tvb, ioffset, 
                                4, values->vstring, "Output Entry Specifier - %s", values->vstring);
                        estree = proto_item_add_subtree(esitem, ett_nds);
                        ioffset = ioffset + 4;
                        ioffset = print_es_type(estree, tvb, values, value2, ioffset);
                        value3 = tvb_get_letohl(tvb, ioffset);   /* ES Type */
                        values->vstring = match_strval(value3, es_type);
                        if (values->vstring == NULL)
                        {
                                values->vstring = "No ES Type Found";
                        }        
                        esitem = proto_tree_add_string_format(ntree, hf_es_type, tvb, ioffset, 
                                4, values->vstring, "Input Entry Specifier - %s", values->vstring);
                        estree = proto_item_add_subtree(esitem, ett_nds);
                        ioffset = ioffset + 4;
                        ioffset = print_es_type(estree, tvb, values, value3, ioffset);
                        value4 = tvb_get_letohl(tvb, ioffset);
		        aitem = proto_tree_add_uint_format(ntree, hf_referral_record, tvb, ioffset, 4,
		                value4, "Referral Protocols - %d", value4);
                        atree = proto_item_add_subtree(aitem, ett_nds);
                        ioffset += 4;               
                        for (i = 0 ; i < value4; i++ ) 
                        {
                               value5 = tvb_get_letohl(tvb, ioffset);
                               valuestr = match_strval(value5, nds_protocol_type);
                               if (valuestr == NULL)
                               { 
                                               valuestr="(Undefined Protocol)";
                               }
                               proto_tree_add_string_format(atree, hf_value_string, tvb, ioffset,
                               4, valuestr, "Protocol -> %s", valuestr);
                               ioffset = ioffset+4;
                        }
                        value6 = tvb_get_letohl(tvb, ioffset);
		        aitem = proto_tree_add_uint_format(ntree, hf_referral_record, tvb, ioffset, 4,
		                value6, "Tree Walking Protocols - %d", value6);
                        atree = proto_item_add_subtree(aitem, ett_nds);
                        ioffset += 4;               
                        for (i = 0 ; i < value6; i++ ) 
                        {
                               value7 = tvb_get_letohl(tvb, ioffset);
                               valuestr = match_strval(value7, nds_protocol_type);
                               if (valuestr == NULL)
                               { 
                                               valuestr="(Undefined Protocol)";
                               }
                               proto_tree_add_string_format(atree, hf_value_string, tvb, ioffset,
                               4, valuestr, "Protocol -> %s", valuestr);
                               ioffset = ioffset+4;
                        }
                        break;

                case MVTYPE_PRINT_TIMESTAMP:	/* Print Timestamp */
                        replica_num = tvb_get_letohs(tvb, ioffset);   /* Replica */
                        proto_tree_add_item(ncp_tree, hf_nds_replica_num, tvb, ioffset, 
                                2, replica_num);
                        ioffset = ioffset + 2;
                        event_num = tvb_get_letohs(tvb, ioffset);   /* Event */
                        proto_tree_add_item(ncp_tree, hf_nds_event_num, tvb, ioffset, 
                                2, event_num);
                        ioffset = ioffset + 2;
			/* fall through */

                case MVTYPE_LIST_PARTITIONS:	/* List Partitions */
                        number_of_referrals = values->vvalue;
                        for (i = 0; i < number_of_referrals; i++)
                        {        
                                bvalue = 0x00000001;
        	
                                for (r = 0 ; r < 32; r++ ) 
                                {
                                        if (values->vflags & bvalue) 
                                        {
                                                switch(bvalue)
                                                {
                                                        case 0x00000001:                /* Information Flags */
                                                                temp_values.vvalue = tvb_get_letohs(tvb, ioffset);
                                                                temp_values.vtype = VTYPE_BITFIELD;
                                                                temp_values.vstring = "";
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
                                                                temp_values.vstring = "";
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
                                                                temp_values.vstring = "";
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
                                                                        4, value1, "Subordinate Count %d", value1);
                                                                ioffset = ioffset + 4;        
                                                                break;
                                                        case 0x0000010:                 /* Modification Time */
                                                                value1 = tvb_get_letohl(tvb, ioffset);
                                                                proto_tree_add_uint_format(ntree, hf_es_seconds, tvb, ioffset,
                                                                        4, value1, "Modification Time in Seconds %d", value1);
                                                                ioffset = ioffset + 4;        
                                                                break;
                                                        case 0x0000020:                 /* Modification Timestamp */
                                                                value1 = tvb_get_letohl(tvb, ioffset);
                                                                proto_tree_add_uint_format(ntree, hf_es_seconds, tvb, ioffset,
                                                                        4, value1, "Modification Timestamp Seconds %d", value1);
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
                                                                value1 = tvb_get_letohl(tvb, ioffset);
                                                                proto_tree_add_uint_format(ntree, hf_es_seconds, tvb, ioffset,
                                                                        4, value1, "Creation Timestamp Seconds %d", value1);
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
                                                                        4, value1, "Revision Count %d", value1);
                                                                ioffset = ioffset + 4;        
                                                                break;
                                                        case 0x00000400:                /* Replica Type & State */
                                                                value1 = tvb_get_letohl(tvb, ioffset);
                                                                value2 = value1 & 0x00ff;
                                                                temp_values.vstring = match_strval(value2, nds_replica_type);
                                                                if (temp_values.vstring == NULL)
                                                                {
                                                                        temp_values.vstring = "No Replica Type Found";
                                                                }        
                                                                proto_tree_add_string(ntree, hf_replica_type, tvb, ioffset, 
                                                                4, temp_values.vstring);
                                                                value3 = value1 & 0xff00;
                                                                temp_values.vstring = match_strval(value3, nds_replica_state);
                                                                if (temp_values.vstring == NULL)
                                                                {
                                                                        temp_values.vstring = "No Replica State Found";
                                                                }        
                                                                proto_tree_add_string(ntree, hf_replica_state, tvb, ioffset, 
                                                                4, temp_values.vstring);
                                                                ioffset = ioffset + 4;
                                                                break;
                                                        case 0x00000800:                /* Base Class */
                                                                value1 = tvb_get_letohl(tvb, ioffset);
                                                                ioffset = ioffset + 4;
                                                                get_string(tvb, ioffset, value1, mval_buf.buffer);
                                                                temp_values.vstring = mval_buf.buffer;                                
                                                                proto_tree_add_string(ntree, hf_nds_base, tvb, ioffset, 
                                                                        value1, temp_values.vstring);
                                                                ioffset = ioffset + value1;        
                                                                break;
                                                        case 0x00001000:                /* Relative Distinguished Name */
                                                                value1 = tvb_get_letohl(tvb, ioffset);
                                                                ioffset = ioffset + 4;
                                                                get_string(tvb, ioffset, value1, mval_buf.buffer);
                                                                temp_values.vstring = mval_buf.buffer;                                
                                                                proto_tree_add_string(ntree, hf_nds_relative_dn, tvb, ioffset, 
                                                                        value1, temp_values.vstring);
                                                                ioffset = ioffset + value1;        
                                                                break;
                                                        case 0x00002000:                /* Distinguished Name */
                                                                value1 = tvb_get_letohl(tvb, ioffset);
                                                                ioffset = ioffset + 4;
                                                                get_string(tvb, ioffset, value1, mval_buf.buffer);
                                                                temp_values.vstring = mval_buf.buffer;                                
                                                                proto_tree_add_string(ntree, hf_nds_name, tvb, ioffset, 
                                                                        value1, temp_values.vstring);
                                                                ioffset = ioffset + value1;        
                                                                break;
                                                        case 0x00004000:                /* Root Distinguished Name */
                                                                value1 = tvb_get_letohl(tvb, ioffset);
                                                                ioffset = ioffset + 4;
                                                                get_string(tvb, ioffset, value1, mval_buf.buffer);
                                                                temp_values.vstring = mval_buf.buffer;                                
                                                                proto_tree_add_string(ntree, hf_nds_name, tvb, ioffset, 
                                                                        value1, temp_values.vstring);
                                                                ioffset = ioffset + value1;        
                                                                break;
                                                        case 0x00008000:                /* Parent Distinguished Name */
                                                                value1 = tvb_get_letohl(tvb, ioffset);
                                                                ioffset = ioffset + 4;
                                                                get_string(tvb, ioffset, value1, mval_buf.buffer);
                                                                temp_values.vstring = mval_buf.buffer;                                
                                                                proto_tree_add_string(ntree, hf_nds_name, tvb, ioffset, 
                                                                        value1, temp_values.vstring);
                                                                ioffset = ioffset + value1;        
                                                                break;
                                                        case 0x00010000:                /* Purge Time */
                                                                value1 = tvb_get_letohl(tvb, ioffset);
                                                                proto_tree_add_uint_format(ntree, hf_nds_purge, tvb, ioffset,
                                                                        4, value1, "Purge Time %d", value1);
                                                                ioffset = ioffset + 4;        
                                                                break;
                                                        case 0x00020000:                /* Dereference Base Class */
                                                                value1 = tvb_get_letohl(tvb, ioffset);
                                                                ioffset = ioffset + 4;
                                                                get_string(tvb, ioffset, value1, mval_buf.buffer);
                                                                temp_values.vstring = mval_buf.buffer;                                
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

                case MVTYPE_CLASS_NAMES:	/* Class Names */
                        number_of_referrals = values->vvalue;
                        for (i = 0; i < number_of_referrals; i++)
                        {        
                                ioffset += align_4(tvb, ioffset);
                                value1 = tvb_get_letohl(tvb, ioffset);
                                ioffset = ioffset + 4;
                                get_string(tvb, ioffset, value1, mval_buf.buffer);
                                temp_values.vstring = mval_buf.buffer;                                
                                sub1item = proto_tree_add_string(ntree, hf_nds_base_class, tvb, ioffset, 
                                        value1, temp_values.vstring);
                                sub1tree = proto_item_add_subtree(sub1item, ett_nds);
                                ioffset = ioffset + value1;        
                                ioffset += align_4(tvb, ioffset);
                                if(values->vflags != 0)
                                {
                                        temp_values.vvalue = tvb_get_letohl(tvb, ioffset);
                                        temp_values.vtype = VTYPE_BITFIELD;
                                        temp_values.vstring = "";
                                        temp_values.vdesc = "Class Flags:";
                                        temp_values.vlength = 2;
                                        temp_values.hfname= hf_nds_cflags;
                                        temp_values.voffset = ioffset;
                                        temp_values.bit1 = "Ambiguous Containment";
                                        temp_values.bit1hfname = hf_bit1cflags;
                                        temp_values.bit2 = "Ambiguous Naming";
                                        temp_values.bit2hfname = hf_bit2cflags;
                                        temp_values.bit3 = "Class Definition Cannot be Removed";
                                        temp_values.bit3hfname = hf_bit3cflags;
                                        temp_values.bit4 = "Effective Class";
                                        temp_values.bit4hfname = hf_bit4cflags;
                                        temp_values.bit5 = "Container Class";
                                        temp_values.bit5hfname = hf_bit5cflags;
                                        temp_values.bit6 = "Not Defined";
                                        temp_values.bit6hfname = hf_bit6cflags;
                                        temp_values.bit7 = "Not Defined";
                                        temp_values.bit7hfname = hf_bit7cflags;
                                        temp_values.bit8 = "Not Defined";
                                        temp_values.bit8hfname = hf_bit8cflags;
                                        temp_values.bit9 = "Not Defined";
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
                                                if(value1 > tvb_length_remaining(tvb, ioffset))
                                                {
                                                         break;
                                                }
                                                ioffset += 4;
                                                proto_tree_add_bytes(sub1tree, hf_nds_asn1, tvb, ioffset, value1, tvb_get_ptr(tvb, ioffset, value1));
                                                ioffset += value1;
                                                ioffset += (value1%2);
                                        }
                                        if(values->vflags == 1 || values->vflags == 2 || values->vflags == 4)
                                        {
                                                value1 = tvb_get_letohl(tvb, ioffset);  /* Super Classes */
                                                sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_purge, tvb, ioffset,
                                                        4, value1, "Super Classes %d", value1);
                                                sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                                                ioffset = ioffset + 4;        
                                                for (r = 0; r < value1; r++)
                                                {
                                                        value2 = tvb_get_letohl(tvb, ioffset);
                                                        ioffset = ioffset + 4;
                                                        get_string(tvb, ioffset, value2, mval_buf.buffer);
                                                        temp_values.vstring = mval_buf.buffer;                                
                                                        proto_tree_add_string(sub2tree, hf_nds_super, tvb, ioffset, 
                                                                value2, temp_values.vstring);
                                                        ioffset = ioffset + value2;        
                                                        ioffset += align_4(tvb, ioffset);
                                                }        
                                                value1 = tvb_get_letohl(tvb, ioffset);  /* Containment Classes */
                                                sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_purge, tvb, ioffset,
                                                        4, value1, "Containment Classes %d", value1);
                                                sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                                                ioffset = ioffset + 4;        
                                                for (r = 0; r < value1; r++)
                                                {
                                                        value2 = tvb_get_letohl(tvb, ioffset);
                                                        ioffset = ioffset + 4;
                                                        get_string(tvb, ioffset, value2, mval_buf.buffer);
                                                        temp_values.vstring = mval_buf.buffer;                                
                                                        proto_tree_add_string(sub2tree, hf_nds_base_class, tvb, ioffset, 
                                                                value2, temp_values.vstring);
                                                        ioffset = ioffset + value2;        
                                                        ioffset += align_4(tvb, ioffset);
                                                }        
                                                value1 = tvb_get_letohl(tvb, ioffset);  /* Naming Attributes */
                                                sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_purge, tvb, ioffset,
                                                        4, value1, "Naming Attributes %d", value1);
                                                sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                                                ioffset = ioffset + 4;        
                                                for (r = 0; r < value1; r++)
                                                {
                                                        value2 = tvb_get_letohl(tvb, ioffset);
                                                        ioffset = ioffset + 4;
                                                        get_string(tvb, ioffset, value2, mval_buf.buffer);
                                                        temp_values.vstring = mval_buf.buffer;                                
                                                        proto_tree_add_string(sub2tree, hf_mv_string, tvb, ioffset, 
                                                                value2, temp_values.vstring);
                                                        ioffset = ioffset + value2;        
                                                        ioffset += align_4(tvb, ioffset);
                                                }        
                                                value1 = tvb_get_letohl(tvb, ioffset);  /* Mandatory Attributes */
                                                sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_purge, tvb, ioffset,
                                                        4, value1, "Mandatory Attributes %d", value1);
                                                sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                                                ioffset = ioffset + 4;        
                                                for (r = 0; r < value1; r++)
                                                {
                                                        value2 = tvb_get_letohl(tvb, ioffset);
                                                        ioffset = ioffset + 4;
                                                        get_string(tvb, ioffset, value2, mval_buf.buffer);
                                                        temp_values.vstring = mval_buf.buffer;                                
                                                        proto_tree_add_string(sub2tree, hf_mv_string, tvb, ioffset, 
                                                                value2, temp_values.vstring);
                                                        ioffset = ioffset + value2;        
                                                        ioffset += align_4(tvb, ioffset);
                                                }        
                                                value1 = tvb_get_letohl(tvb, ioffset);  /* Optional Attributes */
                                                sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_purge, tvb, ioffset,
                                                        4, value1, "Optional Attributes %d", value1);
                                                sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                                                ioffset = ioffset + 4;        
                                                for (r = 0; r < value1; r++)
                                                {
                                                        ioffset += align_4(tvb, ioffset);
                                                        value2 = tvb_get_letohl(tvb, ioffset);
                                                        ioffset = ioffset + 4;
                                                        get_string(tvb, ioffset, value2, mval_buf.buffer);
                                                        temp_values.vstring = mval_buf.buffer;                                
                                                        proto_tree_add_string(sub2tree, hf_mv_string, tvb, ioffset, 
                                                                value2, temp_values.vstring);
                                                        ioffset = ioffset + value2;        
                                                        if(tvb_length_remaining(tvb, ioffset) < 4 )
                                                        {
                                                                break;
                                                        }
                                                }        
                                        }
                                        if(values->vflags == 2 || values->vflags == 4)   /* Class Definitions of Super Classes */
                                        {
                                                value1 = tvb_get_letohl(tvb, ioffset);  /* Containment Classes */
                                                sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_purge, tvb, ioffset,
                                                        4, value1, "Containment Classes %d", value1);
                                                sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                                                ioffset = ioffset + 4;        
                                                for (r = 0; r < value1; r++)
                                                {
                                                        value2 = tvb_get_letohl(tvb, ioffset);
                                                        ioffset = ioffset + 4;
                                                        get_string(tvb, ioffset, value2, mval_buf.buffer);
                                                        temp_values.vstring = mval_buf.buffer;                                
                                                        proto_tree_add_string(sub2tree, hf_nds_base_class, tvb, ioffset, 
                                                                value2, temp_values.vstring);
                                                        ioffset = ioffset + value2;        
                                                        ioffset += align_4(tvb, ioffset);
                                                }        
                                                value1 = tvb_get_letohl(tvb, ioffset);  /* Naming Attributes */
                                                sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_purge, tvb, ioffset,
                                                        4, value1, "Naming Attributes %d", value1);
                                                sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                                                ioffset = ioffset + 4;        
                                                for (r = 0; r < value1; r++)
                                                {
                                                        value2 = tvb_get_letohl(tvb, ioffset);
                                                        ioffset = ioffset + 4;
                                                        get_string(tvb, ioffset, value2, mval_buf.buffer);
                                                        temp_values.vstring = mval_buf.buffer;                                
                                                        proto_tree_add_string(sub2tree, hf_mv_string, tvb, ioffset, 
                                                                value2, temp_values.vstring);
                                                        ioffset = ioffset + value2;        
                                                        ioffset += align_4(tvb, ioffset);
                                                }        
                                                value1 = tvb_get_letohl(tvb, ioffset);  /* Mandatory Attributes */
                                                sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_purge, tvb, ioffset,
                                                        4, value1, "Mandatory Attributes %d", value1);
                                                sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                                                ioffset = ioffset + 4;        
                                                for (r = 0; r < value1; r++)
                                                {
                                                        value2 = tvb_get_letohl(tvb, ioffset);
                                                        ioffset = ioffset + 4;
                                                        get_string(tvb, ioffset, value2, mval_buf.buffer);
                                                        temp_values.vstring = mval_buf.buffer;                                
                                                        proto_tree_add_string(sub2tree, hf_mv_string, tvb, ioffset, 
                                                                value2, temp_values.vstring);
                                                        ioffset = ioffset + value2;        
                                                        ioffset += align_4(tvb, ioffset);
                                                }        
                                                value1 = tvb_get_letohl(tvb, ioffset);  /* Optional Attributes */
                                                sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_purge, tvb, ioffset,
                                                        4, value1, "Optional Attributes %d", value1);
                                                sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                                                ioffset = ioffset + 4;        
                                                for (r = 0; r < value1; r++)
                                                {
                                                        value2 = tvb_get_letohl(tvb, ioffset);
                                                        ioffset = ioffset + 4;
                                                        get_string(tvb, ioffset, value2, mval_buf.buffer);
                                                        temp_values.vstring = mval_buf.buffer;                                
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
                                                value1 = tvb_get_letohl(tvb, ioffset);         /* Creation Timestamp */
                                                proto_tree_add_uint_format(sub1tree, hf_es_seconds, tvb, ioffset,
                                                        4, value1, "Creation Timestamp Seconds %d", value1);
                                                ioffset = ioffset + 4;        
                                                replica_num = tvb_get_letohs(tvb, ioffset);   /* Replica */
                                                proto_tree_add_item(sub1tree, hf_nds_replica_num, tvb, ioffset, 
                                                        2, replica_num);
                                                ioffset = ioffset + 2;
                                                event_num = tvb_get_letohs(tvb, ioffset);   /* Event */
                                                proto_tree_add_item(sub1tree, hf_nds_event_num, tvb, ioffset, 
                                                        2, event_num);
                                                ioffset = ioffset + 2;
                                                value1 = tvb_get_letohl(tvb, ioffset);          /* Modification Timestamp */
                                                proto_tree_add_uint_format(sub1tree, hf_es_seconds, tvb, ioffset,
                                                        4, value1, "Modification Timestamp Seconds %d", value1);
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
                                                sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_purge, tvb, ioffset,
                                                        4, value1, "Super Classes %d", value1);
                                                sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                                                ioffset = ioffset + 4;        
                                                for (r = 0; r < value1; r++)
                                                {
                                                        value2 = tvb_get_letohl(tvb, ioffset);
                                                        ioffset = ioffset + 4;
                                                        get_string(tvb, ioffset, value2, mval_buf.buffer);
                                                        temp_values.vstring = mval_buf.buffer;                                
                                                        proto_tree_add_string(sub2tree, hf_nds_super, tvb, ioffset, 
                                                                value2, temp_values.vstring);
                                                        ioffset = ioffset + value2;        
                                                        ioffset += align_4(tvb, ioffset);
                                                }        
                                                value1 = tvb_get_letohl(tvb, ioffset);  /* Containment Classes */
                                                sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_purge, tvb, ioffset,
                                                        4, value1, "Containment Classes %d", value1);
                                                sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                                                ioffset = ioffset + 4;        
                                                for (r = 0; r < value1; r++)
                                                {
                                                        value2 = tvb_get_letohl(tvb, ioffset);
                                                        ioffset = ioffset + 4;
                                                        get_string(tvb, ioffset, value2, mval_buf.buffer);
                                                        temp_values.vstring = mval_buf.buffer;                                
                                                        proto_tree_add_string(sub2tree, hf_nds_base_class, tvb, ioffset, 
                                                                value2, temp_values.vstring);
                                                        ioffset = ioffset + value2;        
                                                        ioffset += align_4(tvb, ioffset);
                                                }        
                                                value1 = tvb_get_letohl(tvb, ioffset);  /* Naming Attributes */
                                                sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_purge, tvb, ioffset,
                                                        4, value1, "Naming Attributes %d", value1);
                                                sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                                                ioffset = ioffset + 4;        
                                                for (r = 0; r < value1; r++)
                                                {
                                                        value2 = tvb_get_letohl(tvb, ioffset);
                                                        ioffset = ioffset + 4;
                                                        get_string(tvb, ioffset, value2, mval_buf.buffer);
                                                        temp_values.vstring = mval_buf.buffer;                                
                                                        proto_tree_add_string(sub2tree, hf_mv_string, tvb, ioffset, 
                                                                value2, temp_values.vstring);
                                                        ioffset = ioffset + value2;        
                                                        ioffset += align_4(tvb, ioffset);
                                                }        
                                                value1 = tvb_get_letohl(tvb, ioffset);  /* Mandatory Attributes */
                                                sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_purge, tvb, ioffset,
                                                        4, value1, "Mandatory Attributes %d", value1);
                                                sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                                                ioffset = ioffset + 4;        
                                                for (r = 0; r < value1; r++)
                                                {
                                                        value2 = tvb_get_letohl(tvb, ioffset);
                                                        ioffset = ioffset + 4;
                                                        get_string(tvb, ioffset, value2, mval_buf.buffer);
                                                        temp_values.vstring = mval_buf.buffer;                                
                                                        proto_tree_add_string(sub2tree, hf_mv_string, tvb, ioffset, 
                                                                value2, temp_values.vstring);
                                                        ioffset = ioffset + value2;        
                                                        ioffset += align_4(tvb, ioffset);
                                                }        
                                                value1 = tvb_get_letohl(tvb, ioffset);  /* Optional Attributes */
                                                sub2item = proto_tree_add_uint_format(sub1tree, hf_nds_purge, tvb, ioffset,
                                                        4, value1, "Optional Attributes %d", value1);
                                                sub2tree = proto_item_add_subtree(sub2item, ett_nds);
                                                ioffset = ioffset + 4;        
                                                for (r = 0; r < value1; r++)
                                                {
                                                        value2 = tvb_get_letohl(tvb, ioffset);
                                                        ioffset = ioffset + 4;
                                                        get_string(tvb, ioffset, value2, mval_buf.buffer);
                                                        temp_values.vstring = mval_buf.buffer;                                
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

                case MVTYPE_MODIFY_CLASS:	/* Modify Class */
                        for (i = 1 ; i <= values->vvalue; i++ )   /* Attribute Names to add*/
                        {
                                ioffset += align_4(tvb, ioffset);
                                value1 = tvb_get_letohl(tvb, ioffset);
                                ioffset = ioffset + 4;
                                get_string(tvb, ioffset, value1, mval_buf.buffer);
                                values->vstring = mval_buf.buffer;                                
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
                                4, value1, "Attribute Names to Delete %d", value1);
                        ioffset = ioffset + 4;        
                        for (i = 1 ; i <= value1; i++ )   /* Attribute Names to delete*/
                        {
                                ioffset += align_4(tvb, ioffset);
                                value2 = tvb_get_letohl(tvb, ioffset);
                                ioffset = ioffset + 4;
                                get_string(tvb, ioffset, value2, mval_buf.buffer);
                                values->vstring = mval_buf.buffer;                                
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
                                4, value1, "ACL Templates to Add %d", value1);
                        ioffset = ioffset + 4;        
                        for (i = 1 ; i <= value1; i++ )   /* ACL templates to add*/
                        {
                                ioffset += align_4(tvb, ioffset);
                                value2 = tvb_get_letohl(tvb, ioffset);  /* Attribute Name */
                                ioffset = ioffset + 4;
                                get_string(tvb, ioffset, value2, mval_buf.buffer);
                                values->vstring = mval_buf.buffer;                                
                                proto_tree_add_string(ntree, hf_nds_attribute_dn, tvb, ioffset, 
                                        value2, values->vstring);
                                ioffset = ioffset + value2;        
                                ioffset += align_4(tvb, ioffset);
                                value2 = tvb_get_letohl(tvb, ioffset);  /* DN of Trustee */
                                ioffset = ioffset + 4;
                                get_string(tvb, ioffset, value2, mval_buf.buffer);
                                values->vstring = mval_buf.buffer;                                
                                proto_tree_add_string(ntree, hf_nds_trustee_dn, tvb, ioffset, 
                                        value2, values->vstring);
                                ioffset = ioffset + value2;        
                                ioffset += align_4(tvb, ioffset);
                                value1 = tvb_get_letohl(tvb, ioffset);    
                                proto_tree_add_uint_format(ntree, hf_nds_privileges, tvb, ioffset,
                                        4, value1, "Priviledges 0x%08x", value1);
                                ioffset = ioffset + 4;        
                        }
                        if(tvb_length_remaining(tvb, ioffset) < 4 )
                        {
                                break;
                        }
                        ioffset += align_4(tvb, ioffset);
                        value1 = tvb_get_letohl(tvb, ioffset);    
                        proto_tree_add_uint_format(ntree, hf_nds_acl_del, tvb, ioffset,
                                4, value1, "ACL Templates to Delete %d", value1);
                        ioffset = ioffset + 4;        
                        for (i = 1 ; i <= value1; i++ )   /* ACL templates to delete*/
                        {
                                ioffset += align_4(tvb, ioffset);
                                value2 = tvb_get_letohl(tvb, ioffset);  /* Attribute Name */
                                ioffset = ioffset + 4;
                                get_string(tvb, ioffset, value2, mval_buf.buffer);
                                values->vstring = mval_buf.buffer;                                
                                proto_tree_add_string(ntree, hf_nds_attribute_dn, tvb, ioffset, 
                                        value2, values->vstring);
                                ioffset = ioffset + value2;        
                                ioffset += align_4(tvb, ioffset);
                                value2 = tvb_get_letohl(tvb, ioffset);  /* DN of Trustee */
                                ioffset = ioffset + 4;
                                get_string(tvb, ioffset, value2, mval_buf.buffer);
                                values->vstring = mval_buf.buffer;                                
                                proto_tree_add_string(ntree, hf_nds_trustee_dn, tvb, ioffset, 
                                        value2, values->vstring);
                                ioffset = ioffset + value2;        
                                ioffset += align_4(tvb, ioffset);
                                value1 = tvb_get_letohl(tvb, ioffset);  /* Priviledges */  
                                proto_tree_add_uint_format(ntree, hf_nds_privileges, tvb, ioffset,
                                        4, value1, "Priviledges 0x%08x", value1);
                                ioffset = ioffset + 4;        
                        }
                        break;
                default:        
                        break;
        }
}

void
dissect_ncp_request(tvbuff_t *tvb, packet_info *pinfo,
		guint16 nw_connection, guint8 sequence,
		guint16 type, proto_tree *ncp_tree)
{
	guint8			func, subfunc = 0;
	gboolean		requires_subfunc;
	gboolean		has_length = TRUE;
	ncp_req_hash_value	*request_value = NULL;
	const ncp_record	*ncp_rec = NULL;
	conversation_t		*conversation;
	ptvcursor_t		*ptvc = NULL;
	proto_tree		*temp_tree = NULL;
	gboolean		run_req_cond = FALSE;
	gboolean		run_info_str = FALSE;
        guint32                 length_remaining;
        guint32                 testvar;

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
                                }        
                        }        
                        else
                        {
			        ncp_rec = &ncp1111_request;
                        }        
			break;
		case NCP_SERVICE_REQUEST:
			ncp_rec = ncp_record_find(func, subfunc);
			break;
		case NCP_DEALLOCATE_SLOT:
			ncp_rec = &ncp5555_request;
			break;
		case NCP_BROADCAST_SLOT:
			ncp_rec = &ncpbbbb_request;
			break;
                case NCP_LIP_ECHO:
                        ncp_rec = &ncplip_echo;
                        break;        
		default:
			ncp_rec = NULL;
	}

	/* Fill in the INFO column. */
	if (check_col(pinfo->cinfo, COL_INFO)) {
       		if (ncp_rec) {
        		col_add_fstr(pinfo->cinfo, COL_INFO, "C %s", ncp_rec->name);
        	}
        	else {
        		if (requires_subfunc) {
        			col_add_fstr(pinfo->cinfo, COL_INFO,
        				"C Unknown Function %u %u (0x%02X/0x%02x)",
        				func, subfunc, func, subfunc);
        		}
        		else {
        			col_add_fstr(pinfo->cinfo, COL_INFO,
        				"C Unknown Function %u (0x%02x)",
        				func, func);
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
		conversation = find_conversation(&pinfo->src, &pinfo->dst,
		    PT_NCP, nw_connection, nw_connection, 0);

		if (conversation == NULL) {
			/* It's not part of any conversation - create a new one. */
			conversation = conversation_new(&pinfo->src, &pinfo->dst,
			    PT_NCP, nw_connection, nw_connection, 0);
		}
		request_value = ncp_hash_insert(conversation, sequence, ncp_rec);
		request_value->req_frame_num = pinfo->fd->num;

		/* If this is the first time we're examining the packet,
		 * check to see if this NCP type uses a "request condition".
		 * If so, we have to build a proto_tree because request conditions
		 * use display filters to work, and without a proto_tree,
		 * display filters can't possibly work. If we already have
		 * a proto_tree, then wonderful. If we don't, we need to build
		 * one. */
		if (ncp_rec) {
       			if (ncp_rec->req_cond_indexes) {
        			run_req_cond = TRUE;
       			}
	        	/* Only create info string if COL_INFO is available. */
	        	if (ncp_rec->req_info_str && check_col(pinfo->cinfo, COL_INFO)) {
	        		run_info_str = TRUE;
	        	}
	        	/* We also have to use a tree if we have to construct an info_str */
	        	if ((run_info_str || run_req_cond) && !ncp_tree) {
	        		proto_item *ti;
                       
	        		temp_tree = proto_tree_create_root();
	        		proto_tree_set_visible(temp_tree, FALSE);
	        		ti = proto_tree_add_item(temp_tree, proto_ncp, tvb, 0, -1, FALSE);
	        		ncp_tree = proto_item_add_subtree(ti, ett_ncp);
                        }
		}
	}

	if (ncp_tree) {
		/* If the dissection throws an exception, be sure to free
		 * the temporary proto_tree that was created. Because of the
		 * way the CLEANUP_PUSH macro works, we can't put it in an 'if'
		 * block; it has to be in the same scope as the terminating
		 * CLEANUP_POP or CLEANUP_POP_AND_ALLOC. So, we always
		 * call CLEANUP_POP and friends, but the value of temp_tree is
		 * NULL if no cleanup is needed, and non-null if cleanup is needed. */
		CLEANUP_PUSH(free_proto_tree, temp_tree);

		/* Before the dissection, if we're saving data for a request
		 * condition, we have to prime the proto tree using the
		 * dfilter information */
		if (run_req_cond) {
			const int	*needed;
			dfilter_t	*dfilter;

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

		conversation = find_conversation(&pinfo->src, &pinfo->dst,
		    PT_NCP, nw_connection, nw_connection, 0);

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

		if (requires_subfunc) {
			if (has_length) {
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
		 * information to display anyway. */
		if (ncp_rec) {
			proto_tree_add_text(ncp_tree, tvb, 6, 1, "Group: %s",
					ncp_groups[ncp_rec->group]);
		}

		if (ncp_rec && ncp_rec->request_ptvc) {
			clear_repeat_vars();
			process_ptvc_record(ptvc, ncp_rec->request_ptvc, NULL, TRUE, ncp_rec);
		}
		ptvcursor_free(ptvc);

		/* Now that the dissection is done, do we need to run
		 * some display filters on the resulting tree in order
		 * to save results for "request conditions" ? */
		if (run_req_cond) {
			const int	*needed;
			gboolean	*results;
			dfilter_t	*dfilter;

			results = g_new0(gboolean, NUM_REQ_CONDS);
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
			int i, len;
			field_info *finfo;
                        int info_type;
                        
			parray = proto_get_finfo_ptr_array(ncp_tree,
				*ncp_rec->req_info_str->hf_ptr);
			len = g_ptr_array_len(parray);
                        
			if (len > 0) {
                        
				col_set_str(pinfo->cinfo, COL_INFO, "C ");

				finfo = g_ptr_array_index(parray, 0);

                                info_type = get_info_type((gchar*) ncp_rec->req_info_str->first_string);
                                                            
                                if (info_type == 2) {    /* Is this  a string or not? */
                                
                                        col_append_fstr(pinfo->cinfo, COL_INFO,
      		               	                (gchar*) ncp_rec->req_info_str->first_string,
                               	                fvalue_get(finfo->value));
                                }
                                else
                                {
                                
            			        col_append_fstr(pinfo->cinfo, COL_INFO,
                			        (gchar*) ncp_rec->req_info_str->first_string,
        		        	        fvalue_get_integer(finfo->value));
                                }
                        }
			if (len > 1) {
				for (i = 1; i < len; i++) {
					finfo = g_ptr_array_index(parray, i);
                                        info_type = get_info_type((gchar*) ncp_rec->req_info_str->repeat_string);
                                                                    
                                        if (info_type == 2) {    /* Is this  a string or not? */
                                        
                                                col_append_fstr(pinfo->cinfo, COL_INFO,
              		               	                (gchar*) ncp_rec->req_info_str->repeat_string,
                                       	                fvalue_get(finfo->value));
                                        }
                                        else
                                        {
                                        
                    			        col_append_fstr(pinfo->cinfo, COL_INFO,
                        			        (gchar*) ncp_rec->req_info_str->repeat_string,
                		        	        fvalue_get_integer(finfo->value));
                                        }
                                }
			}
		}


		/* Free the temporary proto_tree */
		CLEANUP_CALL_AND_POP;
	}
}


void
dissect_ncp_reply(tvbuff_t *tvb, packet_info *pinfo,
	guint16 nw_connection, guint8 sequence, guint16 type,
	proto_tree *ncp_tree)
{
	conversation_t			*conversation = NULL;
	ncp_req_hash_value		*request_value = NULL;
	ncp_req_eid_hash_value		*request_eid_value = NULL;
	const ncp_record		*ncp_rec = NULL;
	int				*req_cond_results;
	guint8				completion_code=0;
	guint				length;
	ptvcursor_t			*ptvc = NULL;
	const char			*error_string;
        guint32                         nds_string_len = 0;
        guint8                          ping_version = 0;
        guint32                         nds_flags = 0;
        guint32                         nds_offset = 0;
        nw_uni_t                        reply_buffer;
        char *                          verb_string="";
        guint32                         nds_error_code = 0;
        guint32                         nds_reply_buffer = 0;
        char *                          nds_error_string = NULL;
        guint32                         nds_frag=0;
	nds_val				pvalues[9];
        gboolean                        resolve_eid=FALSE;
        guint32                         global_eid=0;
        gboolean                        add_eid = FALSE;
        char                            *global_object_name='\0';
	int				i;
        
        reply_buffer.buffer = "\0";
	if (!pinfo->fd->flags.visited) {
		/* Find the conversation whence the request would have come. */
		conversation = find_conversation(&pinfo->src, &pinfo->dst,
			    PT_NCP, nw_connection, nw_connection, 0);
		if (conversation != NULL) {
			/* find the record telling us the request made that caused
			   this reply */
			request_value = ncp_hash_lookup(conversation, sequence);
			if (request_value) {
				ncp_rec = request_value->ncp_rec;
			}
			p_add_proto_data(pinfo->fd, proto_ncp, (void*) request_value);
		}
		/* else... we haven't seen an NCP Request for that conversation and sequence. */
	}
	else {
		request_value = p_get_proto_data(pinfo->fd, proto_ncp);
		if (request_value) {
			ncp_rec = request_value->ncp_rec;
		}
	}

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
	if (ncp_rec && ncp_rec->errors) {
		error_string = ncp_error_string(ncp_rec->errors, completion_code);
	}
	else if (completion_code == 0) {
		if(type == NCP_POSITIVE_ACK)
                {
                        error_string = "Server Busy, Request Being Processed";
                }
                else
                {                
                        error_string = "OK";
                }        
	}
	else {
		error_string = "Not OK";
	}
        if (type == NCP_SERVICE_REPLY && ncp_rec && ncp_rec->func==0x68 &&
            ncp_rec->subfunc==0x02)
        {
                nds_offset = 8;
                nds_reply_buffer = tvb_get_letohl(tvb, nds_offset);        
                nds_frag = tvb_get_letohl(tvb, 12);        
                if (nds_reply_buffer > 7)
                {                        
                        nds_offset = 16; 
                        nds_error_code = tvb_get_letohl(tvb, nds_offset);
                        nds_error_string = match_strval(nds_error_code, nds_reply_errors);
                        if (nds_error_string == NULL)
                        {
                                nds_offset = 19;
                                nds_error_code = tvb_get_letohl(tvb, nds_offset);
                                nds_error_string = match_strval(nds_error_code, nds_reply_errors);
                        }
                        if (nds_error_string == NULL || nds_error_code == 0x00000000)
                        {
                                if (nds_frag != 0xffffffff)
                                {
                                        nds_error_string = "NDS Fragment";
                                }
                                else
                                {        
                                        nds_error_string = "Ok";
                                }
                        }        
                }
        }

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
		    type == NCP_SERVICE_REPLY ? "R" : "ACK",
		    nds_error_string ? nds_error_string : error_string);
	}

	if (ncp_tree) {
		if (request_value) {
			proto_tree_add_uint(ncp_tree, hf_ncp_req_frame_num, tvb, 0, 0,
				request_value->req_frame_num);
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

		proto_tree_add_uint_format(ncp_tree, hf_ncp_completion_code, tvb, 6, 1,
			completion_code, "Completion Code: %d (0x%02x), %s",
			completion_code, completion_code, error_string);

		proto_tree_add_item(ncp_tree, hf_ncp_connection_status, tvb, 7, 1, FALSE);

		/*
		 * Unless this is a reply, that's all there is to parse.
		 */
		if (type != NCP_SERVICE_REPLY)
			return;

                /* Decode NDS Reply packets */
                if (ncp_rec) {
                        if (ncp_rec->func == 0x68 && ncp_rec->subfunc == 0x01) {
                                ping_version = tvb_get_guint8(tvb, 8);
                		proto_tree_add_item(ncp_tree, hf_ping_version, tvb, 8, 1, TRUE);
                                if (ping_version == 9) {
                                        nds_string_len = tvb_get_ntohl(tvb, 9);
                                        nds_offset = nds_string_len+16;
                		        proto_tree_add_item(ncp_tree, hf_nds_tree_name, tvb, 16, nds_string_len, FALSE);
                                       	proto_tree_add_item(ncp_tree, hf_nds_reply_depth, tvb, nds_offset, 4, FALSE);
                                       	proto_tree_add_item(ncp_tree, hf_nds_reply_rev, tvb, (nds_offset+4), 4, FALSE);
                                       	proto_tree_add_item(ncp_tree, hf_nds_reply_flags, tvb, (nds_offset+8), 4, TRUE);
                                }
                                else {
                                        nds_offset = 12;
                                        nds_flags = request_value->req_nds_flags;
                                        if (nds_flags & 0x00200000) {
                                                nds_offset = nds_offset+4;
                                        }
                                        if (nds_flags & 0x00000002) {
                                            	proto_tree_add_item(ncp_tree, hf_nds_reply_depth, tvb, nds_offset, 4, TRUE);
                                                nds_offset = nds_offset+4;
                                        }
                                        if (nds_flags & 0x00000004) {
                                            	proto_tree_add_item(ncp_tree, hf_nds_reply_rev, tvb, nds_offset, 4, TRUE);
                                                nds_offset = nds_offset+4;
                                        }
                                        if (nds_flags & 0x00000008) {
                                            	proto_tree_add_item(ncp_tree, hf_nds_reply_flags, tvb, nds_offset, 4, TRUE);
                                                nds_offset = nds_offset+4;
                                        }
                                        if (nds_flags & 0x00020000) {
                                                nds_string_len = tvb_get_letohl(tvb, nds_offset);
                                                get_string(tvb, nds_offset+4, nds_string_len, reply_buffer.buffer);
                                                proto_tree_add_text(ncp_tree, tvb, nds_offset+4, nds_string_len, "NDS Tree Name: %s", reply_buffer.buffer);
                                        }
                                }        
                        }
                        if (ncp_rec->func == 0x68 && ncp_rec->subfunc == 0x02) 
                        {       
                                nds_offset = 8;
                                        
                                nds_reply_buffer = tvb_get_letohl(tvb, nds_offset);        
                                proto_tree_add_uint(ncp_tree, hf_ncp_fragment_size, tvb, 8,
                                        4, nds_reply_buffer);
                                nds_frag = tvb_get_letohl(tvb, 12);        
                                proto_tree_add_uint(ncp_tree, hf_ncp_fragment_handle, tvb, 12,
                                        4, nds_frag);
                                if (nds_reply_buffer > 7)
                                {                        
                                        proto_tree_add_uint_format(ncp_tree, hf_nds_reply_error, tvb, nds_offset,
                                                4, nds_error_code, "NDS Completion Code: 0x%08x, %s",
        				        nds_error_code, nds_error_string);
                                }
                                if (request_value && nds_error_code == 0x00000000 && nds_frag == 0xffffffff)
                                {
                                        nds_offset = 20;
					for (i = 0; i < 9; i++) {
						pvalues[i].vtype = 0;
						pvalues[i].vvalue = 0;
						pvalues[i].vlength = 0;
						pvalues[i].voffset = 0;
						pvalues[i].hfname = 0;
						pvalues[i].vdesc = "";
						pvalues[i].vstring = "";
					}
                                        switch (request_value->nds_request_verb)
                                        {
                                                case 0x01:
                                                        verb_string = "Resolve Name";
                                                        if(request_value->nds_version == 0)
                                                        { 
                                                                pvalues[0].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                pvalues[0].vstring = match_strval(pvalues[0].vvalue, nds_tags);
                                                                if(pvalues[0].vstring == NULL)
                                                                {
                                                                        pvalues[0].vstring = "No Tags Set";
                                                                }
                                                                pvalues[0].vtype = VTYPE_STRING;
                                                                pvalues[0].vdesc = "Tag: %s";
                                                                pvalues[0].vlength = 4;
                                                                pvalues[0].voffset = nds_offset;
                                                                pvalues[0].hfname = hf_nds_tag_string;
                                                                nds_offset = nds_offset+pvalues[0].vlength;
                                                                switch(pvalues[0].vvalue)
                                                                {
                                                                        case 0:         /* No Such Entry */
                                                                                break;
                                                                        case 1:         /* Local Entry */
                                                                                pvalues[1].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                pvalues[1].vstring = "";
                                                                                pvalues[1].vtype = VTYPE_UINT32;
                                                                                pvalues[1].vdesc = "Entry ID: 0x%08x";
                                                                                add_eid = TRUE;
                                                                                global_object_name = request_value->object_name;
                                                                                global_eid = pvalues[1].vvalue;
                                                                                pvalues[1].vlength = 4;
                                                                                pvalues[1].voffset = nds_offset;
                                                                                pvalues[1].hfname = hf_nds_eid;
                                                                                nds_offset = nds_offset+pvalues[1].vlength;
                                                                                pvalues[2].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                pvalues[2].vtype = VTYPE_MULTIVALUE_UINT32;
                                                                                pvalues[2].vstring = "";
                                                                                pvalues[2].vdesc = "Referral Records: %u";
                                                                                pvalues[2].vlength = 4;
                                                                                pvalues[2].voffset = nds_offset;
                                                                                pvalues[2].hfname = hf_nds_referrals;
                                                                                pvalues[2].mvtype = MVTYPE_LOC_ADDR_REFERRAL_REPLY;
                                                                                break;
                                                                        case 2:         /* Remote Entry */
                                                                                nds_offset += 4;   /* GUINT32 reserved field */
                                                                                pvalues[1].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                pvalues[1].vstring = "";
                                                                                pvalues[1].vtype = VTYPE_UINT32;
                                                                                pvalues[1].vdesc = "Entry ID: 0x%08x";
                                                                                add_eid = TRUE;
                                                                                global_eid = pvalues[1].vvalue;
                                                                                global_object_name = request_value->object_name;
                                                                                pvalues[1].vlength = 4;
                                                                                pvalues[1].voffset = nds_offset;
                                                                                pvalues[1].hfname = hf_nds_eid;
                                                                                nds_offset = nds_offset+pvalues[1].vlength;
                                                                                pvalues[2].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                pvalues[2].vtype = VTYPE_MULTIVALUE_UINT32;
                                                                                pvalues[2].vstring = "";
                                                                                pvalues[2].vdesc = "Referral Records: %u";
                                                                                pvalues[2].vlength = 4;
                                                                                pvalues[2].voffset = nds_offset;
                                                                                pvalues[2].hfname = hf_nds_referrals;
                                                                                pvalues[2].mvtype = MVTYPE_LOC_ADDR_REFERRAL_REPLY;
                                                                                break;
                                                                        case 3:         /* Alias Entry */
                                                                                pvalues[1].vtype = VTYPE_STRING;
                                                                                pvalues[1].vdesc = "Alias Name: %s";
                                                                                pvalues[1].vstring = "";
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
                                                                                get_string(tvb, pvalues[1].voffset, pvalues[1].vlength, pvalues[1].vstring);
                                                                                nds_offset += pvalues[1].vlength;
                                                                                nds_offset += align_4(tvb, nds_offset);
                                                                                pvalues[1].hfname= hf_nds_name;
                                                                                break;
                                                                        case 4:         /* Referral Information */
                                                                                pvalues[1].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                pvalues[1].vstring = "";
                                                                                pvalues[1].vtype = VTYPE_UINT32;
                                                                                pvalues[1].vdesc = "Distance Object is From Root: 0x%08x";
                                                                                pvalues[1].vlength = 4;
                                                                                pvalues[1].voffset = nds_offset;
                                                                                pvalues[1].hfname = hf_nds_eid;
                                                                                nds_offset = nds_offset+pvalues[1].vlength;
                                                                                pvalues[2].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                pvalues[2].vtype = VTYPE_MULTIVALUE_UINT32;
                                                                                pvalues[2].vstring = "";
                                                                                pvalues[2].vdesc = "Referral Records: %u";
                                                                                pvalues[2].vlength = 4;
                                                                                pvalues[2].voffset = nds_offset;
                                                                                pvalues[2].hfname = hf_nds_depth;
                                                                                pvalues[2].mvtype = MVTYPE_LOC_ADDR_REFERRAL_REPLY;
                                                                                break;
                                                                        case 6:          /* Entry and Referrals */
                                                                                pvalues[1].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                pvalues[1].vstring = "";
                                                                                pvalues[1].vtype = VTYPE_UINT32;
                                                                                pvalues[1].vdesc = "Result Flags: 0x%08x";
                                                                                pvalues[1].vlength = 4;
                                                                                pvalues[1].voffset = nds_offset;
                                                                                pvalues[1].hfname = hf_nds_result_flags;
                                                                                nds_offset = nds_offset+pvalues[1].vlength;
                                                                                pvalues[2].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                pvalues[2].vstring = "";
                                                                                pvalues[2].vtype = VTYPE_UINT32;
                                                                                pvalues[2].vdesc = "Entry ID: 0x%08x";
                                                                                add_eid = TRUE;
                                                                                global_eid = pvalues[2].vvalue;
                                                                                global_object_name = request_value->object_name;
                                                                                pvalues[2].vlength = 4;
                                                                                pvalues[2].voffset = nds_offset;
                                                                                pvalues[2].hfname = hf_nds_eid;
                                                                                nds_offset = nds_offset+pvalues[2].vlength;
                                                                                pvalues[3].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                pvalues[3].vtype = VTYPE_MULTIVALUE_UINT32;
                                                                                pvalues[3].vstring = "";
                                                                                pvalues[3].vdesc = "Referral Records: %u";
                                                                                pvalues[3].vlength = 4;
                                                                                pvalues[3].voffset = nds_offset;
                                                                                pvalues[3].mvtype = MVTYPE_ADDR_REFERRAL_REPLY;
                                                                                pvalues[3].hfname = hf_nds_referrals;
                                                                                break;
                                                                        default:
                                                                                break;
                                                                }
                                                        }
                                                        else
                                                        {
                                                                pvalues[0].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                pvalues[0].vstring = "";
                                                                pvalues[0].vtype = VTYPE_UINT32;
                                                                pvalues[0].vdesc = "CRC: 0x%08x";
                                                                pvalues[0].vlength = 4;
                                                                pvalues[0].voffset = nds_offset;
                                                                pvalues[0].hfname = hf_nds_crc;
                                                                nds_offset = nds_offset+pvalues[0].vlength;
                                                                pvalues[1].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                pvalues[1].vstring = match_strval(pvalues[1].vvalue, nds_tags);
                                                                if(pvalues[1].vstring == NULL)
                                                                {
                                                                        pvalues[1].vstring = "No Tags Set";
                                                                }
                                                                pvalues[1].vtype = VTYPE_STRING;
                                                                pvalues[1].vdesc = "Tag: %s";
                                                                pvalues[1].vlength = 4;
                                                                pvalues[1].voffset = nds_offset;
                                                                nds_offset = nds_offset+pvalues[1].vlength;
                                                                pvalues[1].hfname = hf_nds_tag_string;
                                                                switch(pvalues[1].vvalue)
                                                                {
                                                                        case 0:         /* No Such Entry */
                                                                                break;
                                                                        case 1:         /* Local Entry */
                                                                                pvalues[2].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                pvalues[2].vstring = "";
                                                                                pvalues[2].vtype = VTYPE_UINT32;
                                                                                pvalues[2].vdesc = "Entry ID: 0x%08x";
                                                                                add_eid = TRUE;
                                                                                global_eid = pvalues[2].vvalue;
                                                                                global_object_name = request_value->object_name;
                                                                                pvalues[2].vlength = 4;
                                                                                pvalues[2].voffset = nds_offset;
                                                                                pvalues[2].hfname = hf_nds_eid;
                                                                                nds_offset = nds_offset+pvalues[2].vlength;
                                                                                pvalues[3].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                pvalues[3].vtype = VTYPE_MULTIVALUE_UINT32;
                                                                                pvalues[3].vstring = "";
                                                                                pvalues[3].vdesc = "Referral Records: %u";
                                                                                pvalues[3].vlength = 4;
                                                                                pvalues[3].voffset = nds_offset;
                                                                                pvalues[3].hfname = hf_nds_referrals;
                                                                                pvalues[3].mvtype = MVTYPE_LOC_ADDR_REFERRAL_REPLY;
                                                                                break;
                                                                        case 2:         /* Remote Entry */
                                                                                nds_offset += 4;   /* GUINT32 reserved field */
                                                                                pvalues[2].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                pvalues[2].vstring = "";
                                                                                add_eid = TRUE;
                                                                                global_eid = pvalues[2].vvalue;
                                                                                global_object_name = request_value->object_name;
                                                                                pvalues[2].vtype = VTYPE_UINT32;
                                                                                pvalues[2].vdesc = "Entry ID: 0x%08x";
                                                                                pvalues[2].vlength = 4;
                                                                                pvalues[2].voffset = nds_offset;
                                                                                pvalues[2].hfname = hf_nds_eid;
                                                                                nds_offset = nds_offset+pvalues[2].vlength;
                                                                                pvalues[3].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                pvalues[3].vtype = VTYPE_MULTIVALUE_UINT32;
                                                                                pvalues[3].vstring = "";
                                                                                pvalues[3].vdesc = "Referral Records: %u";
                                                                                pvalues[3].vlength = 4;
                                                                                pvalues[3].voffset = nds_offset;
                                                                                pvalues[3].hfname = hf_nds_referrals;
                                                                                pvalues[3].mvtype = MVTYPE_LOC_ADDR_REFERRAL_REPLY;
                                                                                break;
                                                                        case 3:         /* Alias Entry */
                                                                                pvalues[2].vtype = VTYPE_STRING;
                                                                                pvalues[2].vdesc = "Alias Name: %s";
                                                                                pvalues[2].vstring = "";
                                                                                pvalues[2].mvtype = MVTYPE_ATTR_REQUEST;
                                                                                pvalues[2].vvalue = 0;
                                                                                pvalues[2].vlength = 256;
                                                                                pvalues[2].vlength = tvb_get_letohl(tvb, nds_offset);
                                                                                if (pvalues[2].vlength == 0x00)
                                                                                {
                                                                                        pvalues[2].vtype = VTYPE_NONE;
                                                                                        break;
                                                                                }
                                                                                pvalues[2].voffset = nds_offset+4;
                                                                                nds_offset += 4;
                                                                                get_string(tvb, pvalues[2].voffset, pvalues[2].vlength, pvalues[2].vstring);
                                                                                nds_offset += pvalues[2].vlength;
                                                                                nds_offset += align_4(tvb, nds_offset);
                                                                                pvalues[2].hfname= hf_nds_name;
                                                                                break;
                                                                        case 4:         /* Referral Information */
                                                                                pvalues[2].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                pvalues[2].vstring = "";
                                                                                pvalues[2].vtype = VTYPE_UINT32;
                                                                                pvalues[2].vdesc = "Distance Object is From Root: 0x%08x";
                                                                                pvalues[2].vlength = 4;
                                                                                pvalues[2].voffset = nds_offset;
                                                                                pvalues[2].hfname = hf_nds_eid;
                                                                                nds_offset = nds_offset+pvalues[2].vlength;
                                                                                pvalues[3].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                pvalues[3].vtype = VTYPE_MULTIVALUE_UINT32;
                                                                                pvalues[3].vstring = "";
                                                                                pvalues[3].vdesc = "Referral Records: %u";
                                                                                pvalues[3].vlength = 4;
                                                                                pvalues[3].voffset = nds_offset;
                                                                                pvalues[3].hfname = hf_nds_depth;
                                                                                pvalues[3].mvtype = MVTYPE_ADDR_REFERRAL_REPLY;
                                                                                break;
                                                                        case 6:          /* Entry and Referrals */
                                                                                pvalues[2].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                pvalues[2].vstring = "";
                                                                                pvalues[2].vtype = VTYPE_UINT32;
                                                                                pvalues[2].vdesc = "Result Flags: 0x%08x";
                                                                                pvalues[2].vlength = 4;
                                                                                pvalues[2].voffset = nds_offset;
                                                                                pvalues[2].hfname = hf_nds_result_flags;
                                                                                nds_offset = nds_offset+pvalues[2].vlength;
                                                                                pvalues[3].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                pvalues[3].vstring = "";
                                                                                pvalues[3].vtype = VTYPE_UINT32;
                                                                                pvalues[3].vdesc = "Entry ID: 0x%08x";
                                                                                add_eid = TRUE;
                                                                                global_object_name = request_value->object_name;
                                                                                global_eid = pvalues[3].vvalue;
                                                                                pvalues[3].vlength = 4;
                                                                                pvalues[3].voffset = nds_offset;
                                                                                pvalues[3].hfname = hf_nds_eid;
                                                                                nds_offset = nds_offset+pvalues[3].vlength;
                                                                                pvalues[4].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                pvalues[4].vtype = VTYPE_MULTIVALUE_UINT32;
                                                                                pvalues[4].vstring = "";
                                                                                pvalues[4].vdesc = "Referral Records: %u";
                                                                                pvalues[4].vlength = 4;
                                                                                pvalues[4].voffset = nds_offset;
                                                                                pvalues[4].mvtype = MVTYPE_ADDR_REFERRAL_REPLY;
                                                                                pvalues[4].hfname = hf_nds_referrals;
                                                                                break;
                                                                        default:
                                                                                break;
                                                                }
                                                                
                                                        }
                                                        break;
                                                case 0x02:    
                                                        verb_string = "Read Entry Information";
                                                        if(request_value->nds_version != 0x000000fe)
                                                        { 
                                                                pvalues[0].vvalue = 1;
                                                                pvalues[0].vtype = VTYPE_MULTIVALUE_UINT32;
                                                                pvalues[0].vstring = "";
                                                                pvalues[0].vdesc = "Entry Information";
                                                                pvalues[0].vlength = 0;
                                                                pvalues[0].voffset = nds_offset-4;
                                                                pvalues[0].hfname = hf_nds_name;
                                                                pvalues[0].mvtype = MVTYPE_LIST_PARTITIONS;
                                                                pvalues[0].vflags = request_value->req_nds_flags;
                                                        }
                                                        else
                                                        {
                                                                pvalues[0].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                pvalues[0].vstring = "";
                                                                pvalues[0].vtype = VTYPE_UINT32;
                                                                pvalues[0].vdesc = "CRC: 0x%08x";
                                                                pvalues[0].vlength = 4;
                                                                pvalues[0].voffset = nds_offset;
                                                                pvalues[0].hfname = hf_nds_crc;
                                                                nds_offset = nds_offset+pvalues[0].vlength;
                                                                pvalues[1].vvalue = 1;
                                                                pvalues[1].vtype = VTYPE_MULTIVALUE_UINT32;
                                                                pvalues[1].vstring = "";
                                                                pvalues[1].vdesc = "Entry Information";
                                                                pvalues[1].vlength = 0;
                                                                pvalues[1].voffset = nds_offset-4;
                                                                pvalues[1].hfname = hf_nds_name;
                                                                pvalues[1].mvtype = MVTYPE_LIST_PARTITIONS;
                                                                pvalues[1].vflags = request_value->req_nds_flags;
                                                        }
                                                        break;
                                                case 0x03:    
                                                        verb_string = "Read";
                                                        if(request_value->nds_version != 0x000000fe)
                                                        { 
                                                                pvalues[0].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                pvalues[0].vstring = "";
                                                                pvalues[0].vtype = VTYPE_UINT32;
                                                                pvalues[0].vdesc = "Iteration Handle: 0x%08x";
                                                                pvalues[0].vlength = 4;
                                                                pvalues[0].voffset = nds_offset;
                                                                pvalues[0].hfname = hf_nds_iteration;
                                                                nds_offset = nds_offset+pvalues[0].vlength;
                                                                pvalues[1].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                pvalues[1].vstring = match_strval(pvalues[1].vvalue, nds_info_type);
                                                                if(pvalues[1].vstring == NULL)
                                                                {
                                                                        pvalues[1].vstring = "No Info Type Set";
                                                                }
                                                                pvalues[1].vtype = VTYPE_STRING;
                                                                pvalues[1].vdesc = "Info Type: %s";
                                                                pvalues[1].vlength = 4;
                                                                pvalues[1].voffset = nds_offset;
                                                                pvalues[1].hfname = hf_nds_info_type;
                                                                nds_offset = nds_offset+pvalues[1].vlength;
                                                                pvalues[2].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                pvalues[2].vtype = VTYPE_MULTIVALUE_UINT32;
                                                                pvalues[2].vstring = "";
                                                                pvalues[2].vdesc = "Number of Attributes: %u";
                                                                pvalues[2].vlength = 4;
                                                                pvalues[2].voffset = nds_offset;
                                                                pvalues[2].hfname = hf_nds_attr;
                                                                pvalues[2].mvtype = MVTYPE_ATTR_REPLY;
                                                                pvalues[2].vflags = request_value->req_nds_flags;
                                                                pvalues[2].nds_version = request_value->nds_version;
                                                        }
                                                        else
                                                        {
                                                                pvalues[0].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                pvalues[0].vstring = "";
                                                                pvalues[0].vtype = VTYPE_UINT32;
                                                                pvalues[0].vdesc = "CRC: 0x%08x";
                                                                pvalues[0].vlength = 4;
                                                                pvalues[0].voffset = nds_offset;
                                                                pvalues[0].hfname = hf_nds_crc;
                                                                nds_offset = nds_offset+pvalues[0].vlength;
                                                                pvalues[1].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                pvalues[1].vstring = "";
                                                                pvalues[1].vtype = VTYPE_UINT32;
                                                                pvalues[1].vdesc = "Iteration Handle: 0x%08x";
                                                                pvalues[1].vlength = 4;
                                                                pvalues[1].voffset = nds_offset;
                                                                pvalues[1].hfname = hf_nds_iteration;
                                                                nds_offset = nds_offset+pvalues[1].vlength;
                                                                pvalues[2].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                pvalues[2].vstring = match_strval(pvalues[2].vvalue, nds_info_type);
                                                                if(pvalues[2].vstring == NULL)
                                                                {
                                                                        pvalues[2].vstring = "No Info Type Set";
                                                                }
                                                                pvalues[2].vtype = VTYPE_STRING;
                                                                pvalues[2].vdesc = "Info Type: %s";
                                                                pvalues[2].vlength = 4;
                                                                pvalues[2].voffset = nds_offset;
                                                                pvalues[2].hfname = hf_nds_info_type;
                                                                nds_offset = nds_offset+pvalues[2].vlength;
                                                                pvalues[3].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                pvalues[3].vtype = VTYPE_MULTIVALUE_UINT32;
                                                                pvalues[3].vstring = "";
                                                                pvalues[3].vdesc = "Number of Attributes: %u";
                                                                pvalues[3].vlength = 4;
                                                                pvalues[3].voffset = nds_offset;
                                                                pvalues[3].hfname = hf_nds_attr;
                                                                pvalues[3].mvtype = MVTYPE_ATTR_REPLY;
                                                                pvalues[3].vflags = request_value->req_nds_flags;
                                                                pvalues[3].nds_version = request_value->nds_version;
                                                        }
                                                        break;
                                                case 0x04:    
                                                        verb_string = "Compare";
                                                        pvalues[0].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                        if (pvalues[0].vvalue == 0x00000000)
                                                        {
                                                                pvalues[0].vstring = "Did Not Match";
                                                        }        
                                                        else
                                                        {
                                                                pvalues[0].vstring = "Matched";
                                                        }
                                                        pvalues[0].vtype = VTYPE_STRING;
                                                        pvalues[0].vdesc = "Compare Values Returned - %s";
                                                        pvalues[0].vlength = 4;
                                                        pvalues[0].voffset = nds_offset;
                                                        pvalues[0].mvtype = 0;
                                                        pvalues[0].hfname= hf_nds_compare_results;
                                                        nds_offset += pvalues[0].vlength;
                                                        break;
                                                case 0x05:    
                                                        verb_string = "List";
                                                        pvalues[0].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                        pvalues[0].vstring = "";
                                                        pvalues[0].vtype = VTYPE_UINT32;
                                                        pvalues[0].vdesc = "Iteration Handle: 0x%08x";
                                                        pvalues[0].vlength = 4;
                                                        pvalues[0].voffset = nds_offset;
                                                        pvalues[0].hfname = hf_nds_iteration;
                                                        nds_offset = nds_offset+pvalues[0].vlength;
                                                        pvalues[1].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                        pvalues[1].vtype = VTYPE_MULTIVALUE_UINT32;
                                                        pvalues[1].vstring = "";
                                                        pvalues[1].vdesc = "Entry Information";
                                                        pvalues[1].vlength = 0;
                                                        pvalues[1].voffset = nds_offset;
                                                        pvalues[1].hfname = hf_nds_name;
                                                        pvalues[1].mvtype = MVTYPE_LIST_PARTITIONS;
                                                        pvalues[1].vflags = request_value->req_nds_flags;
                                                        break;
                                                case 0x06:    
                                                        verb_string = "Search Entries";
                                                        break;
                                                case 0x07:    
                                                        verb_string = "Add Entry";
                                                        break;
                                                case 0x08:    
                                                        verb_string = "Remove Entry";
                                                        break;
                                                case 0x09:    
                                                        verb_string = "Modify Entry";
                                                        break;
                                                case 0x0a:    
                                                        verb_string = "Modify RDN";
                                                        break;
                                                case 0x0b:    
                                                        verb_string = "Define Attribute";
                                                        break;
                                                case 0x0c:    
                                                        verb_string = "Read Attribute Definition";
                                                        break;
                                                case 0x0d:    
                                                        verb_string = "Remove Attribute Definition";
                                                        break;
                                                case 0x0e:    
                                                        verb_string = "Define Class";
                                                        break;
                                                case 0x0f:    
                                                        verb_string = "Read Class Definition";
                                                        pvalues[0].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                        pvalues[0].vstring = "";
                                                        pvalues[0].vtype = VTYPE_UINT32;
                                                        pvalues[0].vdesc = "Iteration Handle: 0x%08x";
                                                        pvalues[0].vlength = 4;
                                                        pvalues[0].voffset = nds_offset;
                                                        pvalues[0].hfname = hf_nds_iteration;
                                                        nds_offset = nds_offset+pvalues[0].vlength;
                                                        pvalues[1].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                        pvalues[1].vstring = match_strval(pvalues[1].vvalue, class_def_type);
                                                        if(pvalues[1].vstring == NULL)
                                                        {
                                                                pvalues[1].vstring = "No Class Definition Type Set";
                                                        }
                                                        pvalues[1].vtype = VTYPE_STRING;
                                                        pvalues[1].vdesc = "Class Definition Type: %s";
                                                        pvalues[1].vlength = 4;
                                                        pvalues[1].voffset = nds_offset;
                                                        pvalues[1].mvtype = 0;
                                                        pvalues[1].hfname= hf_nds_class_def_type;
                                                        nds_offset = nds_offset + pvalues[1].vlength;
                                                        pvalues[2].vvalue = tvb_get_letohl(tvb, nds_offset);;
                                                        pvalues[2].vtype = VTYPE_MULTIVALUE_UINT32;
                                                        pvalues[2].vstring = "";
                                                        pvalues[2].vdesc = "Class Definitions %u";
                                                        pvalues[2].vlength = 0;
                                                        pvalues[2].voffset = nds_offset;
                                                        pvalues[2].hfname = hf_nds_classes;
                                                        pvalues[2].mvtype = MVTYPE_CLASS_NAMES;
                                                        pvalues[2].vflags = request_value->req_nds_flags;
                                                        break;
                                                case 0x10:    
                                                        verb_string = "Modify Class Definition";
                                                        break;
                                                case 0x11:    
                                                        verb_string = "Remove Class Definition";
                                                        break;
                                                case 0x12:    
                                                        verb_string = "List Containable Classes";
                                                        pvalues[0].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                        pvalues[0].vstring = "";
                                                        pvalues[0].vtype = VTYPE_UINT32;
                                                        pvalues[0].vdesc = "Iteration Handle: 0x%08x";
                                                        pvalues[0].vlength = 4;
                                                        pvalues[0].voffset = nds_offset;
                                                        pvalues[0].hfname = hf_nds_iteration;
                                                        nds_offset = nds_offset+pvalues[0].vlength;
                                                        pvalues[1].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                        pvalues[1].vtype = VTYPE_MULTIVALUE_UINT32;
                                                        pvalues[1].vstring = "";
                                                        pvalues[1].vdesc = "Classes: %u";
                                                        pvalues[1].vlength = 4;
                                                        pvalues[1].voffset = nds_offset;
                                                        pvalues[1].mvtype = MVTYPE_READ_CLASS_REQ;
                                                        pvalues[1].hfname= hf_nds_classes;
                                                        break;
                                                case 0x13:    
                                                        pvalues[0].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                        pvalues[0].vstring = "";
                                                        pvalues[0].vtype = VTYPE_UINT32;
                                                        pvalues[0].vdesc = "Privileges: 0x%08x";
                                                        pvalues[0].vlength = 4;
                                                        pvalues[0].voffset = nds_offset;
                                                        pvalues[0].hfname = hf_nds_privileges;
                                                        nds_offset = nds_offset+pvalues[0].vlength;
                                                        break;
                                                case 0x14:    
                                                        verb_string = "Add Partition";
                                                        break;
                                                case 0x15:    
                                                        verb_string = "Remove Partition";
                                                        break;
                                                case 0x16:    
                                                        verb_string = "List Partitions";
                                                        pvalues[0].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                        pvalues[0].vstring = "";
                                                        pvalues[0].vtype = VTYPE_UINT32;
                                                        pvalues[0].vdesc = "Iteration Handle: 0x%08x";
                                                        pvalues[0].vlength = 4;
                                                        pvalues[0].voffset = nds_offset;
                                                        pvalues[0].hfname = hf_nds_iteration;
                                                        nds_offset = nds_offset+pvalues[0].vlength;
                                                        pvalues[1].vtype = VTYPE_STRING;
                                                        pvalues[1].vdesc = "Server Distinguished Name: %s";
                                                        pvalues[1].vstring = "";
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
                                                        get_string(tvb, pvalues[1].voffset, pvalues[1].vlength, pvalues[1].vstring);
                                                        nds_offset += pvalues[1].vlength;
                                                        nds_offset += align_4(tvb, nds_offset);
                                                        pvalues[1].hfname= hf_nds_name;
                                                        nds_offset += align_4(tvb, nds_offset);
                                                        pvalues[2].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                        pvalues[2].vtype = VTYPE_MULTIVALUE_UINT32;
                                                        pvalues[2].vstring = "";
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
                                                        verb_string = "Split Partition";
                                                        break;
                                                case 0x18:    
                                                        verb_string = "Join Partitions";
                                                        break;
                                                case 0x19:    
                                                        verb_string = "Add Replica";
                                                        break;
                                                case 0x1a:    
                                                        verb_string = "Remove Replica";
                                                        break;
                                                case 0x1b:    
                                                        verb_string = "Open Stream";
                                                        pvalues[0].vvalue = tvb_get_ntohl(tvb, nds_offset);
                                                        pvalues[0].vstring = "";
                                                        pvalues[0].vtype = VTYPE_UINT32;
                                                        pvalues[0].vdesc = "File Handle: 0x%08x";
                                                        pvalues[0].vlength = 4;
                                                        pvalues[0].voffset = nds_offset;
                                                        pvalues[0].hfname = hf_nds_file_handle;
                                                        nds_offset = nds_offset+pvalues[0].vlength;
                                                        pvalues[1].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                        pvalues[1].vstring = "";
                                                        pvalues[1].vtype = VTYPE_UINT32;
                                                        pvalues[1].vdesc = "File Size: %u";
                                                        pvalues[1].vlength = 4;
                                                        pvalues[1].voffset = nds_offset;
                                                        pvalues[1].hfname = hf_nds_file_size;
                                                        nds_offset = nds_offset+pvalues[1].vlength;
                                                        break;
                                                case 0x1c:    
                                                        verb_string = "Search Filter";
                                                        break;
                                                case 0x1d:    
                                                        verb_string = "Create Subordinate Reference";
                                                        break;
                                                case 0x1e:    
                                                        verb_string = "Link Replica";
                                                        break;
                                                case 0x1f:    
                                                        verb_string = "Change Replica Type";
                                                        break;
                                                case 0x20:    
                                                        verb_string = "Start Update Schema";
                                                        break;
                                                case 0x21:    
                                                        verb_string = "End Update Schema";
                                                        break;
                                                case 0x22:    
                                                        verb_string = "Update Schema";
                                                        break;
                                                case 0x23:    
                                                        verb_string = "Start Update Replica";
                                                        break;
                                                case 0x24:    
                                                        verb_string = "End Update Replica";
                                                        break;
                                                case 0x25:    
                                                        verb_string = "Update Replica";
                                                        break;
                                                case 0x26:    
                                                        verb_string = "Synchronize Partition";
                                                        break;
                                                case 0x27:    
                                                        verb_string = "Synchronize Schema";
                                                        break;
                                                case 0x28:    
                                                        verb_string = "Read Syntaxes";
                                                        break;
                                                case 0x29:    
                                                        verb_string = "Get Replica Root ID";
                                                        break;                  
                                                case 0x2a:    
                                                        verb_string = "Begin Move Entry";
                                                        break;
                                                case 0x2b:    
                                                        verb_string = "Finish Move Entry";
                                                        break;
                                                case 0x2c:    
                                                        verb_string = "Release Moved Entry";
                                                        break;
                                                case 0x2d:    
                                                        verb_string = "Backup Entry";
                                                        break;
                                                case 0x2e:    
                                                        verb_string = "Restore Entry";
                                                        break;
                                                case 0x2f:    
                                                        verb_string = "Save DIB";
                                                        break;
                                                case 0x30:
                                                        verb_string = "Control";
                                                        break;
                                                case 0x31:
                                                        verb_string = "Remove Backlink";
                                                        break;
                                                case 0x32:    
                                                        verb_string = "Close Iteration";
                                                        break;
                                                case 0x33:    
                                                        verb_string = "Mutate Entry";
                                                        break;
                                                case 0x34:    
                                                        verb_string = "Audit Skulking";
                                                        break;
                                                case 0x35:    
                                                        verb_string = "Get Server Address";
                                                        if(request_value->nds_version != 0x000000fe)
                                                        { 
                                                                pvalues[0].vtype = VTYPE_STRING;
                                                                pvalues[0].vdesc = "Distinguished Name: %s";
                                                                pvalues[0].vstring = "";
                                                                pvalues[0].mvtype = MVTYPE_ATTR_REQUEST;
                                                                pvalues[0].vvalue = 0;
                                                                pvalues[0].vlength = 256;
                                                                pvalues[0].vlength = tvb_get_letohl(tvb, nds_offset);
                                                                if (pvalues[0].vlength == 0x00)
                                                                {
                                                                        pvalues[0].vtype = VTYPE_NONE;
                                                                        break;
                                                                }
                                                                pvalues[0].voffset = nds_offset+4;
                                                                nds_offset += 4;
                                                                get_string(tvb, pvalues[0].voffset, pvalues[0].vlength, pvalues[0].vstring);
                                                                nds_offset += pvalues[0].vlength;
                                                                nds_offset += align_4(tvb, nds_offset);
                                                                pvalues[0].hfname= hf_nds_name;
                                                                pvalues[1].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                pvalues[1].vtype = VTYPE_MULTIVALUE_UINT32;
                                                                pvalues[1].vstring = "";
                                                                pvalues[1].vdesc = "Referral Records: %u";
                                                                pvalues[1].vlength = 4;
                                                                pvalues[1].voffset = nds_offset;
                                                                pvalues[1].hfname = hf_nds_referrals;
                                                                pvalues[1].mvtype = MVTYPE_LOC_ADDR_REFERRAL_REPLY;
                                                        }
                                                        else
                                                        {
                                                                pvalues[0].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                pvalues[0].vstring = "";
                                                                pvalues[0].vtype = VTYPE_UINT32;
                                                                pvalues[0].vdesc = "Iteration Handle: 0x%08x";
                                                                pvalues[0].vlength = 4;
                                                                pvalues[0].voffset = nds_offset;
                                                                pvalues[0].hfname = hf_nds_iteration;
                                                                nds_offset = nds_offset+pvalues[0].vlength;
                                                                pvalues[1].vtype = VTYPE_STRING;
                                                                pvalues[1].vdesc = "Distinguished Name: %s";
                                                                pvalues[1].vstring = "";
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
                                                                get_string(tvb, pvalues[1].voffset, pvalues[1].vlength, pvalues[1].vstring);
                                                                nds_offset += pvalues[1].vlength;
                                                                nds_offset += align_4(tvb, nds_offset);
                                                                pvalues[1].hfname= hf_nds_name;
                                                                pvalues[2].vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                pvalues[2].vtype = VTYPE_MULTIVALUE_UINT32;
                                                                pvalues[2].vstring = "";
                                                                pvalues[2].vdesc = "Referral Records: %u";
                                                                pvalues[2].vlength = 4;
                                                                pvalues[2].voffset = nds_offset;
                                                                pvalues[2].hfname = hf_nds_referrals;
                                                                pvalues[2].mvtype = MVTYPE_LOC_ADDR_REFERRAL_REPLY;
                                                        }        
                                                        break;
                                                case 0x36:    
                                                        verb_string = "Set Keys";
                                                        break;
                                                case 0x37:    
                                                        verb_string = "Change Password";
                                                        break;
                                                case 0x38:    
                                                        verb_string = "Verify Password";
                                                        break;
                                                case 0x39:    
                                                        verb_string = "Begin Login";
                                                        break;
                                                case 0x3a:    
                                                        verb_string = "Finish Login";
                                                        break;
                                                case 0x3b:    
                                                        verb_string = "Begin Authentication";
                                                        break;
                                                case 0x3c:    
                                                        verb_string = "Finish Authentication";
                                                        break;
                                                case 0x3d:    
                                                        verb_string = "Logout";
                                                        break;
                                                case 0x3e:    
                                                        verb_string = "Repair Ring";
                                                        break;
                                                case 0x3f:    
                                                        verb_string = "Repair Timestamps";
                                                        break;
                                                case 0x40:    
                                                        verb_string = "Create Back Link";
                                                        break;
                                                case 0x41:              
                                                        verb_string = "Delete External Reference";
                                                        break;
                                                case 0x42:    
                                                        verb_string = "Rename External Reference";
                                                        break;
                                                case 0x43:    
                                                        verb_string = "Create Directory Entry";
                                                        break;
                                                case 0x44:    
                                                        verb_string = "Remove Directory Entry";
                                                        break;
                                                case 0x45:    
                                                        verb_string = "Designate New Master";
                                                        break;
                                                case 0x46:    
                                                        verb_string = "Change Tree Name";
                                                        break;
                                                case 0x47:    
                                                        verb_string = "Partition Entry Count";
                                                        break;
                                                case 0x48:    
                                                        verb_string = "Check Login Restrictions";
                                                        break;
                                                case 0x49:    
                                                        verb_string = "Start Join";
                                                        break;
                                                case 0x4a:    
                                                        verb_string = "Low Level Split";
                                                        break;
                                                case 0x4b:    
                                                        verb_string = "Low Level Join";
                                                        break;
                                                case 0x4c:    
                                                        verb_string = "Abort Low Level Join";
                                                        break;
                                                case 0x4d:    
                                                        verb_string = "Get All Servers";
                                                        break;
               		                        default:
                       			                verb_string = "NDS Continuation Fragment";
                                                        break;
                                        }        
        			        if(request_value->nds_request_verb != 0)
                                        {
                                                proto_tree_add_uint_format(ncp_tree, hf_ncp_nds_verb, tvb, 6, 0,
			        	                request_value->nds_request_verb, "NDS Verb: %d, %s",
				                        request_value->nds_request_verb, verb_string);
                                        }
                                        /* NDS Entry ID's (EID) is identified in the reply packet of an NDS 
	                                 * resolve name. We need to store this EID and it's associated
	                                 * name into our hash so that we can resolve the name for 
	                                 * other NDS requests. */
                                        if (!pinfo->fd->flags.visited) {
                                                if(add_eid)
                                                {
			                                request_eid_value = ncp_eid_hash_lookup(conversation, global_eid);
			                                        if (!request_eid_value) {
        	                                                        request_eid_value = ncp_eid_hash_insert(global_eid);
                                                                        strcpy(request_eid_value->object_name, global_object_name);
                                                                }        
                                                }
                                        }
                                        /* For NDS requests with just an EID, resolve name from hash table. */
                                        if(resolve_eid)
                                        {
			                        request_eid_value = ncp_eid_hash_lookup(conversation, global_eid);
			                        if (request_eid_value) {
                                                        global_object_name = request_eid_value->object_name;
                                                        proto_tree_add_string_format(ncp_tree, hf_nds_name, tvb, 6, 0,
	        		        	                global_object_name, "NDS Name for EID - %s",
		        		                        global_object_name);
			                        }
                                        }
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
							    pvalues[i].vlength, pvalues[i].vstring, pvalues[i].vdesc,
							    pvalues[i].vstring);
							break;

						case VTYPE_BITFIELD:
							process_bitfield(ncp_tree, tvb, &pvalues[i]);
							break;

						case VTYPE_MULTIVALUE_UINT32:
							process_multivalues(ncp_tree, tvb, &pvalues[i]);
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
                }

		length = tvb_length(tvb);
		if (!ncp_rec && length > 8) {
			proto_tree_add_text(ncp_tree, tvb, 8, length - 8,
					"No request record found. Parsing is impossible.");
		}
		else if (ncp_rec && ncp_rec->reply_ptvc) {
			/* If a non-zero completion code was found, it is
			 * legal to not have any fields, even if the packet
			 * type is defined as having fields. */
			if (completion_code != 0 && tvb_length(tvb) == 8) {
				return;
			}
			/*printf("func=0x%x subfunc=0x%x\n", ncp_rec->func, ncp_rec->subfunc);*/

			/* Any request condition results? */
			if (request_value) {
				req_cond_results = request_value->req_cond_results;
			}
			else {
				req_cond_results = NULL;
			}

			clear_repeat_vars();
			ptvc = ptvcursor_new(ncp_tree, tvb, 8);
			process_ptvc_record(ptvc, ncp_rec->reply_ptvc, req_cond_results,
					TRUE, ncp_rec);
			ptvcursor_free(ptvc);
		}
	}
}

void
dissect_nds_request(tvbuff_t *tvb, packet_info *pinfo,
		guint16 nw_connection, guint8 sequence,
		guint16 type, proto_tree *ncp_tree)
{
	guint8			func, subfunc = 0;
	ncp_req_hash_value	*request_value = NULL;
	ncp_req_eid_hash_value	*request_eid_value = NULL;
	const ncp_record	*ncp_rec = NULL;          
	conversation_t		*conversation;
	ptvcursor_t		*ptvc = NULL;
	proto_tree		*temp_tree = NULL;
        guint8                  nds_verb = 0;
        char *                  verb_string = "";
        guint32                 nds_frag = 0;
        nds_val			pvalues[9];
        guint8                  nds_version = 0;
        guint32                 foffset = 0;
        guint32                 nds_reply_buffer;
        nw_uni_t                req_buffer;
        char *                  global_object_name="\0";
        guint32                 global_eid=0;
        gboolean                resolve_eid=FALSE;
        guint32                 global_flags=0;
	int			i;
        
	for (i = 0; i < 9; i++) {
		pvalues[i].vtype = 0;
		pvalues[i].mvtype = 0;
	}
        req_buffer.buffer = "\0";
        func = tvb_get_guint8(tvb, 6);
        subfunc = tvb_get_guint8(tvb, 7);
        
       	ncp_rec = ncp_record_find(func, subfunc);

        /* Check to see if this is a fragment packet */
        nds_frag = tvb_get_letohl(tvb, 8);
        
        /* Get NDS Verb */
        if (nds_frag == 0xffffffff) {
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
                nds_reply_buffer = tvb_get_letohl(tvb, foffset);        
                proto_tree_add_uint(ncp_tree, hf_nds_buffer_size, tvb, foffset,
                        4, nds_reply_buffer);
                foffset = foffset+4;        
                switch(nds_verb) {
                
                        case 0x01:
                                verb_string = "Resolve Name -> ";
                                pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
                                nds_version = pvalues[0].vvalue;
                                pvalues[0].vstring = "";
                                pvalues[0].vtype = VTYPE_UINT32;
                                pvalues[0].vdesc = "Version: %u";
                                pvalues[0].vlength = 4;
                                pvalues[0].hfname = hf_nds_ver;
                                pvalues[0].voffset = foffset;
                                foffset = foffset+pvalues[0].vlength;
                                pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[1].vtype = VTYPE_BITFIELD;
                                pvalues[1].vstring = "";
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
                                        pvalues[2].vstring = "";
                                        pvalues[2].vlength = 4;
                                        pvalues[2].voffset = foffset;
                                        pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
                                        pvalues[2].hfname= hf_nds_scope;
                                        foffset = foffset+pvalues[2].vlength;
                                        pvalues[3].vtype = VTYPE_STRING;
                                        pvalues[3].vdesc = "Name: %s";
                                        pvalues[3].vstring = "";
                                        pvalues[3].mvtype = MVTYPE_ATTR_REQUEST;
                                        pvalues[3].vvalue = 0;
                                        pvalues[3].vlength = 256;
                                        pvalues[3].vlength = tvb_get_letohl(tvb, foffset);
                                        if (pvalues[3].vlength == 0x00)
                                        {
                                                pvalues[3].vtype = VTYPE_NONE;
                                                break;
                                        }
                                        pvalues[3].voffset = foffset+4;
                                        foffset = foffset + 4;
                                        get_string(tvb, pvalues[3].voffset, pvalues[3].vlength, req_buffer.buffer);
                                        pvalues[3].vstring = req_buffer.buffer;
                                        global_object_name = req_buffer.buffer;
                                        pvalues[3].hfname= hf_nds_name;
                                        foffset = foffset+pvalues[3].vlength;
                                        foffset += align_4(tvb, foffset);
                                        pvalues[4].vvalue = tvb_get_letohl(tvb, foffset);
                                        pvalues[4].vtype = VTYPE_MULTIVALUE_UINT32;
                                        pvalues[4].vstring = "";
                                        pvalues[4].vdesc = "Communications Transports: %u";
                                        pvalues[4].vlength = 4;
                                        pvalues[4].hfname= hf_nds_comm_trans;
                                        pvalues[4].voffset = foffset;
                                        pvalues[4].mvtype = MVTYPE_ADDR_REFERRAL_REQUEST;
                                        foffset = foffset + (pvalues[4].vvalue * 4) + 4;
                                        pvalues[5].vvalue = tvb_get_letohl(tvb, foffset);
                                        pvalues[5].vtype = VTYPE_MULTIVALUE_UINT32;
                                        pvalues[5].vstring = "";
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
                                        pvalues[2].vstring = "";
                                        pvalues[2].vlength = 4;
                                        pvalues[2].voffset = foffset;
                                        pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
                                        pvalues[2].hfname= hf_min_nds_ver;
                                        foffset = foffset+pvalues[2].vlength;
                                        pvalues[3].vvalue = tvb_get_letohl(tvb, foffset);
                                        pvalues[3].vtype = VTYPE_MULTIVALUE_UINT32;
                                        pvalues[3].vstring = "";
                                        pvalues[3].vdesc = "Number of Versions to Include: %u";
                                        pvalues[3].vlength = 4;
                                        pvalues[3].mvtype = MVTYPE_ATTR_REQUEST2;
                                        pvalues[3].voffset = foffset;
                                        pvalues[3].hfname= hf_nds_ver_include;
                                        foffset += (pvalues[3].vvalue * 4) + 4;
                                        pvalues[4].vvalue = tvb_get_letohl(tvb, foffset);
                                        pvalues[4].vtype = VTYPE_MULTIVALUE_UINT32;
                                        pvalues[4].vstring = "";
                                        pvalues[4].vdesc = "Number of Versions to Exclude: %u";
                                        pvalues[4].vlength = 4;
                                        pvalues[4].mvtype = MVTYPE_ATTR_REQUEST2;
                                        pvalues[4].hfname= hf_nds_ver_exclude;
                                        pvalues[4].voffset = foffset;
                                        foffset += 4;
                                        pvalues[5].vtype = VTYPE_UINT32;
                                        pvalues[5].vdesc = "DN Output Type: %u";
                                        pvalues[5].vstring = "";
                                        pvalues[5].vlength = 4;
                                        pvalues[5].voffset = foffset;
                                        pvalues[5].vvalue = tvb_get_letohl(tvb, foffset);
                                        pvalues[5].hfname= hf_nds_dn_output_type;
                                        foffset = foffset+pvalues[5].vlength;
                                        pvalues[6].vtype = VTYPE_UINT32;
                                        pvalues[6].vdesc = "Nested Output Type: %u";
                                        pvalues[6].vstring = "";
                                        pvalues[6].vlength = 4;
                                        pvalues[6].voffset = foffset;
                                        pvalues[6].vvalue = tvb_get_letohl(tvb, foffset);
                                        pvalues[6].hfname= hf_nds_nested_output_type;
                                        foffset = foffset+pvalues[6].vlength;
                                        pvalues[7].vtype = VTYPE_STRING;
                                        pvalues[7].vdesc = "Output Delimiter: %s";
                                        pvalues[7].vstring = "";
                                        pvalues[7].mvtype = MVTYPE_ATTR_REQUEST;
                                        pvalues[7].vvalue = 0;
                                        pvalues[7].vlength = 256;
                                        pvalues[7].vlength = tvb_get_letohl(tvb, foffset);
                                        pvalues[7].voffset = foffset+4;
                                        foffset = foffset + 4;
                                        get_string(tvb, pvalues[7].voffset, pvalues[7].vlength, req_buffer.buffer);
                                        pvalues[7].vstring = req_buffer.buffer;
                                        pvalues[7].hfname= hf_nds_output_delimiter;
                                        foffset = foffset+pvalues[7].vlength;
                                        foffset += align_4(tvb, foffset);
                                        pvalues[8].vvalue = tvb_get_letohl(tvb, foffset);
                                        pvalues[8].vtype = VTYPE_MULTIVALUE_UINT32;
                                        pvalues[8].vstring = "";
                                        pvalues[8].vdesc = "Size of Entry Specifier: %u";
                                        pvalues[8].vlength = 4;
                                        pvalues[8].mvtype = MVTYPE_PROC_ENTRY_SPECIFIERS;
                                        pvalues[8].hfname= hf_nds_output_entry_specifier;
                                        pvalues[8].voffset = foffset;
                                }
                                break;
                        case 0x02:    
                                verb_string = "Read Entry Information";
                                pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[0].vstring = "";
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
                                                pvalues[1].vstring = "";
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
                                                pvalues[1].vstring = "";
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
                                                if((pvalues[1].vvalue&&0xf000) == 0xc000)
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
                                                pvalues[3].vstring = "";
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
                                                pvalues[1].vstring = "";
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
                                                if((pvalues[1].vvalue&&0xf000) == 0xc000)
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
                                                pvalues[3].vstring = "";
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
                                                pvalues[4].vstring = "";
                                                pvalues[4].vdesc = "Information Flags (high) Byte:";
                                                pvalues[4].vlength = 2;
                                                pvalues[4].hfname= hf_nds_rflags;
                                                pvalues[4].voffset = foffset;
                                                pvalues[4].bit1 = "Purge Time";
                                                pvalues[4].bit1hfname = hf_bit1infoflagsh;
                                                pvalues[4].bit2 = "Dereference Base Class";
                                                pvalues[4].bit2hfname = hf_bit2infoflagsh;
                                                pvalues[4].bit3 = "Not Defined";
                                                pvalues[4].bit3hfname = hf_bit3infoflagsh;
                                                pvalues[4].bit4 = "Not Defined";
                                                pvalues[4].bit4hfname = hf_bit4infoflagsh;
                                                pvalues[4].bit5 = "Not Defined";
                                                pvalues[4].bit5hfname = hf_bit5infoflagsh;
                                                pvalues[4].bit6 = "Not Defined";
                                                pvalues[4].bit6hfname = hf_bit6infoflagsh;
                                                pvalues[4].bit7 = "Not Defined";
                                                pvalues[4].bit7hfname = hf_bit7infoflagsh;
                                                pvalues[4].bit8 = "Not Defined";
                                                pvalues[4].bit8hfname = hf_bit8infoflagsh;
                                                pvalues[4].bit9 = "Not Defined";
                                                pvalues[4].bit9hfname = hf_bit9infoflagsh;
                                                pvalues[4].bit10 = "Not Defined";
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
                                                pvalues[5].vstring = "";
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
                                verb_string = "Read -> ";
                                pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[0].vstring = "";
                                pvalues[0].vtype = VTYPE_UINT32;
                                pvalues[0].vdesc = "Version: %u";
                                pvalues[0].vlength = 4;
                                pvalues[0].voffset = foffset;
                                pvalues[0].hfname= hf_nds_ver;
                                foffset = foffset+pvalues[0].vlength;
                                if(pvalues[0].vvalue == 0)
                                {
                                        pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                                        pvalues[1].vstring = "";
                                        pvalues[1].vtype = VTYPE_UINT32;
                                        pvalues[1].vdesc = "Iteration Handle: 0x%08x";
                                        pvalues[1].vlength = 4;
                                        pvalues[1].voffset = foffset;
                                        pvalues[1].hfname= hf_nds_iteration;
                                        foffset = foffset+pvalues[1].vlength;
                                        pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
                                        pvalues[2].vstring = "";
                                        pvalues[2].vtype = VTYPE_UINT32;
                                        pvalues[2].vdesc = "Entry ID: 0x%08x";
                                        pvalues[2].vlength = 4;
                                        resolve_eid = TRUE;
                                        global_eid = pvalues[2].vvalue;
                                        pvalues[2].voffset = foffset;
                                        pvalues[2].hfname= hf_nds_eid;
                                        foffset = foffset+pvalues[2].vlength;
                                        pvalues[3].vvalue = tvb_get_letohl(tvb, foffset);
                                        pvalues[3].vstring = match_strval(pvalues[3].vvalue, nds_info_type);
                                        global_flags = pvalues[3].vvalue;
                                        if(pvalues[3].vstring == NULL)
                                        {
                                                pvalues[3].vstring = "No Info Type Set";
                                        }
                                        pvalues[3].vtype = VTYPE_STRING;
                                        pvalues[3].vdesc = "Info Type: %s";
                                        pvalues[3].vlength = 4;
                                        pvalues[3].voffset = foffset;
                                        pvalues[3].mvtype = MVTYPE_ATTR_REQUEST;
                                        pvalues[3].hfname= hf_nds_info_type;
                                        foffset = foffset + pvalues[3].vlength;
                                        pvalues[4].vvalue = tvb_get_letohl(tvb, foffset);
                                        pvalues[4].vstring = "";
                                        pvalues[4].vtype = VTYPE_UINT32;
                                        pvalues[4].vdesc = "All Attributes: %u";
                                        pvalues[4].vlength = 4;
                                        pvalues[4].voffset = foffset;
                                        pvalues[4].hfname= hf_nds_all_attr;
                                        foffset = foffset+pvalues[4].vlength;
                                        pvalues[5].vvalue = tvb_get_letohl(tvb, foffset);
                                        pvalues[5].vtype = VTYPE_MULTIVALUE_UINT32;
                                        pvalues[5].vstring = "";
                                        pvalues[5].vdesc = "Attributes: %u";
                                        pvalues[5].vlength = 4;
                                        pvalues[5].voffset = foffset;
                                        pvalues[5].mvtype = MVTYPE_ATTR_REQUEST;
                                        pvalues[5].hfname= hf_nds_attr;
                                }
                                else
                                {
                                        pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                                        pvalues[1].vstring = "";
                                        pvalues[1].vtype = VTYPE_UINT32;
                                        pvalues[1].vdesc = "Request Flags: 0x%08x";
                                        pvalues[1].vlength = 4;
                                        pvalues[1].voffset = foffset;
                                        pvalues[1].hfname= hf_nds_req_flags;
                                        foffset = foffset+pvalues[1].vlength;
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
                                        pvalues[3].vdesc = "Entry ID: 0x%08x";
                                        pvalues[3].vlength = 4;
                                        resolve_eid = TRUE;
                                        global_eid = pvalues[3].vvalue;
                                        pvalues[3].voffset = foffset;
                                        pvalues[3].hfname= hf_nds_eid;
                                        foffset = foffset+pvalues[3].vlength;
                                        pvalues[4].vvalue = tvb_get_letohl(tvb, foffset);
                                        pvalues[4].vstring = match_strval(pvalues[4].vvalue, nds_info_type);
                                        global_flags = pvalues[4].vvalue;
                                        if(pvalues[4].vstring == NULL)
                                        {
                                                pvalues[4].vstring = "No Info Type Set";
                                        }
                                        pvalues[4].vtype = VTYPE_STRING;
                                        pvalues[4].vdesc = "Info Type: %s";
                                        pvalues[4].vlength = 4;
                                        pvalues[4].voffset = foffset;
                                        pvalues[4].hfname= hf_nds_info_type;
                                        pvalues[4].mvtype = MVTYPE_ATTR_REQUEST;
                                        foffset = foffset+pvalues[4].vlength;
                                        pvalues[5].vvalue = tvb_get_letohl(tvb, foffset);
                                        pvalues[5].vstring = "";
                                        pvalues[5].vtype = VTYPE_UINT32;
                                        pvalues[5].vdesc = "All Attributes: %u";
                                        pvalues[5].vlength = 4;
                                        pvalues[5].voffset = foffset;
                                        pvalues[5].hfname= hf_nds_all_attr;
                                        foffset = foffset+pvalues[5].vlength;
                                        pvalues[6].vvalue = tvb_get_letohl(tvb, foffset);
                                        pvalues[6].vtype = VTYPE_MULTIVALUE_UINT32;
                                        pvalues[6].vstring = "";
                                        pvalues[6].vdesc = "Attributes: %u";
                                        pvalues[6].vlength = 4;
                                        pvalues[6].voffset = foffset;
                                        pvalues[6].mvtype = MVTYPE_ATTR_REQUEST;
                                        pvalues[6].hfname= hf_nds_attr;
                                }
                                break;
                        case 0x04:    
                                verb_string = "Compare";
                                pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[0].vstring = "";
                                pvalues[0].vtype = VTYPE_UINT32;
                                pvalues[0].vdesc = "Version: %u";
                                pvalues[0].vlength = 4;
                                pvalues[0].voffset = foffset;
                                pvalues[0].hfname= hf_nds_ver;
                                foffset = foffset+pvalues[0].vlength;
                                pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[1].vstring = "";
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
                                pvalues[2].vstring = "";
                                pvalues[2].mvtype = MVTYPE_ATTR_REQUEST;
                                pvalues[2].vvalue = 0;
                                pvalues[2].vlength = 256;
                                pvalues[2].vlength = tvb_get_letohl(tvb, foffset);
                                if (pvalues[2].vlength == 0x00)
                                {
                                        pvalues[2].vtype = VTYPE_NONE;
                                        break;
                                }
                                pvalues[2].voffset = foffset+4;
                                foffset = foffset + 4;
                                get_string(tvb, pvalues[2].voffset, pvalues[2].vlength, req_buffer.buffer);
                                pvalues[2].vstring = req_buffer.buffer;
                                global_object_name = req_buffer.buffer;
                                pvalues[2].hfname= hf_nds_name;
                                foffset = foffset+pvalues[2].vlength;
                                foffset += align_4(tvb, foffset);
                                foffset += 4;       /* Attribute Value Count = 1 */
                                /***************
                                 * Need Trace file to test. Will have to create a 
                                 * new mvtype to call print_nds_values.
                                 ***************/
                                break;
                        case 0x05:    
                                verb_string = "List -> ";
                                pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[0].vstring = "";
                                pvalues[0].vtype = VTYPE_UINT32;
                                pvalues[0].vdesc = "Version: %u";
                                pvalues[0].vlength = 4;
                                pvalues[0].voffset = foffset;
                                pvalues[0].hfname= hf_nds_ver;
                                foffset = foffset+pvalues[0].vlength;
                                pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[1].vtype = VTYPE_BITFIELD;
                                pvalues[1].vstring = "";
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
                                pvalues[3].vdesc = "Parent ID: 0x%08x";
                                pvalues[3].vlength = 4;
                                pvalues[3].voffset = foffset;
                                pvalues[3].hfname= hf_nds_parent;
                                foffset = foffset+pvalues[3].vlength;
                                pvalues[4].vvalue = tvb_get_letohs(tvb, foffset);
                                global_flags = tvb_get_letohl(tvb, foffset);
                                pvalues[4].vtype = VTYPE_BITFIELD;
                                pvalues[4].vstring = "";
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
                                pvalues[5].vstring = "";
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
                                pvalues[6].vstring = "";
                                pvalues[6].mvtype = MVTYPE_ATTR_REQUEST;
                                pvalues[6].vvalue = 0;
                                pvalues[6].vlength = 256;
                                pvalues[6].vlength = tvb_get_letohl(tvb, foffset);
                                pvalues[6].voffset = foffset+4;
                                foffset = foffset + 4;
                                get_string(tvb, pvalues[6].voffset, pvalues[6].vlength, pvalues[6].vstring);
                                pvalues[6].hfname= hf_nds_name_filter;
                                foffset = foffset+pvalues[6].vlength;
                                if(pvalues[0].vvalue == 0)
                                {
                                        break;
                                }        
                                foffset += align_4(tvb, foffset);
                                pvalues[7].vtype = VTYPE_STRING;
                                pvalues[7].vdesc = "Class Filter: %s";
                                pvalues[7].vstring = "";
                                pvalues[7].mvtype = MVTYPE_ATTR_REQUEST;
                                pvalues[7].vvalue = 0;
                                pvalues[7].vlength = 256;
                                pvalues[7].vlength = tvb_get_letohl(tvb, foffset);
                                pvalues[7].voffset = foffset+4;
                                foffset = foffset + 4;
                                get_string(tvb, pvalues[7].voffset, pvalues[7].vlength, pvalues[7].vstring);
                                pvalues[7].hfname= hf_nds_class_filter;
                                foffset = foffset+pvalues[7].vlength;
                                if(pvalues[0].vvalue == 1)
                                {
                                        break;
                                }        
                                foffset += align_4(tvb, foffset);
                                pvalues[8].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[8].vtype = VTYPE_MULTIVALUE_UINT32;
                                pvalues[8].vstring = "";
                                pvalues[8].vdesc = "Seconds %u";
                                pvalues[8].vlength = 4;
                                pvalues[8].mvtype = MVTYPE_PRINT_TIMESTAMP;
                                pvalues[8].hfname= hf_nds_time_filter;
                                pvalues[8].voffset = foffset;
                                break;
                        case 0x06:    
                                verb_string = "Search Entries";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x07:    
                                verb_string = "Add Entry";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x08:    
                                verb_string = "Remove Entry";
                                pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[0].vstring = "";
                                pvalues[0].vtype = VTYPE_UINT32;
                                pvalues[0].vdesc = "Version: %u";
                                pvalues[0].vlength = 4;
                                pvalues[0].voffset = foffset;
                                pvalues[0].hfname= hf_nds_ver;
                                foffset = foffset+pvalues[0].vlength;
                                pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[1].vstring = "";
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
                                verb_string = "Modify Entry";
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
                                break;
                        case 0x0a:    
                                verb_string = "Modify RDN";
                                pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[0].vstring = "";
                                pvalues[0].vtype = VTYPE_UINT32;
                                pvalues[0].vdesc = "Version: %u";
                                pvalues[0].vlength = 4;
                                pvalues[0].voffset = foffset;
                                pvalues[0].hfname= hf_nds_ver;
                                foffset = foffset+pvalues[0].vlength;
                                pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[1].vstring = "";
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
                                pvalues[3].vstring = "";
                                pvalues[3].mvtype = 0;
                                pvalues[3].vvalue = 0;
                                pvalues[3].vlength = 256;
                                pvalues[3].vlength = tvb_get_letohl(tvb, foffset);
                                pvalues[3].voffset = foffset+4;
                                foffset = foffset + 4;
                                get_string(tvb, pvalues[3].voffset, pvalues[3].vlength, pvalues[3].vstring);
                                pvalues[3].hfname= hf_nds_new_rdn;
                                foffset = foffset+pvalues[3].vlength;
                                break;
                        case 0x0b:    
                                verb_string = "Define Attribute ->";
                                pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[0].vstring = "";
                                pvalues[0].vtype = VTYPE_UINT32;
                                pvalues[0].vdesc = "Version: %u";
                                pvalues[0].vlength = 4;
                                pvalues[0].voffset = foffset;
                                pvalues[0].hfname= hf_nds_ver;
                                foffset = foffset+pvalues[0].vlength;
                                pvalues[1].vvalue = tvb_get_letohs(tvb, foffset);
                                global_flags = tvb_get_letohl(tvb, foffset);
                                pvalues[1].vtype = VTYPE_BITFIELD;
                                pvalues[1].vstring = "";
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
                                pvalues[2].vstring = "";
                                pvalues[2].mvtype = MVTYPE_ATTR_REQUEST;
                                pvalues[2].vvalue = 0;
                                pvalues[2].vlength = 256;
                                pvalues[2].vlength = tvb_get_letohl(tvb, foffset);
                                if (pvalues[2].vlength == 0x00)
                                {
                                        pvalues[2].vtype = VTYPE_NONE;
                                        break;
                                }
                                pvalues[2].voffset = foffset+4;
                                foffset = foffset + 4;
                                get_string(tvb, pvalues[2].voffset, pvalues[2].vlength, req_buffer.buffer);
                                pvalues[2].vstring = req_buffer.buffer;
                                global_object_name = req_buffer.buffer;
                                pvalues[2].hfname= hf_nds_name;
                                foffset = foffset+pvalues[2].vlength;
                                foffset += align_4(tvb, foffset);
                                pvalues[3].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[3].vstring = match_strval(pvalues[3].vvalue, nds_syntax);
                                if(pvalues[3].vstring == NULL)
                                {
                                        pvalues[3].vstring = "No Syntax Found";
                                }
                                pvalues[3].vtype = VTYPE_STRING;
                                pvalues[3].vdesc = "Syntax: %s";
                                pvalues[3].vlength = 4;
                                pvalues[3].voffset = foffset;
                                pvalues[3].hfname= hf_nds_syntax;
                                pvalues[3].mvtype = 0;
                                foffset = foffset+pvalues[3].vlength;
                                pvalues[4].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[4].vstring = "";
                                pvalues[4].vtype = VTYPE_UINT32;
                                pvalues[4].vdesc = "Lower Limit Value %u";
                                pvalues[4].vlength = 4;
                                pvalues[4].voffset = foffset;
                                pvalues[4].hfname = hf_nds_lower;
                                foffset += 4;
                                pvalues[5].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[5].vstring = "";
                                pvalues[5].vtype = VTYPE_UINT32;
                                pvalues[5].vdesc = "Upper Limit Value %u";
                                pvalues[5].vlength = 4;
                                pvalues[5].voffset = foffset;
                                pvalues[5].hfname = hf_nds_upper;
                                pvalues[6].vvalue = tvb_get_letohl(tvb, foffset); /* Length of bytes field */
                                foffset += 4;
                                pvalues[6].vstring = "";
                                pvalues[6].vtype = VTYPE_BYTES;
                                pvalues[6].vdesc = "ASN.1 ID";
                                pvalues[6].vlength = pvalues[6].vvalue;
                                pvalues[6].voffset = foffset;
                                pvalues[6].hfname = hf_nds_asn1;
                                break;
                        case 0x0c:    
                                verb_string = "Read Attribute Definition";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x0d:    
                                verb_string = "Remove Attribute Definition";
                                pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[0].vstring = "";
                                pvalues[0].vtype = VTYPE_UINT32;
                                pvalues[0].vdesc = "Version: %u";
                                pvalues[0].vlength = 4;
                                pvalues[0].voffset = foffset;
                                pvalues[0].hfname= hf_nds_ver;
                                foffset = foffset+pvalues[0].vlength;
                                pvalues[1].vtype = VTYPE_STRING;
                                pvalues[1].vdesc = "Attribute Name: %s";
                                pvalues[1].vstring = "";
                                pvalues[1].mvtype = MVTYPE_ATTR_REQUEST;
                                pvalues[1].vvalue = 0;
                                pvalues[1].vlength = 256;
                                pvalues[1].vlength = tvb_get_letohl(tvb, foffset);
                                if (pvalues[1].vlength == 0x00)
                                {
                                        pvalues[1].vtype = VTYPE_NONE;
                                        break;
                                }
                                pvalues[1].voffset = foffset+4;
                                foffset = foffset + 4;
                                get_string(tvb, pvalues[1].voffset, pvalues[1].vlength, req_buffer.buffer);
                                pvalues[1].vstring = req_buffer.buffer;
                                global_object_name = req_buffer.buffer;
                                pvalues[1].hfname= hf_nds_attribute_dn;
                                break;
                        case 0x0e:    
                                verb_string = "Define Class";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x0f:    
                                verb_string = "Read Class Definition ->";
                                pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[0].vstring = "";
                                pvalues[0].vtype = VTYPE_UINT32;
                                pvalues[0].vdesc = "Version: %u";
                                pvalues[0].vlength = 4;
                                pvalues[0].voffset = foffset;
                                pvalues[0].hfname= hf_nds_ver;
                                foffset = foffset+pvalues[0].vlength;
                                pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[1].vstring = "";
                                pvalues[1].vtype = VTYPE_UINT32;
                                pvalues[1].vdesc = "Iteration Handle: 0x%08x";
                                pvalues[1].vlength = 4;
                                pvalues[1].voffset = foffset;
                                pvalues[1].hfname= hf_nds_iteration;
                                foffset = foffset+pvalues[1].vlength;
                                pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
                                global_flags = pvalues[2].vvalue;
                                pvalues[2].vstring = match_strval(pvalues[2].vvalue, class_def_type);
                                if(pvalues[2].vstring == NULL)
                                {
                                        pvalues[2].vstring = "No Class Definition Type Set";
                                }
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
                                        pvalues[3].vstring = "Return All Classes = False";
                                }        
                                else
                                {
                                        pvalues[3].vstring = "Return All Classes = True";
                                }
                                pvalues[3].vtype = VTYPE_STRING;
                                pvalues[3].vdesc = "Return all Classes %s";
                                pvalues[3].vlength = 4;
                                pvalues[3].voffset = foffset;
                                pvalues[3].mvtype = 0;
                                pvalues[3].hfname= hf_nds_return_all_classes;
                                foffset = foffset + pvalues[3].vlength;
                                foffset += align_4(tvb, foffset);
                                pvalues[4].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[4].vtype = VTYPE_MULTIVALUE_UINT32;
                                pvalues[4].vstring = "";
                                pvalues[4].vdesc = "Classes: %d";
                                pvalues[4].vlength = 4;
                                pvalues[4].voffset = foffset;
                                pvalues[4].mvtype = MVTYPE_READ_CLASS_REQ;
                                pvalues[4].hfname= hf_nds_classes;
                                break;
                        case 0x10:    
                                verb_string = "Modify Class Definition -> ";
                                pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[0].vstring = "";
                                pvalues[0].vtype = VTYPE_UINT32;
                                pvalues[0].vdesc = "Version: %u";
                                pvalues[0].vlength = 4;
                                pvalues[0].voffset = foffset;
                                pvalues[0].hfname= hf_nds_ver;
                                foffset = foffset+pvalues[0].vlength;
                                pvalues[1].vtype = VTYPE_STRING;
                                pvalues[1].vdesc = "Class Name: %s";
                                pvalues[1].vstring = "";
                                pvalues[1].mvtype = MVTYPE_ATTR_REQUEST;
                                pvalues[1].vvalue = 0;
                                pvalues[1].vlength = 256;
                                pvalues[1].vlength = tvb_get_letohl(tvb, foffset);
                                if (pvalues[1].vlength == 0x00)
                                {
                                        pvalues[1].vtype = VTYPE_NONE;
                                        break;
                                }
                                pvalues[1].voffset = foffset+4;
                                foffset = foffset + 4;
                                get_string(tvb, pvalues[1].voffset, pvalues[1].vlength, req_buffer.buffer);
                                pvalues[1].vstring = req_buffer.buffer;
                                global_object_name = req_buffer.buffer;
                                pvalues[1].hfname= hf_nds_base_class;
                                foffset = foffset+pvalues[1].vlength;
                                foffset += align_4(tvb, foffset);
                                pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[2].vtype = VTYPE_MULTIVALUE_UINT32;
                                pvalues[2].vstring = "";
                                pvalues[2].vdesc = "Number of Attributes to Add: %u";
                                pvalues[2].vlength = 4;
                                pvalues[2].voffset = foffset;
                                pvalues[2].mvtype = MVTYPE_MODIFY_CLASS;
                                pvalues[2].hfname= hf_nds_att_add;
                                break;
                        case 0x11:    
                                verb_string = "Remove Class Definition";
                                pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[0].vstring = "";
                                pvalues[0].vtype = VTYPE_UINT32;
                                pvalues[0].vdesc = "Version: %u";
                                pvalues[0].vlength = 4;
                                pvalues[0].voffset = foffset;
                                pvalues[0].hfname= hf_nds_ver;
                                foffset = foffset+pvalues[0].vlength;
                                pvalues[1].vtype = VTYPE_STRING;
                                pvalues[1].vdesc = "Class Name: %s";
                                pvalues[1].vstring = "";
                                pvalues[1].mvtype = MVTYPE_ATTR_REQUEST;
                                pvalues[1].vvalue = 0;
                                pvalues[1].vlength = 256;
                                pvalues[1].vlength = tvb_get_letohl(tvb, foffset);
                                if (pvalues[1].vlength == 0x00)
                                {
                                        pvalues[1].vtype = VTYPE_NONE;
                                        break;
                                }
                                pvalues[1].voffset = foffset+4;
                                foffset = foffset + 4;
                                get_string(tvb, pvalues[1].voffset, pvalues[1].vlength, req_buffer.buffer);
                                pvalues[1].vstring = req_buffer.buffer;
                                global_object_name = req_buffer.buffer;
                                pvalues[1].hfname= hf_nds_base;
                                break;
                        case 0x12:    
                                verb_string = "List Containable Classes";
                                pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[0].vstring = "";
                                pvalues[0].vtype = VTYPE_UINT32;
                                pvalues[0].vdesc = "Version: %u";
                                pvalues[0].vlength = 4;
                                pvalues[0].voffset = foffset;
                                pvalues[0].hfname= hf_nds_ver;
                                foffset = foffset+pvalues[0].vlength;
                                pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[1].vstring = "";
                                pvalues[1].vtype = VTYPE_UINT32;
                                pvalues[1].vdesc = "Iteration Handle: 0x%08x";
                                pvalues[1].vlength = 4;
                                pvalues[1].voffset = foffset;
                                pvalues[1].hfname= hf_nds_iteration;
                                foffset = foffset+pvalues[1].vlength;
                                pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[2].vstring = "";
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
                                verb_string = "Get Effective Rights -> ";
                                pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[0].vstring = "";
                                pvalues[0].vtype = VTYPE_UINT32;
                                pvalues[0].vdesc = "Version: %u";
                                pvalues[0].vlength = 4;
                                pvalues[0].voffset = foffset;
                                pvalues[0].hfname= hf_nds_ver;
                                foffset = foffset+pvalues[0].vlength;
                                pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[1].vstring = "";
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
                                pvalues[2].vstring = "";
                                pvalues[2].mvtype = MVTYPE_ATTR_REQUEST;
                                pvalues[2].vvalue = 0;
                                pvalues[2].vlength = 256;
                                pvalues[2].vlength = tvb_get_letohl(tvb, foffset);
                                if (pvalues[2].vlength == 0x00)
                                {
                                        pvalues[2].vtype = VTYPE_NONE;
                                        break;
                                }
                                pvalues[2].voffset = foffset+4;
                                foffset = foffset + 4;
                                get_string(tvb, pvalues[2].voffset, pvalues[2].vlength, req_buffer.buffer);
                                pvalues[2].vstring = req_buffer.buffer;
                                pvalues[2].hfname= hf_nds_name;
                                foffset = foffset+pvalues[2].vlength;
                                foffset += align_4(tvb, foffset);
                                pvalues[3].vtype = VTYPE_STRING;
                                pvalues[3].vdesc = "Attribute to be Checked: %s";
                                pvalues[3].vstring = "";
                                pvalues[3].mvtype = 0;
                                pvalues[3].vvalue = 0;
                                pvalues[3].vlength = 256;
                                pvalues[3].vlength = tvb_get_letohl(tvb, foffset);
                                if (pvalues[3].vlength == 0x00)
                                {
                                        pvalues[3].vtype = VTYPE_NONE;
                                        break;
                                }
                                pvalues[3].voffset = foffset+4;
                                foffset = foffset + 4;
                                get_string(tvb, pvalues[3].voffset, pvalues[3].vlength, pvalues[3].vstring);
                                pvalues[3].hfname= hf_nds_name;
                                foffset = foffset+pvalues[3].vlength;
                                foffset += align_4(tvb, foffset);
                                if(pvalues[0].vvalue != 0)
                                {
                                        pvalues[4].vtype = VTYPE_STRING;
                                        pvalues[4].vdesc = "Security Equivalence: %s";
                                        pvalues[4].vstring = "";
                                        pvalues[4].mvtype = MVTYPE_ATTR_REQUEST;
                                        pvalues[4].vvalue = 0;
                                        pvalues[4].vlength = 256;
                                        pvalues[4].vlength = tvb_get_letohl(tvb, foffset);
                                        if (pvalues[4].vlength == 0x00)
                                        {
                                                pvalues[4].vtype = VTYPE_NONE;
                                                break;
                                        }
                                        pvalues[4].voffset = foffset+4;
                                        foffset = foffset + 4;
                                        get_string(tvb, pvalues[4].voffset, pvalues[4].vlength, pvalues[4].vstring);
                                        pvalues[4].hfname= hf_nds_name;
                                        foffset = foffset+pvalues[4].vlength;
                                        foffset += align_4(tvb, foffset);
                                }
                                break;
                        case 0x14:    
                                verb_string = "Add Partition";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x15:    
                                verb_string = "Remove Partition";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x16:    
                                verb_string = "List Partitions";
                                pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[0].vstring = "";
                                pvalues[0].vtype = VTYPE_UINT32;
                                pvalues[0].vdesc = "Version: %u";
                                pvalues[0].vlength = 4;
                                pvalues[0].voffset = foffset;
                                pvalues[0].hfname= hf_nds_ver;
                                foffset = foffset+pvalues[0].vlength;
                                pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[1].vtype = VTYPE_BITFIELD;
                                pvalues[1].vstring = "";
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
                                pvalues[2].vstring = "";
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
                                pvalues[3].vstring = "";
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
                                pvalues[4].vstring = "";
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
                                pvalues[5].vstring = "";
                                pvalues[5].vtype = VTYPE_UINT32;
                                pvalues[5].vdesc = "Partition Root ID: 0x%08x";
                                pvalues[5].vlength = 4;
                                pvalues[5].voffset = foffset;
                                pvalues[5].hfname= hf_nds_partition_root_id;
                                foffset = foffset+pvalues[5].vlength;
                                break;
                        case 0x17:    
                                verb_string = "Split Partition";
                                pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
                                nds_version = pvalues[0].vvalue;
                                pvalues[0].vstring = "";
                                pvalues[0].vtype = VTYPE_UINT32;
                                pvalues[0].vdesc = "Version: %u";
                                pvalues[0].vlength = 4;
                                pvalues[0].hfname = hf_nds_ver;
                                pvalues[0].voffset = foffset;
                                foffset = foffset+pvalues[0].vlength;
                                pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                                nds_version = pvalues[1].vvalue;
                                pvalues[1].vstring = "";
                                pvalues[1].vtype = VTYPE_UINT32;
                                pvalues[1].vdesc = "Flags: 0x%08x";
                                pvalues[1].vlength = 4;
                                pvalues[1].hfname = hf_nds_req_flags;
                                pvalues[1].voffset = foffset;
                                foffset = foffset+pvalues[1].vlength;
                                pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[2].vstring = "";
                                pvalues[2].vtype = VTYPE_UINT32;
                                pvalues[2].vdesc = "New Partition Root ID: 0x%08x";
                                pvalues[2].vlength = 4;
                                pvalues[2].voffset = foffset;
                                pvalues[2].hfname= hf_nds_new_part_id;
                                foffset = foffset+pvalues[2].vlength;
                                break;
                        case 0x18:    
                                verb_string = "Join Partitions";
                                pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
                                nds_version = pvalues[0].vvalue;
                                pvalues[0].vstring = "";
                                pvalues[0].vtype = VTYPE_UINT32;
                                pvalues[0].vdesc = "Version: %u";
                                pvalues[0].vlength = 4;
                                pvalues[0].hfname = hf_nds_ver;
                                pvalues[0].voffset = foffset;
                                foffset = foffset+pvalues[0].vlength;
                                pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                                nds_version = pvalues[1].vvalue;
                                pvalues[1].vstring = "";
                                pvalues[1].vtype = VTYPE_UINT32;
                                pvalues[1].vdesc = "Flags: 0x%08x";
                                pvalues[1].vlength = 4;
                                pvalues[1].hfname = hf_nds_req_flags;
                                pvalues[1].voffset = foffset;
                                foffset = foffset+pvalues[1].vlength;
                                pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[2].vstring = "";
                                pvalues[2].vtype = VTYPE_UINT32;
                                pvalues[2].vdesc = "Child Partition Root ID: 0x%08x";
                                pvalues[2].vlength = 4;
                                pvalues[2].voffset = foffset;
                                pvalues[2].hfname= hf_nds_child_part_id;
                                foffset = foffset+pvalues[2].vlength;
                                break;
                        case 0x19:    
                                verb_string = "Add Replica";
                                pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
                                nds_version = pvalues[0].vvalue;
                                pvalues[0].vstring = "";
                                pvalues[0].vtype = VTYPE_UINT32;
                                pvalues[0].vdesc = "Version: %u";
                                pvalues[0].vlength = 4;
                                pvalues[0].hfname = hf_nds_ver;
                                pvalues[0].voffset = foffset;
                                foffset = foffset+pvalues[0].vlength;
                                pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                                nds_version = pvalues[1].vvalue;
                                pvalues[1].vstring = "";
                                pvalues[1].vtype = VTYPE_UINT32;
                                pvalues[1].vdesc = "Flags: 0x%08x";
                                pvalues[1].vlength = 4;
                                pvalues[1].hfname = hf_nds_req_flags;
                                pvalues[1].voffset = foffset;
                                foffset = foffset+pvalues[1].vlength;
                                pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[2].vstring = "";
                                pvalues[2].vtype = VTYPE_UINT32;
                                pvalues[2].vdesc = "Master Partition Root ID: 0x%08x";
                                pvalues[2].vlength = 4;
                                pvalues[2].voffset = foffset;
                                pvalues[2].hfname= hf_nds_master_part_id;
                                foffset = foffset+pvalues[2].vlength;
                                pvalues[3].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[3].vstring = match_strval(pvalues[3].vvalue, nds_replica_type);
                                if(pvalues[3].vstring == NULL)
                                {
                                        pvalues[3].vstring = "No Replica Type Found";
                                }
                                pvalues[3].vtype = VTYPE_STRING;
                                pvalues[3].vdesc = "Replica Type: %s";
                                pvalues[3].vlength = 4;
                                pvalues[3].voffset = foffset;
                                pvalues[3].mvtype = 0;
                                pvalues[3].hfname= hf_replica_type;
                                foffset = foffset + pvalues[3].vlength;
                                pvalues[4].vtype = VTYPE_STRING;
                                pvalues[4].vdesc = "Target Server Name: %s";
                                pvalues[4].vstring = "";
                                pvalues[4].mvtype = 0;
                                pvalues[4].vvalue = 0;
                                pvalues[4].vlength = 256;
                                pvalues[4].vlength = tvb_get_letohl(tvb, foffset);
                                if (pvalues[4].vlength == 0x00)
                                {
                                        pvalues[4].vtype = VTYPE_NONE;
                                        break;
                                }
                                pvalues[4].voffset = foffset+4;
                                foffset = foffset + 4;
                                get_string(tvb, pvalues[4].voffset, pvalues[4].vlength, pvalues[4].vstring);
                                pvalues[4].hfname= hf_nds_target_name;
                                break;
                        case 0x1a:    
                                verb_string = "Remove Replica";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x1b:    
                                verb_string = "Open Stream -> ";
                                pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
                                nds_version = pvalues[0].vvalue;
                                pvalues[0].vstring = "";
                                pvalues[0].vtype = VTYPE_UINT32;
                                pvalues[0].vdesc = "Version: %u";
                                pvalues[0].vlength = 4;
                                pvalues[0].hfname = hf_nds_ver;
                                pvalues[0].voffset = foffset;
                                foffset = foffset+pvalues[0].vlength;
                                pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                                nds_version = pvalues[1].vvalue;
                                pvalues[1].vstring = "";
                                pvalues[1].vtype = VTYPE_UINT32;
                                pvalues[1].vdesc = "Streams Flags: 0x%08x";
                                pvalues[1].vlength = 4;
                                pvalues[1].hfname = hf_nds_stream_flags;
                                pvalues[1].voffset = foffset;
                                foffset = foffset+pvalues[1].vlength;
                                pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[2].vstring = "";
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
                                pvalues[3].vstring = "";
                                pvalues[3].mvtype = MVTYPE_ATTR_REQUEST;
                                pvalues[3].vvalue = 0;
                                pvalues[3].vlength = 256;
                                pvalues[3].vlength = tvb_get_letohl(tvb, foffset);
                                if (pvalues[3].vlength == 0x00)
                                {
                                        pvalues[3].vtype = VTYPE_NONE;
                                        break;
                                }
                                pvalues[3].voffset = foffset+4;
                                foffset += 4;
                                get_string(tvb, pvalues[3].voffset, pvalues[3].vlength, pvalues[3].vstring);
                                foffset += pvalues[3].vlength;
                                foffset += align_4(tvb, foffset);
                                pvalues[3].hfname= hf_nds_stream_name;
                                break;
                        case 0x1c:    
                                verb_string = "Search Filter";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x1d:    
                                verb_string = "Create Subordinate Reference";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x1e:    
                                verb_string = "Link Replica";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x1f:    
                                verb_string = "Change Replica Type";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x20:    
                                verb_string = "Start Update Schema";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x21:    
                                verb_string = "End Update Schema";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x22:    
                                verb_string = "Update Schema";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x23:    
                                verb_string = "Start Update Replica";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x24:    
                                verb_string = "End Update Replica";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x25:    
                                verb_string = "Update Replica";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x26:    
                                verb_string = "Synchronize Partition";
                                pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
                                nds_version = pvalues[0].vvalue;
                                pvalues[0].vstring = "";
                                pvalues[0].vtype = VTYPE_UINT32;
                                pvalues[0].vdesc = "Version: %u";
                                pvalues[0].vlength = 4;
                                pvalues[0].hfname = hf_nds_ver;
                                pvalues[0].voffset = foffset;
                                foffset = foffset+pvalues[0].vlength;
                                pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                                nds_version = pvalues[1].vvalue;
                                pvalues[1].vstring = "";
                                pvalues[1].vtype = VTYPE_UINT32;
                                pvalues[1].vdesc = "Flags: 0x%08x";
                                pvalues[1].vlength = 4;
                                pvalues[1].hfname = hf_nds_req_flags;
                                pvalues[1].voffset = foffset;
                                foffset = foffset+pvalues[1].vlength;
                                pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[2].vstring = "";
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
                                        pvalues[3].vstring = "";
                                        pvalues[3].mvtype = MVTYPE_ATTR_REQUEST;
                                        pvalues[3].vvalue = 0;
                                        pvalues[3].vlength = 256;
                                        pvalues[3].vlength = tvb_get_letohl(tvb, foffset);
                                        if (pvalues[3].vlength == 0x00)
                                        {
                                                pvalues[3].vtype = VTYPE_NONE;
                                                break;
                                        }
                                        pvalues[3].voffset = foffset+4;
                                        foffset += 4;
                                        get_string(tvb, pvalues[3].voffset, pvalues[3].vlength, pvalues[3].vstring);
                                        foffset += pvalues[3].vlength;
                                        foffset += align_4(tvb, foffset);
                                        pvalues[3].hfname= hf_nds_root_name;
                                }
                                else
                                {
                                        pvalues[3].vvalue = tvb_get_letohl(tvb, foffset);
                                        pvalues[3].vstring = "";
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
                                verb_string = "Synchronize Schema";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x28:    
                                verb_string = "Read Syntaxes";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x29:    
                                verb_string = "Get Replica Root ID";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x2a:    
                                verb_string = "Begin Move Entry";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x2b:    
                                verb_string = "Finish Move Entry";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x2c:    
                                verb_string = "Release Moved Entry";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x2d:    
                                verb_string = "Backup Entry";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x2e:    
                                verb_string = "Restore Entry";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x2f:    
                                verb_string = "Save DIB";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x30:
                                verb_string = "Control";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x31:
                                verb_string = "Remove Backlink";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x32:    
                                verb_string = "Close Iteration";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x33:    
                                verb_string = "Mutate Entry";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x34:    
                                verb_string = "Audit Skulking";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x35:    
                                verb_string = "Get Server Address";
                                pvalues[0].vvalue = 0;
                                break;
                        case 0x36:    
                                verb_string = "Set Keys";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x37:    
                                verb_string = "Change Password";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x38:    
                                verb_string = "Verify Password";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x39:    
                                verb_string = "Begin Login";
                                pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[0].vstring = "";
                                pvalues[0].vtype = VTYPE_UINT32;
                                pvalues[0].vdesc = "Version: %u";
                                pvalues[0].vlength = 4;
                                pvalues[0].voffset = foffset;
                                pvalues[0].hfname= hf_nds_ver;
                                foffset = foffset+pvalues[0].vlength;
                                pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[1].vstring = "";
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
                                verb_string = "Finish Login";
                                pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[0].vstring = "";
                                pvalues[0].vtype = VTYPE_UINT32;
                                pvalues[0].vdesc = "Reply Buffer Size: %u";
                                pvalues[0].vlength = 4;
                                pvalues[0].voffset = foffset;
                                pvalues[0].hfname= hf_nds_buffer_size;
                                foffset = foffset+pvalues[0].vlength;
                                pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[1].vstring = "";
                                pvalues[1].vtype = VTYPE_UINT32;
                                pvalues[1].vdesc = "Version: %u";
                                pvalues[1].vlength = 4;
                                pvalues[1].voffset = foffset;
                                pvalues[1].hfname= hf_nds_ver;
                                foffset = foffset+pvalues[1].vlength;
                                pvalues[2].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[2].vstring = "";
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
                                verb_string = "Begin Authentication";
                                pvalues[0].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[0].vstring = "";
                                pvalues[0].vtype = VTYPE_UINT32;
                                pvalues[0].vdesc = "Version: %u";
                                pvalues[0].vlength = 4;
                                pvalues[0].voffset = foffset;
                                pvalues[0].hfname= hf_nds_ver;
                                foffset = foffset+pvalues[0].vlength;
                                pvalues[1].vvalue = tvb_get_letohl(tvb, foffset);
                                pvalues[1].vstring = "";
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
                                verb_string = "Finish Authentication";
                                break;
                        case 0x3d:    
                                verb_string = "Logout";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x3e:    
                                verb_string = "Repair Ring";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x3f:    
                                verb_string = "Repair Timestamps";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x40:    
                                verb_string = "Create Back Link";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x41:    
                                verb_string = "Delete External Reference";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x42:    
                                verb_string = "Rename External Reference";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x43:    
                                verb_string = "Create Directory Entry";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x44:    
                                verb_string = "Remove Directory Entry";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x45:    
                                verb_string = "Designate New Master";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x46:    
                                verb_string = "Change Tree Name";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x47:    
                                verb_string = "Partition Entry Count";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x48:    
                                verb_string = "Check Login Restrictions";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x49:    
                                verb_string = "Start Join";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x4a:    
                                verb_string = "Low Level Split";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x4b:    
                                verb_string = "Low Level Join";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x4c:    
                                verb_string = "Abort Low Level Join";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
                        case 0x4d:    
                                verb_string = "Get All Servers";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
                                break;
               		default:
               			verb_string = "NDS Continuation Fragment";
                                pvalues[0].vtype = VTYPE_NONE; /* Not Defined */
               	}
        }
        /* Fill in the INFO column. */
        if (check_col(pinfo->cinfo, COL_INFO)) {
        	if (ncp_rec) {
                      
              		col_set_str(pinfo->cinfo, COL_PROTOCOL, "NDS");
                        if (nds_frag != 0xffffffff) {
                                col_add_fstr(pinfo->cinfo, COL_INFO, "C Continue NDS Fragment %08x", nds_frag);
                        }
                        else {
                       		col_add_fstr(pinfo->cinfo, COL_INFO, "C NDS %s", verb_string);
              	        }
                }
               	else {
         		col_add_fstr(pinfo->cinfo, COL_INFO,
         			"C Unknown Function %d (0x%02x)",
         			func, func);
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
                        
        	conversation = find_conversation(&pinfo->src, &pinfo->dst,
        	    PT_NCP, nw_connection, nw_connection, 0);
                
        	if (conversation == NULL) {
        		/* It's not part of any conversation - create a new one. */
        		conversation = conversation_new(&pinfo->src, &pinfo->dst,
        		    PT_NCP, nw_connection, nw_connection, 0);
        	}
                        
        	request_value = ncp_hash_insert(conversation, sequence, ncp_rec);
        	request_value->req_frame_num = pinfo->fd->num;
                
        	/* If this is the first time we're examining the packet,
        	 * check to see if this NCP type uses a "request condition".
        	 * If so, we have to build a proto_tree because request conditions
        	 * use display filters to work, and without a proto_tree,
        	 * display filters can't possibly work. If we already have
        	 * a proto_tree, then wonderful. If we don't, we need to build
        	 * one. */
        	if (ncp_rec && !ncp_tree) {
              		proto_item *ti;
                                       
               		temp_tree = proto_tree_create_root();
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
               
        	conversation = find_conversation(&pinfo->src, &pinfo->dst,
        	    PT_NCP, nw_connection, nw_connection, 0);
                    
                    
                
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
                                        
        				proto_tree_add_item(ncp_tree, hf_ncp_nds_flag, tvb, 20, 4, FALSE);
                                        
       				        proto_tree_add_uint_format(ncp_tree, hf_ncp_nds_verb, tvb, 24, 4,
       					        nds_verb, "NDS Verb: %d, (0x%02x), %s",
       					        nds_verb, nds_verb, verb_string);
					for (i = 0; i < 9; i++) {
						switch (pvalues[i].vtype) {

						case VTYPE_NONE: /* no value */
							break;

						case VTYPE_UINT8:
							proto_tree_add_uint_format(ncp_tree, pvalues[i].hfname, tvb, pvalues[i].voffset,
							    pvalues[i].vlength, pvalues[i].vtype, "NDS Parameter not defined %d",
							    pvalues[i].vtype);
							break;

						case VTYPE_UINT16:
							proto_tree_add_uint_format(ncp_tree, pvalues[i].hfname, tvb, pvalues[i].voffset,
							    pvalues[i].vlength, pvalues[i].vtype, "NDS Parameter not defined %d",
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
							break;

						case VTYPE_BITFIELD:
							process_bitfield(ncp_tree, tvb, &pvalues[i]);
							break;

						case VTYPE_MULTIVALUE_UINT32:
							process_multivalues(ncp_tree, tvb, &pvalues[i]);
							if (pvalues[i].mvtype == MVTYPE_PROC_ENTRY_SPECIFIERS) {
								/*
								 * The "vstring" value is set to the input ES type
								 * by "process_multivalues()".
								 */
								global_object_name = pvalues[i].vstring;
							}
							if (pvalues[i].mvtype == MVTYPE_ATTR_REQUEST || pvalues[i].mvtype == MVTYPE_PROC_ENTRY_SPECIFIERS) {
								/*
								 * The "vstring" value is set to the input ES type
								 * for MVTYPE_PROC_ENTRY_SPECIFIERS,
								 * and the last string for MVTYPE_ATTR_REQUEST,
								 * by "process_multivalues()".
								 */
								if (check_col(pinfo->cinfo, COL_INFO))
									col_append_str(pinfo->cinfo, COL_INFO, pvalues[i].vstring);
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
                                                if(resolve_eid) {
                
                                                        /* For NDS requests with just an EID, resolve name from hash table. */
                                                        request_eid_value = ncp_eid_hash_lookup(conversation, global_eid);
                                                        if (request_eid_value) {
                                                                global_object_name = request_eid_value->object_name;
                                                                if (check_col(pinfo->cinfo, COL_INFO)) 
                                                                {
                                                                        col_append_str(pinfo->cinfo, COL_INFO, ", Object Name - ");
                                                                        col_append_str(pinfo->cinfo, COL_INFO, global_object_name);
                                                                }
                                                        }
                                                }        
                                        }
                                        if (request_value)
                                        {
                                                request_value->nds_request_verb = nds_verb;
                                                request_value->nds_version = nds_version;
                                                request_value->object_name = global_object_name;
                                                request_value->req_nds_flags = global_flags;
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
		guint16 nw_connection, guint8 sequence,
		guint16 type, proto_tree *ncp_tree)
{
	guint8			func, subfunc = 0;
	ncp_req_hash_value	*request_value = NULL;
	const ncp_record	*ncp_rec = NULL;          
	conversation_t		*conversation;
	ptvcursor_t		*ptvc = NULL;
	proto_tree		*temp_tree = NULL;
        gint                    length_remaining = 0;
	char			flags_str[256];
        char *                  sep = NULL;
	proto_tree		*flags_tree;
        guint32                 nds_flags;
	proto_item		*tinew;
        guint32                 nds_flag_tree = 0x00020000;
        guint32                 nds_flag_depth = 0x00000002;
        guint32                 nds_flag_rev = 0x00000004;
        guint32                 nds_flag_flags = 0x00000008;
        
	func = tvb_get_guint8(tvb, 6);
        subfunc = tvb_get_guint8(tvb, 7);
        
        ncp_rec = ncp_record_find(func, subfunc);

       	/* Fill in the INFO column. */
       	if (check_col(pinfo->cinfo, COL_INFO)) 
        {
       		if (ncp_rec) 
                {
                        
        		col_set_str(pinfo->cinfo, COL_PROTOCOL, "NDS");
                        col_add_fstr(pinfo->cinfo, COL_INFO, "C Ping for NDS");
               	}
                
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
                
       		conversation = find_conversation(&pinfo->src, &pinfo->dst,
       		    PT_NCP, nw_connection, nw_connection, 0);
        
       		if (conversation == NULL) 
                {
       			/* It's not part of any conversation - create a new one. */
       			conversation = conversation_new(&pinfo->src, &pinfo->dst,
       			    PT_NCP, nw_connection, nw_connection, 0);
       		}
                
       		request_value = ncp_hash_insert(conversation, sequence, ncp_rec);
       		request_value->req_frame_num = pinfo->fd->num;
        
       		/* If this is the first time we're examining the packet,
       		 * check to see if this NCP type uses a "request condition".
       		 * If so, we have to build a proto_tree because request conditions
       		 * use display filters to work, and without a proto_tree,
       		 * display filters can't possibly work. If we already have
       		 * a proto_tree, then wonderful. If we don't, we need to build
       		 * one. */
       		if (ncp_rec && !ncp_tree) {
         		proto_item *ti;
                               
         		temp_tree = proto_tree_create_root();
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
				proto_tree_add_item(ncp_tree, hf_nds_version, tvb, 8, 4,
					FALSE);

				nds_flags = tvb_get_letohl(tvb, 12);
				if (request_value)
					request_value->req_nds_flags = nds_flags;

				strcpy(flags_str, " ");
				sep = "(";
				if (nds_flags & nds_flag_tree) {
					strcat(flags_str, sep);
					strcat(flags_str, "Tree");
					sep = ",";
				}
				if (nds_flags & nds_flag_depth) {
					strcat(flags_str, sep);
					strcat(flags_str, "Depth");
					sep = ",";
				}
				if (nds_flags & nds_flag_rev) {
					strcat(flags_str, sep);
					strcat(flags_str, "Revision");
					sep = ",";
				}
				if (nds_flags & nds_flag_flags) {
					strcat(flags_str, sep);
					strcat(flags_str, "Flags");
				}
				if (flags_str[0] != '\0') {
					strcat(flags_str, ")");
					tinew = proto_tree_add_uint_format(ncp_tree, hf_nds_flags,
						tvb, 12, 4, nds_flags, "Flags: 0x%08x -%s", nds_flags,
						flags_str);

					flags_tree = proto_item_add_subtree(tinew, ett_nds);
                                                
					proto_tree_add_item(flags_tree, hf_nds_flags_tree,
						tvb, 12, 4, TRUE);
					proto_tree_add_item(flags_tree, hf_nds_flags_flags,
						tvb, 12, 4, TRUE);
					proto_tree_add_item(flags_tree, hf_nds_flags_rev,
						tvb, 12, 4, TRUE);
					proto_tree_add_item(flags_tree, hf_nds_flags_depth,
						tvb, 12, 4, TRUE);
				}
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
