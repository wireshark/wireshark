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
 * $Id: packet-ncp2222.inc,v 1.31 2002/10/10 23:52:51 guy Exp $
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
        guint8          icounter;
        guint32         number_of_values = 0;
        guint32         number_of_items = 0;
        guint8          r;
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
                4, number_of_values, "Number of Values: %d", number_of_values);
        
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
                                        4, number_of_items, "Number of Addresses: %d", number_of_items);
        
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
        guint8          r;
        guint8          i;
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
		                r, "NDS Referral Record #%d", r);
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
        guint8          i;
        guint8          r;
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
        if(values->mvtype != 12)
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
                case 1:         /* Attribute Request */
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
                case 2:         /* Attribute Reply */
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
                case 3:         /* Attribute Request */
                        for (i = 1 ; i <= values->vvalue; i++ )
                        {
                                ioffset += align_4(tvb, ioffset);
                                value1 = tvb_get_letohl(tvb, ioffset);
                                proto_tree_add_uint_format(ntree, hf_nds_uint32value, tvb, ioffset,
                                        4, value1, "Value %d", value1);
                                ioffset = ioffset + value1;        
                        }
                        break;
                case 4:         /* Read Class Request */
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
                case 5:         /* Read Replicas */
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
                case 6:         /* Modify Attribute Request */        
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
                case 7:         /* Address Referral Request */        
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
                case 8:         /* Address Referral Reply */
                        number_of_referrals = values->vvalue;
                        
                        for (r = 1 ; r <= number_of_referrals; r++ )
                        {
		                aitem = proto_tree_add_uint_format(ntree, hf_referral_record, tvb, 6, 0,
		                r, "NDS Referral Record #%d", r);
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
                case 9:         /* Local Address Referral Reply */
                        number_of_referrals = values->vvalue;

                        for (r = 1 ; r <= number_of_referrals; r++ )
                        {
		                aitem = proto_tree_add_uint_format(ntree, hf_referral_record, tvb, 6, 0,
		                r, "NDS Referral Record #%d", r);
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
                case 10:                        /* Process Entry Specifiers */
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
                case 11:                /* Print Timestamp */
                                replica_num = tvb_get_letohs(tvb, ioffset);   /* Replica */
                                proto_tree_add_item(ncp_tree, hf_nds_replica_num, tvb, ioffset, 
                                        2, replica_num);
                                ioffset = ioffset + 2;
                                event_num = tvb_get_letohs(tvb, ioffset);   /* Event */
                                proto_tree_add_item(ncp_tree, hf_nds_event_num, tvb, ioffset, 
                                        2, event_num);
                                ioffset = ioffset + 2;
                case 12:        /* List Partitions */
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
                                                                temp_values.vtype = 5; /* Bitfield */
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
                                                                temp_values.vtype = 5; /* Bitfield */
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
                                                                temp_values.vtype = 5; /* Bitfield */
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
                case 13:        /* Class Names */
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
                                        temp_values.vtype = 5; /* Bitfield */
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
                case 14:        /* Modify Class */
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
        				"C Unknown Function %d %d (0x%02X/0x%02x)",
        				func, subfunc, func, subfunc);
        		}
        		else {
        			col_add_fstr(pinfo->cinfo, COL_INFO,
        				"C Unknown Function %d (0x%02x)",
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
					func, "Function: %d (0x%02X), %s",
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
					subfunc, "SubFunction: %d (0x%02x)",
					subfunc, subfunc);
				ptvc = ptvcursor_new(ncp_tree, tvb, 10);
			}
			else {
				proto_tree_add_uint_format(ncp_tree, hf_ncp_subfunc, tvb, 7, 1,
					subfunc, "SubFunction: %d (0x%02x)",
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
        nds_val                         p1values;
        nds_val                         p2values;
        nds_val                         p3values;
        nds_val                         p4values;
        nds_val                         p5values;
        nds_val                         p6values;
        nds_val                         p7values;
        nds_val                         p8values;      
        nds_val                         p9values;
        gboolean                        resolve_eid=FALSE;
        guint32                         global_eid=0;
        gboolean                        add_eid = FALSE;
        char                            *global_object_name='\0';
        

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
				ncp_rec->func, "Function: %d (0x%02X), %s",
				ncp_rec->func, ncp_rec->func, ncp_rec->name);
			if (ncp_requires_subfunc(ncp_rec->func)) {
				proto_tree_add_uint_format(ncp_tree, hf_ncp_subfunc, tvb, 6, 0,
					ncp_rec->subfunc, "SubFunction: %d (0x%02x)",
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
                                        p1values.vtype = 0;
                                        p2values.vtype = 0;
                                        p3values.vtype = 0;
                                        p4values.vtype = 0;
                                        p5values.vtype = 0;
                                        p6values.vtype = 0;
                                        p7values.vtype = 0;
                                        p8values.vtype = 0;
                                        p9values.vtype = 0;
                                        p1values.vvalue = 0;
                                        p2values.vvalue = 0;
                                        p3values.vvalue = 0;
                                        p4values.vvalue = 0;
                                        p5values.vvalue = 0;
                                        p6values.vvalue = 0;
                                        p7values.vvalue = 0;
                                        p8values.vvalue = 0;
                                        p9values.vvalue = 0;
                                        p1values.vlength = 0;
                                        p2values.vlength = 0;
                                        p3values.vlength = 0;
                                        p4values.vlength = 0;
                                        p5values.vlength = 0;
                                        p6values.vlength = 0;
                                        p7values.vlength = 0;
                                        p8values.vlength = 0;
                                        p9values.vlength = 0;
                                        p1values.voffset = 0;
                                        p2values.voffset = 0;
                                        p3values.voffset = 0;
                                        p4values.voffset = 0;
                                        p5values.voffset = 0;
                                        p6values.voffset = 0;
                                        p7values.voffset = 0;
                                        p8values.voffset = 0;
                                        p9values.voffset = 0;
                                        p1values.hfname = 0;
                                        p2values.hfname = 0;
                                        p3values.hfname = 0;
                                        p4values.hfname = 0;
                                        p5values.hfname = 0;
                                        p6values.hfname = 0;
                                        p7values.hfname = 0;
                                        p8values.hfname = 0;
                                        p9values.hfname = 0;
                                        p1values.vdesc = "";
                                        p2values.vdesc = "";
                                        p3values.vdesc = "";
                                        p4values.vdesc = "";
                                        p5values.vdesc = "";
                                        p6values.vdesc = "";
                                        p7values.vdesc = "";
                                        p8values.vdesc = "";
                                        p9values.vdesc = "";
                                        p1values.vstring = "";
                                        p2values.vstring = "";
                                        p3values.vstring = "";
                                        p4values.vstring = "";
                                        p5values.vstring = "";
                                        p6values.vstring = "";
                                        p7values.vstring = "";
                                        p8values.vstring = "";
                                        p9values.vstring = "";
                                        switch (request_value->nds_request_verb)
                                        {
                                                case 0x01:
                                                        verb_string = "Resolve Name";
                                                        if(request_value->nds_version == 0)
                                                        { 
                                                                p1values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                p1values.vstring = match_strval(p1values.vvalue, nds_tags);
                                                                if(p1values.vstring == NULL)
                                                                {
                                                                        p1values.vstring = "No Tags Set";
                                                                }
                                                                p1values.vtype = 4; /* String */
                                                                p1values.vdesc = "Tag: %s";
                                                                p1values.vlength = 4;
                                                                p1values.voffset = nds_offset;
                                                                p1values.hfname = hf_nds_tag_string;
                                                                nds_offset = nds_offset+p1values.vlength;
                                                                switch(p1values.vvalue)
                                                                {
                                                                        case 0:         /* No Such Entry */
                                                                                break;
                                                                        case 1:         /* Local Entry */
                                                                                p2values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                p2values.vstring = "";
                                                                                p2values.vtype = 3; /* Uint32 */
                                                                                p2values.vdesc = "Entry ID: 0x%08x";
                                                                                add_eid = TRUE;
                                                                                global_object_name = request_value->object_name;
                                                                                global_eid = p2values.vvalue;
                                                                                p2values.vlength = 4;
                                                                                p2values.voffset = nds_offset;
                                                                                p2values.hfname = hf_nds_eid;
                                                                                nds_offset = nds_offset+p2values.vlength;
                                                                                p3values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                p3values.vtype = 6; /* Multivalue Uint32 */
                                                                                p3values.vstring = "";
                                                                                p3values.vdesc = "Referral Records: %d";
                                                                                p3values.vlength = 4;
                                                                                p3values.voffset = nds_offset;
                                                                                p3values.hfname = hf_nds_referrals;
                                                                                p3values.mvtype = 9;
                                                                                break;
                                                                        case 2:         /* Remote Entry */
                                                                                nds_offset += 4;   /* GUINT32 reserved field */
                                                                                p2values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                p2values.vstring = "";
                                                                                p2values.vtype = 3; /* Uint32 */
                                                                                p2values.vdesc = "Entry ID: 0x%08x";
                                                                                add_eid = TRUE;
                                                                                global_eid = p2values.vvalue;
                                                                                global_object_name = request_value->object_name;
                                                                                p2values.vlength = 4;
                                                                                p2values.voffset = nds_offset;
                                                                                p2values.hfname = hf_nds_eid;
                                                                                nds_offset = nds_offset+p2values.vlength;
                                                                                p3values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                p3values.vtype = 6; /* Multivalue Uint32 */
                                                                                p3values.vstring = "";
                                                                                p3values.vdesc = "Referral Records: %d";
                                                                                p3values.vlength = 4;
                                                                                p3values.voffset = nds_offset;
                                                                                p3values.hfname = hf_nds_referrals;
                                                                                p3values.mvtype = 9;
                                                                                break;
                                                                        case 3:         /* Alias Entry */
                                                                                p2values.vtype = 4; /* String */
                                                                                p2values.vdesc = "Alias Name: %s";
                                                                                p2values.vstring = "";
                                                                                p2values.mvtype = 1;
                                                                                p2values.vvalue = 0;
                                                                                p2values.vlength = 256;
                                                                                p2values.vlength = tvb_get_letohl(tvb, nds_offset);
                                                                                if (p2values.vlength == 0x00)
                                                                                {
                                                                                        p2values.vtype = 0;
                                                                                        break;
                                                                                }
                                                                                p2values.voffset = nds_offset+4;
                                                                                nds_offset += 4;
                                                                                get_string(tvb, p2values.voffset, p2values.vlength, p2values.vstring);
                                                                                nds_offset += p2values.vlength;
                                                                                nds_offset += align_4(tvb, nds_offset);
                                                                                p2values.hfname= hf_nds_name;
                                                                                break;
                                                                        case 4:         /* Referral Information */
                                                                                p2values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                p2values.vstring = "";
                                                                                p2values.vtype = 3; /* Uint32 */
                                                                                p2values.vdesc = "Distance Object is From Root: 0x%08x";
                                                                                p2values.vlength = 4;
                                                                                p2values.voffset = nds_offset;
                                                                                p2values.hfname = hf_nds_eid;
                                                                                nds_offset = nds_offset+p2values.vlength;
                                                                                p3values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                p3values.vtype = 6; /* Multivalue Uint32 */
                                                                                p3values.vstring = "";
                                                                                p3values.vdesc = "Referral Records: %d";
                                                                                p3values.vlength = 4;
                                                                                p3values.voffset = nds_offset;
                                                                                p3values.hfname = hf_nds_depth;
                                                                                p3values.mvtype = 9;
                                                                                break;
                                                                        case 6:          /* Entry and Referrals */
                                                                                p2values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                p2values.vstring = "";
                                                                                p2values.vtype = 3; /* Uint32 */
                                                                                p2values.vdesc = "Result Flags: 0x%08x";
                                                                                p2values.vlength = 4;
                                                                                p2values.voffset = nds_offset;
                                                                                p2values.hfname = hf_nds_result_flags;
                                                                                nds_offset = nds_offset+p2values.vlength;
                                                                                p3values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                p3values.vstring = "";
                                                                                p3values.vtype = 3; /* Uint32 */
                                                                                p3values.vdesc = "Entry ID: 0x%08x";
                                                                                add_eid = TRUE;
                                                                                global_eid = p3values.vvalue;
                                                                                global_object_name = request_value->object_name;
                                                                                p3values.vlength = 4;
                                                                                p3values.voffset = nds_offset;
                                                                                p3values.hfname = hf_nds_eid;
                                                                                nds_offset = nds_offset+p3values.vlength;
                                                                                p4values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                p4values.vtype = 6; /* Multivalue Uint32 */
                                                                                p4values.vstring = "";
                                                                                p4values.vdesc = "Referral Records: %d";
                                                                                p4values.vlength = 4;
                                                                                p4values.voffset = nds_offset;
                                                                                p4values.mvtype = 8;
                                                                                p4values.hfname = hf_nds_referrals;
                                                                                break;
                                                                        default:
                                                                                break;
                                                                }
                                                        }
                                                        else
                                                        {
                                                                p1values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                p1values.vstring = "";
                                                                p1values.vtype = 3; /* Uint32 */
                                                                p1values.vdesc = "CRC: 0x%08x";
                                                                p1values.vlength = 4;
                                                                p1values.voffset = nds_offset;
                                                                p1values.hfname = hf_nds_crc;
                                                                nds_offset = nds_offset+p1values.vlength;
                                                                p2values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                p2values.vstring = match_strval(p2values.vvalue, nds_tags);
                                                                if(p2values.vstring == NULL)
                                                                {
                                                                        p2values.vstring = "No Tags Set";
                                                                }
                                                                p2values.vtype = 4; /* String */
                                                                p2values.vdesc = "Tag: %s";
                                                                p2values.vlength = 4;
                                                                p2values.voffset = nds_offset;
                                                                nds_offset = nds_offset+p2values.vlength;
                                                                p2values.hfname = hf_nds_tag_string;
                                                                switch(p2values.vvalue)
                                                                {
                                                                        case 0:         /* No Such Entry */
                                                                                break;
                                                                        case 1:         /* Local Entry */
                                                                                p3values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                p3values.vstring = "";
                                                                                p3values.vtype = 3; /* Uint32 */
                                                                                p3values.vdesc = "Entry ID: 0x%08x";
                                                                                add_eid = TRUE;
                                                                                global_eid = p3values.vvalue;
                                                                                global_object_name = request_value->object_name;
                                                                                p3values.vlength = 4;
                                                                                p3values.voffset = nds_offset;
                                                                                p3values.hfname = hf_nds_eid;
                                                                                nds_offset = nds_offset+p3values.vlength;
                                                                                p4values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                p4values.vtype = 6; /* Multivalue Uint32 */
                                                                                p4values.vstring = "";
                                                                                p4values.vdesc = "Referral Records: %d";
                                                                                p4values.vlength = 4;
                                                                                p4values.voffset = nds_offset;
                                                                                p4values.hfname = hf_nds_referrals;
                                                                                p4values.mvtype = 9;
                                                                                break;
                                                                        case 2:         /* Remote Entry */
                                                                                nds_offset += 4;   /* GUINT32 reserved field */
                                                                                p3values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                p3values.vstring = "";
                                                                                add_eid = TRUE;
                                                                                global_eid = p3values.vvalue;
                                                                                global_object_name = request_value->object_name;
                                                                                p3values.vtype = 3; /* Uint32 */
                                                                                p3values.vdesc = "Entry ID: 0x%08x";
                                                                                p3values.vlength = 4;
                                                                                p3values.voffset = nds_offset;
                                                                                p3values.hfname = hf_nds_eid;
                                                                                nds_offset = nds_offset+p3values.vlength;
                                                                                p4values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                p4values.vtype = 6; /* Multivalue Uint32 */
                                                                                p4values.vstring = "";
                                                                                p4values.vdesc = "Referral Records: %d";
                                                                                p4values.vlength = 4;
                                                                                p4values.voffset = nds_offset;
                                                                                p4values.hfname = hf_nds_referrals;
                                                                                p4values.mvtype = 9;
                                                                                break;
                                                                        case 3:         /* Alias Entry */
                                                                                p3values.vtype = 4; /* String */
                                                                                p3values.vdesc = "Alias Name: %s";
                                                                                p3values.vstring = "";
                                                                                p3values.mvtype = 1;
                                                                                p3values.vvalue = 0;
                                                                                p3values.vlength = 256;
                                                                                p3values.vlength = tvb_get_letohl(tvb, nds_offset);
                                                                                if (p3values.vlength == 0x00)
                                                                                {
                                                                                        p3values.vtype = 0;
                                                                                        break;
                                                                                }
                                                                                p3values.voffset = nds_offset+4;
                                                                                nds_offset += 4;
                                                                                get_string(tvb, p3values.voffset, p3values.vlength, p3values.vstring);
                                                                                nds_offset += p3values.vlength;
                                                                                nds_offset += align_4(tvb, nds_offset);
                                                                                p3values.hfname= hf_nds_name;
                                                                                break;
                                                                        case 4:         /* Referral Information */
                                                                                p3values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                p3values.vstring = "";
                                                                                p3values.vtype = 3; /* Uint32 */
                                                                                p3values.vdesc = "Distance Object is From Root: 0x%08x";
                                                                                p3values.vlength = 4;
                                                                                p3values.voffset = nds_offset;
                                                                                p3values.hfname = hf_nds_eid;
                                                                                nds_offset = nds_offset+p3values.vlength;
                                                                                p4values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                p4values.vtype = 6; /* Multivalue Uint32 */
                                                                                p4values.vstring = "";
                                                                                p4values.vdesc = "Referral Records: %d";
                                                                                p4values.vlength = 4;
                                                                                p4values.voffset = nds_offset;
                                                                                p4values.hfname = hf_nds_depth;
                                                                                p4values.mvtype = 8;
                                                                                break;
                                                                        case 6:          /* Entry and Referrals */
                                                                                p3values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                p3values.vstring = "";
                                                                                p3values.vtype = 3; /* Uint32 */
                                                                                p3values.vdesc = "Result Flags: 0x%08x";
                                                                                p3values.vlength = 4;
                                                                                p3values.voffset = nds_offset;
                                                                                p3values.hfname = hf_nds_result_flags;
                                                                                nds_offset = nds_offset+p3values.vlength;
                                                                                p4values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                p4values.vstring = "";
                                                                                p4values.vtype = 3; /* Uint32 */
                                                                                p4values.vdesc = "Entry ID: 0x%08x";
                                                                                add_eid = TRUE;
                                                                                global_object_name = request_value->object_name;
                                                                                global_eid = p4values.vvalue;
                                                                                p4values.vlength = 4;
                                                                                p4values.voffset = nds_offset;
                                                                                p4values.hfname = hf_nds_eid;
                                                                                nds_offset = nds_offset+p4values.vlength;
                                                                                p5values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                                p5values.vtype = 6; /* Multivalue Uint32 */
                                                                                p5values.vstring = "";
                                                                                p5values.vdesc = "Referral Records: %d";
                                                                                p5values.vlength = 4;
                                                                                p5values.voffset = nds_offset;
                                                                                p5values.mvtype = 8;
                                                                                p5values.hfname = hf_nds_referrals;
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
                                                                p1values.vvalue = 1;
                                                                p1values.vtype = 6; /* Multivalue Uint32 */
                                                                p1values.vstring = "";
                                                                p1values.vdesc = "Entry Information";
                                                                p1values.vlength = 0;
                                                                p1values.voffset = nds_offset-4;
                                                                p1values.hfname = hf_nds_name;
                                                                p1values.mvtype = 12;
                                                                p1values.vflags = request_value->req_nds_flags;
                                                        }
                                                        else
                                                        {
                                                                p1values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                p1values.vstring = "";
                                                                p1values.vtype = 3; /* Uint32 */
                                                                p1values.vdesc = "CRC: 0x%08x";
                                                                p1values.vlength = 4;
                                                                p1values.voffset = nds_offset;
                                                                p1values.hfname = hf_nds_crc;
                                                                nds_offset = nds_offset+p1values.vlength;
                                                                p2values.vvalue = 1;
                                                                p2values.vtype = 6; /* Multivalue Uint32 */
                                                                p2values.vstring = "";
                                                                p2values.vdesc = "Entry Information";
                                                                p2values.vlength = 0;
                                                                p2values.voffset = nds_offset-4;
                                                                p2values.hfname = hf_nds_name;
                                                                p2values.mvtype = 12;
                                                                p2values.vflags = request_value->req_nds_flags;
                                                        }
                                                        break;
                                                case 0x03:    
                                                        verb_string = "Read";
                                                        if(request_value->nds_version != 0x000000fe)
                                                        { 
                                                                p1values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                p1values.vstring = "";
                                                                p1values.vtype = 3; /* Uint32 */
                                                                p1values.vdesc = "Iteration Handle: 0x%08x";
                                                                p1values.vlength = 4;
                                                                p1values.voffset = nds_offset;
                                                                p1values.hfname = hf_nds_iteration;
                                                                nds_offset = nds_offset+p1values.vlength;
                                                                p2values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                p2values.vstring = match_strval(p2values.vvalue, nds_info_type);
                                                                if(p2values.vstring == NULL)
                                                                {
                                                                        p2values.vstring = "No Info Type Set";
                                                                }
                                                                p2values.vtype = 4; /* String */
                                                                p2values.vdesc = "Info Type: %s";
                                                                p2values.vlength = 4;
                                                                p2values.voffset = nds_offset;
                                                                p2values.hfname = hf_nds_info_type;
                                                                nds_offset = nds_offset+p2values.vlength;
                                                                p3values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                p3values.vtype = 6; /* Multivalue Uint32 */
                                                                p3values.vstring = "";
                                                                p3values.vdesc = "Number of Attributes: %d";
                                                                p3values.vlength = 4;
                                                                p3values.voffset = nds_offset;
                                                                p3values.hfname = hf_nds_attr;
                                                                p3values.mvtype = 2;
                                                                p3values.vflags = request_value->req_nds_flags;
                                                                p3values.nds_version = request_value->nds_version;
                                                        }
                                                        else
                                                        {
                                                                p1values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                p1values.vstring = "";
                                                                p1values.vtype = 3; /* Uint32 */
                                                                p1values.vdesc = "CRC: 0x%08x";
                                                                p1values.vlength = 4;
                                                                p1values.voffset = nds_offset;
                                                                p1values.hfname = hf_nds_crc;
                                                                nds_offset = nds_offset+p1values.vlength;
                                                                p2values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                p2values.vstring = "";
                                                                p2values.vtype = 3; /* Uint32 */
                                                                p2values.vdesc = "Iteration Handle: 0x%08x";
                                                                p2values.vlength = 4;
                                                                p2values.voffset = nds_offset;
                                                                p2values.hfname = hf_nds_iteration;
                                                                nds_offset = nds_offset+p2values.vlength;
                                                                p3values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                p3values.vstring = match_strval(p3values.vvalue, nds_info_type);
                                                                if(p3values.vstring == NULL)
                                                                {
                                                                        p3values.vstring = "No Info Type Set";
                                                                }
                                                                p3values.vtype = 4; /* String */
                                                                p3values.vdesc = "Info Type: %s";
                                                                p3values.vlength = 4;
                                                                p3values.voffset = nds_offset;
                                                                p3values.hfname = hf_nds_info_type;
                                                                nds_offset = nds_offset+p3values.vlength;
                                                                p4values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                p4values.vtype = 6; /* Multivalue Uint32 */
                                                                p4values.vstring = "";
                                                                p4values.vdesc = "Number of Attributes: %d";
                                                                p4values.vlength = 4;
                                                                p4values.voffset = nds_offset;
                                                                p4values.hfname = hf_nds_attr;
                                                                p4values.mvtype = 2;
                                                                p4values.vflags = request_value->req_nds_flags;
                                                                p4values.nds_version = request_value->nds_version;
                                                        }
                                                        break;
                                                case 0x04:    
                                                        verb_string = "Compare";
                                                        p1values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                        if (p1values.vvalue == 0x00000000)
                                                        {
                                                                p1values.vstring = "Did Not Match";
                                                        }        
                                                        else
                                                        {
                                                                p1values.vstring = "Matched";
                                                        }
                                                        p1values.vtype = 4; /* String */
                                                        p1values.vdesc = "Compare Values Returned - %s";
                                                        p1values.vlength = 4;
                                                        p1values.voffset = nds_offset;
                                                        p1values.mvtype = 0;
                                                        p1values.hfname= hf_nds_compare_results;
                                                        nds_offset += p1values.vlength;
                                                        break;
                                                case 0x05:    
                                                        verb_string = "List";
                                                        p1values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                        p1values.vstring = "";
                                                        p1values.vtype = 3; /* Uint32 */
                                                        p1values.vdesc = "Iteration Handle: 0x%08x";
                                                        p1values.vlength = 4;
                                                        p1values.voffset = nds_offset;
                                                        p1values.hfname = hf_nds_iteration;
                                                        nds_offset = nds_offset+p1values.vlength;
                                                        p2values.vvalue = tvb_get_letohl(tvb, nds_offset);;
                                                        p2values.vtype = 6; /* Multivalue Uint32 */
                                                        p2values.vstring = "";
                                                        p2values.vdesc = "Entry Information";
                                                        p2values.vlength = 0;
                                                        p2values.voffset = nds_offset;
                                                        p2values.hfname = hf_nds_name;
                                                        p2values.mvtype = 12;
                                                        p2values.vflags = request_value->req_nds_flags;
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
                                                        p1values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                        p1values.vstring = "";
                                                        p1values.vtype = 3; /* Uint32 */
                                                        p1values.vdesc = "Iteration Handle: 0x%08x";
                                                        p1values.vlength = 4;
                                                        p1values.voffset = nds_offset;
                                                        p1values.hfname = hf_nds_iteration;
                                                        nds_offset = nds_offset+p1values.vlength;
                                                        p2values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                        p2values.vstring = match_strval(p2values.vvalue, class_def_type);
                                                        if(p2values.vstring == NULL)
                                                        {
                                                                p2values.vstring = "No Class Definition Type Set";
                                                        }
                                                        p2values.vtype = 4; /* String */
                                                        p2values.vdesc = "Class Definition Type: %s";
                                                        p2values.vlength = 4;
                                                        p2values.voffset = nds_offset;
                                                        p2values.mvtype = 0;
                                                        p2values.hfname= hf_nds_class_def_type;
                                                        nds_offset = nds_offset + p2values.vlength;
                                                        p3values.vvalue = tvb_get_letohl(tvb, nds_offset);;
                                                        p3values.vtype = 6; /* Multivalue Uint32 */
                                                        p3values.vstring = "";
                                                        p3values.vdesc = "Class Definitions %d";
                                                        p3values.vlength = 0;
                                                        p3values.voffset = nds_offset;
                                                        p3values.hfname = hf_nds_classes;
                                                        p3values.mvtype = 13;
                                                        p3values.vflags = request_value->req_nds_flags;
                                                        break;
                                                case 0x10:    
                                                        verb_string = "Modify Class Definition";
                                                        break;
                                                case 0x11:    
                                                        verb_string = "Remove Class Definition";
                                                        break;
                                                case 0x12:    
                                                        verb_string = "List Containable Classes";
                                                        p1values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                        p1values.vstring = "";
                                                        p1values.vtype = 3; /* Uint32 */
                                                        p1values.vdesc = "Iteration Handle: 0x%08x";
                                                        p1values.vlength = 4;
                                                        p1values.voffset = nds_offset;
                                                        p1values.hfname = hf_nds_iteration;
                                                        nds_offset = nds_offset+p1values.vlength;
                                                        p2values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                        p2values.vtype = 6; /* Multivalue Uint32 */
                                                        p2values.vstring = "";
                                                        p2values.vdesc = "Classes: %d";
                                                        p2values.vlength = 4;
                                                        p2values.voffset = nds_offset;
                                                        p2values.mvtype = 4;
                                                        p2values.hfname= hf_nds_classes;
                                                        break;
                                                case 0x13:    
                                                        p1values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                        p1values.vstring = "";
                                                        p1values.vtype = 3; /* Uint32 */
                                                        p1values.vdesc = "Privileges: 0x%08x";
                                                        p1values.vlength = 4;
                                                        p1values.voffset = nds_offset;
                                                        p1values.hfname = hf_nds_privileges;
                                                        nds_offset = nds_offset+p1values.vlength;
                                                        break;
                                                case 0x14:    
                                                        verb_string = "Add Partition";
                                                        break;
                                                case 0x15:    
                                                        verb_string = "Remove Partition";
                                                        break;
                                                case 0x16:    
                                                        verb_string = "List Partitions";
                                                        p1values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                        p1values.vstring = "";
                                                        p1values.vtype = 3; /* Uint32 */
                                                        p1values.vdesc = "Iteration Handle: 0x%08x";
                                                        p1values.vlength = 4;
                                                        p1values.voffset = nds_offset;
                                                        p1values.hfname = hf_nds_iteration;
                                                        nds_offset = nds_offset+p1values.vlength;
                                                        p2values.vtype = 4; /* String */
                                                        p2values.vdesc = "Server Distinguished Name: %s";
                                                        p2values.vstring = "";
                                                        p2values.mvtype = 1;
                                                        p2values.vvalue = 0;
                                                        p2values.vlength = 256;
                                                        p2values.vlength = tvb_get_letohl(tvb, nds_offset);
                                                        if (p2values.vlength == 0x00)
                                                        {
                                                                p2values.vtype = 0;
                                                                break;
                                                        }
                                                        p2values.voffset = nds_offset+4;
                                                        nds_offset += 4;
                                                        get_string(tvb, p2values.voffset, p2values.vlength, p2values.vstring);
                                                        nds_offset += p2values.vlength;
                                                        nds_offset += align_4(tvb, nds_offset);
                                                        p2values.hfname= hf_nds_name;
                                                        nds_offset += align_4(tvb, nds_offset);
                                                        p3values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                        p3values.vtype = 6; /* Multivalue Uint32 */
                                                        p3values.vstring = "";
                                                        p3values.vdesc = "Replicas: %d";
                                                        p3values.vlength = 4;
                                                        p3values.voffset = nds_offset;
                                                        p3values.hfname = hf_nds_replicas;
                                                        p3values.mvtype = 5;
                                                        p3values.bit1 = "Output Flags";
                                                        p3values.bit2 = "Entry ID";
                                                        p3values.bit3 = "Replica State";
                                                        p3values.bit4 = "Modification Timestamp";
                                                        p3values.bit5 = "Purge Time";
                                                        p3values.bit6 = "Local Partition ID";
                                                        p3values.bit7 = "Distinguished Name";
                                                        p3values.bit8 = "Replica Type";
                                                        p3values.bit9 = "Partition Busy";
                                                        p3values.vflags = request_value->req_nds_flags;
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
                                                        p1values.vvalue = tvb_get_ntohl(tvb, nds_offset);
                                                        p1values.vstring = "";
                                                        p1values.vtype = 3; /* Uint32 */
                                                        p1values.vdesc = "File Handle: 0x%08x";
                                                        p1values.vlength = 4;
                                                        p1values.voffset = nds_offset;
                                                        p1values.hfname = hf_nds_file_handle;
                                                        nds_offset = nds_offset+p1values.vlength;
                                                        p2values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                        p2values.vstring = "";
                                                        p2values.vtype = 3; /* Uint32 */
                                                        p2values.vdesc = "File Size: %d";
                                                        p2values.vlength = 4;
                                                        p2values.voffset = nds_offset;
                                                        p2values.hfname = hf_nds_file_size;
                                                        nds_offset = nds_offset+p2values.vlength;
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
                                                                p1values.vtype = 4; /* String */
                                                                p1values.vdesc = "Distinguished Name: %s";
                                                                p1values.vstring = "";
                                                                p1values.mvtype = 1;
                                                                p1values.vvalue = 0;
                                                                p1values.vlength = 256;
                                                                p1values.vlength = tvb_get_letohl(tvb, nds_offset);
                                                                if (p1values.vlength == 0x00)
                                                                {
                                                                        p1values.vtype = 0;
                                                                        break;
                                                                }
                                                                p1values.voffset = nds_offset+4;
                                                                nds_offset += 4;
                                                                get_string(tvb, p1values.voffset, p1values.vlength, p1values.vstring);
                                                                nds_offset += p1values.vlength;
                                                                nds_offset += align_4(tvb, nds_offset);
                                                                p1values.hfname= hf_nds_name;
                                                                p2values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                p2values.vtype = 6; /* Multivalue Uint32 */
                                                                p2values.vstring = "";
                                                                p2values.vdesc = "Referral Records: %d";
                                                                p2values.vlength = 4;
                                                                p2values.voffset = nds_offset;
                                                                p2values.hfname = hf_nds_referrals;
                                                                p2values.mvtype = 9;
                                                        }
                                                        else
                                                        {
                                                                p1values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                p1values.vstring = "";
                                                                p1values.vtype = 3; /* Uint32 */
                                                                p1values.vdesc = "Iteration Handle: 0x%08x";
                                                                p1values.vlength = 4;
                                                                p1values.voffset = nds_offset;
                                                                p1values.hfname = hf_nds_iteration;
                                                                nds_offset = nds_offset+p1values.vlength;
                                                                p2values.vtype = 4; /* String */
                                                                p2values.vdesc = "Distinguished Name: %s";
                                                                p2values.vstring = "";
                                                                p2values.mvtype = 1;
                                                                p2values.vvalue = 0;
                                                                p2values.vlength = 256;
                                                                p2values.vlength = tvb_get_letohl(tvb, nds_offset);
                                                                if (p2values.vlength == 0x00)
                                                                {
                                                                        p2values.vtype = 0;
                                                                        break;
                                                                }
                                                                p2values.voffset = nds_offset+4;
                                                                nds_offset += 4;
                                                                get_string(tvb, p2values.voffset, p2values.vlength, p2values.vstring);
                                                                nds_offset += p2values.vlength;
                                                                nds_offset += align_4(tvb, nds_offset);
                                                                p2values.hfname= hf_nds_name;
                                                                p3values.vvalue = tvb_get_letohl(tvb, nds_offset);
                                                                p3values.vtype = 6; /* Multivalue Uint32 */
                                                                p3values.vstring = "";
                                                                p3values.vdesc = "Referral Records: %d";
                                                                p3values.vlength = 4;
                                                                p3values.voffset = nds_offset;
                                                                p3values.hfname = hf_nds_referrals;
                                                                p3values.mvtype = 9;
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
                                        if (p1values.vtype != 0) {
                                                switch (p1values.vtype) {
                                                        case 1:         /* uint8 */
                                        			proto_tree_add_uint_format(ncp_tree, p1values.hfname, tvb, p1values.voffset,
                                                                p1values.vlength, p1values.vtype, "NDS Parameter not defined %d",
        				                        p1values.vtype);
                                                                break;
                                                        case 2:         /* uint16 */
                                        			proto_tree_add_uint_format(ncp_tree, p1values.hfname, tvb, p1values.voffset,
                                                                p1values.vlength, p1values.vtype, "NDS Parameter not defined %d",
        				                        p1values.vtype);
                                                                break;
                                                        case 3:         /* uint32 */
                                        			proto_tree_add_uint_format(ncp_tree, p1values.hfname, tvb, p1values.voffset,
                                                                p1values.vlength, p1values.vvalue, p1values.vdesc,
        				                        p1values.vvalue);
                                                                break;
                                                        case 4:         /* string */
                                                                proto_tree_add_string_format(ncp_tree, p1values.hfname, tvb, p1values.voffset, 
                                                                p1values.vlength, p1values.vstring, p1values.vdesc, p1values.vstring);
                                                                break;
                                                        case 5:         /* boolean */
                                                                process_bitfield(ncp_tree, tvb, &p1values);
                                                                break;
                                                        case 6:         /*multivalue uint32 */
                                                                process_multivalues(ncp_tree, tvb, &p1values);
                                                                break;
                                                        default:
                                        			proto_tree_add_uint_format(ncp_tree, hf_nds_p1type, tvb, p1values.voffset,
                                                                p1values.vlength, p1values.vtype, "NDS Parameter not defined %d",
        				                        p1values.vtype);
                                                                break;
                                                }
                                                switch (p2values.vtype) {
                                                        case 1:         /* uint8 */
                                                                break;
                                                        case 2:         /* uint16 */
                                                                break;
                                                        case 3:         /* uint32 */
                                        			proto_tree_add_uint_format(ncp_tree, p2values.hfname, tvb, p2values.voffset,
                                                                p2values.vlength, p2values.vvalue, p2values.vdesc,
        				                        p2values.vvalue);
                                                                break;
                                                        case 4:         /* string */
                                                                proto_tree_add_string_format(ncp_tree, p2values.hfname, tvb, p2values.voffset, 
                                                                p2values.vlength, p2values.vstring, p2values.vdesc, p2values.vstring);
                                                                break;
                                                        case 5:         /* boolean */
                                                                process_bitfield(ncp_tree, tvb, &p2values);
                                                                break;
                                                        case 6:         /*multivalue uint32 */
                                                                process_multivalues(ncp_tree, tvb, &p2values);
                                                                break;
                                                        default:
                                                                break;
                                                }
                                                switch (p3values.vtype) {
                                                        case 1:         /* uint8 */
                                                                break;
                                                        case 2:         /* uint16 */
                                                                break;
                                                        case 3:         /* uint32 */
                                        			proto_tree_add_uint_format(ncp_tree, p3values.hfname, tvb, p3values.voffset,
                                                                p3values.vlength, p3values.vvalue, p3values.vdesc,
        				                        p3values.vvalue);
                                                                break;
                                                        case 4:         /* string */
                                                                proto_tree_add_string_format(ncp_tree, p3values.hfname, tvb, p3values.voffset, 
                                                                p3values.vlength, p3values.vstring, p3values.vdesc, p3values.vstring);
                                                                break;
                                                        case 5:         /* boolean */
                                                                process_bitfield(ncp_tree, tvb, &p3values);
                                                                break;
                                                        case 6:         /*multivalue uint32 */
                                                                process_multivalues(ncp_tree, tvb, &p3values);
                                                                break;
                                                        default:
                                                                break;
                                                }
                                                switch (p4values.vtype) {
                                                        case 1:         /* uint8 */
                                                                break;
                                                        case 2:         /* uint16 */
                                                                break;
                                                        case 3:         /* uint32 */
                                        			proto_tree_add_uint_format(ncp_tree, p4values.hfname, tvb, p4values.voffset,
                                                                p4values.vlength, p4values.vvalue, p4values.vdesc,
        				                        p4values.vvalue);
                                                                break;
                                                        case 4:         /* string */
                                                                proto_tree_add_string_format(ncp_tree, p4values.hfname, tvb, p4values.voffset, 
                                                                p4values.vlength, p4values.vstring, p4values.vdesc, p4values.vstring);
                                                                break;
                                                        case 5:         /* boolean */
                                                                process_bitfield(ncp_tree, tvb, &p4values);
                                                                break;
                                                        case 6:         /*multivalue uint32 */
                                                                process_multivalues(ncp_tree, tvb, &p4values);
                                                                break;
                                                        default:
                                                                break;
                                                }
                                                switch (p5values.vtype) {
                                                        case 1:         /* uint8 */
                                                                break;
                                                        case 2:         /* uint16 */
                                                                break;
                                                        case 3:         /* uint32 */
                                        			proto_tree_add_uint_format(ncp_tree, p5values.hfname, tvb, p5values.voffset,
                                                                p5values.vlength, p5values.vvalue, p5values.vdesc,
        				                        p5values.vvalue);
                                                                break;
                                                        case 4:         /* string */
                                                                proto_tree_add_string_format(ncp_tree, p5values.hfname, tvb, p5values.voffset, 
                                                                p5values.vlength, p5values.vstring, p5values.vdesc, p5values.vstring);
                                                                break;
                                                        case 5:         /* boolean */
                                                                process_bitfield(ncp_tree, tvb, &p5values);
                                                                break;
                                                        case 6:         /*multivalue uint32 */
                                                                process_multivalues(ncp_tree, tvb, &p5values);
                                                                break;
                                                        default:
                                                                break;
                                                }
                                                switch (p6values.vtype) {
                                                        case 1:         /* uint8 */
                                                                break;
                                                        case 2:         /* uint16 */
                                                                break;
                                                        case 3:         /* uint32 */
                                        			proto_tree_add_uint_format(ncp_tree, p6values.hfname, tvb, p6values.voffset,
                                                                p6values.vlength, p6values.vvalue, p6values.vdesc,
        				                        p6values.vvalue);
                                                                break;
                                                        case 4:         /* string */
                                                                proto_tree_add_string_format(ncp_tree, p6values.hfname, tvb, p6values.voffset, 
                                                                p6values.vlength, p6values.vstring, p6values.vdesc, p6values.vstring);
                                                                break;
                                                        case 5:         /* boolean */
                                                                process_bitfield(ncp_tree, tvb, &p6values);
                                                                break;
                                                        case 6:         /*multivalue uint32 */
                                                                process_multivalues(ncp_tree, tvb, &p6values);
                                                                break;
                                                        default:
                                                                break;
                                                }
                                                switch (p7values.vtype) {
                                                        case 1:         /* uint8 */
                                                                break;
                                                        case 2:         /* uint16 */
                                                                break;
                                                        case 3:         /* uint32 */
                                        			proto_tree_add_uint_format(ncp_tree, p7values.hfname, tvb, p7values.voffset,
                                                                p7values.vlength, p7values.vvalue, p7values.vdesc,
        				                        p7values.vvalue);
                                                                break;
                                                        case 4:         /* string */
                                                                proto_tree_add_string_format(ncp_tree, p7values.hfname, tvb, p7values.voffset, 
                                                                p7values.vlength, p7values.vstring, p7values.vdesc, p7values.vstring);
                                                                break;
                                                        case 5:         /* boolean */
                                                                process_bitfield(ncp_tree, tvb, &p7values);
                                                                break;
                                                        case 6:         /*multivalue uint32 */
                                                                process_multivalues(ncp_tree, tvb, &p7values);
                                                                break;
                                                        default:
                                                                break;
                                                }
                                                switch (p8values.vtype) {
                                                        case 1:         /* uint8 */
                                                                break;
                                                        case 2:         /* uint16 */
                                                                break;
                                                        case 3:         /* uint32 */
                                        			proto_tree_add_uint_format(ncp_tree, p8values.hfname, tvb, p8values.voffset,
                                                                p8values.vlength, p8values.vvalue, p8values.vdesc,
        				                        p8values.vvalue);
                                                                break;
                                                        case 4:         /* string */
                                                                proto_tree_add_string_format(ncp_tree, p8values.hfname, tvb, p8values.voffset, 
                                                                p8values.vlength, p8values.vstring, p8values.vdesc, p8values.vstring);
                                                                break;
                                                        case 5:         /* boolean */
                                                                process_bitfield(ncp_tree, tvb, &p8values);
                                                                break;
                                                        case 6:         /*multivalue uint32 */
                                                                process_multivalues(ncp_tree, tvb, &p8values);
                                                                break;
                                                        default:
                                                                break;
                                                }
                                                switch (p9values.vtype) {
                                                        case 1:         /* uint8 */
                                                                break;
                                                        case 2:         /* uint16 */
                                                                break;
                                                        case 3:         /* uint32 */
                                        			proto_tree_add_uint_format(ncp_tree, p9values.hfname, tvb, p9values.voffset,
                                                                p9values.vlength, p9values.vvalue, p9values.vdesc,
        				                        p9values.vvalue);
                                                                break;
                                                        case 4:         /* string */
                                                                proto_tree_add_string_format(ncp_tree, p9values.hfname, tvb, p9values.voffset, 
                                                                p9values.vlength, p9values.vstring, p9values.vdesc, p9values.vstring);
                                                                break;
                                                        case 5:         /* boolean */
                                                                process_bitfield(ncp_tree, tvb, &p9values);
                                                                break;
                                                        case 6:         /*multivalue uint32 */
                                                                process_multivalues(ncp_tree, tvb, &p9values);
                                                                break;
                                                        default:
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
        nds_val                 p1values;
        nds_val                 p2values;
        nds_val                 p3values;
        nds_val                 p4values;
        nds_val                 p5values;
        nds_val                 p6values;
        nds_val                 p7values;
        nds_val                 p8values;
        nds_val                 p9values;
        guint8                  nds_version = 0;
        guint32                 foffset = 0;
        guint32                 nds_reply_buffer;
        nw_uni_t                req_buffer;
        char *                  global_object_name="\0";
        guint32                 global_eid=0;
        gboolean                resolve_eid=FALSE;
        guint32                 global_flags=0;
        
        p1values.vtype = 0;
        p2values.vtype = 0;
        p3values.vtype = 0;
        p4values.vtype = 0;
        p5values.vtype = 0;
        p6values.vtype = 0;
        p7values.vtype = 0;
        p8values.vtype = 0;
        p9values.vtype = 0;
        p1values.mvtype = 0;
        p2values.mvtype = 0;
        p3values.mvtype = 0;
        p4values.mvtype = 0;
        p5values.mvtype = 0;
        p6values.mvtype = 0;
        p7values.mvtype = 0;
        p8values.mvtype = 0;
        p9values.mvtype = 0;
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
                                p1values.vvalue = tvb_get_letohl(tvb, foffset);
                                nds_version = p1values.vvalue;
                                p1values.vstring = "";
                                p1values.vtype = 3; /* Uint32 */
                                p1values.vdesc = "Version: %d";
                                p1values.vlength = 4;
                                p1values.hfname = hf_nds_ver;
                                p1values.voffset = foffset;
                                foffset = foffset+p1values.vlength;
                                p2values.vvalue = tvb_get_letohl(tvb, foffset);
                                p2values.vtype = 5; /* Bitfield */
                                p2values.vstring = "";
                                p2values.vdesc = "Flags:";
                                p2values.vlength = 2;
                                p2values.hfname= hf_nds_nflags;
                                p2values.voffset = foffset;
                                p2values.bit1 = "Entry ID";
                                p2values.bit1hfname = hf_bit1nflags;
                                p2values.bit2 = "Readable";
                                p2values.bit2hfname = hf_bit2nflags;
                                p2values.bit3 = "Writeable";
                                p2values.bit3hfname = hf_bit3nflags;
                                p2values.bit4 = "Master";
                                p2values.bit4hfname = hf_bit4nflags;
                                p2values.bit5 = "Create ID";
                                p2values.bit5hfname = hf_bit5nflags;
                                p2values.bit6 = "Walk Tree";
                                p2values.bit6hfname = hf_bit6nflags;
                                p2values.bit7 = "Dereference Alias";
                                p2values.bit7hfname = hf_bit7nflags;
                                p2values.bit8 = "Not Defined";
                                p2values.bit8hfname = hf_bit8nflags;
                                p2values.bit9 = "Not Defined";
                                p2values.bit9hfname = hf_bit9nflags;
                                p2values.bit10 = "Not Defined";
                                p2values.bit10hfname = hf_bit10nflags;
                                p2values.bit11= "Not Defined";
                                p2values.bit11hfname = hf_bit11nflags;
                                p2values.bit12 = "Not Defined";
                                p2values.bit12hfname = hf_bit12nflags;
                                p2values.bit13 = "Not Defined";
                                p2values.bit13hfname = hf_bit13nflags;
                                p2values.bit14 = "Prefer Referrals";
                                p2values.bit14hfname = hf_bit14nflags;
                                p2values.bit15 = "Prefer Only Referrals";
                                p2values.bit15hfname = hf_bit15nflags;
                                p2values.bit16 = "Not Defined";
                                p2values.bit16hfname = hf_bit16nflags;
                                foffset = foffset+4;
                                if (p1values.vvalue == 0 || p1values.vvalue == 1)
                                {
                                        p3values.vtype = 3; /* Uint32 */
                                        p3values.vdesc = "Scope: %d";
                                        p3values.vstring = "";
                                        p3values.vlength = 4;
                                        p3values.voffset = foffset;
                                        p3values.vvalue = tvb_get_letohl(tvb, foffset);
                                        p3values.hfname= hf_nds_scope;
                                        foffset = foffset+p3values.vlength;
                                        p4values.vtype = 4; /* String */
                                        p4values.vdesc = "Name: %s";
                                        p4values.vstring = "";
                                        p4values.mvtype = 1;
                                        p4values.vvalue = 0;
                                        p4values.vlength = 256;
                                        p4values.vlength = tvb_get_letohl(tvb, foffset);
                                        if (p4values.vlength == 0x00)
                                        {
                                                p4values.vtype = 0;
                                                break;
                                        }
                                        p4values.voffset = foffset+4;
                                        foffset = foffset + 4;
                                        get_string(tvb, p4values.voffset, p4values.vlength, req_buffer.buffer);
                                        p4values.vstring = req_buffer.buffer;
                                        global_object_name = req_buffer.buffer;
                                        p4values.hfname= hf_nds_name;
                                        foffset = foffset+p4values.vlength;
                                        foffset += align_4(tvb, foffset);
                                        p5values.vvalue = tvb_get_letohl(tvb, foffset);
                                        p5values.vtype = 6; /* Mulitvalue Uint32 */
                                        p5values.vstring = "";
                                        p5values.vdesc = "Communications Transports: %d";
                                        p5values.vlength = 4;
                                        p5values.hfname= hf_nds_comm_trans;
                                        p5values.voffset = foffset;
                                        p5values.mvtype = 7;
                                        foffset = foffset + (p5values.vvalue * 4) + 4;
                                        p6values.vvalue = tvb_get_letohl(tvb, foffset);
                                        p6values.vtype = 6; /* Multivalue Uint32 */
                                        p6values.vstring = "";
                                        p6values.vdesc = "Tree Walker Transport Type: %d";
                                        p6values.vlength = 4;
                                        p6values.mvtype = 7;
                                        p6values.hfname= hf_nds_tree_trans;
                                        p6values.voffset = foffset;
                                }
                                else
                                {
                                        p3values.vtype = 3; /* Uint32 */
                                        p3values.vdesc = "Minimum DS Version: %d";
                                        p3values.vstring = "";
                                        p3values.vlength = 4;
                                        p3values.voffset = foffset;
                                        p3values.vvalue = tvb_get_letohl(tvb, foffset);
                                        p3values.hfname= hf_min_nds_ver;
                                        foffset = foffset+p3values.vlength;
                                        p4values.vvalue = tvb_get_letohl(tvb, foffset);
                                        p4values.vtype = 6; /* Multivalue Uint32 */
                                        p4values.vstring = "";
                                        p4values.vdesc = "Number of Versions to Include: %d";
                                        p4values.vlength = 4;
                                        p4values.mvtype = 3;
                                        p4values.voffset = foffset;
                                        p4values.hfname= hf_nds_ver_include;
                                        foffset += (p4values.vvalue * 4) + 4;
                                        p5values.vvalue = tvb_get_letohl(tvb, foffset);
                                        p5values.vtype = 6; /* Multivalue Uint32 */
                                        p5values.vstring = "";
                                        p5values.vdesc = "Number of Versions to Exclude: %d";
                                        p5values.vlength = 4;
                                        p5values.mvtype = 3;
                                        p5values.hfname= hf_nds_ver_exclude;
                                        p5values.voffset = foffset;
                                        foffset += 4;
                                        p6values.vtype = 3; /* Uint32 */
                                        p6values.vdesc = "DN Output Type: %d";
                                        p6values.vstring = "";
                                        p6values.vlength = 4;
                                        p6values.voffset = foffset;
                                        p6values.vvalue = tvb_get_letohl(tvb, foffset);
                                        p6values.hfname= hf_nds_dn_output_type;
                                        foffset = foffset+p6values.vlength;
                                        p7values.vtype = 3; /* Uint32 */
                                        p7values.vdesc = "Nested Output Type: %d";
                                        p7values.vstring = "";
                                        p7values.vlength = 4;
                                        p7values.voffset = foffset;
                                        p7values.vvalue = tvb_get_letohl(tvb, foffset);
                                        p7values.hfname= hf_nds_nested_output_type;
                                        foffset = foffset+p7values.vlength;
                                        p8values.vtype = 4; /* String */
                                        p8values.vdesc = "Output Delimiter: %s";
                                        p8values.vstring = "";
                                        p8values.mvtype = 1;
                                        p8values.vvalue = 0;
                                        p8values.vlength = 256;
                                        p8values.vlength = tvb_get_letohl(tvb, foffset);
                                        p8values.voffset = foffset+4;
                                        foffset = foffset + 4;
                                        get_string(tvb, p8values.voffset, p8values.vlength, req_buffer.buffer);
                                        p8values.vstring = req_buffer.buffer;
                                        p8values.hfname= hf_nds_output_delimiter;
                                        foffset = foffset+p8values.vlength;
                                        foffset += align_4(tvb, foffset);
                                        p9values.vvalue = tvb_get_letohl(tvb, foffset);
                                        p9values.vtype = 6; /* Multivalue Uint32 */
                                        p9values.vstring = "";
                                        p9values.vdesc = "Size of Entry Specifier: %d";
                                        p9values.vlength = 4;
                                        p9values.mvtype = 10;
                                        p9values.hfname= hf_nds_output_entry_specifier;
                                        p9values.voffset = foffset;
                                }
                                break;
                        case 0x02:    
                                verb_string = "Read Entry Information";
                                p1values.vvalue = tvb_get_letohl(tvb, foffset);
                                p1values.vstring = "";
                                p1values.vtype = 3; /* Uint32 */
                                p1values.vdesc = "Version: %d";
                                p1values.vlength = 4;
                                p1values.voffset = foffset;
                                p1values.hfname= hf_nds_ver;
                                foffset = foffset+p1values.vlength;
                                switch(p1values.vvalue)
                                {
                                        case 0:
                                                p2values.vvalue = tvb_get_letohl(tvb, foffset);
                                                p2values.vstring = "";
                                                p2values.vtype = 3; /* Uint32 */
                                                p2values.vdesc = "Entry ID: 0x%08x";
                                                p2values.vlength = 4;
                                                resolve_eid = TRUE;
                                                global_eid = p2values.vvalue;
                                                p2values.voffset = foffset;
                                                p2values.hfname = hf_nds_eid;
                                                foffset = foffset+p2values.vlength;
                                                break;
                                        case 1:
                                                p2values.vvalue = tvb_get_letohl(tvb, foffset);
                                                p2values.vtype = 5; /* Bitfield */
                                                p2values.vstring = "";
                                                p2values.vdesc = "Request Flags:";
                                                p2values.vlength = 2;
                                                p2values.hfname= hf_nds_rflags;
                                                p2values.voffset = foffset;
                                                p2values.bit1 = "Typeless";
                                                p2values.bit1hfname = hf_bit1rflags;
                                                p2values.bit2 = "Slashed";
                                                p2values.bit2hfname = hf_bit2rflags;
                                                p2values.bit3 = "Dotted";
                                                p2values.bit3hfname = hf_bit3rflags;
                                                p2values.bit4 = "Tuned";
                                                p2values.bit4hfname = hf_bit4rflags;
                                                p2values.bit5 = "Not Defined";
                                                p2values.bit5hfname = hf_bit5rflags;
                                                p2values.bit6 = "Not Defined";
                                                p2values.bit6hfname = hf_bit6rflags;
                                                p2values.bit7 = "Not Defined";
                                                p2values.bit7hfname = hf_bit7rflags;
                                                p2values.bit8 = "Not Defined";
                                                p2values.bit8hfname = hf_bit8rflags;
                                                p2values.bit9 = "Not Defined";
                                                p2values.bit9hfname = hf_bit9rflags;
                                                p2values.bit10 = "Not Defined";
                                                p2values.bit10hfname = hf_bit10rflags;
                                                p2values.bit11 = "Not Defined";
                                                p2values.bit11hfname = hf_bit11rflags;
                                                p2values.bit12 = "Not Defined";
                                                p2values.bit12hfname = hf_bit12rflags;
                                                p2values.bit13 = "Not Defined";
                                                p2values.bit13hfname = hf_bit13rflags;
                                                p2values.bit14 = "Not Defined";
                                                p2values.bit14hfname = hf_bit14rflags;
                                                p2values.bit15 = "Not Defined";
                                                p2values.bit15hfname = hf_bit15rflags;
                                                p2values.bit16 = "Not Defined";
                                                p2values.bit16hfname = hf_bit16rflags;
                                                if((p2values.vvalue&&0xf000) == 0xc000)
                                                {
                                                        p3values.vtype = 4; /* String */
                                                        p3values.vdesc = "Name Type: %s";
                                                        p3values.vstring = "Partial";
                                                        p3values.mvtype = 0;
                                                        p3values.vvalue = 0;
                                                        p3values.vlength = 0;
                                                        p3values.voffset = 0;
                                                        p3values.hfname= hf_nds_name_type;
                                                }
                                                else
                                                {
                                                        p3values.vtype = 4; /* String */
                                                        p3values.vdesc = "Name Type: %s";
                                                        p3values.vstring = "Full";
                                                        p3values.vvalue = 0;
                                                        p3values.mvtype = 0;
                                                        p3values.vlength = 0;
                                                        p3values.voffset = 0;
                                                        p3values.hfname= hf_nds_name_type;
                                                }
                                                foffset = foffset+4;
                                                p4values.vvalue = tvb_get_letohl(tvb, foffset);
                                                p4values.vstring = "";
                                                p4values.vtype = 3; /* Uint32 */
                                                p4values.vdesc = "Entry ID: 0x%08x";
                                                p4values.vlength = 4;
                                                p4values.voffset = foffset;
                                                resolve_eid = TRUE;
                                                global_eid = p4values.vvalue;
                                                p4values.hfname = hf_nds_eid;
                                                foffset = foffset+p4values.vlength;
                                                break;
                                        case 2:
                                                p2values.vvalue = tvb_get_letohl(tvb, foffset);
                                                p2values.vtype = 5; /* Bitfield */
                                                p2values.vstring = "";
                                                p2values.vdesc = "Request Flags:";
                                                p2values.vlength = 2;
                                                p2values.hfname= hf_nds_rflags;
                                                p2values.voffset = foffset;
                                                p2values.bit1 = "Typeless";
                                                p2values.bit1hfname = hf_bit1rflags;
                                                p2values.bit2 = "Slashed";
                                                p2values.bit2hfname = hf_bit2rflags;
                                                p2values.bit3 = "Dotted";
                                                p2values.bit3hfname = hf_bit3rflags;
                                                p2values.bit4 = "Tuned";
                                                p2values.bit4hfname = hf_bit4rflags;
                                                p2values.bit5 = "Not Defined";
                                                p2values.bit5hfname = hf_bit5rflags;
                                                p2values.bit6 = "Not Defined";
                                                p2values.bit6hfname = hf_bit6rflags;
                                                p2values.bit7 = "Not Defined";
                                                p2values.bit7hfname = hf_bit7rflags;
                                                p2values.bit8 = "Not Defined";
                                                p2values.bit8hfname = hf_bit8rflags;
                                                p2values.bit9 = "Not Defined";
                                                p2values.bit9hfname = hf_bit9rflags;
                                                p2values.bit10 = "Not Defined";
                                                p2values.bit10hfname = hf_bit10rflags;
                                                p2values.bit11 = "Not Defined";
                                                p2values.bit11hfname = hf_bit11rflags;
                                                p2values.bit12 = "Not Defined";
                                                p2values.bit12hfname = hf_bit12rflags;
                                                p2values.bit13 = "Not Defined";
                                                p2values.bit13hfname = hf_bit13rflags;
                                                p2values.bit14 = "Not Defined";
                                                p2values.bit14hfname = hf_bit14rflags;
                                                p2values.bit15 = "Not Defined";
                                                p2values.bit15hfname = hf_bit15rflags;
                                                p2values.bit16 = "Not Defined";
                                                p2values.bit16hfname = hf_bit16rflags;
                                                if((p2values.vvalue&&0xf000) == 0xc000)
                                                {
                                                        p3values.vtype = 4; /* String */
                                                        p3values.vdesc = "Name Type: %s";
                                                        p3values.vstring = "Return Partion Name";
                                                        p3values.vvalue = 0;
                                                        p3values.vlength = 4;
                                                        p3values.voffset = p2values.voffset;
                                                        p3values.mvtype = 0;
                                                        p3values.hfname= hf_nds_name_type;
                                                }
                                                else
                                                {
                                                        p3values.vtype = 4; /* String */
                                                        p3values.vdesc = "Name Type: %s";
                                                        p3values.vstring = "Return Full Name";
                                                        p3values.vvalue = 0;
                                                        p3values.vlength = 4;
                                                        p3values.mvtype = 0;
                                                        p3values.voffset = p2values.voffset;
                                                        p3values.hfname= hf_nds_name_type;
                                                }
                                                foffset = foffset+4;
                                                p4values.vvalue = tvb_get_letohs(tvb, foffset);
                                                global_flags = tvb_get_letohl(tvb, foffset);
                                                p4values.vtype = 5; /* Bitfield */
                                                p4values.vstring = "";
                                                p4values.vdesc = "Information Flags (low) Byte:";
                                                p4values.vlength = 2;
                                                p4values.hfname= hf_nds_rflags;
                                                p4values.voffset = foffset;
                                                p4values.bit1 = "Output Flags";
                                                p4values.bit1hfname = hf_bit1infoflagsl;
                                                p4values.bit2 = "Entry ID";
                                                p4values.bit2hfname = hf_bit2infoflagsl;
                                                p4values.bit3 = "Entry Flags";
                                                p4values.bit3hfname = hf_bit3infoflagsl;
                                                p4values.bit4 = "Subordinate Count";
                                                p4values.bit4hfname = hf_bit4infoflagsl;
                                                p4values.bit5 = "Modification Time";
                                                p4values.bit5hfname = hf_bit5infoflagsl;
                                                p4values.bit6 = "Modification Timestamp";
                                                p4values.bit6hfname = hf_bit6infoflagsl;
                                                p4values.bit7 = "Creation Timestamp";
                                                p4values.bit7hfname = hf_bit7infoflagsl;
                                                p4values.bit8 = "Partition Root ID";
                                                p4values.bit8hfname = hf_bit8infoflagsl;
                                                p4values.bit9 = "Parent ID";
                                                p4values.bit9hfname = hf_bit9infoflagsl;
                                                p4values.bit10 = "Revision Count";
                                                p4values.bit10hfname = hf_bit10infoflagsl;
                                                p4values.bit11 = "Replica Type";
                                                p4values.bit11hfname = hf_bit11infoflagsl;
                                                p4values.bit12 = "Base Class";
                                                p4values.bit12hfname = hf_bit12infoflagsl;
                                                p4values.bit13 = "Relative Distinguished Name";
                                                p4values.bit13hfname = hf_bit13infoflagsl;
                                                p4values.bit14 = "Distinguished Name";
                                                p4values.bit14hfname = hf_bit14infoflagsl;
                                                p4values.bit15 = "Root Distinguished Name";
                                                p4values.bit15hfname = hf_bit15infoflagsl;
                                                p4values.bit16 = "Parent Distinguished Name";
                                                p4values.bit16hfname = hf_bit16infoflagsl;
                                                foffset = foffset+2;
                                                p5values.vvalue = tvb_get_letohs(tvb, foffset);
                                                p5values.vtype = 5; /* Bitfield */
                                                p5values.vstring = "";
                                                p5values.vdesc = "Information Flags (high) Byte:";
                                                p5values.vlength = 2;
                                                p5values.hfname= hf_nds_rflags;
                                                p5values.voffset = foffset;
                                                p5values.bit1 = "Purge Time";
                                                p5values.bit1hfname = hf_bit1infoflagsh;
                                                p5values.bit2 = "Dereference Base Class";
                                                p5values.bit2hfname = hf_bit2infoflagsh;
                                                p5values.bit3 = "Not Defined";
                                                p5values.bit3hfname = hf_bit3infoflagsh;
                                                p5values.bit4 = "Not Defined";
                                                p5values.bit4hfname = hf_bit4infoflagsh;
                                                p5values.bit5 = "Not Defined";
                                                p5values.bit5hfname = hf_bit5infoflagsh;
                                                p5values.bit6 = "Not Defined";
                                                p5values.bit6hfname = hf_bit6infoflagsh;
                                                p5values.bit7 = "Not Defined";
                                                p5values.bit7hfname = hf_bit7infoflagsh;
                                                p5values.bit8 = "Not Defined";
                                                p5values.bit8hfname = hf_bit8infoflagsh;
                                                p5values.bit9 = "Not Defined";
                                                p5values.bit9hfname = hf_bit9infoflagsh;
                                                p5values.bit10 = "Not Defined";
                                                p5values.bit10hfname = hf_bit10infoflagsh;
                                                p5values.bit11 = "Not Defined";
                                                p5values.bit11hfname = hf_bit11infoflagsh;
                                                p5values.bit12 = "Not Defined";
                                                p5values.bit12hfname = hf_bit12infoflagsh;
                                                p5values.bit13 = "Not Defined";
                                                p5values.bit13hfname = hf_bit13infoflagsh;
                                                p5values.bit14 = "Not Defined";
                                                p5values.bit14hfname = hf_bit14infoflagsh;
                                                p5values.bit15 = "Not Defined";
                                                p5values.bit15hfname = hf_bit15infoflagsh;
                                                p5values.bit16 = "Not Defined";
                                                p5values.bit16hfname = hf_bit16infoflagsh;
                                                foffset = foffset+2;
                                                p6values.vvalue = tvb_get_letohl(tvb, foffset);
                                                p6values.vstring = "";
                                                p6values.vtype = 3; /* Uint32 */
                                                p6values.vdesc = "Entry ID: 0x%08x";
                                                p6values.vlength = 4;
                                                p6values.voffset = foffset;
                                                resolve_eid = TRUE;
                                                global_eid = p6values.vvalue;
                                                p6values.hfname = hf_nds_eid;
                                                foffset = foffset+p6values.vlength;
                                                break;
                                        default:
                                                break;
                                }
                                
                                break;
                        case 0x03:    
                                verb_string = "Read -> ";
                                p1values.vvalue = tvb_get_letohl(tvb, foffset);
                                p1values.vstring = "";
                                p1values.vtype = 3; /* Uint32 */
                                p1values.vdesc = "Version: %d";
                                p1values.vlength = 4;
                                p1values.voffset = foffset;
                                p1values.hfname= hf_nds_ver;
                                foffset = foffset+p1values.vlength;
                                if(p1values.vvalue == 0)
                                {
                                        p2values.vvalue = tvb_get_letohl(tvb, foffset);
                                        p2values.vstring = "";
                                        p2values.vtype = 3; /* Uint32 */
                                        p2values.vdesc = "Iteration Handle: 0x%08x";
                                        p2values.vlength = 4;
                                        p2values.voffset = foffset;
                                        p2values.hfname= hf_nds_iteration;
                                        foffset = foffset+p2values.vlength;
                                        p3values.vvalue = tvb_get_letohl(tvb, foffset);
                                        p3values.vstring = "";
                                        p3values.vtype = 3; /* Uint32 */
                                        p3values.vdesc = "Entry ID: 0x%08x";
                                        p3values.vlength = 4;
                                        resolve_eid = TRUE;
                                        global_eid = p3values.vvalue;
                                        p3values.voffset = foffset;
                                        p3values.hfname= hf_nds_eid;
                                        foffset = foffset+p3values.vlength;
                                        p4values.vvalue = tvb_get_letohl(tvb, foffset);
                                        p4values.vstring = match_strval(p4values.vvalue, nds_info_type);
                                        global_flags = p4values.vvalue;
                                        if(p4values.vstring == NULL)
                                        {
                                                p4values.vstring = "No Info Type Set";
                                        }
                                        p4values.vtype = 4; /* String */
                                        p4values.vdesc = "Info Type: %s";
                                        p4values.vlength = 4;
                                        p4values.voffset = foffset;
                                        p4values.mvtype = 1;
                                        p4values.hfname= hf_nds_info_type;
                                        foffset = foffset + p4values.vlength;
                                        p5values.vvalue = tvb_get_letohl(tvb, foffset);
                                        p5values.vstring = "";
                                        p5values.vtype = 3; /* Uint32 */
                                        p5values.vdesc = "All Attributes: %d";
                                        p5values.vlength = 4;
                                        p5values.voffset = foffset;
                                        p5values.hfname= hf_nds_all_attr;
                                        foffset = foffset+p5values.vlength;
                                        p6values.vvalue = tvb_get_letohl(tvb, foffset);
                                        p6values.vtype = 6; /* Multivalue Uint32 */
                                        p6values.vstring = "";
                                        p6values.vdesc = "Attributes: %d";
                                        p6values.vlength = 4;
                                        p6values.voffset = foffset;
                                        p6values.mvtype = 1;
                                        p6values.hfname= hf_nds_attr;
                                }
                                else
                                {
                                        p2values.vvalue = tvb_get_letohl(tvb, foffset);
                                        p2values.vstring = "";
                                        p2values.vtype = 3; /* Uint32 */
                                        p2values.vdesc = "Request Flags: 0x%08x";
                                        p2values.vlength = 4;
                                        p2values.voffset = foffset;
                                        p2values.hfname= hf_nds_req_flags;
                                        foffset = foffset+p2values.vlength;
                                        p3values.vvalue = tvb_get_letohl(tvb, foffset);
                                        p3values.vstring = "";
                                        p3values.vtype = 3; /* Uint32 */
                                        p3values.vdesc = "Iteration Handle: 0x%08x";
                                        p3values.vlength = 4;
                                        p3values.voffset = foffset;
                                        p3values.hfname= hf_nds_iteration;
                                        foffset = foffset+p3values.vlength;
                                        p4values.vvalue = tvb_get_letohl(tvb, foffset);
                                        p4values.vstring = "";
                                        p4values.vtype = 3; /* Uint32 */
                                        p4values.vdesc = "Entry ID: 0x%08x";
                                        p4values.vlength = 4;
                                        resolve_eid = TRUE;
                                        global_eid = p4values.vvalue;
                                        p4values.voffset = foffset;
                                        p4values.hfname= hf_nds_eid;
                                        foffset = foffset+p4values.vlength;
                                        p5values.vvalue = tvb_get_letohl(tvb, foffset);
                                        p5values.vstring = match_strval(p5values.vvalue, nds_info_type);
                                        global_flags = p5values.vvalue;
                                        if(p5values.vstring == NULL)
                                        {
                                                p5values.vstring = "No Info Type Set";
                                        }
                                        p5values.vtype = 4; /* String */
                                        p5values.vdesc = "Info Type: %s";
                                        p5values.vlength = 4;
                                        p5values.voffset = foffset;
                                        p5values.hfname= hf_nds_info_type;
                                        p5values.mvtype = 1;
                                        foffset = foffset+p5values.vlength;
                                        p6values.vvalue = tvb_get_letohl(tvb, foffset);
                                        p6values.vstring = "";
                                        p6values.vtype = 3; /* Uint32 */
                                        p6values.vdesc = "All Attributes: %d";
                                        p6values.vlength = 4;
                                        p6values.voffset = foffset;
                                        p6values.hfname= hf_nds_all_attr;
                                        foffset = foffset+p6values.vlength;
                                        p7values.vvalue = tvb_get_letohl(tvb, foffset);
                                        p7values.vtype = 6; /* Multivalue Uint32 */
                                        p7values.vstring = "";
                                        p7values.vdesc = "Attributes: %d";
                                        p7values.vlength = 4;
                                        p7values.voffset = foffset;
                                        p7values.mvtype = 1;
                                        p7values.hfname= hf_nds_attr;
                                }
                                break;
                        case 0x04:    
                                verb_string = "Compare";
                                p1values.vvalue = tvb_get_letohl(tvb, foffset);
                                p1values.vstring = "";
                                p1values.vtype = 3; /* Uint32 */
                                p1values.vdesc = "Version: %d";
                                p1values.vlength = 4;
                                p1values.voffset = foffset;
                                p1values.hfname= hf_nds_ver;
                                foffset = foffset+p1values.vlength;
                                p2values.vvalue = tvb_get_letohl(tvb, foffset);
                                p2values.vstring = "";
                                p2values.vtype = 3; /* Uint32 */
                                p2values.vdesc = "Entry ID: 0x%08x";
                                p2values.vlength = 4;
                                resolve_eid = TRUE;
                                global_eid = p2values.vvalue;
                                p2values.voffset = foffset;
                                p2values.hfname = hf_nds_eid;
                                foffset = foffset+p2values.vlength;
                                foffset += 4;       /* Attribute Count = 1 */
                                p3values.vtype = 4; /* String */
                                p3values.vdesc = "Attribute Name Being Compared: %s";
                                p3values.vstring = "";
                                p3values.mvtype = 1;
                                p3values.vvalue = 0;
                                p3values.vlength = 256;
                                p3values.vlength = tvb_get_letohl(tvb, foffset);
                                if (p3values.vlength == 0x00)
                                {
                                        p3values.vtype = 0;
                                        break;
                                }
                                p3values.voffset = foffset+4;
                                foffset = foffset + 4;
                                get_string(tvb, p3values.voffset, p3values.vlength, req_buffer.buffer);
                                p3values.vstring = req_buffer.buffer;
                                global_object_name = req_buffer.buffer;
                                p3values.hfname= hf_nds_name;
                                foffset = foffset+p3values.vlength;
                                foffset += align_4(tvb, foffset);
                                foffset += 4;       /* Attribute Value Count = 1 */
                                /***************
                                 * Need Trace file to test. Will have to create a 
                                 * new mvtype to call print_nds_values.
                                 ***************/
                                break;
                        case 0x05:    
                                verb_string = "List -> ";
                                p1values.vvalue = tvb_get_letohl(tvb, foffset);
                                p1values.vstring = "";
                                p1values.vtype = 3; /* Uint32 */
                                p1values.vdesc = "Version: %d";
                                p1values.vlength = 4;
                                p1values.voffset = foffset;
                                p1values.hfname= hf_nds_ver;
                                foffset = foffset+p1values.vlength;
                                p2values.vvalue = tvb_get_letohl(tvb, foffset);
                                p2values.vtype = 5; /* Bitfield */
                                p2values.vstring = "";
                                p2values.vdesc = "Request Flags:";
                                p2values.vlength = 2;
                                p2values.hfname= hf_nds_rflags;
                                p2values.voffset = foffset;
                                p2values.bit1 = "List Typeless";
                                p2values.bit1hfname = hf_bit1lflags;
                                p2values.bit2 = "List Containers";
                                p2values.bit2hfname = hf_bit2lflags;
                                p2values.bit3 = "List Slashed";
                                p2values.bit3hfname = hf_bit3lflags;
                                p2values.bit4 = "List Dotted";
                                p2values.bit4hfname = hf_bit4lflags;
                                p2values.bit5 = "Dereference Alias";
                                p2values.bit5hfname = hf_bit5lflags;
                                p2values.bit6 = "List All Containers";
                                p2values.bit6hfname = hf_bit6lflags;
                                p2values.bit7 = "List Obsolete";
                                p2values.bit7hfname = hf_bit7lflags;
                                p2values.bit8 = "List Tuned Output";
                                p2values.bit8hfname = hf_bit8lflags;
                                p2values.bit9 = "List External Reference";
                                p2values.bit9hfname = hf_bit9lflags;
                                p2values.bit10 = "Not Defined";
                                p2values.bit10hfname = hf_bit10lflags;
                                p2values.bit11 = "Not Defined";
                                p2values.bit11hfname = hf_bit11lflags;
                                p2values.bit12 = "Not Defined";
                                p2values.bit12hfname = hf_bit12lflags;
                                p2values.bit13 = "Not Defined";
                                p2values.bit13hfname = hf_bit13lflags;
                                p2values.bit14 = "Not Defined";
                                p2values.bit14hfname = hf_bit14lflags;
                                p2values.bit15 = "Not Defined";
                                p2values.bit15hfname = hf_bit15lflags;
                                p2values.bit16 = "Not Defined";
                                p2values.bit16hfname = hf_bit16lflags;
                                foffset = foffset+p2values.vlength;
                                foffset += 2;
                                p3values.vvalue = tvb_get_letohl(tvb, foffset);
                                p3values.vstring = "";
                                p3values.vtype = 3; /* Uint32 */
                                p3values.vdesc = "Iteration Handle: 0x%08x";
                                p3values.vlength = 4;
                                p3values.voffset = foffset;
                                p3values.hfname= hf_nds_iteration;
                                foffset = foffset+p3values.vlength;
                                p4values.vvalue = tvb_get_letohl(tvb, foffset);
                                p4values.vstring = "";
                                p4values.vtype = 3; /* Uint32 */
                                p4values.vdesc = "Parent ID: 0x%08x";
                                p4values.vlength = 4;
                                p4values.voffset = foffset;
                                p4values.hfname= hf_nds_parent;
                                foffset = foffset+p4values.vlength;
                                p5values.vvalue = tvb_get_letohs(tvb, foffset);
                                global_flags = tvb_get_letohl(tvb, foffset);
                                p5values.vtype = 5; /* Bitfield */
                                p5values.vstring = "";
                                p5values.vdesc = "Information Flags (low) Byte:";
                                p5values.vlength = 2;
                                p5values.hfname= hf_nds_rflags;
                                p5values.voffset = foffset;
                                p5values.bit1 = "Output Flags";
                                p5values.bit1hfname = hf_bit1infoflagsl;
                                p5values.bit2 = "Entry ID";
                                p5values.bit2hfname = hf_bit2infoflagsl;
                                p5values.bit3 = "Entry Flags";
                                p5values.bit3hfname = hf_bit3infoflagsl;
                                p5values.bit4 = "Subordinate Count";
                                p5values.bit4hfname = hf_bit4infoflagsl;
                                p5values.bit5 = "Modification Time";
                                p5values.bit5hfname = hf_bit5infoflagsl;
                                p5values.bit6 = "Modification Timestamp";
                                p5values.bit6hfname = hf_bit6infoflagsl;
                                p5values.bit7 = "Creation Timestamp";
                                p5values.bit7hfname = hf_bit7infoflagsl;
                                p5values.bit8 = "Partition Root ID";
                                p5values.bit8hfname = hf_bit8infoflagsl;
                                p5values.bit9 = "Parent ID";
                                p5values.bit9hfname = hf_bit9infoflagsl;
                                p5values.bit10 = "Revision Count";
                                p5values.bit10hfname = hf_bit10infoflagsl;
                                p5values.bit11 = "Replica Type";
                                p5values.bit11hfname = hf_bit11infoflagsl;
                                p5values.bit12 = "Base Class";
                                p5values.bit12hfname = hf_bit12infoflagsl;
                                p5values.bit13 = "Relative Distinguished Name";
                                p5values.bit13hfname = hf_bit13infoflagsl;
                                p5values.bit14 = "Distinguished Name";
                                p5values.bit14hfname = hf_bit14infoflagsl;
                                p5values.bit15 = "Root Distinguished Name";
                                p5values.bit15hfname = hf_bit15infoflagsl;
                                p5values.bit16 = "Parent Distinguished Name";
                                p5values.bit16hfname = hf_bit16infoflagsl;
                                foffset = foffset+2;
                                p6values.vvalue = tvb_get_letohs(tvb, foffset);
                                p6values.vtype = 5; /* Bitfield */
                                p6values.vstring = "";
                                p6values.vdesc = "Information Flags (high) Byte:";
                                p6values.vlength = 2;
                                p6values.hfname= hf_nds_rflags;
                                p6values.voffset = foffset;
                                p6values.bit1 = "Purge Time";
                                p6values.bit1hfname = hf_bit1infoflagsh;
                                p6values.bit2 = "Dereference Base Class";
                                p6values.bit2hfname = hf_bit2infoflagsh;
                                p6values.bit3 = "Not Defined";
                                p6values.bit3hfname = hf_bit3infoflagsh;
                                p6values.bit4 = "Not Defined";
                                p6values.bit4hfname = hf_bit4infoflagsh;
                                p6values.bit5 = "Not Defined";
                                p6values.bit5hfname = hf_bit5infoflagsh;
                                p6values.bit6 = "Not Defined";
                                p6values.bit6hfname = hf_bit6infoflagsh;
                                p6values.bit7 = "Not Defined";
                                p6values.bit7hfname = hf_bit7infoflagsh;
                                p6values.bit8 = "Not Defined";
                                p6values.bit8hfname = hf_bit8infoflagsh;
                                p6values.bit9 = "Not Defined";
                                p6values.bit9hfname = hf_bit9infoflagsh;
                                p6values.bit10 = "Not Defined";
                                p6values.bit10hfname = hf_bit10infoflagsh;
                                p6values.bit11 = "Not Defined";
                                p6values.bit11hfname = hf_bit11infoflagsh;
                                p6values.bit12 = "Not Defined";
                                p6values.bit12hfname = hf_bit12infoflagsh;
                                p6values.bit13 = "Not Defined";
                                p6values.bit13hfname = hf_bit13infoflagsh;
                                p6values.bit14 = "Not Defined";
                                p6values.bit14hfname = hf_bit14infoflagsh;
                                p6values.bit15 = "Not Defined";
                                p6values.bit15hfname = hf_bit15infoflagsh;
                                p6values.bit16 = "Not Defined";
                                p6values.bit16hfname = hf_bit16infoflagsh;
                                foffset = foffset+2;
                                p7values.vtype = 4; /* String */
                                p7values.vdesc = "Name Filter: %s";
                                p7values.vstring = "";
                                p7values.mvtype = 1;
                                p7values.vvalue = 0;
                                p7values.vlength = 256;
                                p7values.vlength = tvb_get_letohl(tvb, foffset);
                                p7values.voffset = foffset+4;
                                foffset = foffset + 4;
                                get_string(tvb, p7values.voffset, p7values.vlength, p7values.vstring);
                                p7values.hfname= hf_nds_name_filter;
                                foffset = foffset+p7values.vlength;
                                if(p1values.vvalue == 0)
                                {
                                        break;
                                }        
                                foffset += align_4(tvb, foffset);
                                p8values.vtype = 4; /* String */
                                p8values.vdesc = "Class Filter: %s";
                                p8values.vstring = "";
                                p8values.mvtype = 1;
                                p8values.vvalue = 0;
                                p8values.vlength = 256;
                                p8values.vlength = tvb_get_letohl(tvb, foffset);
                                p8values.voffset = foffset+4;
                                foffset = foffset + 4;
                                get_string(tvb, p8values.voffset, p8values.vlength, p8values.vstring);
                                p8values.hfname= hf_nds_class_filter;
                                foffset = foffset+p8values.vlength;
                                if(p1values.vvalue == 1)
                                {
                                        break;
                                }        
                                foffset += align_4(tvb, foffset);
                                p9values.vvalue = tvb_get_letohl(tvb, foffset);
                                p9values.vtype = 6; /* Multivalue Uint32 */
                                p9values.vstring = "";
                                p9values.vdesc = "Seconds %d";
                                p9values.vlength = 4;
                                p9values.mvtype = 11;
                                p9values.hfname= hf_nds_time_filter;
                                p9values.voffset = foffset;
                                break;
                        case 0x06:    
                                verb_string = "Search Entries";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x07:    
                                verb_string = "Add Entry";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x08:    
                                verb_string = "Remove Entry";
                                p1values.vvalue = tvb_get_letohl(tvb, foffset);
                                p1values.vstring = "";
                                p1values.vtype = 3; /* Uint32 */
                                p1values.vdesc = "Version: %d";
                                p1values.vlength = 4;
                                p1values.voffset = foffset;
                                p1values.hfname= hf_nds_ver;
                                foffset = foffset+p1values.vlength;
                                p2values.vvalue = tvb_get_letohl(tvb, foffset);
                                p2values.vstring = "";
                                p2values.vtype = 3; /* Uint32 */
                                p2values.vdesc = "Entry ID: 0x%08x";
                                p2values.vlength = 4;
                                resolve_eid = TRUE;
                                global_eid = p2values.vvalue;
                                p2values.voffset = foffset;
                                p2values.hfname= hf_nds_eid;
                                foffset = foffset+p2values.vlength;
                                break;
                        case 0x09:    
                                verb_string = "Modify Entry";
                                p1values.vvalue = tvb_get_letohl(tvb, foffset);
                                p1values.vstring = "";
                                p1values.vtype = 3; /* Uint32 */
                                p1values.vdesc = "Version: %d";
                                p1values.vlength = 4;
                                p1values.voffset = foffset;
                                p1values.hfname= hf_nds_ver;
                                foffset = foffset+p1values.vlength;
                                p2values.vvalue = tvb_get_letohl(tvb, foffset);
                                p2values.vtype = 3; /* Uint32 */
                                p2values.vstring = "";
                                p2values.vdesc = "Request Flags: 0x%08x";  /* always 0 */
                                p2values.vlength = 4;
                                p2values.hfname= hf_nds_rflags;
                                p2values.voffset = foffset;
                                foffset = foffset+4;
                                p3values.vvalue = tvb_get_letohl(tvb, foffset);
                                p3values.vtype = 3; /* Uint32 */
                                p3values.vstring = "";
                                p3values.vdesc = "Iteration Handle: 0x%08x";  /* always 0 */
                                p3values.vlength = 4;
                                p3values.hfname= hf_nds_iteration;
                                p3values.voffset = foffset;
                                foffset = foffset+4;
                                p4values.vvalue = tvb_get_letohl(tvb, foffset);
                                p4values.vstring = "";
                                p4values.vtype = 3; /* Uint32 */
                                p4values.vdesc = "Entry ID: 0x%08x";
                                p4values.vlength = 4;
                                p4values.voffset = foffset;
                                resolve_eid = TRUE;
                                global_eid = p4values.vvalue;
                                p4values.hfname = hf_nds_eid;
                                foffset = foffset+p4values.vlength;
                                p5values.vvalue = tvb_get_letohl(tvb, foffset);
                                p5values.vtype = 6; /* Multivalue Uint32 */
                                p5values.vstring = "";
                                p5values.vdesc = "Number of Attributes to Change %d";
                                p5values.vlength = 4;
                                p5values.mvtype = 6;
                                p5values.hfname= hf_nds_number_of_changes;
                                p5values.voffset = foffset;
                                break;
                        case 0x0a:    
                                verb_string = "Modify RDN";
                                p1values.vvalue = tvb_get_letohl(tvb, foffset);
                                p1values.vstring = "";
                                p1values.vtype = 3; /* Uint32 */
                                p1values.vdesc = "Version: %d";
                                p1values.vlength = 4;
                                p1values.voffset = foffset;
                                p1values.hfname= hf_nds_ver;
                                foffset = foffset+p1values.vlength;
                                p2values.vvalue = tvb_get_letohl(tvb, foffset);
                                p2values.vstring = "";
                                p2values.vtype = 3; /* Uint32 */
                                p2values.vdesc = "Entry ID: 0x%08x";
                                p2values.vlength = 4;
                                resolve_eid = TRUE;
                                global_eid = p2values.vvalue;
                                p2values.voffset = foffset;
                                p2values.hfname = hf_nds_eid;
                                foffset = foffset+p2values.vlength;
                                p3values.vvalue = tvb_get_letohl(tvb, foffset);
                                p3values.vtype = 8; /* Boolean */
                                p3values.vdesc = "Keep Original RDN: %s";
                                p3values.vlength = 4;
                                p3values.voffset = foffset;
                                p3values.mvtype = 0;
                                p3values.hfname= hf_nds_keep;
                                foffset = foffset+4;
                                foffset += align_4(tvb, foffset);
                                p4values.vtype = 4; /* String */
                                p4values.vdesc = "New RDN: %s";
                                p4values.vstring = "";
                                p4values.mvtype = 0;
                                p4values.vvalue = 0;
                                p4values.vlength = 256;
                                p4values.vlength = tvb_get_letohl(tvb, foffset);
                                p4values.voffset = foffset+4;
                                foffset = foffset + 4;
                                get_string(tvb, p4values.voffset, p4values.vlength, p4values.vstring);
                                p4values.hfname= hf_nds_new_rdn;
                                foffset = foffset+p4values.vlength;
                                break;
                        case 0x0b:    
                                verb_string = "Define Attribute ->";
                                p1values.vvalue = tvb_get_letohl(tvb, foffset);
                                p1values.vstring = "";
                                p1values.vtype = 3; /* Uint32 */
                                p1values.vdesc = "Version: %d";
                                p1values.vlength = 4;
                                p1values.voffset = foffset;
                                p1values.hfname= hf_nds_ver;
                                foffset = foffset+p1values.vlength;
                                p2values.vvalue = tvb_get_letohs(tvb, foffset);
                                global_flags = tvb_get_letohl(tvb, foffset);
                                p2values.vtype = 5; /* Bitfield */
                                p2values.vstring = "";
                                p2values.vdesc = "Attribute Constraints:";
                                p2values.vlength = 2;
                                p2values.hfname= hf_nds_acflags;
                                p2values.voffset = foffset;
                                p2values.bit1 = "Single Valued";
                                p2values.bit1hfname = hf_bit1acflags;
                                p2values.bit2 = "Sized";
                                p2values.bit2hfname = hf_bit2acflags;
                                p2values.bit3 = "Non-Removable";
                                p2values.bit3hfname = hf_bit3acflags;
                                p2values.bit4 = "Read Only";
                                p2values.bit4hfname = hf_bit4acflags;
                                p2values.bit5 = "Hidden";
                                p2values.bit5hfname = hf_bit5acflags;
                                p2values.bit6 = "String";
                                p2values.bit6hfname = hf_bit6acflags;
                                p2values.bit7 = "Synchronize Immediate";
                                p2values.bit7hfname = hf_bit7acflags;
                                p2values.bit8 = "Public Read";
                                p2values.bit8hfname = hf_bit8acflags;
                                p2values.bit9 = "Server Read";
                                p2values.bit9hfname = hf_bit9acflags;
                                p2values.bit10 = "Write Managed";
                                p2values.bit10hfname = hf_bit10acflags;
                                p2values.bit11 = "Per Replica";
                                p2values.bit11hfname = hf_bit11acflags;
                                p2values.bit12 = "Never Schedule Synchronization";
                                p2values.bit12hfname = hf_bit12acflags;
                                p2values.bit13 = "Operational";
                                p2values.bit13hfname = hf_bit13acflags;
                                p2values.bit14 = "Not Defined";
                                p2values.bit14hfname = hf_bit14acflags;
                                p2values.bit15 = "Not Defined";
                                p2values.bit15hfname = hf_bit15acflags;
                                p2values.bit16 = "Not Defined";
                                p2values.bit16hfname = hf_bit16acflags;
                                foffset = foffset+4;
                                p3values.vtype = 4; /* String */
                                p3values.vdesc = "Attribute Name: %s";
                                p3values.vstring = "";
                                p3values.mvtype = 1;
                                p3values.vvalue = 0;
                                p3values.vlength = 256;
                                p3values.vlength = tvb_get_letohl(tvb, foffset);
                                if (p3values.vlength == 0x00)
                                {
                                        p3values.vtype = 0;
                                        break;
                                }
                                p3values.voffset = foffset+4;
                                foffset = foffset + 4;
                                get_string(tvb, p3values.voffset, p3values.vlength, req_buffer.buffer);
                                p3values.vstring = req_buffer.buffer;
                                global_object_name = req_buffer.buffer;
                                p3values.hfname= hf_nds_name;
                                foffset = foffset+p3values.vlength;
                                foffset += align_4(tvb, foffset);
                                p4values.vvalue = tvb_get_letohl(tvb, foffset);
                                p4values.vstring = match_strval(p4values.vvalue, nds_syntax);
                                if(p4values.vstring == NULL)
                                {
                                        p4values.vstring = "No Syntax Found";
                                }
                                p4values.vtype = 4; /* String */
                                p4values.vdesc = "Syntax: %s";
                                p4values.vlength = 4;
                                p4values.voffset = foffset;
                                p4values.hfname= hf_nds_syntax;
                                p4values.mvtype = 0;
                                foffset = foffset+p4values.vlength;
                                p5values.vvalue = tvb_get_letohl(tvb, foffset);
                                p5values.vstring = "";
                                p5values.vtype = 3; /* Uint32 */
                                p5values.vdesc = "Lower Limit Value %d";
                                p5values.vlength = 4;
                                p5values.voffset = foffset;
                                p5values.hfname = hf_nds_lower;
                                foffset += 4;
                                p6values.vvalue = tvb_get_letohl(tvb, foffset);
                                p6values.vstring = "";
                                p6values.vtype = 3; /* Uint32 */
                                p6values.vdesc = "Upper Limit Value %d";
                                p6values.vlength = 4;
                                p6values.voffset = foffset;
                                p6values.hfname = hf_nds_upper;
                                p7values.vvalue = tvb_get_letohl(tvb, foffset); /* Length of bytes field */
                                foffset += 4;
                                p7values.vstring = "";
                                p7values.vtype = 7; /* Bytes */
                                p7values.vdesc = "ASN.1 ID";
                                p7values.vlength = p7values.vvalue;
                                p7values.voffset = foffset;
                                p7values.hfname = hf_nds_asn1;
                                break;
                        case 0x0c:    
                                verb_string = "Read Attribute Definition";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x0d:    
                                verb_string = "Remove Attribute Definition";
                                p1values.vvalue = tvb_get_letohl(tvb, foffset);
                                p1values.vstring = "";
                                p1values.vtype = 3; /* Uint32 */
                                p1values.vdesc = "Version: %d";
                                p1values.vlength = 4;
                                p1values.voffset = foffset;
                                p1values.hfname= hf_nds_ver;
                                foffset = foffset+p1values.vlength;
                                p2values.vtype = 4; /* String */
                                p2values.vdesc = "Attribute Name: %s";
                                p2values.vstring = "";
                                p2values.mvtype = 1;
                                p2values.vvalue = 0;
                                p2values.vlength = 256;
                                p2values.vlength = tvb_get_letohl(tvb, foffset);
                                if (p2values.vlength == 0x00)
                                {
                                        p2values.vtype = 0;
                                        break;
                                }
                                p2values.voffset = foffset+4;
                                foffset = foffset + 4;
                                get_string(tvb, p2values.voffset, p2values.vlength, req_buffer.buffer);
                                p2values.vstring = req_buffer.buffer;
                                global_object_name = req_buffer.buffer;
                                p2values.hfname= hf_nds_attribute_dn;
                                break;
                        case 0x0e:    
                                verb_string = "Define Class";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x0f:    
                                verb_string = "Read Class Definition ->";
                                p1values.vvalue = tvb_get_letohl(tvb, foffset);
                                p1values.vstring = "";
                                p1values.vtype = 3; /* Uint32 */
                                p1values.vdesc = "Version: %d";
                                p1values.vlength = 4;
                                p1values.voffset = foffset;
                                p1values.hfname= hf_nds_ver;
                                foffset = foffset+p1values.vlength;
                                p2values.vvalue = tvb_get_letohl(tvb, foffset);
                                p2values.vstring = "";
                                p2values.vtype = 3; /* Uint32 */
                                p2values.vdesc = "Iteration Handle: 0x%08x";
                                p2values.vlength = 4;
                                p2values.voffset = foffset;
                                p2values.hfname= hf_nds_iteration;
                                foffset = foffset+p2values.vlength;
                                p3values.vvalue = tvb_get_letohl(tvb, foffset);
                                global_flags = p3values.vvalue;
                                p3values.vstring = match_strval(p3values.vvalue, class_def_type);
                                if(p3values.vstring == NULL)
                                {
                                        p3values.vstring = "No Class Definition Type Set";
                                }
                                p3values.vtype = 4; /* String */
                                p3values.vdesc = "Class Definition Type: %s";
                                p3values.vlength = 4;
                                p3values.voffset = foffset;
                                p3values.mvtype = 0;
                                p3values.hfname= hf_nds_class_def_type;
                                foffset = foffset + p3values.vlength;
                                p4values.vvalue = tvb_get_letohl(tvb, foffset);
                                if (p4values.vvalue == 0x00000000)
                                {
                                        p4values.vstring = "Return All Classes = False";
                                }        
                                else
                                {
                                        p4values.vstring = "Return All Classes = True";
                                }
                                p4values.vtype = 4; /* String */
                                p4values.vdesc = "Return all Classes %s";
                                p4values.vlength = 4;
                                p4values.voffset = foffset;
                                p4values.mvtype = 0;
                                p4values.hfname= hf_nds_return_all_classes;
                                foffset = foffset + p4values.vlength;
                                foffset += align_4(tvb, foffset);
                                p5values.vvalue = tvb_get_letohl(tvb, foffset);
                                p5values.vtype = 6; /* Multivalue Uint32 */
                                p5values.vstring = "";
                                p5values.vdesc = "Classes: %d";
                                p5values.vlength = 4;
                                p5values.voffset = foffset;
                                p5values.mvtype = 4;
                                p5values.hfname= hf_nds_classes;
                                break;
                        case 0x10:    
                                verb_string = "Modify Class Definition -> ";
                                p1values.vvalue = tvb_get_letohl(tvb, foffset);
                                p1values.vstring = "";
                                p1values.vtype = 3; /* Uint32 */
                                p1values.vdesc = "Version: %d";
                                p1values.vlength = 4;
                                p1values.voffset = foffset;
                                p1values.hfname= hf_nds_ver;
                                foffset = foffset+p1values.vlength;
                                p2values.vtype = 4; /* String */
                                p2values.vdesc = "Class Name: %s";
                                p2values.vstring = "";
                                p2values.mvtype = 1;
                                p2values.vvalue = 0;
                                p2values.vlength = 256;
                                p2values.vlength = tvb_get_letohl(tvb, foffset);
                                if (p2values.vlength == 0x00)
                                {
                                        p2values.vtype = 0;
                                        break;
                                }
                                p2values.voffset = foffset+4;
                                foffset = foffset + 4;
                                get_string(tvb, p2values.voffset, p2values.vlength, req_buffer.buffer);
                                p2values.vstring = req_buffer.buffer;
                                global_object_name = req_buffer.buffer;
                                p2values.hfname= hf_nds_base_class;
                                foffset = foffset+p2values.vlength;
                                foffset += align_4(tvb, foffset);
                                p3values.vvalue = tvb_get_letohl(tvb, foffset);
                                p3values.vtype = 6; /* Multivalue Uint32 */
                                p3values.vstring = "";
                                p3values.vdesc = "Number of Attributes to Add: %d";
                                p3values.vlength = 4;
                                p3values.voffset = foffset;
                                p3values.mvtype = 14;
                                p3values.hfname= hf_nds_att_add;
                                break;
                        case 0x11:    
                                verb_string = "Remove Class Definition";
                                p1values.vvalue = tvb_get_letohl(tvb, foffset);
                                p1values.vstring = "";
                                p1values.vtype = 3; /* Uint32 */
                                p1values.vdesc = "Version: %d";
                                p1values.vlength = 4;
                                p1values.voffset = foffset;
                                p1values.hfname= hf_nds_ver;
                                foffset = foffset+p1values.vlength;
                                p2values.vtype = 4; /* String */
                                p2values.vdesc = "Class Name: %s";
                                p2values.vstring = "";
                                p2values.mvtype = 1;
                                p2values.vvalue = 0;
                                p2values.vlength = 256;
                                p2values.vlength = tvb_get_letohl(tvb, foffset);
                                if (p2values.vlength == 0x00)
                                {
                                        p2values.vtype = 0;
                                        break;
                                }
                                p2values.voffset = foffset+4;
                                foffset = foffset + 4;
                                get_string(tvb, p2values.voffset, p2values.vlength, req_buffer.buffer);
                                p2values.vstring = req_buffer.buffer;
                                global_object_name = req_buffer.buffer;
                                p2values.hfname= hf_nds_base;
                                break;
                        case 0x12:    
                                verb_string = "List Containable Classes";
                                p1values.vvalue = tvb_get_letohl(tvb, foffset);
                                p1values.vstring = "";
                                p1values.vtype = 3; /* Uint32 */
                                p1values.vdesc = "Version: %d";
                                p1values.vlength = 4;
                                p1values.voffset = foffset;
                                p1values.hfname= hf_nds_ver;
                                foffset = foffset+p1values.vlength;
                                p2values.vvalue = tvb_get_letohl(tvb, foffset);
                                p2values.vstring = "";
                                p2values.vtype = 3; /* Uint32 */
                                p2values.vdesc = "Iteration Handle: 0x%08x";
                                p2values.vlength = 4;
                                p2values.voffset = foffset;
                                p2values.hfname= hf_nds_iteration;
                                foffset = foffset+p2values.vlength;
                                p3values.vvalue = tvb_get_letohl(tvb, foffset);
                                p3values.vstring = "";
                                p3values.vtype = 3; /* Uint32 */
                                p3values.vdesc = "Entry ID: 0x%08x";
                                p3values.vlength = 4;
                                resolve_eid = TRUE;
                                global_eid = p3values.vvalue;
                                p3values.voffset = foffset;
                                p3values.hfname= hf_nds_eid;
                                foffset = foffset+p3values.vlength;
                                break;
                        case 0x13:    
                                verb_string = "Get Effective Rights -> ";
                                p1values.vvalue = tvb_get_letohl(tvb, foffset);
                                p1values.vstring = "";
                                p1values.vtype = 3; /* Uint32 */
                                p1values.vdesc = "Version: %d";
                                p1values.vlength = 4;
                                p1values.voffset = foffset;
                                p1values.hfname= hf_nds_ver;
                                foffset = foffset+p1values.vlength;
                                p2values.vvalue = tvb_get_letohl(tvb, foffset);
                                p2values.vstring = "";
                                p2values.vtype = 3; /* Uint32 */
                                p2values.vdesc = "Entry ID: 0x%08x";
                                p2values.vlength = 4;
                                resolve_eid = TRUE;
                                global_eid = p2values.vvalue;
                                p2values.voffset = foffset;
                                p2values.hfname= hf_nds_eid;
                                foffset = foffset+p2values.vlength;
                                p3values.vtype = 4; /* String */
                                p3values.vdesc = "Trustee Name: %s";
                                p3values.vstring = "";
                                p3values.mvtype = 1;
                                p3values.vvalue = 0;
                                p3values.vlength = 256;
                                p3values.vlength = tvb_get_letohl(tvb, foffset);
                                if (p3values.vlength == 0x00)
                                {
                                        p3values.vtype = 0;
                                        break;
                                }
                                p3values.voffset = foffset+4;
                                foffset = foffset + 4;
                                get_string(tvb, p3values.voffset, p3values.vlength, req_buffer.buffer);
                                p3values.vstring = req_buffer.buffer;
                                p3values.hfname= hf_nds_name;
                                foffset = foffset+p3values.vlength;
                                foffset += align_4(tvb, foffset);
                                p4values.vtype = 4; /* String */
                                p4values.vdesc = "Attribute to be Checked: %s";
                                p4values.vstring = "";
                                p4values.mvtype = 0;
                                p4values.vvalue = 0;
                                p4values.vlength = 256;
                                p4values.vlength = tvb_get_letohl(tvb, foffset);
                                if (p4values.vlength == 0x00)
                                {
                                        p4values.vtype = 0;
                                        break;
                                }
                                p4values.voffset = foffset+4;
                                foffset = foffset + 4;
                                get_string(tvb, p4values.voffset, p4values.vlength, p4values.vstring);
                                p4values.hfname= hf_nds_name;
                                foffset = foffset+p4values.vlength;
                                foffset += align_4(tvb, foffset);
                                if(p1values.vvalue != 0)
                                {
                                        p5values.vtype = 4; /* String */
                                        p5values.vdesc = "Security Equivalence: %s";
                                        p5values.vstring = "";
                                        p5values.mvtype = 1;
                                        p5values.vvalue = 0;
                                        p5values.vlength = 256;
                                        p5values.vlength = tvb_get_letohl(tvb, foffset);
                                        if (p5values.vlength == 0x00)
                                        {
                                                p5values.vtype = 0;
                                                break;
                                        }
                                        p5values.voffset = foffset+4;
                                        foffset = foffset + 4;
                                        get_string(tvb, p5values.voffset, p5values.vlength, p5values.vstring);
                                        p5values.hfname= hf_nds_name;
                                        foffset = foffset+p5values.vlength;
                                        foffset += align_4(tvb, foffset);
                                }
                                break;
                        case 0x14:    
                                verb_string = "Add Partition";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x15:    
                                verb_string = "Remove Partition";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x16:    
                                verb_string = "List Partitions";
                                p1values.vvalue = tvb_get_letohl(tvb, foffset);
                                p1values.vstring = "";
                                p1values.vtype = 3; /* Uint32 */
                                p1values.vdesc = "Version: %d";
                                p1values.vlength = 4;
                                p1values.voffset = foffset;
                                p1values.hfname= hf_nds_ver;
                                foffset = foffset+p1values.vlength;
                                p2values.vvalue = tvb_get_letohl(tvb, foffset);
                                p2values.vtype = 5; /* Bitfield */
                                p2values.vstring = "";
                                p2values.vdesc = "Request Flags:";
                                p2values.vlength = 2;
                                p2values.hfname= hf_nds_rflags;
                                p2values.voffset = foffset;
                                p2values.bit1 = "Typeless";
                                p2values.bit1hfname = hf_nds_bit1;
                                p2values.bit2 = "All Containers";
                                p2values.bit2hfname = hf_nds_bit2;
                                p2values.bit3 = "Slashed";
                                p2values.bit3hfname = hf_nds_bit3;
                                p2values.bit4 = "Dotted";
                                p2values.bit4hfname = hf_nds_bit4;
                                p2values.bit5 = "Tuned";
                                p2values.bit5hfname = hf_nds_bit5;
                                p2values.bit6 = "Not Defined";
                                p2values.bit6hfname = hf_nds_bit6;
                                p2values.bit7 = "Not Defined";
                                p2values.bit7hfname = hf_nds_bit7;
                                p2values.bit8 = "Not Defined";
                                p2values.bit8hfname = hf_nds_bit8;
                                p2values.bit9 = "Not Defined";
                                p2values.bit9hfname = hf_nds_bit9;
                                p2values.bit10 = "Not Defined";
                                p2values.bit10hfname = hf_nds_bit10;
                                p2values.bit11 = "Not Defined";
                                p2values.bit11hfname = hf_nds_bit11;
                                p2values.bit12 = "Not Defined";
                                p2values.bit12hfname = hf_nds_bit12;
                                p2values.bit13 = "Not Defined";
                                p2values.bit13hfname = hf_nds_bit13;
                                p2values.bit14 = "Not Defined";
                                p2values.bit14hfname = hf_nds_bit14;
                                p2values.bit15 = "Not Defined";
                                p2values.bit15hfname = hf_nds_bit15;
                                p2values.bit16 = "Not Defined";
                                p2values.bit16hfname = hf_nds_bit16;
                                foffset = foffset+p2values.vlength;
                                p3values.vvalue = tvb_get_letohl(tvb, foffset);
                                p3values.vstring = "";
                                p3values.vtype = 3; /* Uint32 */
                                p3values.vdesc = "Iteration Handle: 0x%08x";
                                p3values.vlength = 4;
                                p3values.voffset = foffset;
                                p3values.hfname= hf_nds_iteration;
                                foffset = foffset+p3values.vlength;
                                if(p1values.vvalue == 0)
                                {
                                        global_flags = 0x000000c0;
                                        break;
                                }
                                p4values.vvalue = tvb_get_letohs(tvb, foffset);
                                p4values.vtype = 5; /* Bitfield */
                                p4values.vstring = "";
                                p4values.vdesc = "Information Flags (low) Byte:";
                                p4values.vlength = 2;
                                p4values.hfname= hf_nds_rflags;
                                p4values.voffset = foffset;
                                p4values.bit1 = "Output Flags";
                                p4values.bit1hfname = hf_bit1l1flagsl;
                                p4values.bit2 = "Entry ID";
                                p4values.bit2hfname = hf_bit2l1flagsl;
                                p4values.bit3 = "Replica State";
                                p4values.bit3hfname = hf_bit3l1flagsl;
                                p4values.bit4 = "Modification Timestamp";
                                p4values.bit4hfname = hf_bit4l1flagsl;
                                p4values.bit5 = "Purge Time";
                                p4values.bit5hfname = hf_bit5l1flagsl;
                                p4values.bit6 = "Local Partition ID";
                                p4values.bit6hfname = hf_bit6l1flagsl;
                                p4values.bit7 = "Distinguished Name";
                                p4values.bit7hfname = hf_bit7l1flagsl;
                                p4values.bit8 = "Replica Type";
                                p4values.bit8hfname = hf_bit8l1flagsl;
                                p4values.bit9 = "Partition Busy";
                                p4values.bit9hfname = hf_bit9l1flagsl;
                                p4values.bit10 = "Not Defined";
                                p4values.bit10hfname = hf_bit10l1flagsl;
                                p4values.bit11 = "Not Defined";
                                p4values.bit11hfname = hf_bit11l1flagsl;
                                p4values.bit12 = "Not Defined";
                                p4values.bit12hfname = hf_bit12l1flagsl;
                                p4values.bit13 = "Not Defined";
                                p4values.bit13hfname = hf_bit13l1flagsl;
                                p4values.bit14 = "Not Defined";
                                p4values.bit14hfname = hf_bit14l1flagsl;
                                p4values.bit15 = "Not Defined";
                                p4values.bit15hfname = hf_bit15l1flagsl;
                                p4values.bit16 = "Not Defined";
                                p4values.bit16hfname = hf_bit16l1flagsl;
                                global_flags = p4values.vvalue;
                                foffset = foffset+2;
                                p5values.vvalue = tvb_get_letohs(tvb, foffset);
                                p5values.vtype = 5; /* Bitfield */
                                p5values.vstring = "";
                                p5values.vdesc = "Information Flags (high) Byte:";
                                p5values.vlength = 2;
                                p5values.hfname= hf_nds_rflags;
                                p5values.voffset = foffset;
                                p5values.bit1 = "Not Defined";
                                p5values.bit1hfname = hf_bit1l1flagsl;
                                p5values.bit2 = "Not Defined";
                                p5values.bit2hfname = hf_bit2l1flagsl;
                                p5values.bit3 = "Not Defined";
                                p5values.bit3hfname = hf_bit3l1flagsl;
                                p5values.bit4 = "Not Defined";
                                p5values.bit4hfname = hf_bit4l1flagsl;
                                p5values.bit5 = "Not Defined";
                                p5values.bit5hfname = hf_bit5l1flagsl;
                                p5values.bit6 = "Not Defined";
                                p5values.bit6hfname = hf_bit6l1flagsl;
                                p5values.bit7 = "Not Defined";
                                p5values.bit7hfname = hf_bit7l1flagsl;
                                p5values.bit8 = "Not Defined";
                                p5values.bit8hfname = hf_bit8l1flagsl;
                                p5values.bit9 = "Not Defined";
                                p5values.bit9hfname = hf_bit9l1flagsl;
                                p5values.bit10 = "Not Defined";
                                p5values.bit10hfname = hf_bit10l1flagsl;
                                p5values.bit11 = "Not Defined";
                                p5values.bit11hfname = hf_bit11l1flagsl;
                                p5values.bit12 = "Not Defined";
                                p5values.bit12hfname = hf_bit12l1flagsl;
                                p5values.bit13 = "Not Defined";
                                p5values.bit13hfname = hf_bit13l1flagsl;
                                p5values.bit14 = "Not Defined";
                                p5values.bit14hfname = hf_bit14l1flagsl;
                                p5values.bit15 = "Not Defined";
                                p5values.bit15hfname = hf_bit15l1flagsl;
                                p5values.bit16 = "Not Defined";
                                p5values.bit16hfname = hf_bit16l1flagsl;
                                foffset = foffset+2;
                                if(p1values.vvalue == 1)
                                {
                                        break;
                                }
                                p6values.vvalue = tvb_get_letohl(tvb, foffset);
                                p6values.vstring = "";
                                p6values.vtype = 3; /* Uint32 */
                                p6values.vdesc = "Partition Root ID: 0x%08x";
                                p6values.vlength = 4;
                                p6values.voffset = foffset;
                                p6values.hfname= hf_nds_partition_root_id;
                                foffset = foffset+p6values.vlength;
                                break;
                        case 0x17:    
                                verb_string = "Split Partition";
                                p1values.vvalue = tvb_get_letohl(tvb, foffset);
                                nds_version = p1values.vvalue;
                                p1values.vstring = "";
                                p1values.vtype = 3; /* Uint32 */
                                p1values.vdesc = "Version: %d";
                                p1values.vlength = 4;
                                p1values.hfname = hf_nds_ver;
                                p1values.voffset = foffset;
                                foffset = foffset+p1values.vlength;
                                p2values.vvalue = tvb_get_letohl(tvb, foffset);
                                nds_version = p2values.vvalue;
                                p2values.vstring = "";
                                p2values.vtype = 3; /* Uint32 */
                                p2values.vdesc = "Flags: 0x%08x";
                                p2values.vlength = 4;
                                p2values.hfname = hf_nds_req_flags;
                                p2values.voffset = foffset;
                                foffset = foffset+p2values.vlength;
                                p3values.vvalue = tvb_get_letohl(tvb, foffset);
                                p3values.vstring = "";
                                p3values.vtype = 3; /* Uint32 */
                                p3values.vdesc = "New Partition Root ID: 0x%08x";
                                p3values.vlength = 4;
                                p3values.voffset = foffset;
                                p3values.hfname= hf_nds_new_part_id;
                                foffset = foffset+p3values.vlength;
                                break;
                        case 0x18:    
                                verb_string = "Join Partitions";
                                p1values.vvalue = tvb_get_letohl(tvb, foffset);
                                nds_version = p1values.vvalue;
                                p1values.vstring = "";
                                p1values.vtype = 3; /* Uint32 */
                                p1values.vdesc = "Version: %d";
                                p1values.vlength = 4;
                                p1values.hfname = hf_nds_ver;
                                p1values.voffset = foffset;
                                foffset = foffset+p1values.vlength;
                                p2values.vvalue = tvb_get_letohl(tvb, foffset);
                                nds_version = p2values.vvalue;
                                p2values.vstring = "";
                                p2values.vtype = 3; /* Uint32 */
                                p2values.vdesc = "Flags: 0x%08x";
                                p2values.vlength = 4;
                                p2values.hfname = hf_nds_req_flags;
                                p2values.voffset = foffset;
                                foffset = foffset+p2values.vlength;
                                p3values.vvalue = tvb_get_letohl(tvb, foffset);
                                p3values.vstring = "";
                                p3values.vtype = 3; /* Uint32 */
                                p3values.vdesc = "Child Partition Root ID: 0x%08x";
                                p3values.vlength = 4;
                                p3values.voffset = foffset;
                                p3values.hfname= hf_nds_child_part_id;
                                foffset = foffset+p3values.vlength;
                                break;
                        case 0x19:    
                                verb_string = "Add Replica";
                                p1values.vvalue = tvb_get_letohl(tvb, foffset);
                                nds_version = p1values.vvalue;
                                p1values.vstring = "";
                                p1values.vtype = 3; /* Uint32 */
                                p1values.vdesc = "Version: %d";
                                p1values.vlength = 4;
                                p1values.hfname = hf_nds_ver;
                                p1values.voffset = foffset;
                                foffset = foffset+p1values.vlength;
                                p2values.vvalue = tvb_get_letohl(tvb, foffset);
                                nds_version = p2values.vvalue;
                                p2values.vstring = "";
                                p2values.vtype = 3; /* Uint32 */
                                p2values.vdesc = "Flags: 0x%08x";
                                p2values.vlength = 4;
                                p2values.hfname = hf_nds_req_flags;
                                p2values.voffset = foffset;
                                foffset = foffset+p2values.vlength;
                                p3values.vvalue = tvb_get_letohl(tvb, foffset);
                                p3values.vstring = "";
                                p3values.vtype = 3; /* Uint32 */
                                p3values.vdesc = "Master Partition Root ID: 0x%08x";
                                p3values.vlength = 4;
                                p3values.voffset = foffset;
                                p3values.hfname= hf_nds_master_part_id;
                                foffset = foffset+p3values.vlength;
                                p4values.vvalue = tvb_get_letohl(tvb, foffset);
                                p4values.vstring = match_strval(p4values.vvalue, nds_replica_type);
                                if(p4values.vstring == NULL)
                                {
                                        p4values.vstring = "No Replica Type Found";
                                }
                                p4values.vtype = 4; /* String */
                                p4values.vdesc = "Replica Type: %s";
                                p4values.vlength = 4;
                                p4values.voffset = foffset;
                                p4values.mvtype = 0;
                                p4values.hfname= hf_replica_type;
                                foffset = foffset + p4values.vlength;
                                p5values.vtype = 4; /* String */
                                p5values.vdesc = "Target Server Name: %s";
                                p5values.vstring = "";
                                p5values.mvtype = 0;
                                p5values.vvalue = 0;
                                p5values.vlength = 256;
                                p5values.vlength = tvb_get_letohl(tvb, foffset);
                                if (p5values.vlength == 0x00)
                                {
                                        p5values.vtype = 0;
                                        break;
                                }
                                p5values.voffset = foffset+4;
                                foffset = foffset + 4;
                                get_string(tvb, p5values.voffset, p5values.vlength, p5values.vstring);
                                p5values.hfname= hf_nds_target_name;
                                break;
                        case 0x1a:    
                                verb_string = "Remove Replica";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x1b:    
                                verb_string = "Open Stream -> ";
                                p1values.vvalue = tvb_get_letohl(tvb, foffset);
                                nds_version = p1values.vvalue;
                                p1values.vstring = "";
                                p1values.vtype = 3; /* Uint32 */
                                p1values.vdesc = "Version: %d";
                                p1values.vlength = 4;
                                p1values.hfname = hf_nds_ver;
                                p1values.voffset = foffset;
                                foffset = foffset+p1values.vlength;
                                p2values.vvalue = tvb_get_letohl(tvb, foffset);
                                nds_version = p2values.vvalue;
                                p2values.vstring = "";
                                p2values.vtype = 3; /* Uint32 */
                                p2values.vdesc = "Streams Flags: 0x%08x";
                                p2values.vlength = 4;
                                p2values.hfname = hf_nds_stream_flags;
                                p2values.voffset = foffset;
                                foffset = foffset+p2values.vlength;
                                p3values.vvalue = tvb_get_letohl(tvb, foffset);
                                p3values.vstring = "";
                                p3values.vtype = 3; /* Uint32 */
                                p3values.vdesc = "Entry ID: 0x%08x";
                                p3values.vlength = 4;
                                resolve_eid = TRUE;
                                global_eid = p3values.vvalue;
                                p3values.voffset = foffset;
                                p3values.hfname= hf_nds_eid;
                                foffset = foffset+p3values.vlength;
                                p4values.vtype = 4; /* String */
                                p4values.vdesc = "Stream Name: %s";
                                p4values.vstring = "";
                                p4values.mvtype = 1;
                                p4values.vvalue = 0;
                                p4values.vlength = 256;
                                p4values.vlength = tvb_get_letohl(tvb, foffset);
                                if (p4values.vlength == 0x00)
                                {
                                        p4values.vtype = 0;
                                        break;
                                }
                                p4values.voffset = foffset+4;
                                foffset += 4;
                                get_string(tvb, p4values.voffset, p4values.vlength, p4values.vstring);
                                foffset += p4values.vlength;
                                foffset += align_4(tvb, foffset);
                                p4values.hfname= hf_nds_stream_name;
                                break;
                        case 0x1c:    
                                verb_string = "Search Filter";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x1d:    
                                verb_string = "Create Subordinate Reference";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x1e:    
                                verb_string = "Link Replica";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x1f:    
                                verb_string = "Change Replica Type";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x20:    
                                verb_string = "Start Update Schema";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x21:    
                                verb_string = "End Update Schema";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x22:    
                                verb_string = "Update Schema";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x23:    
                                verb_string = "Start Update Replica";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x24:    
                                verb_string = "End Update Replica";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x25:    
                                verb_string = "Update Replica";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x26:    
                                verb_string = "Synchronize Partition";
                                p1values.vvalue = tvb_get_letohl(tvb, foffset);
                                nds_version = p1values.vvalue;
                                p1values.vstring = "";
                                p1values.vtype = 3; /* Uint32 */
                                p1values.vdesc = "Version: %d";
                                p1values.vlength = 4;
                                p1values.hfname = hf_nds_ver;
                                p1values.voffset = foffset;
                                foffset = foffset+p1values.vlength;
                                p2values.vvalue = tvb_get_letohl(tvb, foffset);
                                nds_version = p2values.vvalue;
                                p2values.vstring = "";
                                p2values.vtype = 3; /* Uint32 */
                                p2values.vdesc = "Flags: 0x%08x";
                                p2values.vlength = 4;
                                p2values.hfname = hf_nds_req_flags;
                                p2values.voffset = foffset;
                                foffset = foffset+p2values.vlength;
                                p3values.vvalue = tvb_get_letohl(tvb, foffset);
                                p3values.vstring = "";
                                p3values.vtype = 3; /* Uint32 */
                                p3values.vdesc = "Time Delay in Seconds: %d";
                                p3values.vlength = 4;
                                p3values.voffset = foffset;
                                p3values.hfname= hf_nds_time_delay;
                                foffset = foffset+p3values.vlength;
                                if(p1values.vvalue == 0)
                                {
                                        p4values.vtype = 4; /* String */
                                        p4values.vdesc = "Root Most Object Name: %s";
                                        p4values.vstring = "";
                                        p4values.mvtype = 1;
                                        p4values.vvalue = 0;
                                        p4values.vlength = 256;
                                        p4values.vlength = tvb_get_letohl(tvb, foffset);
                                        if (p4values.vlength == 0x00)
                                        {
                                                p4values.vtype = 0;
                                                break;
                                        }
                                        p4values.voffset = foffset+4;
                                        foffset += 4;
                                        get_string(tvb, p4values.voffset, p4values.vlength, p4values.vstring);
                                        foffset += p4values.vlength;
                                        foffset += align_4(tvb, foffset);
                                        p4values.hfname= hf_nds_root_name;
                                }
                                else
                                {
                                        p4values.vvalue = tvb_get_letohl(tvb, foffset);
                                        p4values.vstring = "";
                                        p4values.vtype = 3; /* Uint32 */
                                        p4values.vdesc = "Entry ID: 0x%08x";
                                        p4values.vlength = 4;
                                        resolve_eid = TRUE;
                                        global_eid = p4values.vvalue;
                                        p4values.voffset = foffset;
                                        p4values.hfname= hf_nds_eid;
                                        foffset = foffset+p4values.vlength;
                                        resolve_eid = TRUE;
                                        global_eid = p4values.vvalue;
                                }
                                break;
                        case 0x27:    
                                verb_string = "Synchronize Schema";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x28:    
                                verb_string = "Read Syntaxes";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x29:    
                                verb_string = "Get Replica Root ID";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x2a:    
                                verb_string = "Begin Move Entry";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x2b:    
                                verb_string = "Finish Move Entry";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x2c:    
                                verb_string = "Release Moved Entry";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x2d:    
                                verb_string = "Backup Entry";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x2e:    
                                verb_string = "Restore Entry";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x2f:    
                                verb_string = "Save DIB";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x30:
                                verb_string = "Control";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x31:
                                verb_string = "Remove Backlink";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x32:    
                                verb_string = "Close Iteration";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x33:    
                                verb_string = "Mutate Entry";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x34:    
                                verb_string = "Audit Skulking";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x35:    
                                verb_string = "Get Server Address";
                                p1values.vvalue = 0;
                                break;
                        case 0x36:    
                                verb_string = "Set Keys";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x37:    
                                verb_string = "Change Password";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x38:    
                                verb_string = "Verify Password";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x39:    
                                verb_string = "Begin Login";
                                p1values.vvalue = tvb_get_letohl(tvb, foffset);
                                p1values.vstring = "";
                                p1values.vtype = 3; /* Uint32 */
                                p1values.vdesc = "Version: %d";
                                p1values.vlength = 4;
                                p1values.voffset = foffset;
                                p1values.hfname= hf_nds_ver;
                                foffset = foffset+p1values.vlength;
                                p2values.vvalue = tvb_get_letohl(tvb, foffset);
                                p2values.vstring = "";
                                p2values.vtype = 3; /* Uint32 */
                                p2values.vdesc = "Entry ID: 0x%08x";
                                p2values.vlength = 4;
                                resolve_eid = TRUE;
                                global_eid = p2values.vvalue;
                                p2values.voffset = foffset;
                                p2values.hfname= hf_nds_eid;
                                foffset = foffset+p2values.vlength;
                                break;
                        case 0x3a:    
                                verb_string = "Finish Login";
                                p1values.vvalue = tvb_get_letohl(tvb, foffset);
                                p1values.vstring = "";
                                p1values.vtype = 3; /* Uint32 */
                                p1values.vdesc = "Reply Buffer Size: %d";
                                p1values.vlength = 4;
                                p1values.voffset = foffset;
                                p1values.hfname= hf_nds_buffer_size;
                                foffset = foffset+p1values.vlength;
                                p2values.vvalue = tvb_get_letohl(tvb, foffset);
                                p2values.vstring = "";
                                p2values.vtype = 3; /* Uint32 */
                                p2values.vdesc = "Version: %d";
                                p2values.vlength = 4;
                                p2values.voffset = foffset;
                                p2values.hfname= hf_nds_ver;
                                foffset = foffset+p2values.vlength;
                                p3values.vvalue = tvb_get_letohl(tvb, foffset);
                                p3values.vstring = "";
                                p3values.vtype = 3; /* Uint32 */
                                p3values.vdesc = "Entry ID: 0x%08x";
                                p3values.vlength = 4;
                                resolve_eid = TRUE;
                                global_eid = p3values.vvalue;
                                p3values.voffset = foffset;
                                p3values.hfname= hf_nds_eid;
                                foffset = foffset+p3values.vlength;
                                break;
                        case 0x3b:    
                                verb_string = "Begin Authentication";
                                p1values.vvalue = tvb_get_letohl(tvb, foffset);
                                p1values.vstring = "";
                                p1values.vtype = 3; /* Uint32 */
                                p1values.vdesc = "Version: %d";
                                p1values.vlength = 4;
                                p1values.voffset = foffset;
                                p1values.hfname= hf_nds_ver;
                                foffset = foffset+p1values.vlength;
                                p2values.vvalue = tvb_get_letohl(tvb, foffset);
                                p2values.vstring = "";
                                p2values.vtype = 3; /* Uint32 */
                                p2values.vdesc = "Entry ID: 0x%08x";
                                p2values.vlength = 4;
                                resolve_eid = TRUE;
                                global_eid = p2values.vvalue;
                                p2values.voffset = foffset;
                                p2values.hfname= hf_nds_eid;
                                foffset = foffset+p2values.vlength;
                                break;
                        case 0x3c:    
                                verb_string = "Finish Authentication";
                                break;
                        case 0x3d:    
                                verb_string = "Logout";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x3e:    
                                verb_string = "Repair Ring";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x3f:    
                                verb_string = "Repair Timestamps";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x40:    
                                verb_string = "Create Back Link";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x41:    
                                verb_string = "Delete External Reference";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x42:    
                                verb_string = "Rename External Reference";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x43:    
                                verb_string = "Create Directory Entry";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x44:    
                                verb_string = "Remove Directory Entry";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x45:    
                                verb_string = "Designate New Master";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x46:    
                                verb_string = "Change Tree Name";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x47:    
                                verb_string = "Partition Entry Count";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x48:    
                                verb_string = "Check Login Restrictions";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x49:    
                                verb_string = "Start Join";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x4a:    
                                verb_string = "Low Level Split";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x4b:    
                                verb_string = "Low Level Join";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x4c:    
                                verb_string = "Abort Low Level Join";
                                p1values.vtype = 0; /* Not Defined */
                                break;
                        case 0x4d:    
                                verb_string = "Get All Servers";
                                p1values.vtype = 0; /* Not Defined */
                                break;
               		default:
               			verb_string = "NDS Continuation Fragment";
                                p1values.vtype = 0; /* Not Defined */
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
                                        if (p1values.vtype != 0) {
                                                switch (p1values.vtype) {
                                                        case 1:         /* uint8 */
                                        			proto_tree_add_uint_format(ncp_tree, p1values.hfname, tvb, p1values.voffset,
                                                                p1values.vlength, p1values.vtype, "NDS Parameter not defined %d",
        				                        p1values.vtype);
                                                                break;
                                                        case 2:         /* uint16 */
                                        			proto_tree_add_uint_format(ncp_tree, p1values.hfname, tvb, p1values.voffset,
                                                                p1values.vlength, p1values.vtype, "NDS Parameter not defined %d",
        				                        p1values.vtype);
                                                                break;
                                                        case 3:         /* uint32 */
                                        			proto_tree_add_uint_format(ncp_tree, p1values.hfname, tvb, p1values.voffset,
                                                                p1values.vlength, p1values.vvalue, p1values.vdesc,
        				                        p1values.vvalue);
                                                                break;
                                                        case 4:         /* string */
                                                                proto_tree_add_string_format(ncp_tree, p1values.hfname, tvb, p1values.voffset, 
                                                                p1values.vlength, p1values.vstring, p1values.vdesc, p1values.vstring);
                                                                if (p1values.mvtype == 1)
                                                                {
                                                                        if (check_col(pinfo->cinfo, COL_INFO)) 
                                                                        {
                                                                                col_append_str(pinfo->cinfo, COL_INFO, p1values.vstring);
                                                                        }
                                                                }
                                                                break;
                                                        case 5:         /* bitfield */
                                                                process_bitfield(ncp_tree, tvb, &p1values);
                                                                break;
                                                        case 6:         /*multivalue uint32 */
                                                                process_multivalues(ncp_tree, tvb, &p1values);
                                                                if (p1values.mvtype == 1 || p1values.mvtype == 10)
                                                                {
                                                                        if (p1values.mvtype == 10)
                                                                        {
                                                                                global_object_name = p1values.vstring;
                                                                        }
                                                                        if (check_col(pinfo->cinfo, COL_INFO)) 
                                                                        {
                                                                                col_append_str(pinfo->cinfo, COL_INFO, p1values.vstring);
                                                                        }
                                                                }
                                                                break;
                                                        case 7:         /* Bytes */
                                                                proto_tree_add_bytes(ncp_tree, p1values.hfname, tvb, p1values.voffset,
                                                                p1values.vlength, tvb_get_ptr(tvb, p1values.voffset, p1values.vvalue));
                                                                break;
                                                        case 8:
	                                                        proto_tree_add_item(ncp_tree, p1values.hfname, tvb, p1values.voffset, p1values.vlength, TRUE);
                                                                break;
                                                        default:
                                        			proto_tree_add_uint_format(ncp_tree, hf_nds_p1type, tvb, p1values.voffset,
                                                                p1values.vlength, p1values.vtype, "NDS Parameter not defined %d",
        				                        p1values.vtype);
                                                                break;
                                                }
                                                switch (p2values.vtype) {
                                                        case 1:         /* uint8 */
                                                                break;
                                                        case 2:         /* uint16 */
                                                                break;
                                                        case 3:         /* uint32 */
                                        			proto_tree_add_uint_format(ncp_tree, p2values.hfname, tvb, p2values.voffset,
                                                                p2values.vlength, p2values.vvalue, p2values.vdesc,
        				                        p2values.vvalue);
                                                                break;
                                                        case 4:         /* string */
                                                                proto_tree_add_string_format(ncp_tree, p2values.hfname, tvb, p2values.voffset, 
                                                                p2values.vlength, p2values.vstring, p2values.vdesc, p2values.vstring);
                                                                if (p2values.mvtype == 1)
                                                                {
                                                                        if (check_col(pinfo->cinfo, COL_INFO)) 
                                                                        {
                                                                                col_append_str(pinfo->cinfo, COL_INFO, p2values.vstring);
                                                                        }
                                                                }
                                                                break;
                                                        case 5:         /* boolean */
                                                                process_bitfield(ncp_tree, tvb, &p2values);
                                                                break;
                                                        case 6:         /*multivalue uint32 */
                                                                process_multivalues(ncp_tree, tvb, &p2values);
                                                                if (p2values.mvtype == 1 || p2values.mvtype == 10)
                                                                {
                                                                        if (p2values.mvtype == 10)
                                                                        {
                                                                                global_object_name = p1values.vstring;
                                                                        }
                                                                        if (check_col(pinfo->cinfo, COL_INFO)) 
                                                                        {
                                                                                col_append_str(pinfo->cinfo, COL_INFO, p2values.vstring);
                                                                        }
                                                                }
                                                                break;
                                                        case 7:         /* Bytes */
                                                                proto_tree_add_bytes(ncp_tree, p2values.hfname, tvb, p2values.voffset,
                                                                p2values.vlength, tvb_get_ptr(tvb, p2values.voffset, p2values.vvalue));
                                                                break;
                                                        case 8:
	                                                        proto_tree_add_item(ncp_tree, p2values.hfname, tvb, p2values.voffset, p2values.vlength, TRUE);
                                                                break;
                                                        default:
                                                                break;
                                                }
                                                switch (p3values.vtype) {
                                                        case 1:         /* uint8 */
                                                                break;
                                                        case 2:         /* uint16 */
                                                                break;
                                                        case 3:         /* uint32 */
                                        			proto_tree_add_uint_format(ncp_tree, p3values.hfname, tvb, p3values.voffset,
                                                                p3values.vlength, p3values.vvalue, p3values.vdesc,
        				                        p3values.vvalue);
                                                                break;
                                                        case 4:         /* string */
                                                                proto_tree_add_string_format(ncp_tree, p3values.hfname, tvb, p3values.voffset, 
                                                                p3values.vlength, p3values.vstring, p3values.vdesc, p3values.vstring);
                                                                if (p3values.mvtype == 1)
                                                                {
                                                                        if (check_col(pinfo->cinfo, COL_INFO)) 
                                                                        {
                                                                                col_append_str(pinfo->cinfo, COL_INFO, p3values.vstring);
                                                                        }
                                                                }
                                                                break;
                                                        case 5:         /* boolean */
                                                                process_bitfield(ncp_tree, tvb, &p3values);
                                                                break;
                                                        case 6:         /*multivalue uint32 */
                                                                process_multivalues(ncp_tree, tvb, &p3values);
                                                                if (p3values.mvtype == 1 || p3values.mvtype == 10)
                                                                {
                                                                        if (p3values.mvtype == 10)
                                                                        {
                                                                                global_object_name = p3values.vstring;
                                                                        }
                                                                        if (check_col(pinfo->cinfo, COL_INFO)) 
                                                                        {
                                                                                col_append_str(pinfo->cinfo, COL_INFO, p3values.vstring);
                                                                        }
                                                                }
                                                                break;
                                                        case 7:         /* Bytes */
                                                                proto_tree_add_bytes(ncp_tree, p3values.hfname, tvb, p3values.voffset,
                                                                p3values.vlength, tvb_get_ptr(tvb, p3values.voffset, p3values.vvalue));
                                                                break;
                                                        case 8:
	                                                        proto_tree_add_item(ncp_tree, p3values.hfname, tvb, p3values.voffset, p3values.vlength, TRUE);
                                                                break;
                                                        default:
                                                                break;
                                                }
                                                switch (p4values.vtype) {
                                                        case 1:         /* uint8 */
                                                                break;
                                                        case 2:         /* uint16 */
                                                                break;
                                                        case 3:         /* uint32 */
                                        			proto_tree_add_uint_format(ncp_tree, p4values.hfname, tvb, p4values.voffset,
                                                                p4values.vlength, p4values.vvalue, p4values.vdesc,
        				                        p4values.vvalue);
                                                                break;
                                                        case 4:         /* string */
                                                                proto_tree_add_string_format(ncp_tree, p4values.hfname, tvb, p4values.voffset, 
                                                                p4values.vlength, p4values.vstring, p4values.vdesc, p4values.vstring);
                                                                if (p4values.mvtype == 1)
                                                                {
                                                                        if (check_col(pinfo->cinfo, COL_INFO)) 
                                                                        {
                                                                                col_append_str(pinfo->cinfo, COL_INFO, p4values.vstring);
                                                                        }
                                                                }
                                                                break;
                                                        case 5:         /* boolean */
                                                                process_bitfield(ncp_tree, tvb, &p4values);
                                                                break;
                                                        case 6:         /*multivalue uint32 */
                                                                process_multivalues(ncp_tree, tvb, &p4values);
                                                                if (p4values.mvtype == 1 || p4values.mvtype == 10)
                                                                {
                                                                        if (p4values.mvtype == 10)
                                                                        {
                                                                                global_object_name = p4values.vstring;
                                                                        }
                                                                        if (check_col(pinfo->cinfo, COL_INFO)) 
                                                                        {
                                                                                col_append_str(pinfo->cinfo, COL_INFO, p4values.vstring);
                                                                        }
                                                                }
                                                                break;
                                                        case 7:         /* Bytes */
                                                                proto_tree_add_bytes(ncp_tree, p4values.hfname, tvb, p4values.voffset,
                                                                p4values.vlength, tvb_get_ptr(tvb, p4values.voffset, p4values.vvalue));
                                                                break;
                                                        case 8:
	                                                        proto_tree_add_item(ncp_tree, p4values.hfname, tvb, p4values.voffset, p4values.vlength, TRUE);
                                                                break;
                                                        default:
                                                                break;
                                                }
                                                switch (p5values.vtype) {
                                                        case 1:         /* uint8 */
                                                                break;
                                                        case 2:         /* uint16 */
                                                                break;
                                                        case 3:         /* uint32 */
                                        			proto_tree_add_uint_format(ncp_tree, p5values.hfname, tvb, p5values.voffset,
                                                                p5values.vlength, p5values.vvalue, p5values.vdesc,
        				                        p5values.vvalue);
                                                                break;
                                                        case 4:         /* string */
                                                                proto_tree_add_string_format(ncp_tree, p5values.hfname, tvb, p5values.voffset, 
                                                                p5values.vlength, p5values.vstring, p5values.vdesc, p5values.vstring);
                                                                if (p5values.mvtype == 1 || p5values.mvtype == 10)
                                                                {
                                                                        if (p5values.mvtype == 10)
                                                                        {
                                                                                global_object_name = p5values.vstring;
                                                                        }
                                                                        if (check_col(pinfo->cinfo, COL_INFO)) 
                                                                        {
                                                                                col_append_str(pinfo->cinfo, COL_INFO, p5values.vstring);
                                                                        }
                                                                }
                                                                break;
                                                        case 5:         /* boolean */
                                                                process_bitfield(ncp_tree, tvb, &p5values);
                                                                break;
                                                        case 6:         /*multivalue uint32 */
                                                                process_multivalues(ncp_tree, tvb, &p5values);
                                                                if (p5values.mvtype == 1)
                                                                {
                                                                        if (check_col(pinfo->cinfo, COL_INFO)) 
                                                                        {
                                                                                col_append_str(pinfo->cinfo, COL_INFO, p5values.vstring);
                                                                        }
                                                                }
                                                                break;
                                                        case 7:         /* Bytes */
                                                                proto_tree_add_bytes(ncp_tree, p5values.hfname, tvb, p5values.voffset,
                                                                p5values.vlength, tvb_get_ptr(tvb, p5values.voffset, p5values.vvalue));
                                                                break;
                                                        case 8:
	                                                        proto_tree_add_item(ncp_tree, p5values.hfname, tvb, p5values.voffset, p5values.vlength, TRUE);
                                                                break;
                                                        default:
                                                                break;
                                                }
                                                switch (p6values.vtype) {
                                                        case 1:         /* uint8 */
                                                                break;
                                                        case 2:         /* uint16 */
                                                                break;
                                                        case 3:         /* uint32 */
                                        			proto_tree_add_uint_format(ncp_tree, p6values.hfname, tvb, p6values.voffset,
                                                                p6values.vlength, p6values.vvalue, p6values.vdesc,
        				                        p6values.vvalue);
                                                                break;
                                                        case 4:         /* string */
                                                                proto_tree_add_string_format(ncp_tree, p6values.hfname, tvb, p6values.voffset, 
                                                                p6values.vlength, p6values.vstring, p6values.vdesc, p6values.vstring);
                                                                if (p6values.mvtype == 1 || p6values.mvtype == 10)
                                                                {
                                                                        if (p6values.mvtype == 10)
                                                                        {
                                                                                global_object_name = p6values.vstring;
                                                                        }
                                                                        if (check_col(pinfo->cinfo, COL_INFO)) 
                                                                        {
                                                                                col_append_str(pinfo->cinfo, COL_INFO, p6values.vstring);
                                                                        }
                                                                }
                                                                break;
                                                        case 5:         /* boolean */
                                                                process_bitfield(ncp_tree, tvb, &p6values);
                                                                break;
                                                        case 6:         /*multivalue uint32 */
                                                                process_multivalues(ncp_tree, tvb, &p6values);
                                                                if (p6values.mvtype == 1)
                                                                {
                                                                        if (check_col(pinfo->cinfo, COL_INFO)) 
                                                                        {
                                                                                col_append_str(pinfo->cinfo, COL_INFO, p6values.vstring);
                                                                        }
                                                                }
                                                                break;
                                                        case 7:         /* Bytes */
                                                                proto_tree_add_bytes(ncp_tree, p6values.hfname, tvb, p6values.voffset,
                                                                p6values.vlength, tvb_get_ptr(tvb, p6values.voffset, p6values.vvalue));
                                                                break;
                                                        case 8:
	                                                        proto_tree_add_item(ncp_tree, p6values.hfname, tvb, p6values.voffset, p6values.vlength, TRUE);
                                                                break;
                                                        default:
                                                                break;
                                                }
                                                switch (p7values.vtype) {
                                                        case 1:         /* uint8 */
                                                                break;
                                                        case 2:         /* uint16 */
                                                                break;
                                                        case 3:         /* uint32 */
                                        			proto_tree_add_uint_format(ncp_tree, p7values.hfname, tvb, p7values.voffset,
                                                                p7values.vlength, p7values.vvalue, p7values.vdesc,
        				                        p7values.vvalue);
                                                                break;
                                                        case 4:         /* string */
                                                                proto_tree_add_string_format(ncp_tree, p7values.hfname, tvb, p7values.voffset, 
                                                                p7values.vlength, p7values.vstring, p7values.vdesc, p7values.vstring);
                                                                if (p7values.mvtype == 1 || p7values.mvtype == 10)
                                                                {
                                                                        if (p7values.mvtype == 10)
                                                                        {
                                                                                global_object_name = p7values.vstring;
                                                                        }
                                                                        if (check_col(pinfo->cinfo, COL_INFO)) 
                                                                        {
                                                                                col_append_str(pinfo->cinfo, COL_INFO, p7values.vstring);
                                                                        }
                                                                }
                                                                break;
                                                        case 5:         /* boolean */
                                                                process_bitfield(ncp_tree, tvb, &p7values);
                                                                break;
                                                        case 6:         /*multivalue uint32 */
                                                                process_multivalues(ncp_tree, tvb, &p7values);
                                                                if (p7values.mvtype == 1)
                                                                {
                                                                        if (check_col(pinfo->cinfo, COL_INFO)) 
                                                                        {
                                                                                col_append_str(pinfo->cinfo, COL_INFO, p7values.vstring);
                                                                        }
                                                                }
                                                                break;
                                                        case 7:         /* Bytes */
                                                                proto_tree_add_bytes(ncp_tree, p7values.hfname, tvb, p7values.voffset,
                                                                p7values.vlength, tvb_get_ptr(tvb, p7values.voffset, p7values.vvalue));
                                                                break;
                                                        case 8:
	                                                        proto_tree_add_item(ncp_tree, p7values.hfname, tvb, p7values.voffset, p7values.vlength, TRUE);
                                                                break;
                                                        default:
                                                                break;
                                                }
                                                switch (p8values.vtype) {
                                                        case 1:         /* uint8 */
                                                                break;
                                                        case 2:         /* uint16 */
                                                                break;
                                                        case 3:         /* uint32 */
                                        			proto_tree_add_uint_format(ncp_tree, p8values.hfname, tvb, p8values.voffset,
                                                                p8values.vlength, p8values.vvalue, p8values.vdesc,
        				                        p8values.vvalue);
                                                                break;
                                                        case 4:         /* string */
                                                                proto_tree_add_string_format(ncp_tree, p8values.hfname, tvb, p8values.voffset, 
                                                                p8values.vlength, p8values.vstring, p8values.vdesc, p8values.vstring);
                                                                if (p8values.mvtype == 1)
                                                                {
                                                                        if (check_col(pinfo->cinfo, COL_INFO)) 
                                                                        {
                                                                                col_append_str(pinfo->cinfo, COL_INFO, p8values.vstring);
                                                                        }
                                                                }
                                                                break;
                                                        case 5:         /* boolean */
                                                                process_bitfield(ncp_tree, tvb, &p8values);
                                                                break;
                                                        case 6:         /*multivalue uint32 */
                                                                process_multivalues(ncp_tree, tvb, &p8values);
                                                                if (p8values.mvtype == 1 || p8values.mvtype == 10)
                                                                {
                                                                        if (p8values.mvtype == 10)
                                                                        {
                                                                                global_object_name = p8values.vstring;
                                                                        }
                                                                        if (check_col(pinfo->cinfo, COL_INFO)) 
                                                                        {
                                                                                col_append_str(pinfo->cinfo, COL_INFO, p8values.vstring);
                                                                        }
                                                                }
                                                                break;
                                                        case 7:         /* Bytes */
                                                                proto_tree_add_bytes(ncp_tree, p8values.hfname, tvb, p8values.voffset,
                                                                p8values.vlength, tvb_get_ptr(tvb, p8values.voffset, p8values.vvalue));
                                                                break;
                                                        case 8:
	                                                        proto_tree_add_item(ncp_tree, p8values.hfname, tvb, p8values.voffset, p8values.vlength, TRUE);
                                                                break;
                                                        default:
                                                                break;
                                                }
                                                switch (p9values.vtype) {
                                                        case 1:         /* uint8 */
                                                                break;
                                                        case 2:         /* uint16 */
                                                                break;
                                                        case 3:         /* uint32 */
                                        			proto_tree_add_uint_format(ncp_tree, p9values.hfname, tvb, p9values.voffset,
                                                                p9values.vlength, p9values.vvalue, p9values.vdesc,
        				                        p9values.vvalue);
                                                                break;
                                                        case 4:         /* string */
                                                                proto_tree_add_string_format(ncp_tree, p9values.hfname, tvb, p9values.voffset, 
                                                                p9values.vlength, p9values.vstring, p9values.vdesc, p9values.vstring);
                                                                if (p9values.mvtype == 1)
                                                                {
                                                                        if (check_col(pinfo->cinfo, COL_INFO)) 
                                                                        {
                                                                                col_append_str(pinfo->cinfo, COL_INFO, p9values.vstring);
                                                                        }
                                                                }
                                                                break;
                                                        case 5:         /* boolean */
                                                                process_bitfield(ncp_tree, tvb, &p9values);
                                                                break;
                                                        case 6:         /*multivalue uint32 */
                                                                process_multivalues(ncp_tree, tvb, &p9values);
                                                                if (p9values.mvtype == 1 || p9values.mvtype == 10)
                                                                {
                                                                        if (p9values.mvtype == 10)
                                                                        {
                                                                                global_object_name = p9values.vstring;
                                                                        }
                                                                        if (check_col(pinfo->cinfo, COL_INFO)) 
                                                                        {
                                                                                col_append_str(pinfo->cinfo, COL_INFO, p9values.vstring);
                                                                        }
                                                                }
                                                                break;
                                                        case 7:         /* Bytes */
                                                                proto_tree_add_bytes(ncp_tree, p9values.hfname, tvb, p9values.voffset,
                                                                p9values.vlength, tvb_get_ptr(tvb, p9values.voffset, p9values.vvalue));
                                                                break;
                                                        case 8:
	                                                        proto_tree_add_item(ncp_tree, p9values.hfname, tvb, p9values.voffset, p9values.vlength, TRUE);
                                                                break;
                                                        default:
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
        guint32                 nds_version = 0;
        gint                    length_remaining = 0;
	char			flags_str[1+3+1+3+1+3+1+3+1+1];
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
       		if (ncp_rec) 
                {
         		proto_item *ti;
                               
         		temp_tree = proto_tree_create_root();
         		proto_tree_set_visible(temp_tree, FALSE);
         		ti = proto_tree_add_item(temp_tree, proto_ncp, tvb, 0, -1, FALSE);
         		ncp_tree = proto_item_add_subtree(ti, ett_ncp);
       		}
       	}
        
       	if (ncp_tree) 
        {
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
        
       		switch (type) 
                {
                        case NCP_BROADCAST_SLOT:
       				; /* nothing */
       				break;
        
       			case NCP_SERVICE_REQUEST:
       				proto_tree_add_uint_format(ncp_tree, hf_ncp_func, tvb, 6, 1,
       					func, "Function: %d (0x%02X), %s",
       					func, func, ncp_rec ? ncp_rec->name : "Unknown");
                                        
				proto_tree_add_uint_format(ncp_tree, hf_ncp_subfunc, tvb, 7, 1,
					subfunc, "SubFunction: %d (0x%02x)",
					subfunc, subfunc);
                                        
				proto_tree_add_uint(ncp_tree, hf_nds_version, tvb, 8, 4,
					nds_version);
                               
        		        length_remaining = tvb_length_remaining(tvb, 8);
                                if (length_remaining > 6)
                                {
                                        nds_flags = tvb_get_letohl(tvb, 12);
                        		strcpy(flags_str, " ");
                        		sep = "(";
                        		if (nds_flags & nds_flag_tree) 
                                        {
                        			strcat(flags_str, sep);
                        			strcat(flags_str, "Tree");
                        			sep = ",";
		                        }
		                        if (nds_flags & nds_flag_depth) 
                                        {
			                        strcat(flags_str, sep);
			                        strcat(flags_str, "Depth");
			                        sep = ",";
		                        }
		                        if (nds_flags & nds_flag_rev) 
                                        {
			                        strcat(flags_str, sep);
			                        strcat(flags_str, "Revision");
		                        }
		                        if (nds_flags & nds_flag_flags) 
                                        {
			                        strcat(flags_str, sep);
			                        strcat(flags_str, "Flags");
		                        }
		                        if (flags_str[0] != '\0')
                                        {
			                        strcat(flags_str, ")");
		                                tinew = proto_tree_add_uint_format(ncp_tree, hf_nds_flags,
		                                        tvb, 12, 4, nds_flags, "Flags: 0x%08x -%s", nds_flags,
		                                        flags_str);
                                                
		                                flags_tree = proto_item_add_subtree(tinew, ett_nds);
                                                
                                                if(request_value)
                                                {        
                                                        request_value->req_nds_flags = nds_flags;
                                                }
                                                                                                        
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
