/* packet-ams.c
 * Routines for ethercat packet disassembly
 *
 * Copyright (c) 2007 by Beckhoff Automation GmbH
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* Include files */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>

#include "packet-ams.h"

void proto_register_ams(void);
void proto_reg_handoff_ams(void);

/* Define the ams proto */
int proto_ams = -1;

/* Define the tree for ams */
static int ett_ams = -1;
static int ett_ams_stateflags = -1;
static int ett_ams_adsreadrequest = -1;
static int ett_ams_adsreadresponse = -1;
static int ett_ams_adswriterequest = -1;
static int ett_ams_adswriteresponse = -1;
static int ett_ams_adsreadwriterequest = -1;
static int ett_ams_adsreadwriteresponse = -1;
static int ett_ams_adsreadstaterequest = -1;
static int ett_ams_adsreadstateresponse = -1;
static int ett_ams_adswritectrlrequest = -1;
static int ett_ams_adswritectrlresponse = -1;
static int ett_ams_adsreaddinforequest = -1;
static int ett_ams_adsreaddinforesponse = -1;
static int ett_ams_adsadddnrequest = -1;
static int ett_ams_adsadddnresponse = -1;
static int ett_ams_adsdeldnrequest = -1;
static int ett_ams_adsdeldnresponse = -1;
static int ett_ams_adsdnrequest = -1;

static int hf_ams_sendernetid = -1;
static int hf_ams_senderport = -1;
static int hf_ams_targetnetid = -1;
static int hf_ams_targetport = -1;
static int hf_ams_cmdid = -1;
static int hf_ams_stateflags = -1;
static int hf_ams_stateresponse = -1;
static int hf_ams_statenoreturn = -1;
static int hf_ams_stateadscmd = -1;
static int hf_ams_statesyscmd = -1;
static int hf_ams_statehighprio = -1;
static int hf_ams_statetimestampadded = -1;
static int hf_ams_stateudp = -1;
static int hf_ams_stateinitcmd = -1;
static int hf_ams_statebroadcast = -1;
static int hf_ams_cbdata = -1;
static int hf_ams_errorcode = -1;
static int hf_ams_invokeid = -1;
static int hf_ams_data = -1;

/*ads Commands */
static int hf_ams_adsindexgroup = -1;
static int hf_ams_adsindexoffset = -1;
static int hf_ams_adscblength = -1;
static int hf_ams_adsreadrequest = -1;
static int hf_ams_adsreadresponse = -1;
static int hf_ams_adsinvokeid = -1;
static int hf_ams_adsresult = -1;
static int hf_ams_adsdata = -1;
static int hf_ams_adswriterequest = -1;
static int hf_ams_adswriteresponse = -1;
static int hf_ams_adsreadwriterequest = -1;
static int hf_ams_adsreadwriteresponse = -1;
static int hf_ams_adscbreadlength = -1;
static int hf_ams_adscbwritelength = -1;
static int hf_ams_adsstate = -1;
static int hf_ams_adsdevicestate = -1;
static int hf_ams_adsnotificationhandle = -1;
static int hf_ams_adsreadstaterequest = -1;
static int hf_ams_adsreadstateresponse = -1;
static int hf_ams_adswritectrlrequest = -1;
static int hf_ams_adswritectrlresponse = -1;
static int hf_ams_adsreaddinforequest = -1;
static int hf_ams_adsreaddinforesponse = -1;
static int hf_ams_adsadddnrequest = -1;
static int hf_ams_adsadddnresponse = -1;
static int hf_ams_adsdeldnrequest = -1;
static int hf_ams_adsdeldnresponse = -1;
static int hf_ams_adsdnrequest = -1;
/* static int hf_ams_adsdnresponse = -1; */
/* static int hf_ams_adsnoteattrib = -1; */
/* static int hf_ams_adsnoteblocks = -1; */
/* static int hf_ams_adsversion = -1; */
static int hf_ams_adsdevicename = -1;
static int hf_ams_adsversionversion = -1;
static int hf_ams_adsversionrevision = -1;
static int hf_ams_adsversionbuild = -1;
static int hf_ams_adsnoteblocksstamps = -1;
/* static int hf_ams_adsnoteblocksstamp = -1; */
/* static int hf_ams_adstimestamp = -1; */
/* static int hf_ams_adssamplecnt = -1; */
/* static int hf_ams_adsnoteblockssample = -1; */
static int hf_ams_adstransmode = -1;
static int hf_ams_adsmaxdelay = -1;
static int hf_ams_adscycletime = -1;
/* static int hf_ams_adscmpmax = -1; */
/* static int hf_ams_adscmpmin = -1; */

static const value_string TransMode[] =
{
   {  0, "NO TRANS"},
   {  1, "CLIENT CYCLE"},
   {  2, "CLIENT ON CHANGE"},
   {  3, "SERVER CYCLE"},
   {  4, "SERVER ON CHANGE"},
   { 10, "CLIENT FIRST REQUEST"},
   {  0, NULL }
};

static const value_string ErrorCode[] =
{
   { ERR_NOERROR,                       "NO ERROR"},
   { ERR_INTERNAL,                      "INTERNAL"},
   { ERR_NORTIME,                       "NO RTIME"},
   { ERR_ALLOCLOCKEDMEM,                "ALLOC LOCKED MEM"},
   { ERR_INSERTMAILBOX,                 "INSERT MAILBOX"},
   { ERR_WRONGRECEIVEHMSG,              "WRONGRECEIVEHMSG"},
   { ERR_TARGETPORTNOTFOUND,            "TARGET PORT NOT FOUND"},
   { ERR_TARGETMACHINENOTFOUND,         "TARGET MACHINE NOT FOUND"},
   { ERR_UNKNOWNCMDID,                  "UNKNOWN CMDID"},
   { ERR_BADTASKID,                     "BAD TASKID"},
   { ERR_NOIO,                          "NOIO"},
   { ERR_UNKNOWNAMSCMD,                 "UNKNOWN AMSCMD"},
   { ERR_WIN32ERROR,                    "WIN32 ERROR"},
   { ERR_PORTNOTCONNECTED,              "PORT NOT CONNECTED"},
   { ERR_INVALIDAMSLENGTH,              "INVALID AMS LENGTH"},
   { ERR_INVALIDAMSNETID,               "INVALID AMS NETID"},
   { ERR_LOWINSTLEVEL,                  "LOW INST LEVEL"},
   { ERR_NODEBUGINTAVAILABLE,           "NO DEBUG INT AVAILABLE"},
   { ERR_PORTDISABLED,                  "PORT DISABLED"},
   { ERR_PORTALREADYCONNECTED,          "PORT ALREADY CONNECTED"},
   { ERR_AMSSYNC_W32ERROR,              "AMSSYNC_W32ERROR"},
   { ERR_AMSSYNC_TIMEOUT,               "AMSSYNC_TIMEOUT"},
   { ERR_AMSSYNC_AMSERROR,              "AMSSYNC_AMSERROR"},
   { ERR_AMSSYNC_NOINDEXINMAP,          "AMSSYNC_NOINDEXINMAP"},
   { ERR_INVALIDAMSPORT,                "INVALID AMSPORT"},
   { ERR_NOMEMORY,                      "NO MEMORY"},
   { ERR_TCPSEND,                       "TCP SEND"},
   { ERR_HOSTUNREACHABLE,               "HOST UNREACHABLE"},
   { ROUTERERR_NOLOCKEDMEMORY,          "ROUTERERR_NOLOCKEDMEMORY"},
   { ROUTERERR_RESIZEMEMORY,            "ROUTERERR_RESIZEMEMORY"},
   { ROUTERERR_MAILBOXFULL,             "ROUTERERR_MAILBOXFULL"},
   { ROUTERERR_DEBUGBOXFULL,            "ROUTERERR_DEBUGBOXFULL"},
   { ROUTERERR_UNKNOWNPORTTYPE,         "ROUTERERR_UNKNOWNPORTTYPE"},
   { ROUTERERR_NOTINITIALIZED,          "ROUTERERR_NOTINITIALIZED"},
   { ROUTERERR_PORTALREADYINUSE,        "ROUTERERR_PORTALREADYINUSE"},
   { ROUTERERR_NOTREGISTERED,           "ROUTERERR_NOTREGISTERED   "},
   { ROUTERERR_NOMOREQUEUES,            "ROUTERERR_NOMOREQUEUES"},
   { ROUTERERR_INVALIDPORT,             "ROUTERERR_INVALIDPORT"},
   { ROUTERERR_NOTACTIVATED,            "ROUTERERR_NOTACTIVATED"},
   { IOERR_INTERNAL,                    "IOERR_INTERNAL"},
   { IOERR_BADCARDNO,                   "IOERR_BADCARDNO"},
   { IOERR_INVALIDCARDADDR,             "IOERR_INVALIDCARDADDR"},
   { IOERR_CDLLISTFULL,                 "IOERR_CDLLISTFULL"},
   { IOERR_BADCDLPARAM,                 "IOERR_BADCDLPARAM"},
   { IOERR_OPENIOFAILED,                "IOERR_OPENIOFAILED"},
   { IOERR_RESETIOFAILED,               "IOERR_RESETIOFAILED"},
   { IOERR_UNKNOWNDEVICE,               "IOERR_UNKNOWNDEVICE"},
   { IOERR_UNKNOWNDEVICEID,             "IOERR_UNKNOWNDEVICEID"},
   { IOERR_UNKNOWNIMAGEID,              "IOERR_UNKNOWNIMAGEID"},
   { IOERR_GETIOSTATE,                  "IOERR_GETIOSTATE"},
   { IOERR_BADIMAGEID,                  "IOERR_BADIMAGEID"},
   { IOERR_NOMORECLIENTSPACE,           "IOERR_NOMORECLIENTSPACE"},
   { IOERR_CLIENTINFONOTFOUND,          "IOERR_CLIENTINFONOTFOUND"},
   { IOERR_CDLNOTINUSE,                 "IOERR_CDLNOTINUSE"},
   { IOERR_TIMEOUTWITHDEVICE,           "IOERR_TIMEOUTWITHDEVICE"},
   { IOERR_C1220FUNC_1,                 "IOERR_C1220FUNC_1"},
   { IOERR_C1220FUNC_9,                 "IOERR_C1220FUNC_9"},
   { IOERR_C1220FUNC_C,                 "IOERR_C1220FUNC_C"},
   { IOERR_C1220FUNC_10,                "IOERR_C1220FUNC_10"},
   { IOERR_C1220FUNC_1_MAXSEND,         "IOERR_C1220FUNC_1_MAXSEND"},
   { IOERR_C1220FUNC_1_ADDRSET,         "IOERR_C1220FUNC_1_ADDRSET"},
   { IOERR_C1220FUNC_1_BREAK,           "IOERR_C1220FUNC_1_BREAK"},
   { IOERR_C1220FUNC_1_BREAK0,          "IOERR_C1220FUNC_1_BREAK0"},
   { IOERR_C1220FUNC_1_BREAK1,          "IOERR_C1220FUNC_1_BREAK1"},
   { IOERR_C1220FUNC_1_BREAK2,          "IOERR_C1220FUNC_1_BREAK2"},
   { IOERR_C1220FUNC_1_BREAK3,          "IOERR_C1220FUNC_1_BREAK3"},
   { IOERR_C1220FUNC_1_BREAK4,          "IOERR_C1220FUNC_1_BREAK4"},
   { IOERR_C1220FUNC_1_BREAK5,          "IOERR_C1220FUNC_1_BREAK5"},
   { IOERR_C1220FUNC_1_BREAK6,          "IOERR_C1220FUNC_1_BREAK6"},
   { IOERR_C1220FUNC_1_BREAK7,          "IOERR_C1220FUNC_1_BREAK7"},
   { IOERR_C1220FUNC_1_BREAK8,          "IOERR_C1220FUNC_1_BREAK8"},
   { IOERR_C1220FUNC_1_BREAK9,          "IOERR_C1220FUNC_1_BREAK9"},
   { IOERR_C1220FUNC_1_BREAK10,         "IOERR_C1220FUNC_1_BREAK10"},
   { IOERR_C1220FUNC_1_BREAK11,         "IOERR_C1220FUNC_1_BREAK11"},
   { IOERR_C1220FUNC_1_BREAK12,         "IOERR_C1220FUNC_1_BREAK12"},
   { IOERR_C1220FUNC_1_BREAK13,         "IOERR_C1220FUNC_1_BREAK13"},
   { IOERR_C1220FUNC_1_BREAK14,          "IOERR_C1220FUNC_1_BREAK14"},
   { IOERR_C1220FUNC_1_BREAK15,         "IOERR_C1220FUNC_1_BREAK15"},
   { IOERR_C1220FUNC_1_BREAK16,         "IOERR_C1220FUNC_1_BREAK16"},
   { IOERR_SPC3DEVINITDP,               "IOERR_SPC3DEVINITDP"},
   { IOERR_SPC3UPDATEOUTPUT,            "IOERR_SPC3UPDATEOUTPUT"},
   { IOERR_CIF30READDIAG,               "IOERR_CIF30READDIAG"},
   { IOERR_CIF30COMMNOTSTARTED,         "IOERR_CIF30COMMNOTSTARTED"},
   { IOERR_CIF30SLAVEPARASIZE,          "IOERR_CIF30SLAVEPARASIZE"},
   { IOERR_CIF30NOPARAS,                "IOERR_CIF30NOPARAS"},
   { IOERR_CIF30SLAVEERROR,             "IOERR_CIF30SLAVEERROR"},
   { IOERR_CIF30WATCHDOGEXPIRED,        "IOERR_CIF30WATCHDOGEXPIRED"},
   { IOERR_UNKNOWNDEVICECMD,            "IOERR_UNKNOWNDEVICECMD"},
   { IOERR_CIF40MESSAGEHANDLING,        "IOERR_CIF40MESSAGEHANDLING"},
   { IOERR_CIF40PARAERROR,              "IOERR_CIF40PARAERROR"},
   { IOERR_CIF40WATCHDOGEXPIRED,        "IOERR_CIF40WATCHDOGEXPIRED"},
   { IOERR_CIF40FLAGERROR,              "IOERR_CIF40FLAGERROR"},
   { IOERR_CIF40COMMNOTSTARTED,         "IOERR_CIF40COMMNOTSTARTED"},
   { IOERR_CIF40READDIAG,               "IOERR_CIF40READDIAG"},
   { IOERR_CIF40SLAVEERROR,             "IOERR_CIF40SLAVEERROR"},
   { IOERR_CIF40GLOBALERROR,            "IOERR_CIF40GLOBALERROR"},
   { IOERR_CIF40CONFIGLIST,             "IOERR_CIF40CONFIGLIST"},
   { IOERR_CP5412A2SLAVEPARASIZE,       "IOERR_CP5412A2SLAVEPARASIZE"},
   { IOERR_CP5412A2NOPARAS,             "IOERR_CP5412A2NOPARAS"},
   { IOERR_CP5412A2SLAVEERROR,          "IOERR_CP5412A2SLAVEERROR"},
   { IOERR_CP5412A2FATAL,               "IOERR_CP5412A2FATAL"},
   { IOERR_CP5412A2MAILBOXUSED,         "IOERR_CP5412A2MAILBOXUSED"},
   { IOERR_BEGINCONFIGWHILETICKER,      "IOERR_BEGINCONFIGWHILETICKER"},
   { IOERR_UNEXPECTEDBOXCOUNT,          "IOERR_UNEXPECTEDBOXCOUNT"},
   { IOERR_C1200CHECKADDR,              "IOERR_C1200CHECKADDR"},
   { IOERR_C1200INTENSITYTEST,          "IOERR_C1200INTENSITYTEST"},
   { IOERR_NOIMAGE,                     "IOERR_NOIMAGE"},
   { IOERR_INVALIDIMAGEOFFSSIZE,        "IOERR_INVALIDIMAGEOFFSSIZE"},
   { IOERR_FORCESCOUNTEXCEEDEDMAXIMUM,  "IOERR_FORCESCOUNTEXCEEDEDMAXIMUM"},
   { IOERR_SERCOSLIFECOUNTERERR,        "IOERR_SERCOSLIFECOUNTERERR"},
   { IOERR_C1220NOTFOUND,               "IOERR_C1220NOTFOUND"},
   { IOERR_AMSDEVICENOAMSINTF,          "IOERR_AMSDEVICENOAMSINTF"},
   { IOERR_AMSDEVICEAMSCMDIDNOTSUPP,    "IOERR_AMSDEVICEAMSCMDIDNOTSUPP"},
   { IOERR_AMSDEVICEAMSSERVICERUNNING,  "IOERR_AMSDEVICEAMSSERVICERUNNING"},
   { IOERR_PLCINTERFACE_BUSY,           "IOERR_PLCINTERFACE_BUSY"},
   { IOERR_PLCINTERFACE_FAULT,          "IOERR_PLCINTERFACE_FAULT"},
   { IOERR_PLCINTERFACE_TIMEOUT,        "IOERR_PLCINTERFACE_TIMEOUT"},
   { IOERR_PLCINTERFACE_RESETTIMEOUT,   "IOERR_PLCINTERFACE_RESETTIMEOUT"},
   { IOERR_PLCINTERFACE_NODATAEXCH,     "IOERR_PLCINTERFACE_NODATAEXCH"},
   { IOERR_PLCINTERFACE_RESET,          "IOERR_PLCINTERFACE_RESET"},
   { IOERR_CP5412A2INVALIDADDR,         "IOERR_CP5412A2INVALIDADDR"},
   { IOERR_CP5412A2INVALIDPORT,         "IOERR_CP5412A2INVALIDPORT"},
   { IOERR_AMSDEVICEBADBOXNO,           "IOERR_AMSDEVICEBADBOXNO"},
   { IOERR_AMSDEVICEBADTYPE,            "IOERR_AMSDEVICEBADTYPE"},
   { IOERR_AMSDEVICEILLEGALADDRESS,     "IOERR_AMSDEVICEILLEGALADDRESS"},
   { IOERR_CP5412A2INVALIDBOX,          "IOERR_CP5412A2INVALIDBOX"},
   { IOERR_AMSDEVICEFIFOOVERFLOW,       "IOERR_AMSDEVICEFIFOOVERFLOW"},
   { IOERR_AMSDEVICEAMSSEQUENCEERROR,   "IOERR_AMSDEVICEAMSSEQUENCEERROR"},
   { IOERR_CP5412A2DPV1SYNTAXERROR,     "IOERR_CP5412A2DPV1SYNTAXERROR"},
   { IOERR_CP5412A2DEVICENOTRUNNING,    "IOERR_CP5412A2DEVICENOTRUNNING"},
   { IOERR_AMSDEVICENOTRUNNING,         "IOERR_AMSDEVICENOTRUNNING"},
   { IOERR_AMSDEVICEBOXNOTDEFINED,      "IOERR_AMSDEVICEBOXNOTDEFINED"},
   { IOERR_CP5412A2BADSERVICEPARA,      "IOERR_CP5412A2BADSERVICEPARA"},
   { IOERR_CP5412A2FIFOOVERFLOW,        "IOERR_CP5412A2FIFOOVERFLOW"},
   { IOERR_COMPORTOPENFAILED,           "IOERR_COMPORTOPENFAILED"},
   { IOERR_CIF30BADMESSAGERESPONSE,     "IOERR_CIF30BADMESSAGERESPONSE"},
   { IOERR_CIF30DELETEDATABASE,         "IOERR_CIF30DELETEDATABASE"},
   { IOERR_CIF30STARTSEQFAILED,         "IOERR_CIF30STARTSEQFAILED"},
   { IOERR_CIF30DOWNLOADFAILED,         "IOERR_CIF30DOWNLOADFAILED"},
   { IOERR_CIF30ENDSEQFAILED,           "IOERR_CIF30ENDSEQFAILED"},
   { IOERR_CIF30BUSLOADFAILED,          "IOERR_CIF30BUSLOADFAILED"},
   { IOERR_PLCINTERFACE_RESETREQ,       "IOERR_PLCINTERFACE_RESETREQ"},
   { IOERR_CP5412A2INVALIDCYCLETICKS,   "IOERR_CP5412A2INVALIDCYCLETICKS"},
   { IOERR_CP5412A2DPBUSFAULT,          "IOERR_CP5412A2DPBUSFAULT"},
   { IOERR_INVALIDTERMCONFIG,           "IOERR_INVALIDTERMCONFIG"},
   { IOERR_SERCANSBREAK,                "IOERR_SERCANSBREAK"},
   { IOERR_SERCANSPHASE0,               "IOERR_SERCANSPHASE0"},
   { IOERR_SERCANSPHASE1,               "IOERR_SERCANSPHASE1"},
   { IOERR_SERCANSPHASE2,               "IOERR_SERCANSPHASE2"},
   { IOERR_SERCANSPHASE3,               "IOERR_SERCANSPHASE3"},
   { IOERR_SERCANSPHASE4,               "IOERR_SERCANSPHASE4"},
   { IOERR_SERCANSNCSERVICECHNFAILED,   "IOERR_SERCANSNCSERVICECHNFAILED"},
   { IOERR_RESOURCECONFICT,             "IOERR_RESOURCECONFICT"},
   { IOERR_C1220INITSTRINGCOMM,         "IOERR_C1220INITSTRINGCOMM"},
   { IOERR_C1220REGSTRINGSLAVE,         "IOERR_C1220REGSTRINGSLAVE"},
   { IOERR_C1220STRREGFAULT,            "IOERR_C1220STRREGFAULT"},
   { IOERR_IOSTATEBUSY,                 "IOERR_IOSTATEBUSY"},
   { IOERR_IBSSCITWATCHDOGEXPIRED,      "IOERR_IBSSCITWATCHDOGEXPIRED"},
   { IOERR_IBSSCITSYNCMAILBOXERROR,     "IOERR_IBSSCITSYNCMAILBOXERROR"},
   { IOERR_IBSSCITCONFIRMDIAGERROR,     "IOERR_IBSSCITCONFIRMDIAGERROR"},
   { IOERR_IBSSCITCREATECFGERROR,       "IOERR_IBSSCITCREATECFGERROR"},
   { 0,                                 NULL }
};

static const value_string AdsErrorMode[] =
{
   { ADSERR_NOERR,                       "NO ERROR", },
   { ADSERR_DEVICE_ERROR,                "ERROR", },
   { ADSERR_DEVICE_SRVNOTSUPP,           "SRV NOT SUPP", },
   { ADSERR_DEVICE_INVALIDGRP,           "INVALID GRP", },
   { ADSERR_DEVICE_INVALIDOFFSET,        "INVALID OFFSET", },
   { ADSERR_DEVICE_INVALIDACCESS,        "INVALID ACCESS", },
   { ADSERR_DEVICE_INVALIDSIZE,          "INVALID SIZE", },
   { ADSERR_DEVICE_INVALIDDATA,          "INVALID DATA", },
   { ADSERR_DEVICE_NOTREADY,             "NOT READY", },
   { ADSERR_DEVICE_BUSY,                 "BUSY", },
   { ADSERR_DEVICE_INVALIDCONTEXT,       "INVALID CONTEXT", },
   { ADSERR_DEVICE_NOMEMORY,             "NO MEMORY", },
   { ADSERR_DEVICE_INVALIDPARM,          "INVALID PARM", },
   { ADSERR_DEVICE_NOTFOUND,             "NOT FOUND", },
   { ADSERR_DEVICE_SYNTAX,               "SYNTAX", },
   { ADSERR_DEVICE_INCOMPATIBLE,         "INCOMPATIBLE", },
   { ADSERR_DEVICE_EXISTS,               "EXISTS", },
   { ADSERR_DEVICE_SYMBOLNOTFOUND,       "SYMBOL NOT FOUND", },
   { ADSERR_DEVICE_SYMBOLVERSIONINVALID, "SYMBOL VERSION INVALID", },
   { ADSERR_DEVICE_INVALIDSTATE,         "INVALID STATE", },
   { ADSERR_DEVICE_TRANSMODENOTSUPP,     "TRANS MODE NOT SUPP", },
   { ADSERR_DEVICE_NOTIFYHNDINVALID,     "NOTIFY HND INVALID", },
   { ADSERR_DEVICE_CLIENTUNKNOWN,        "CLIENT UNKNOWN", },
   { ADSERR_DEVICE_NOMOREHDLS,           "NO MORE HDLS", },
   { ADSERR_DEVICE_INVALIDWATCHSIZE,     "INVALID WATCHSIZE", },
   { ADSERR_DEVICE_NOTINIT,              "NOT INIT", },
   { ADSERR_DEVICE_TIMEOUT,              "TIMEOUT", },
   { ADSERR_DEVICE_NOINTERFACE,          "NO INTERFACE", },
   { ADSERR_DEVICE_INVALIDINTERFACE,     "INVALID INTERFACE", },
   { ADSERR_DEVICE_INVALIDCLSID,         "INVALID CLSID", },
   { ADSERR_DEVICE_INVALIDOBJID,         "INVALID OBJID", },
   { ADSERR_DEVICE_PENDING,              "PENDING", },
   { ADSERR_DEVICE_ABORTED,              "ABORTED", },
   { ADSERR_DEVICE_WARNING,              "WARNING", },
   { ADSERR_DEVICE_INVALIDARRAYIDX,      "INVALID ARRAY IDX", },
   { ADSERR_CLIENT_ERROR,                "CLIENT ERROR", },
   { ADSERR_CLIENT_INVALIDPARM,          "CLIENT INVALID PARM", },
   { ADSERR_CLIENT_LISTEMPTY,            "CLIENT LIST EMPTY", },
   { ADSERR_CLIENT_VARUSED,              "CLIENT VAR USED", },
   { ADSERR_CLIENT_DUPLINVOKEID,         "CLIENT DUPL INVOKEID", },
   { ADSERR_CLIENT_SYNCTIMEOUT,          "CLIENT SYNC TIMEOUT", },
   { ADSERR_CLIENT_W32ERROR,             "CLIENT W32ERROR", },
   { ADSERR_CLIENT_TIMEOUTINVALID,       "CLIENT TIMEOUT INVALID", },
   { ADSERR_CLIENT_PORTNOTOPEN,          "CLIENT PORT NOT OPEN", },
   { ADSERR_CLIENT_NOAMSADDR,            "CLIENT NO AMS ADDR", },
   { ADSERR_CLIENT_SYNCINTERNAL,         "CLIENT SYNC INTERNAL", },
   { ADSERR_CLIENT_ADDHASH,              "CLIENT ADD HASH", },
   { ADSERR_CLIENT_REMOVEHASH,           "CLIENT REMOVE HASH", },
   { ADSERR_CLIENT_NOMORESYM,            "CLIENT NO MORE SYM", },
   { ADSERR_CLIENT_SYNCRESINVALID,       "CLIENT SYNC RES INVALID", },
   { ADSERR_CLIENT_SYNCPORTLOCKED,       "CLIENT SYNC PORT LOCKED", },
   {  0,                                 NULL }
};


/* AMS Command Id
 * http://infosys.beckhoff.com/english.php?content=../content/1033/tcadsamsspec/html/tcadsamsspec_adscmd_readstate.htm&id=10652
 */
static const value_string AMS_CommandId_vals[] =
{
   { ADSSRVID_INVALID,                   "Invalid", },
   { ADSSRVID_READDEVICEINFO,            "ADS Read Device Info", },
   { ADSSRVID_READ,                      "ADS Read", },
   { ADSSRVID_WRITE,                     "ADS Write", },
   { ADSSRVID_READSTATE,                 "ADS Read State", },
   { ADSSRVID_WRITECTRL,                 "ADS Write Control", },
   { ADSSRVID_ADDDEVICENOTE,             "ADS Add Device Notification", },
   { ADSSRVID_DELDEVICENOTE,             "ADS Delete Device Notification", },
   { ADSSRVID_DEVICENOTE,                "ADS Device Notification", },
   { ADSSRVID_READWRITE,                 "ADS Read Write", },
   {  0,                                 NULL }
};


static void NetIdFormater(tvbuff_t *tvb, guint offset, char *szText, gint nMax)
{
   g_snprintf ( szText, nMax, "%d.%d.%d.%d.%d.%d", tvb_get_guint8(tvb, offset),
      tvb_get_guint8(tvb, offset+1),
      tvb_get_guint8(tvb, offset+2),
      tvb_get_guint8(tvb, offset+3),
      tvb_get_guint8(tvb, offset+4),
      tvb_get_guint8(tvb, offset+5)
      );
}



/*ams*/
static gint dissect_ams_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
   proto_item *ti, *anItem;
   proto_tree *ams_tree = NULL, *ams_adstree, *ams_statetree;
   guint ams_length = tvb_reported_length(tvb);
   guint16 stateflags = 0;
   guint16 cmdId = 0;
   guint32 cbdata = 0;

   char szText[200];
   int nMax = sizeof(szText)-1;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "AMS");

   col_clear(pinfo->cinfo, COL_INFO);

   if( ams_length < AmsHead_Len )
      return offset;

  if (tree)
  {
     ti = proto_tree_add_item(tree, proto_ams, tvb, 0, -1, ENC_NA);
     ams_tree = proto_item_add_subtree(ti, ett_ams);

     NetIdFormater(tvb, offset, szText, nMax);
     proto_tree_add_string(ams_tree, hf_ams_targetnetid, tvb, offset, AmsNetId_Len, szText);
     offset += AmsNetId_Len;

     proto_tree_add_item(ams_tree, hf_ams_targetport, tvb, offset, (int)sizeof(guint16), ENC_LITTLE_ENDIAN);
     offset += (int)sizeof(guint16);

     NetIdFormater(tvb, offset, szText, nMax);
     proto_tree_add_string(ams_tree, hf_ams_sendernetid, tvb, offset, AmsNetId_Len, szText);
     offset += AmsNetId_Len;

     proto_tree_add_item(ams_tree, hf_ams_senderport, tvb, offset, (int)sizeof(guint16), ENC_LITTLE_ENDIAN);
     offset += (int)sizeof(guint16);

     proto_tree_add_item(ams_tree, hf_ams_cmdid, tvb, offset, (int)sizeof(guint16), ENC_LITTLE_ENDIAN);
     cmdId = tvb_get_letohs(tvb, offset);
     offset+=(int)sizeof(guint16);

     anItem = proto_tree_add_item(ams_tree, hf_ams_stateflags, tvb, offset, (int)sizeof(guint16), ENC_LITTLE_ENDIAN);
     ams_statetree = proto_item_add_subtree(anItem, ett_ams_stateflags);
     proto_tree_add_item(ams_statetree, hf_ams_stateresponse,tvb, offset, (int)sizeof(guint16), ENC_LITTLE_ENDIAN);
     proto_tree_add_item(ams_statetree, hf_ams_statenoreturn,tvb, offset, (int)sizeof(guint16), ENC_LITTLE_ENDIAN);
     proto_tree_add_item(ams_statetree, hf_ams_stateadscmd,tvb, offset, (int)sizeof(guint16), ENC_LITTLE_ENDIAN);
     proto_tree_add_item(ams_statetree, hf_ams_statesyscmd,tvb, offset, (int)sizeof(guint16), ENC_LITTLE_ENDIAN);
     proto_tree_add_item(ams_statetree, hf_ams_statehighprio,tvb, offset, (int)sizeof(guint16), ENC_LITTLE_ENDIAN);
     proto_tree_add_item(ams_statetree, hf_ams_statetimestampadded,tvb, offset, (int)sizeof(guint16), ENC_LITTLE_ENDIAN);
     proto_tree_add_item(ams_statetree, hf_ams_stateudp,tvb, offset, (int)sizeof(guint16), ENC_LITTLE_ENDIAN);
     proto_tree_add_item(ams_statetree, hf_ams_stateinitcmd,tvb, offset, (int)sizeof(guint16), ENC_LITTLE_ENDIAN);
     proto_tree_add_item(ams_statetree, hf_ams_statebroadcast,tvb, offset, (int)sizeof(guint16), ENC_LITTLE_ENDIAN);
     stateflags = tvb_get_letohs(tvb, offset);
     offset+=(int)sizeof(guint16);

     proto_tree_add_item(ams_tree, hf_ams_cbdata, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
	 cbdata = tvb_get_letohl(tvb,offset);
     offset+=(int)sizeof(guint32);

     proto_tree_add_item(ams_tree, hf_ams_errorcode, tvb, offset, (int)sizeof(guint32),ENC_LITTLE_ENDIAN);
     offset+=(int)sizeof(guint32);

     proto_tree_add_item(ams_tree, hf_ams_invokeid, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
     offset+=(int)sizeof(guint32);
  }
  else
  {
     offset+=AmsHead_Len;
  }

  if ( (stateflags & AMSCMDSF_ADSCMD) != 0 )
  {
     /* ADS */
     if ( (stateflags & AMSCMDSF_RESPONSE) == 0 )
     {
        /* Request */
        switch ( cmdId )
        {
        case ADSSRVID_READ:
           {
              col_append_str(pinfo->cinfo, COL_INFO, "ADS Read Request");

              if( tree )
              {
                 anItem = proto_tree_add_item(ams_tree, hf_ams_adsreadrequest, tvb, offset, ams_length-offset, ENC_NA);
                 if( ams_length-offset >= TAdsReadReq_Len )
                 {
                    ams_adstree = proto_item_add_subtree(anItem, ett_ams_adsreadrequest);
                    proto_tree_add_item(ams_adstree, hf_ams_adsindexgroup, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint32);

                    proto_tree_add_item(ams_adstree, hf_ams_adsindexoffset, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint32);

                    proto_tree_add_item(ams_adstree, hf_ams_adscblength, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint32);
                 }
              }
           }
           break;
        case ADSSRVID_WRITE:
           {
              col_append_str(pinfo->cinfo, COL_INFO, "ADS Write Request");

              if( tree )
              {
                 anItem = proto_tree_add_item(ams_tree, hf_ams_adswriterequest, tvb, offset, ams_length-offset, ENC_NA);
                 if( ams_length-offset >= TAdsWriteReq_Len - (int)sizeof(guint16) )
                 {
                    ams_adstree = proto_item_add_subtree(anItem, ett_ams_adswriterequest);
                    proto_tree_add_item(ams_adstree, hf_ams_adsindexgroup, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint32);

                    proto_tree_add_item(ams_adstree, hf_ams_adsindexoffset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint32);

                    proto_tree_add_item(ams_adstree, hf_ams_adscblength, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint32);

                    proto_tree_add_item(ams_adstree, hf_ams_adsdata, tvb, offset, ams_length-offset, ENC_NA);
                 }
              }
           }
           break;
        case ADSSRVID_READWRITE:
           {
              col_append_str(pinfo->cinfo, COL_INFO, "ADS Read Write Request");

              if( tree )
              {
                 anItem = proto_tree_add_item(ams_tree, hf_ams_adsreadwriterequest, tvb, offset, ams_length-offset, ENC_NA);
                 if( ams_length-offset >= TAdsReadWriteReq_Len - (int)sizeof(guint16))
                 {
                    ams_adstree = proto_item_add_subtree(anItem, ett_ams_adsreadwriterequest);
                    proto_tree_add_item(ams_adstree, hf_ams_adsindexgroup, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint32);

                    proto_tree_add_item(ams_adstree, hf_ams_adsindexoffset, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint32);

                    proto_tree_add_item(ams_adstree, hf_ams_adscbreadlength, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint32);

                    proto_tree_add_item(ams_adstree, hf_ams_adscbwritelength, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint32);

                    proto_tree_add_item(ams_adstree, hf_ams_adsdata, tvb, offset, ams_length-offset, ENC_NA);
                 }
              }
           }
           break;
        case ADSSRVID_READSTATE:
           {
              col_append_str(pinfo->cinfo, COL_INFO, "ADS Read State Request");

              if( tree && cbdata !=0 )
              {
                 anItem = proto_tree_add_item(ams_tree, hf_ams_adsreadstaterequest, tvb, offset, ams_length-offset, ENC_NA);
                 if( ams_length-offset >= TAdsReadStateReq_Len )
                 {
                    ams_adstree = proto_item_add_subtree(anItem, ett_ams_adsreadstaterequest);
                    proto_tree_add_item(ams_adstree, hf_ams_adsinvokeid, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                 }
              }
           }
           break;
        case ADSSRVID_WRITECTRL:
           {
              col_append_str(pinfo->cinfo, COL_INFO, "ADS Write Control Request");

              if( tree )
              {
                 anItem = proto_tree_add_item(ams_tree, hf_ams_adswritectrlrequest, tvb, offset, ams_length-offset, ENC_NA);
                 if( ams_length-offset >= TAdsWriteControlReq_Len - (int)sizeof(guint16) )
                 {
                    ams_adstree = proto_item_add_subtree(anItem, ett_ams_adswritectrlrequest);
                    proto_tree_add_item(ams_adstree, hf_ams_adsstate, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint16);

                    proto_tree_add_item(ams_adstree, hf_ams_adsdevicestate, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint16);

                    proto_tree_add_item(ams_adstree, hf_ams_adscblength, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint32);

                    proto_tree_add_item(ams_adstree, hf_ams_adsdata, tvb, offset, ams_length-offset, ENC_NA);
                 }
              }
           }
           break;
        case ADSSRVID_READDEVICEINFO:
           {
              col_append_str(pinfo->cinfo, COL_INFO, "ADS Read Device Info Request");

              if( tree && cbdata !=0 )
              {
                 anItem = proto_tree_add_item(ams_tree, hf_ams_adsreaddinforequest, tvb, offset, ams_length-offset, ENC_NA);
                 if( ams_length-offset >= TAdsReadDeviceInfoReq_Len )
                 {
                    ams_adstree = proto_item_add_subtree(anItem, ett_ams_adsreaddinforequest);
                    proto_tree_add_item(ams_adstree, hf_ams_adsresult, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                 }
              }
           }
           break;
        case ADSSRVID_ADDDEVICENOTE:
           {
              col_append_str(pinfo->cinfo, COL_INFO, "ADS Add Device Notification Request");

              if( tree )
              {
                 anItem = proto_tree_add_item(ams_tree, hf_ams_adsadddnrequest, tvb, offset, ams_length-offset, ENC_NA);
                 if( ams_length-offset >= TAdsAddDeviceNotificationReq_Len )
                 {
                    ams_adstree = proto_item_add_subtree(anItem, ett_ams_adsadddnrequest);
                    proto_tree_add_item(ams_adstree, hf_ams_adsindexgroup, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint32);

                    proto_tree_add_item(ams_adstree, hf_ams_adsindexoffset, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint32);

                    proto_tree_add_item(ams_adstree, hf_ams_adscblength, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint32);

                    proto_tree_add_item(ams_adstree, hf_ams_adstransmode, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint32);

                    proto_tree_add_item(ams_adstree, hf_ams_adsmaxdelay, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint32);

                    proto_tree_add_item(ams_adstree, hf_ams_adscycletime, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint32);
                 }
              }
           }
           break;
        case ADSSRVID_DELDEVICENOTE:
           {
              col_append_str(pinfo->cinfo, COL_INFO, "ADS Delete Device Notification Request");

              if( tree )
              {
                 anItem = proto_tree_add_item(ams_tree, hf_ams_adsdeldnrequest, tvb, offset, ams_length-offset, ENC_NA);
                 if( ams_length-offset >= TAdsDelDeviceNotificationReq_Len )
                 {
                    ams_adstree = proto_item_add_subtree(anItem, ett_ams_adsdeldnrequest);
                    proto_tree_add_item(ams_adstree, hf_ams_adsnotificationhandle, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                 }
              }
           }
           break;
        case ADSSRVID_DEVICENOTE:
           {
              col_append_str(pinfo->cinfo, COL_INFO, "ADS Device Notification Request");

              if( tree )
              {
                 /*guint32 cbLength;
                 guint32 nStamps;*/

                 anItem = proto_tree_add_item(ams_tree, hf_ams_adsdnrequest, tvb, offset, ams_length-offset, ENC_NA);
                 if( ams_length-offset >= TAdsDeviceNotificationReq_Len )
                 {
                    ams_adstree = proto_item_add_subtree(anItem, ett_ams_adsdnrequest);
                    proto_tree_add_item(ams_adstree, hf_ams_adscblength, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                    /*cbLength = tvb_get_letohs(tvb, offset);*/
                    offset+=(int)sizeof(guint32);

                    proto_tree_add_item(ams_adstree, hf_ams_adsnoteblocksstamps, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                    /*nStamps = tvb_get_letohs(tvb, offset);*/
                    offset+=(int)sizeof(guint32);

                    /*ToDo: dissect noteblocks*/
                 }
              }
           }
           break;
        }
     }
     else
     {
        /* Response */
        switch ( cmdId )
        {
        case ADSSRVID_READ:
           {
              col_append_str(pinfo->cinfo, COL_INFO, "ADS Read Response");

              if( tree )
              {
                 anItem = proto_tree_add_item(ams_tree, hf_ams_adsreadresponse, tvb, offset, ams_length-offset, ENC_NA);
                 if( ams_length-offset >= TAdsReadRes_Len - (int)sizeof(guint16) )
                 {
                    ams_adstree = proto_item_add_subtree(anItem, ett_ams_adsreadresponse);
                    proto_tree_add_item(ams_adstree, hf_ams_adsresult, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint32);

                    proto_tree_add_item(ams_adstree, hf_ams_adscblength, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint32);

                    proto_tree_add_item(ams_adstree, hf_ams_adsdata, tvb, offset, ams_length-offset, ENC_NA);
                 }
              }
           }
           break;
        case ADSSRVID_WRITE:
           {
              col_append_str(pinfo->cinfo, COL_INFO, "ADS Write Response");

              if( tree )
              {
                 anItem = proto_tree_add_item(ams_tree, hf_ams_adswriteresponse, tvb, offset, ams_length-offset, ENC_NA);
                 if( ams_length-offset >= TAdsWriteRes_Len )
                 {
                    ams_adstree = proto_item_add_subtree(anItem, ett_ams_adswriteresponse);
                    proto_tree_add_item(ams_adstree, hf_ams_adsresult, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                 }
              }
           }
           break;
        case ADSSRVID_READWRITE:
           {
              col_append_str(pinfo->cinfo, COL_INFO, "ADS Read Write Response");

              if( tree )
              {
                 anItem = proto_tree_add_item(ams_tree, hf_ams_adsreadwriteresponse, tvb, offset, ams_length-offset, ENC_NA);
                 if( ams_length-offset >= TAdsReadWriteRes_Len - (int)sizeof(guint16) )
                 {
                    ams_adstree = proto_item_add_subtree(anItem, ett_ams_adsreadwriteresponse);
                    proto_tree_add_item(ams_adstree, hf_ams_adsresult, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint32);

                    proto_tree_add_item(ams_adstree, hf_ams_adscblength, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint32);

                    proto_tree_add_item(ams_adstree, hf_ams_adsdata, tvb, offset, ams_length-offset, ENC_NA);
                 }
              }
           }
           break;
        case ADSSRVID_READSTATE:
           {
              col_append_str(pinfo->cinfo, COL_INFO, "ADS Read State Response");

              if( tree )
              {
                 anItem = proto_tree_add_item(ams_tree, hf_ams_adsreadstateresponse, tvb, offset, ams_length-offset, ENC_NA);
                 if( ams_length-offset >= TAdsReadStateRes_Len )
                 {
                    ams_adstree = proto_item_add_subtree(anItem, ett_ams_adsreadstateresponse);
                    proto_tree_add_item(ams_adstree, hf_ams_adsresult, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint32);

                    proto_tree_add_item(ams_adstree, hf_ams_adsstate, tvb, offset, (int)sizeof(guint16), ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint32);

                    proto_tree_add_item(ams_adstree, hf_ams_adsdevicestate, tvb, offset, (int)sizeof(guint16), ENC_LITTLE_ENDIAN);
                 }
              }
           }
           break;
        case ADSSRVID_WRITECTRL:
           {
              col_append_str(pinfo->cinfo, COL_INFO, "ADS Write Control Response");

              if( tree )
              {
                 anItem = proto_tree_add_item(ams_tree, hf_ams_adswritectrlresponse, tvb, offset, ams_length-offset, ENC_NA);
                 if( ams_length-offset >= TAdsWriteControlRes_Len )
                 {
                    ams_adstree = proto_item_add_subtree(anItem, ett_ams_adswritectrlresponse);
                    proto_tree_add_item(ams_adstree, hf_ams_adsresult, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                 }
              }
           }
           break;
        case ADSSRVID_READDEVICEINFO:
           {
              col_append_str(pinfo->cinfo, COL_INFO, "ADS Read Device Info Response");

              if( tree )
              {
                 anItem = proto_tree_add_item(ams_tree, hf_ams_adsreaddinforesponse, tvb, offset, ams_length-offset, ENC_NA);
                 if( ams_length-offset >= TAdsReadDeviceInfoRes_Len )
                 {
                    ams_adstree = proto_item_add_subtree(anItem, ett_ams_adsreaddinforesponse);
                    proto_tree_add_item(ams_adstree, hf_ams_adsresult, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint32);

                    proto_tree_add_item(ams_adstree, hf_ams_adsversionversion, tvb, offset++, (int)sizeof(guint8), ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(ams_adstree, hf_ams_adsversionrevision, tvb, offset++, (int)sizeof(guint8), ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(ams_adstree, hf_ams_adsversionbuild, tvb, offset, (int)sizeof(guint16), ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint16);

                    proto_tree_add_item(ams_adstree, hf_ams_adsdevicename, tvb, offset, ams_length-offset, ENC_ASCII|ENC_NA);
                 }
              }
           }
           break;
        case ADSSRVID_ADDDEVICENOTE:
           {
              col_append_str(pinfo->cinfo, COL_INFO, "ADS Device Notification Response");

              if( tree )
              {
                 anItem = proto_tree_add_item(ams_tree, hf_ams_adsadddnresponse, tvb, offset, ams_length-offset, ENC_NA);
                 if( ams_length-offset >= TAdsAddDeviceNotificationRes_Len )
                 {
                    ams_adstree = proto_item_add_subtree(anItem, ett_ams_adsadddnresponse);
                    proto_tree_add_item(ams_adstree, hf_ams_adsresult, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                    offset+=(int)sizeof(guint32);

                    proto_tree_add_item(ams_adstree, hf_ams_adsnotificationhandle, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                 }
              }
           }
           break;
        case ADSSRVID_DELDEVICENOTE:
           {
              col_append_str(pinfo->cinfo, COL_INFO, "ADS Delete Device Notification Response");

              if( tree )
              {
                 anItem = proto_tree_add_item(ams_tree, hf_ams_adsdeldnresponse, tvb, offset, ams_length-offset, ENC_NA);
                 if( ams_length-offset >= TAdsDelDeviceNotificationRes_Len )
                 {
                    ams_adstree = proto_item_add_subtree(anItem, ett_ams_adsdeldnresponse);
                    proto_tree_add_item(ams_adstree, hf_ams_adsresult, tvb, offset, (int)sizeof(guint32), ENC_LITTLE_ENDIAN);
                 }
              }
           }
           break;
        }
     }
  }
  else
  {
    if ( (stateflags & AMSCMDSF_RESPONSE) == 0 )
       col_append_str(pinfo->cinfo, COL_INFO, "AMS Request");
    else
       col_append_str(pinfo->cinfo, COL_INFO, "AMS Response");
    if( tree && ams_length-offset > 0 )
        proto_tree_add_item(ams_tree, hf_ams_data, tvb, offset, ams_length-offset, ENC_NA);
  }
return offset;
}

/*ams*/
static gint dissect_ams(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_ams_pdu(tvb, pinfo, tree, 0);
}

static gint dissect_amstcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if( TcpAdsParserHDR_Len > tvb_reported_length(tvb))
        return 0;

    return dissect_ams_pdu(tvb, pinfo, tree, TcpAdsParserHDR_Len);
}

void proto_register_ams(void)
{
   static const true_false_string flags_set_truth =
   {
      "Set",
      "Not set"
   };

   static hf_register_info hf[] =
   {
      { &hf_ams_sendernetid,
      { "AMS Sender Net Id", "ams.sendernetid",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_senderport,
      { "AMS Sender port", "ams.senderport",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_targetnetid,
      { "AMS Target Net Id", "ams.targetnetid",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_targetport,
      { "AMS Target port", "ams.targetport",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_cmdid,
      { "CmdId", "ams.cmdid",
      FT_UINT16, BASE_DEC, VALS(AMS_CommandId_vals), 0x0,
      NULL, HFILL }
      },
      { &hf_ams_stateflags,
      { "StateFlags", "ams.stateflags",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_stateresponse,
      { "RESPONSE", "ams.state_response",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), AMSCMDSF_RESPONSE,
      NULL, HFILL }
      },
      { &hf_ams_statenoreturn,
      { "NO RETURN", "ams.state_noreturn",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), AMSCMDSF_NORETURN,
      NULL, HFILL }
      },
      { &hf_ams_stateadscmd,
      { "ADS COMMAND", "ams.state_adscmd",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), AMSCMDSF_ADSCMD,
      NULL, HFILL }
      },
      { &hf_ams_statesyscmd,
      { "SYSTEM COMMAND", "ams.state_syscmd",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), AMSCMDSF_SYSCMD,
      NULL, HFILL }
      },
      { &hf_ams_statehighprio,
      { "HIGH PRIORITY COMMAND", "ams.state_highprio",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), AMSCMDSF_HIGHPRIO,
      NULL, HFILL }
      },
      { &hf_ams_statetimestampadded,
      { "TIMESTAMP ADDED", "ams.state_timestampadded",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), AMSCMDSF_TIMESTAMPADDED,
      NULL, HFILL }
      },
      { &hf_ams_stateudp,
      { "UDP COMMAND", "ams.state_udp",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), AMSCMDSF_UDP,
      NULL, HFILL }
      },
      { &hf_ams_stateinitcmd,
      { "INIT COMMAND", "ams.state_initcmd",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), AMSCMDSF_INITCMD,
      NULL, HFILL }
      },
      { &hf_ams_statebroadcast,
      { "BROADCAST", "ams.state_broadcast",
      FT_BOOLEAN, 16, TFS(&flags_set_truth), AMSCMDSF_BROADCAST,
      NULL, HFILL }
      },
      { &hf_ams_cbdata,
      { "cbData", "ams.cbdata",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_errorcode,
      { "ErrorCode", "ams.errorcode",
      FT_UINT32, BASE_HEX, VALS(ErrorCode), 0x0,
      NULL, HFILL }
      },
      { &hf_ams_invokeid,
      { "InvokeId", "ams.invokeid",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsdata,
      { "Data", "ams.ads_data",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_data,
      { "Data", "ams.data",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsindexgroup,
      { "IndexGroup", "ams.ads_indexgroup",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsindexoffset,
      { "IndexOffset", "ams.ads_indexoffset",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adscblength,
      { "CbLength", "ams.ads_cblength",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsreadrequest,
      { "ADS Read Request", "ams.ads_read_req",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsreadresponse,
      { "ADS Read Response", "ams.ads_read_res",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsinvokeid,
      { "InvokeId", "ams.ads_invokeid",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsresult,
      { "Result", "ams.adsresult",
      FT_UINT32, BASE_HEX, VALS(AdsErrorMode), 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adswriterequest,
      { "ADS Write Request", "ams.ads_write_req",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adswriteresponse,
      { "ADS Write Response", "ams.ads_write_res",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsreadwriterequest,
      { "ADS ReadWrite Request", "ams.ads_readwrite_req",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsreadwriteresponse,
      { "ADS ReadWrite Response", "ams.ads_readwrite_res",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adscbreadlength,
      { "CBReadLength", "ams.ads_cbreadlength",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adscbwritelength,
      { "CBWriteLength", "ams.ads_cbwritelength",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsstate,
      { "AdsState", "ams.ads_state",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsdevicestate,
      { "DeviceState", "ams.ads_devicestate",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsnotificationhandle,
      { "NotificationHandle", "ams.ads_notificationhandle",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsreadstaterequest,
      { "ADS Read State Request", "ams.ads_readstate_req",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsreadstateresponse,
      { "ADS Read State Response", "ams.ads_readstate_res",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adswritectrlrequest,
      { "ADS Write Ctrl Request", "ams.ads_writectrl_req",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adswritectrlresponse,
      { "ADS Write Ctrl Response", "ams.ads_writectrl_res",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsreaddinforequest,
      { "ADS Read Device Info Request", "ams.ads_readdinfo_req",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsreaddinforesponse,
      { "ADS Read Device Info Response", "ams.ads_readdinfo_res",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsadddnrequest,
      { "ADS Add Device Notification Request", "ams.ads_adddn_req",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsadddnresponse,
      { "ADS Add Device Notification Response", "ams.ads_adddn_res",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsdeldnrequest,
      { "ADS Delete Device Notification Request", "ams.ads_deldn_req",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsdeldnresponse,
      { "ADS Delete Device Notification Response", "ams.ads_deldn_res",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsdnrequest,
      { "ADS Device Notification Request", "ams.ads_dn_req",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
#if 0
      { &hf_ams_adsdnresponse,
      { "ADS Device Notification Response", "ams.ads_dn_res",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsnoteattrib,
      { "InvokeId", "ams.ads_noteattrib",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsnoteblocks,
      { "InvokeId", "ams.ads_noteblocks",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsversion,
      { "ADS Version", "ams.ads_version",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
      },
#endif
      { &hf_ams_adsdevicename,
      { "Device Name","ams.ads_devicename",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsversionversion,
      { "ADS Major Version", "ams.ads_versionversion",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsversionrevision,
      { "ADS Minor Version", "ams.ads_versionrevision",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsversionbuild,
      { "ADS Version Build", "ams.ads_versionbuild",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsnoteblocksstamps,
      { "Count of Stamps", "ams.ads_noteblocksstamps",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
      },
#if 0
      { &hf_ams_adsnoteblocksstamp,
      { "Notification Stamp", "ams.ads_noteblocksstamp",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adstimestamp,
      { "Time Stamp", "ams.ads_timestamp",
      FT_UINT64, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adssamplecnt,
      { "Count of Stamps", "ams.ads_samplecnt",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsnoteblockssample,
      { "Notification Sample", "ams.ads_noteblockssample",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
#endif
      { &hf_ams_adstransmode,
      { "Trans Mode", "ams.ads_transmode",
      FT_UINT32, BASE_DEC, VALS(TransMode), 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adsmaxdelay,
      { "Max Delay", "ams.ads_maxdelay",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adscycletime,
      { "Cycle Time", "ams.ads_cycletime",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
      },
#if 0
      { &hf_ams_adscmpmax,
      { "Cmp Mad", "ams.ads_cmpmax",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_ams_adscmpmin,
      { "Cmp Min", "ams.ads_cmpmin",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      }
#endif
   };

   static gint *ett[] =
   {
      &ett_ams,
      &ett_ams_stateflags,
      &ett_ams_adsreadrequest,
      &ett_ams_adsreadresponse,
      &ett_ams_adswriterequest,
      &ett_ams_adswriteresponse,
      &ett_ams_adsreadwriterequest,
      &ett_ams_adsreadwriteresponse,
      &ett_ams_adsreadstaterequest,
      &ett_ams_adsreadstateresponse,
      &ett_ams_adswritectrlrequest,
      &ett_ams_adswritectrlresponse,
      &ett_ams_adsreaddinforequest,
      &ett_ams_adsreaddinforesponse,
      &ett_ams_adsadddnrequest,
      &ett_ams_adsadddnresponse,
      &ett_ams_adsdeldnrequest,
      &ett_ams_adsdeldnresponse,
      &ett_ams_adsdnrequest
   };

   proto_ams = proto_register_protocol("AMS", "AMS", "ams");
   proto_register_field_array(proto_ams, hf, array_length(hf));
   proto_register_subtree_array(ett, array_length(ett));

   new_register_dissector("ams", dissect_ams, proto_ams);
}

/* The registration hand-off routing */

void proto_reg_handoff_ams(void)
{
   dissector_handle_t ams_handle, amstcp_handle;

   ams_handle = find_dissector("ams");
   amstcp_handle = new_create_dissector_handle( dissect_amstcp, proto_ams );
   dissector_add_uint("tcp.port", 0xbf02, amstcp_handle);
   dissector_add_uint("ecatf.type", 2, ams_handle);
}
